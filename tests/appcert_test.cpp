// Tests for src/appcert_cipher.cpp — the shared app-cert fetch's custom
// cipher (custom S-box AES-256-CTR), key-blob framing, CRT-limb -> PEM
// rebuild, and the embedded bootstrap values.
//
// The known-answer vectors are ported from
// tools/fetch_slicer_credentials.py --self-test (which itself cites the
// public appcert_decrypt_blob_test.cpp vectors), so this suite and the
// Python reference must always agree. The CRT round-trip builds a synthetic
// SKEY blob from a freshly generated RSA keypair and unwraps it end to end,
// finishing with a sign/verify against the ORIGINAL public key.
//
// Repo convention: int main() + CHECK (see tests/signing_test.cpp).

// OpenSSL 3 marks the low-level RSA_* accessors deprecated; the CRT rebuild
// under test legitimately uses them (see appcert_cipher.cpp).
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "obn/appcert.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#define CHECK(cond) do {                                                    \
    if (!(cond)) {                                                          \
        std::cerr << "FAIL " << __FILE__ << ":" << __LINE__                \
                  << ": " #cond "\n";                                       \
        return 1;                                                           \
    }                                                                       \
} while (0)

namespace {

// Fixed appcert cipher key: 00 01 ... 1f (mirrors appcert_cipher.cpp).
const unsigned char kKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

std::string hex_decode(const std::string& h)
{
    std::string out;
    out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

std::string hex_encode(const std::string& s)
{
    static const char* tbl = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        out.push_back(tbl[c >> 4]);
        out.push_back(tbl[c & 0xF]);
    }
    return out;
}

void u32le(std::string& out, std::uint32_t v)
{
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
}

struct BioDel { void operator()(BIO* p) const { BIO_free(p); } };
struct PkeyDel { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct RsaDel { void operator()(RSA* p) const { RSA_free(p); } };
struct BnDel { void operator()(BIGNUM* p) const { BN_free(p); } };
struct CtxDel { void operator()(BN_CTX* p) const { BN_CTX_free(p); } };
struct MdDel { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };

// --- KATs from fetch_slicer_credentials.py --self-test ---------------------

int test_keystream_kats()
{
    const std::string nonce = hex_decode("303c8f522a171b9a40dc8901");
    CHECK(nonce.size() == 12);
    // Feeding zeros returns the keystream itself. Block i of the keystream is
    // counter 2 + i, so zeros of length 3*(i+1) expose blocks 0..i.
    const std::string ks48 = obn::appcert::detail::ctr_xor(kKey, nonce, std::string(48, '\0'));
    CHECK(ks48.size() == 48);
    CHECK(hex_encode(ks48.substr(0, 16)) ==
          "c6bf1cc1b40dcc16443034d6dabe7b81"); // counter 2
    CHECK(hex_encode(ks48.substr(16, 16)) ==
          "a5dee6b960b56cf67aa24081f505a4b8"); // counter 3
    CHECK(hex_encode(ks48.substr(32, 16)) ==
          "a155d92625a1eb00d8901fef52a8f105"); // counter 4
    return 0;
}

int test_real_ct_header()
{
    const std::string nonce = hex_decode("303c8f522a171b9a40dc8901");
    const std::string ct = hex_decode(
        "9ffa5792b50dcc16443834d65abe7b81"
        "25dee6b9e0b56cf6faa240817505a4b8");
    CHECK(ct.size() == 32);
    const std::string pt = obn::appcert::detail::ctr_xor(kKey, nonce, ct);
    CHECK(hex_encode(pt) ==
          "59454b53010000000008000080000000"
          "80000000800000008000000080000000");
    // Wire magic 59 45 4b 53 = little-endian "SKEY" (ASCII "YEKS").
    CHECK(pt.substr(0, 4) == std::string("\x59\x45\x4B\x53"));
    return 0;
}

int test_ctr_roundtrip()
{
    const std::string nonce = hex_decode("000102030405060708090a0b");
    CHECK(nonce.size() == 12);
    std::string pt(704, '\0');
    pt[0] = '\x59'; pt[1] = '\x45'; pt[2] = '\x4B'; pt[3] = '\x53';
    pt[4] = '\x01';
    for (std::size_t i = 32; i < pt.size(); ++i)
        pt[i] = static_cast<char>((i * 7 + 3) & 0xFF);
    const std::string ct = obn::appcert::detail::ctr_xor(kKey, nonce, pt);
    CHECK(ct.size() == pt.size());
    CHECK(ct != pt);
    const std::string back = obn::appcert::detail::ctr_xor(kKey, nonce, ct);
    CHECK(back == pt);
    // A wrong nonce must not recover the SKEY magic.
    const std::string wrong = obn::appcert::detail::ctr_xor(
        kKey, hex_decode("303c8f522a171b9a40dc8901"), ct);
    CHECK(wrong.size() >= 4);
    CHECK(wrong.substr(0, 4) != pt.substr(0, 4));
    // Non-12-byte nonce is rejected outright.
    CHECK(obn::appcert::detail::ctr_xor(kKey, "short", "x").empty());
    return 0;
}

int test_b64url()
{
    CHECK(obn::appcert::detail::b64url_encode("person") == "cGVyc29u");
    CHECK(obn::appcert::detail::b64url_encode(std::string("\xFB\xFF")) == "-_8=");
    CHECK(obn::appcert::detail::b64url_encode("abc") == "YWJj");
    // b64url output must never contain '+' or '/'.
    const std::string blob(96, '\xFF');
    const std::string enc = obn::appcert::detail::b64url_encode(blob);
    CHECK(enc.find('+') == std::string::npos);
    CHECK(enc.find('/') == std::string::npos);
    return 0;
}

int test_bootstrap_values()
{
    const std::string secret = obn::appcert::client_auth_secret();
    CHECK(secret.size() == 43);
    CHECK(secret.substr(0, 27) == "GLOF3813734089-eed1e0410000");
    CHECK(secret.substr(27) == "11037d8d06ea7c59");

    const std::string wrap(obn::appcert::server_wrap_key_pem());
    std::unique_ptr<BIO, BioDel> bio(
        BIO_new_mem_buf(wrap.data(), static_cast<int>(wrap.size())));
    CHECK(bio != nullptr);
    std::unique_ptr<EVP_PKEY, PkeyDel> pub(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    CHECK(pub != nullptr);
    CHECK(EVP_PKEY_bits(pub.get()) == 2048);
    return 0;
}

int test_secret_env_override()
{
    const std::string def = obn::appcert::client_auth_secret();

    const char fake[] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
#if defined(_WIN32)
    _putenv_s("OBN_CLIENT_AUTH_SECRET", fake);
#else
    setenv("OBN_CLIENT_AUTH_SECRET", fake, 1);
#endif
    CHECK(obn::appcert::client_auth_secret() == fake);

#if defined(_WIN32)
    _putenv_s("OBN_CLIENT_AUTH_SECRET", "");
#else
    unsetenv("OBN_CLIENT_AUTH_SECRET");
#endif
    CHECK(obn::appcert::client_auth_secret() == def);
    return 0;
}

int test_decode_rejects_garbage()
{
    std::array<std::string, 5> limbs;
    std::string err;
    // Not base64 at all.
    CHECK(!obn::appcert::detail::decode_key_blob("!!!!not-base64!!!!", &limbs, &err));
    CHECK(!err.empty());
    // Valid base64 but far too short for the blob header.
    err.clear();
    CHECK(!obn::appcert::detail::decode_key_blob(
        obn::appcert::detail::b64url_encode(std::string(16, 'A')), &limbs, &err));
    CHECK(!err.empty());
    // Correct framing but wrong magic (all-zero plaintext after decrypt).
    err.clear();
    {
        std::string blob;
        blob.assign(12, '\x11');                             // nonce
        blob.append(16, '\0');                               // tag
        u32le(blob, 640);                                    // ct_len
        const std::string ct = obn::appcert::detail::ctr_xor(
            kKey, blob.substr(0, 12), std::string(640, '\0'));
        blob += ct;
        CHECK(!obn::appcert::detail::decode_key_blob(
            obn::appcert::detail::b64url_encode(blob), &limbs, &err));
        CHECK(err.find("SKEY") != std::string::npos);
    }
    return 0;
}

// --- Full CRT round-trip ----------------------------------------------------

int test_crt_blob_roundtrip()
{
    std::unique_ptr<BN_CTX, CtxDel> ctx(BN_CTX_new());
    CHECK(ctx != nullptr);
    std::unique_ptr<BIGNUM, BnDel> p(BN_new()), q(BN_new());
    std::unique_ptr<BIGNUM, BnDel> p1(BN_new()), q1(BN_new());
    std::unique_ptr<BIGNUM, BnDel> gcd(BN_new()), lam(BN_new());
    std::unique_ptr<BIGNUM, BnDel> n(BN_new()), e(BN_new()), d(BN_new());
    std::unique_ptr<BIGNUM, BnDel> dp(BN_new()), dq(BN_new()), iqmp(BN_new());
    CHECK(p && q && p1 && q1 && gcd && lam && n && e && d && dp && dq && iqmp);
    CHECK(BN_generate_prime_ex(p.get(), 1024, 0, nullptr, nullptr, nullptr) == 1);
    CHECK(BN_generate_prime_ex(q.get(), 1024, 0, nullptr, nullptr, nullptr) == 1);
    CHECK(BN_mul(n.get(), p.get(), q.get(), ctx.get()) == 1);
    CHECK(BN_set_word(e.get(), RSA_F4) == 1);
    CHECK(BN_copy(p1.get(), p.get()) != nullptr);
    CHECK(BN_copy(q1.get(), q.get()) != nullptr);
    CHECK(BN_sub(p1.get(), p1.get(), BN_value_one()) == 1);
    CHECK(BN_sub(q1.get(), q1.get(), BN_value_one()) == 1);
    CHECK(BN_gcd(gcd.get(), p1.get(), q1.get(), ctx.get()) == 1);
    CHECK(BN_mul(lam.get(), p1.get(), q1.get(), ctx.get()) == 1);
    CHECK(BN_div(lam.get(), nullptr, lam.get(), gcd.get(), ctx.get()) == 1);
    CHECK(BN_mod_inverse(d.get(), e.get(), lam.get(), ctx.get()) != nullptr);
    CHECK(BN_mod(dp.get(), d.get(), p1.get(), ctx.get()) == 1);
    CHECK(BN_mod(dq.get(), d.get(), q1.get(), ctx.get()) == 1);
    CHECK(BN_mod_inverse(iqmp.get(), q.get(), p.get(), ctx.get()) != nullptr);

    // Equal-width 128-byte limbs (modulus is 2048 bits -> 1024-bit primes).
    constexpr int kLimbLen = 128;
    std::array<std::string, 5> limbs;
    const BIGNUM* raw[5] = {p.get(), q.get(), dp.get(), dq.get(), iqmp.get()};
    for (int i = 0; i < 5; ++i) {
        std::string limb(kLimbLen, '\0');
        CHECK(BN_bn2binpad(raw[i],
                        reinterpret_cast<unsigned char*>(&limb[0]),
                        kLimbLen) == kLimbLen);
        limbs[static_cast<std::size_t>(i)] = limb;
    }

    // Synthetic SKEY plaintext: magic || ver(1) || bitlen(0x800) ||
    // 5 x u32le(128) || limbs, encrypted with a fixed nonce and framed like
    // the cloud response.
    std::string pt;
    pt += std::string("\x59\x45\x4B\x53", 4);
    u32le(pt, 1);
    u32le(pt, 0x800);
    for (int i = 0; i < 5; ++i) u32le(pt, kLimbLen);
    for (const auto& l : limbs) pt += l;
    CHECK(pt.size() == 32 + 5 * kLimbLen);

    const std::string nonce = hex_decode("000102030405060708090a0b");
    const std::string ct = obn::appcert::detail::ctr_xor(kKey, nonce, pt);
    CHECK(ct.size() == pt.size());
    std::string blob = nonce;
    blob.append(16, '\0');                          // GCM tag (carried, unused)
    u32le(blob, static_cast<std::uint32_t>(ct.size()));
    blob += ct;

    std::array<std::string, 5> got;
    std::string err;
    CHECK(obn::appcert::detail::decode_key_blob(
        obn::appcert::detail::b64url_encode(blob), &got, &err));
    for (int i = 0; i < 5; ++i)
        CHECK(got[static_cast<std::size_t>(i)] == limbs[static_cast<std::size_t>(i)]);

    const std::string pem = obn::appcert::detail::rsa_pem_from_crt(got, &err);
    CHECK(!pem.empty());
    CHECK(pem.find("PRIVATE KEY") != std::string::npos);

    // Parse the rebuilt key and sign; verify with a public key built from
    // the ORIGINAL n/e — only a correct CRT rebuild produces a signature the
    // original public key accepts.
    std::unique_ptr<BIO, BioDel> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    CHECK(bio != nullptr);
    std::unique_ptr<EVP_PKEY, PkeyDel> rebuilt(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    CHECK(rebuilt != nullptr);
    CHECK(EVP_PKEY_bits(rebuilt.get()) == 2048);

    std::unique_ptr<RSA, RsaDel> pub_rsa(RSA_new());
    CHECK(pub_rsa != nullptr);
    CHECK(RSA_set0_key(pub_rsa.get(), BN_dup(n.get()), BN_dup(e.get()),
                       nullptr) == 1);
    std::unique_ptr<EVP_PKEY, PkeyDel> pub(EVP_PKEY_new());
    CHECK(pub != nullptr);
    CHECK(EVP_PKEY_assign_RSA(pub.get(), pub_rsa.get()) == 1);
    pub_rsa.release();

    const std::string msg = "appcert CRT round-trip";
    std::unique_ptr<EVP_MD_CTX, MdDel> sig_ctx(EVP_MD_CTX_new());
    CHECK(sig_ctx != nullptr);
    std::size_t sig_len = 0;
    CHECK(EVP_DigestSignInit(sig_ctx.get(), nullptr, EVP_sha256(), nullptr,
                             rebuilt.get()) == 1);
    CHECK(EVP_DigestSignUpdate(sig_ctx.get(), msg.data(), msg.size()) == 1);
    CHECK(EVP_DigestSignFinal(sig_ctx.get(), nullptr, &sig_len) == 1);
    std::string sig(sig_len, '\0');
    CHECK(EVP_DigestSignFinal(sig_ctx.get(),
                              reinterpret_cast<unsigned char*>(&sig[0]),
                              &sig_len) == 1);
    sig.resize(sig_len);

    std::unique_ptr<EVP_MD_CTX, MdDel> ver_ctx(EVP_MD_CTX_new());
    CHECK(ver_ctx != nullptr);
    CHECK(EVP_DigestVerifyInit(ver_ctx.get(), nullptr, EVP_sha256(), nullptr,
                               pub.get()) == 1);
    CHECK(EVP_DigestVerifyUpdate(ver_ctx.get(), msg.data(), msg.size()) == 1);
    CHECK(EVP_DigestVerifyFinal(ver_ctx.get(),
                                reinterpret_cast<const unsigned char*>(sig.data()),
                                sig.size()) == 1);
    return 0;
}

} // namespace

int main()
{
    int rc = 0;
    if (test_keystream_kats()      != 0) rc = 1;
    if (test_real_ct_header()      != 0) rc = 1;
    if (test_ctr_roundtrip()       != 0) rc = 1;
    if (test_b64url()              != 0) rc = 1;
    if (test_bootstrap_values()    != 0) rc = 1;
    if (test_secret_env_override() != 0) rc = 1;
    if (test_decode_rejects_garbage() != 0) rc = 1;
    if (test_crt_blob_roundtrip()  != 0) rc = 1;
    if (rc == 0) std::cout << "appcert_test: ok\n";
    return rc;
}