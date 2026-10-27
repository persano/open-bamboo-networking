// App-cert cipher primitives + the embedded bootstrap credentials for the
// shared slicer app-cert fetch (stock bambu_network_update_cert).
//
// PROVENANCE
// ----------
// Two values are needed to call Bambu's cert endpoint:
//
//   GET /v1/iot-service/api/user/applications/{enc_secret}/cert?aes256=...&ver=1
//
// 1. client_auth_secret (43 bytes, ASCII): the CN of the shared app
//    certificate prefix + a fixed 16-hex tail. The stock plugin embeds it and
//    AES-GCM-encrypts it under an ephemeral session key into the URL path
//    segment; Bambu's server holds the same value and unwraps it. It was
//    recovered from a running stock Bambu Studio process with
//    tools/extract_key_from_dump.py (full-memory dump -> resident secret)
//    and verified live against the endpoint: the fetched chain's leaf serial
//    matched the working slicer_cert.pem in the config dir (2026-10-03).
//
// 2. server wrap key: the public key of CN=service.bambulab.com, published
//    with the reverse-networking documentation (service.crt, valid
//    2024-2034). Only the ephemeral AES session key is wrapped under it, so
//    the public half suffices and nothing secret is embedded for it.
//
// ROTATION: Bambu rotates the app certificate (leaf serial) on its own
// schedule; every fetch returns whatever is current, so no embedded value
// changes on cert rotation. Only a rotation of client_auth_secret itself
// would require an update here. Re-extraction procedure when the endpoint
// starts rejecting the secret (HTTP 4xx with an auth-shaped body):
//
//   1. Install/start stock Bambu Studio and let it finish its cold start
//      (plugin loaded, GUI up), so it has fetched its own credentials.
//   2. Dump the fully-started process (full-memory dump; procdump -ma, or
//      tools/extract_key_from_dump.py's companion memdump approach).
//   3. python tools/extract_key_from_dump.py <dump> --out-dir <tmp>
//   4. Verify before shipping anything:
//        python tools/fetch_slicer_credentials.py ^
//          --client-auth-secret <tmp>\slicer_client_auth_secret.txt ^
//          --server-wrap-key server_wrap_key.pem --out-dir <tmp2>
//      (must print "OK: private key modulus matches leaf certificate")
//   5. Replace kClientAuthSecret below with the new 43 bytes (they are
//      ASCII; keep it a C string) and record the extraction date here.
//
// ALTERNATIVE (no embedded secret): the user supplies slicer_cert.pem /
// slicer_crl.pem / slicer_key.pem in the obn config dir (signing.cpp reads
// them; see README). Note stock Bambu Studio never writes those files itself,
// so in practice they only come from running tools/extract_key_from_dump.py
// (or its companion fetch) against the user's own Bambu Studio process. That
// path needs a manual refresh whenever Bambu rotates the certificate; the
// fetch implemented here does not.
//
// OVERRIDE: setting OBN_CLIENT_AUTH_SECRET (43 ASCII bytes) replaces the
// embedded default at runtime — rotation without a rebuild. A clean-room
// build (-DOBN_EMBED_SECRET=OFF) compiles kClientAuthSecret out entirely;
// such builds take the secret from the env var or from
// <config_dir>/client_auth_secret.txt (checked in appcert_fetch.cpp). The
// disk fallback for the cert material itself already exists in
// cert_store.cpp (ClusterM PR #95).
//
// The cipher itself is Bambu's published appcert_cipher (custom S-box AES-
// 256-CTR over fixed key 00..1f, counter from 2) — ported 1:1 from
// tools/fetch_slicer_credentials.py, which is itself validated against
// public KATs; tests/appcert_test.cpp runs the same vectors.

// OpenSSL 3 marks the low-level RSA_* accessors (RSA_new / RSA_set0_* /
// RSA_free) deprecated, but they remain the only portable way to assemble a
// key from raw CRT limbs — EVP_PKEY_fromdata exposes no dmp1/dmq1/iqmp
// parameters. Suppress the deprecation attributes for this translation unit
// only; the API itself is fully supported in 1.1 through 3.x.
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "obn/appcert.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

namespace obn::appcert {

namespace {

#ifdef OBN_EMBED_SECRET
// The 43-byte client_auth_secret: app-cert CN prefix
// "GLOF3813734089-eed1e0410000" + fixed tail "11037d8d06ea7c59".
// ASCII; hex would be 474c4f46333831333733343038392d65656431653034313030303031313033376438643036656137633539.
constexpr char kClientAuthSecret[] =
    "GLOF3813734089-eed1e041000011037d8d06ea7c59";
static_assert(sizeof(kClientAuthSecret) - 1 == 43,
              "client_auth_secret must stay 43 bytes");
#endif // OBN_EMBED_SECRET

// Public key of CN=service.bambulab.com (server wrap key, published in the
// reverse-networking docs' service.crt). Wraps the ephemeral AES-GCM session
// key of the fetch request with RSA-PKCS#1 v1.5.
constexpr char kServerWrapKeyPem[] = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnbPBC80CMD2VB7Tqj9W/
olQscufbk0rvTqbINriL2WZvfCoBE1WLppJZ/E7cLP02SULh1gB0VuBwRRe4khwk
EFl2A87YaGdp4JRVbP+5xbYYJ09oECRdk0Mrnpo+p9jCW0iw0lxQi+rQ6ZsWwj3S
XzMpNDN3z/Mlx+byU4GkBt6vBsR4cJB8PFRak3KsC4YmWQNybGtoCPMFdCMDIxP6
Qr4o86qEkgK7lJc/ztYaXPDyx+t0uXsna+G1enNELru+2/q4Ppqqrl/Y5pHEdFTK
p4Nj9p2JYT1B5v1qaRExxCJQnQhAlnjANIw2ll7SC5cuSXks909Tbj0G7zofl4N/
kQIDAQAB
-----END PUBLIC KEY-----
)";

// Custom AES S-box (appcert_cipher). A bijection, deliberately NOT the
// standard AES S-box (SBOX[0] = 0xC5, standard = 0x63) — locked by KATs.
constexpr unsigned char kSbox[256] = {
    0xC5, 0x57, 0x4D, 0x6C, 0x3A, 0x95, 0x05, 0xE0, 0xA3, 0xBA, 0x36, 0x1F, 0xEA, 0x51, 0x53, 0x3B,
    0x0E, 0x07, 0x4E, 0x64, 0x50, 0x04, 0x40, 0xE8, 0x62, 0x6E, 0x9F, 0x2D, 0x70, 0x8B, 0x28, 0x49,
    0xD5, 0xF9, 0x65, 0x8D, 0x74, 0x68, 0x7C, 0x6F, 0x0A, 0x6A, 0xB3, 0xAF, 0x38, 0xFE, 0x7E, 0x8A,
    0x47, 0x7F, 0xB0, 0x16, 0x00, 0xD4, 0x0F, 0x13, 0xC9, 0x80, 0x4A, 0xAC, 0x8C, 0x4F, 0xA7, 0x98,
    0x83, 0x94, 0x5D, 0x48, 0xB4, 0xE9, 0x30, 0x19, 0x03, 0x99, 0x25, 0xBF, 0x8E, 0x41, 0xA0, 0xE4,
    0xC3, 0xCF, 0x2C, 0xAB, 0xD2, 0x32, 0x1A, 0x0C, 0x11, 0xB5, 0x56, 0x63, 0x15, 0xA6, 0x69, 0x0B,
    0x88, 0xBB, 0x4C, 0x10, 0xCB, 0x75, 0xFA, 0x81, 0xF8, 0xCD, 0xA1, 0xD6, 0x97, 0xB7, 0x26, 0xC6,
    0x9E, 0xF1, 0x5F, 0xE5, 0xA9, 0x87, 0xC7, 0xDC, 0x8F, 0x7A, 0x86, 0x20, 0x9A, 0xD1, 0x08, 0xC2,
    0x84, 0x09, 0x33, 0x1B, 0xDD, 0x1E, 0xFD, 0x01, 0x71, 0xDA, 0x77, 0x0D, 0xD7, 0xDE, 0x93, 0xCA,
    0xA5, 0xD0, 0xE6, 0x60, 0x89, 0x37, 0xC8, 0x21, 0x59, 0x79, 0x96, 0xAD, 0x24, 0x34, 0xB9, 0x44,
    0xFC, 0xC1, 0xAE, 0xF3, 0x82, 0x46, 0x43, 0x31, 0xE3, 0x2E, 0x4B, 0xFB, 0x92, 0x55, 0xED, 0x45,
    0x76, 0x6D, 0xAA, 0x3F, 0xF5, 0x5A, 0x91, 0x78, 0x22, 0x06, 0xFF, 0xD9, 0x35, 0x7D, 0x7B, 0xDB,
    0x54, 0x12, 0x9C, 0xD8, 0xD3, 0xEE, 0x17, 0x42, 0x52, 0x3E, 0xA4, 0xE7, 0xDF, 0x9D, 0xF2, 0xF4,
    0xEF, 0x73, 0xF6, 0x5E, 0xB1, 0x5B, 0x18, 0xE2, 0x9B, 0x58, 0xA8, 0x2A, 0xE1, 0x3D, 0x90, 0xB6,
    0x1C, 0xBD, 0x61, 0xEB, 0x23, 0xA2, 0x67, 0x39, 0xF0, 0xBC, 0xB2, 0xF7, 0x85, 0x27, 0x72, 0xCC,
    0x29, 0xB8, 0x1D, 0xBE, 0x66, 0xC4, 0x2F, 0xCE, 0x14, 0x3C, 0x6B, 0xEC, 0x5C, 0x2B, 0xC0, 0x02,
};

// Round constants for the key schedule (RCON[0..13]).
constexpr unsigned char kRcon[14] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
};

// Fixed AES-256 key of the appcert cipher: 00 01 02 ... 1f.
constexpr unsigned char kAppcertKey[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

struct ExpandedKey {
    unsigned char rk[15][16];
};

unsigned char xtime(unsigned char a)
{
    return static_cast<unsigned char>((a << 1) ^ ((a & 0x80) ? 0x1B : 0));
}

unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char r = 0;
    while (b) {
        if (b & 1) r = static_cast<unsigned char>(r ^ a);
        a = xtime(a);
        b = static_cast<unsigned char>(b >> 1);
    }
    return r;
}

// AES-256 key schedule with the custom S-box -> 15 round keys of 16 bytes.
// Column-major word layout, ported from key_expand() in
// tools/fetch_slicer_credentials.py.
ExpandedKey key_expand(const unsigned char key[32])
{
    unsigned char w[60][4];
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j)
            w[i][j] = key[4 * i + j];
    for (int i = 8; i < 60; ++i) {
        unsigned char t[4] = {w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3]};
        if (i % 8 == 0) {
            const unsigned char tmp = t[0];
            t[0] = static_cast<unsigned char>(kSbox[t[1]] ^ kRcon[i / 8 - 1]);
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[tmp];
        } else if (i % 8 == 4) {
            for (int k = 0; k < 4; ++k) t[k] = kSbox[t[k]];
        }
        for (int j = 0; j < 4; ++j)
            w[i][j] = static_cast<unsigned char>(w[i - 8][j] ^ t[j]);
    }
    ExpandedKey ek{};
    for (int r = 0; r < 15; ++r)
        for (int c = 0; c < 4; ++c)
            for (int j = 0; j < 4; ++j)
                ek.rk[r][4 * c + j] = w[4 * r + c][j];
    return ek;
}

// One AES-256 block encrypt; column-major state (state[4*col + row]),
// ported from aes_encrypt_block() in tools/fetch_slicer_credentials.py.
void aes_encrypt_block(const unsigned char in[16], const ExpandedKey& ek,
                       unsigned char out[16])
{
    unsigned char s[16];
    for (int i = 0; i < 16; ++i)
        s[i] = static_cast<unsigned char>(in[i] ^ ek.rk[0][i]);
    for (int rnd = 1; rnd < 15; ++rnd) {
        for (int i = 0; i < 16; ++i) s[i] = kSbox[s[i]];
        unsigned char t[16];
        for (int r = 0; r < 4; ++r)
            for (int c = 0; c < 4; ++c)
                t[4 * c + r] = s[4 * ((c + r) % 4) + r];
        std::memcpy(s, t, 16);
        if (rnd < 14) {
            for (int c = 0; c < 4; ++c) {
                const unsigned char a0 = s[4 * c + 0], a1 = s[4 * c + 1];
                const unsigned char a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                s[4 * c + 0] = static_cast<unsigned char>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
                s[4 * c + 1] = static_cast<unsigned char>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
                s[4 * c + 2] = static_cast<unsigned char>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
                s[4 * c + 3] = static_cast<unsigned char>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
            }
        }
        for (int i = 0; i < 16; ++i)
            s[i] = static_cast<unsigned char>(s[i] ^ ek.rk[rnd][i]);
    }
    std::memcpy(out, s, 16);
}

// Blob framing (see research/10.02-secrets.md and the header docs above).
constexpr std::size_t kNonceLen    = 12;
constexpr std::size_t kTagLen      = 16;
constexpr std::size_t kLenFieldLen = 4;
constexpr std::size_t kCtLenOffset = kNonceLen + kTagLen;              // 28
constexpr std::size_t kBlobHdrLen  = kCtLenOffset + kLenFieldLen;      // 32
constexpr std::size_t kPtHdrLen    = 4 + 4 + 4 + 5 * 4;                // 32
constexpr std::size_t kLimbCount   = 5;
constexpr std::uint32_t kFirstCtBlockCounter = 2;

constexpr char kMagic[4] = {'\x59', '\x45', '\x4B', '\x53'}; // LE "SKEY"

constexpr char kB64Tbl[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// base64 decode accepting both standard and URL-safe alphabets, any
// whitespace, with or without padding. Returns false on invalid input.
bool b64_decode_any(const std::string& in, std::string* out, std::string* err)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        s.push_back(c == '-' ? '+' : c == '_' ? '/' : c);
    }
    while (s.size() % 4 != 0) s.push_back('=');
    std::string res;
    res.reserve(s.size() / 4 * 3);
    for (std::size_t i = 0; i < s.size(); i += 4) {
        int q[4];
        for (int j = 0; j < 4; ++j) {
            if (s[i + j] == '=') { q[j] = -2; continue; }
            q[j] = val(s[i + j]);
            if (q[j] < 0) {
                if (err) *err = "invalid base64 character";
                return false;
            }
        }
        if (q[0] < 0 || q[1] < 0) {
            if (err) *err = "truncated base64";
            return false;
        }
        const std::uint32_t w =
            (static_cast<std::uint32_t>(q[0]) << 18) |
            (static_cast<std::uint32_t>(q[1]) << 12) |
            (static_cast<std::uint32_t>(q[2] >= 0 ? q[2] : 0) << 6) |
            static_cast<std::uint32_t>(q[3] >= 0 ? q[3] : 0);
        res.push_back(static_cast<char>((w >> 16) & 0xFF));
        if (q[2] >= 0) res.push_back(static_cast<char>((w >> 8) & 0xFF));
        if (q[3] >= 0) res.push_back(static_cast<char>(w & 0xFF));
    }
    *out = std::move(res);
    return true;
}

struct BioDel { void operator()(BIO* p) const { BIO_free(p); } };
struct PkeyDel { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct RsaDel { void operator()(RSA* p) const { RSA_free(p); } };
struct BnDel { void operator()(BIGNUM* p) const { BN_free(p); } };
struct CtxDel { void operator()(BN_CTX* p) const { BN_CTX_free(p); } };

} // namespace

std::string client_auth_secret()
{
    // Runtime override for rotation without a rebuild, and for builds that
    // ship without the embedded default (see the OVERRIDE note above).
    // A wrong-length value is passed through as-is; the endpoint rejects it
    // with HTTP 4xx.
    if (const char* v = std::getenv("OBN_CLIENT_AUTH_SECRET"); v && *v)
        return v;
#ifdef OBN_EMBED_SECRET
    return kClientAuthSecret;
#else
    return {};
#endif
}

const char* server_wrap_key_pem() { return kServerWrapKeyPem; }

namespace detail {

std::string b64url_encode(const std::string& data)
{
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < data.size(); i += 3) {
        std::uint32_t w = static_cast<std::uint32_t>(
                              static_cast<unsigned char>(data[i])) << 16;
        if (i + 1 < data.size())
            w |= static_cast<std::uint32_t>(
                     static_cast<unsigned char>(data[i + 1])) << 8;
        if (i + 2 < data.size())
            w |= static_cast<unsigned char>(data[i + 2]);
        const char c0 = kB64Tbl[(w >> 18) & 63];
        const char c1 = kB64Tbl[(w >> 12) & 63];
        out.push_back(c0 == '+' ? '-' : c0 == '/' ? '_' : c0);
        out.push_back(c1 == '+' ? '-' : c1 == '/' ? '_' : c1);
        if (i + 1 < data.size()) {
            const char c2 = kB64Tbl[(w >> 6) & 63];
            out.push_back(c2 == '+' ? '-' : c2 == '/' ? '_' : c2);
        } else out.push_back('=');
        if (i + 2 < data.size()) {
            const char c3 = kB64Tbl[w & 63];
            out.push_back(c3 == '+' ? '-' : c3 == '/' ? '_' : c3);
        } else out.push_back('=');
    }
    return out;
}

std::string ctr_xor(const unsigned char key[32], const std::string& nonce,
                    const std::string& data)
{
    if (nonce.size() != kNonceLen) return {};
    const ExpandedKey ek = key_expand(key);
    std::string out(data.size(), '\0');
    const std::size_t blocks = (data.size() + 15) / 16;
    for (std::size_t i = 0; i < blocks; ++i) {
        unsigned char blk[16];
        std::memcpy(blk, nonce.data(), kNonceLen);
        const std::uint32_t ctr =
            kFirstCtBlockCounter + static_cast<std::uint32_t>(i);
        blk[12] = static_cast<unsigned char>(ctr >> 24);
        blk[13] = static_cast<unsigned char>(ctr >> 16);
        blk[14] = static_cast<unsigned char>(ctr >> 8);
        blk[15] = static_cast<unsigned char>(ctr);
        unsigned char ks[16];
        aes_encrypt_block(blk, ek, ks);
        const std::size_t base = i * 16;
        const std::size_t n = data.size() - base < 16 ? data.size() - base : 16;
        for (std::size_t j = 0; j < n; ++j)
            out[base + j] = static_cast<char>(
                static_cast<unsigned char>(data[base + j]) ^ ks[j]);
    }
    return out;
}

bool decode_key_blob(const std::string& blob_b64,
                     std::array<std::string, 5>* limbs, std::string* err)
{
    std::string blob;
    if (!b64_decode_any(blob_b64, &blob, err)) return false;
    if (blob.size() < kBlobHdrLen + kPtHdrLen + kLimbCount) {
        if (err) *err = "key blob too short: " + std::to_string(blob.size()) + " bytes";
        return false;
    }
    std::uint32_t ct_len = 0;
    for (int i = 3; i >= 0; --i)
        ct_len = (ct_len << 8) |
                 static_cast<unsigned char>(blob[kCtLenOffset + i]); // u32le
    if (kBlobHdrLen + ct_len > blob.size())
        ct_len = static_cast<std::uint32_t>(blob.size() - kBlobHdrLen);
    const std::string pt = ctr_xor(
        kAppcertKey, blob.substr(0, kNonceLen),
        blob.substr(kBlobHdrLen, ct_len));
    if (pt.size() < kPtHdrLen + kLimbCount ||
        std::memcmp(pt.data(), kMagic, 4) != 0) {
        if (err) *err = "SKEY magic missing (wrong cipher / framing)";
        return false;
    }
    const std::size_t body = pt.size() - kPtHdrLen;
    if (body == 0 || body % kLimbCount != 0) {
        if (err)
            *err = "SKEY plaintext is not 5 equal CRT limbs: " +
                   std::to_string(pt.size()) + " bytes";
        return false;
    }
    const std::size_t limb = body / kLimbCount;
    for (std::size_t i = 0; i < kLimbCount; ++i)
        (*limbs)[i] = pt.substr(kPtHdrLen + i * limb, limb);
    return true;
}

std::string rsa_pem_from_crt(const std::array<std::string, 5>& limbs,
                             std::string* err)
{
    auto fail = [err](const std::string& e) -> std::string {
        if (err) *err = e;
        return {};
    };
    for (const auto& l : limbs)
        if (l.empty()) return fail("empty CRT limb");

    std::unique_ptr<BIGNUM, BnDel> p(BN_bin2bn(
        reinterpret_cast<const unsigned char*>(limbs[0].data()),
        static_cast<int>(limbs[0].size()), nullptr));
    std::unique_ptr<BIGNUM, BnDel> q(BN_bin2bn(
        reinterpret_cast<const unsigned char*>(limbs[1].data()),
        static_cast<int>(limbs[1].size()), nullptr));
    std::unique_ptr<BIGNUM, BnDel> dp(BN_bin2bn(
        reinterpret_cast<const unsigned char*>(limbs[2].data()),
        static_cast<int>(limbs[2].size()), nullptr));
    std::unique_ptr<BIGNUM, BnDel> dq(BN_bin2bn(
        reinterpret_cast<const unsigned char*>(limbs[3].data()),
        static_cast<int>(limbs[3].size()), nullptr));
    std::unique_ptr<BIGNUM, BnDel> iqmp(BN_bin2bn(
        reinterpret_cast<const unsigned char*>(limbs[4].data()),
        static_cast<int>(limbs[4].size()), nullptr));
    if (!p || !q || !dp || !dq || !iqmp) return fail("BN_bin2bn failed");

    std::unique_ptr<BN_CTX, CtxDel> ctx(BN_CTX_new());
    std::unique_ptr<BIGNUM, BnDel> n(BN_new());
    std::unique_ptr<BIGNUM, BnDel> e(BN_new());
    std::unique_ptr<BIGNUM, BnDel> p1(BN_new());
    std::unique_ptr<BIGNUM, BnDel> q1(BN_new());
    std::unique_ptr<BIGNUM, BnDel> gcd(BN_new());
    std::unique_ptr<BIGNUM, BnDel> lam(BN_new());
    if (!ctx || !n || !e || !p1 || !q1 || !gcd || !lam)
        return fail("BN allocation failed");
    if (BN_mul(n.get(), p.get(), q.get(), ctx.get()) != 1)
        return fail("n = p*q failed");
    if (BN_set_word(e.get(), RSA_F4) != 1) return fail("BN_set_word failed");
    if (BN_copy(p1.get(), p.get()) == nullptr ||
        BN_copy(q1.get(), q.get()) == nullptr ||
        BN_sub(p1.get(), p1.get(), BN_value_one()) != 1 ||
        BN_sub(q1.get(), q1.get(), BN_value_one()) != 1)
        return fail("p-1 / q-1 failed");
    if (BN_gcd(gcd.get(), p1.get(), q1.get(), ctx.get()) != 1)
        return fail("gcd(p-1,q-1) failed");
    // lam = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
    if (BN_mul(lam.get(), p1.get(), q1.get(), ctx.get()) != 1 ||
        BN_div(lam.get(), nullptr, lam.get(), gcd.get(), ctx.get()) != 1)
        return fail("lcm(p-1,q-1) failed");
    // d = e^-1 mod lcm  (the CRT-consistent private exponent)
    std::unique_ptr<BIGNUM, BnDel> d(BN_mod_inverse(nullptr, e.get(), lam.get(), ctx.get()));
    if (!d) return fail("no modular inverse for d (degenerate limbs)");

    std::unique_ptr<RSA, RsaDel> r(RSA_new());
    if (!r) return fail("RSA_new failed");
    // RSA_set0_key / RSA_set0_factors / RSA_set0_crt_params take ownership on
    // success; release the unique_ptrs first so nothing is double-freed when
    // a later set0 call fails.
    BIGNUM* n_raw = n.release();
    BIGNUM* e_raw = e.release();
    BIGNUM* d_raw = d.release();
    BIGNUM* p_raw = p.release();
    BIGNUM* q_raw = q.release();
    BIGNUM* dp_raw = dp.release();
    BIGNUM* dq_raw = dq.release();
    BIGNUM* iqmp_raw = iqmp.release();
    // Each set0 call transfers ownership of its arguments on success; on
    // failure free exactly the arguments that call did not take.
    if (RSA_set0_key(r.get(), n_raw, e_raw, d_raw) != 1) {
        BN_free(n_raw); BN_free(e_raw); BN_free(d_raw);
        return fail("RSA_set0_key failed");
    }
    if (RSA_set0_factors(r.get(), p_raw, q_raw) != 1) {
        BN_free(p_raw); BN_free(q_raw);
        return fail("RSA_set0_factors failed");
    }
    if (RSA_set0_crt_params(r.get(), dp_raw, dq_raw, iqmp_raw) != 1) {
        BN_free(dp_raw); BN_free(dq_raw); BN_free(iqmp_raw);
        return fail("RSA_set0_crt_params failed");
    }
    std::unique_ptr<EVP_PKEY, PkeyDel> pk(EVP_PKEY_new());
    if (!pk || EVP_PKEY_assign_RSA(pk.get(), r.get()) != 1)
        return fail("EVP_PKEY_assign_RSA failed");
    r.release(); // owned by pk now

    std::unique_ptr<BIO, BioDel> bio(BIO_new(BIO_s_mem()));
    if (!bio) return fail("BIO_new failed");
    if (PEM_write_bio_PrivateKey(bio.get(), pk.get(), nullptr, nullptr, 0,
                                 nullptr, nullptr) != 1)
        return fail("PEM_write_bio_PrivateKey failed");
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || !data) return fail("empty PEM output");
    return std::string(data, static_cast<std::size_t>(len));
}

} // namespace detail
} // namespace obn::appcert