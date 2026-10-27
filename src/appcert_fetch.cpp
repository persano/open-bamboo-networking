// Shared app-cert fetch: request build, response validation, credential files.
//
// Implements obn::appcert::fetch_and_store — the network half of stock
// bambu_network_update_cert (Studio check_cert). The cipher, the embedded
// bootstrap values and their provenance live in appcert_cipher.cpp; the
// reference implementation with known-answer tests is
// tools/fetch_slicer_credentials.py (same KATs in tests/appcert_test.cpp).
//
// Request (research/10.02-secrets.md, live-verified 2026-07 / 2026-10):
//   1. Generate a random 32-byte AES-GCM session key + 12-byte IV.
//   2. enc_secret = base64url(IV || AES-256-GCM(client_auth_secret) || tag)
//      — the 43-byte secret never travels in cleartext.
//   3. aes256 = base64url(RSA-PKCS#1-v1.5(session_key) under the published
//      server wrap key of CN=service.bambulab.com).
//   4. GET <api host>/v1/iot-service/api/user/applications/{enc_secret}/cert
//        ?aes256={aes256}&ver=1        (anonymous; any User-Agent works)
// Response: JSON { code, message, cert (PEM, string|array), crl (PEM,
// string|array), key (base64 blob) }. The key blob unwraps with the custom
// appcert cipher into RSA CRT limbs -> PEM.

#include "obn/appcert.hpp"
#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/signing.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace obn::appcert {

namespace {

constexpr std::size_t kGcmIvLen  = 12;
constexpr std::size_t kGcmTagLen = 16;

struct BioDel { void operator()(BIO* p) const { BIO_free(p); } };
struct PkeyDel { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct X509Del { void operator()(X509* p) const { X509_free(p); } };
struct CipherCtxDel { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct PkeyCtxDel { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };

std::string body_prefix(const std::string& s, std::size_t n)
{
    return s.size() <= n ? s : s.substr(0, n) + "...";
}

// RSA modulus of `pk` as a newly allocated BIGNUM (caller frees), or null.
BIGNUM* pkey_modulus(EVP_PKEY* pk)
{
    if (!pk) return nullptr;
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    BIGNUM* n = nullptr;
    if (EVP_PKEY_get_bn_param(pk, "n", &n) == 1 && n) return n;
    return nullptr;
#else
    RSA* r = EVP_PKEY_get0_RSA(pk);
    if (!r) return nullptr;
    const BIGNUM* n = nullptr;
    RSA_get0_key(r, &n, nullptr, nullptr);
    return n ? BN_dup(n) : nullptr;
#endif
}

// First PEM certificate of `chain`, or null (fills *err).
std::unique_ptr<X509, X509Del> parse_leaf(const std::string& chain,
                                          std::string* err)
{
    if (chain.empty()) {
        if (err) *err = "empty certificate chain";
        return nullptr;
    }
    std::unique_ptr<BIO, BioDel> bio(
        BIO_new_mem_buf(chain.data(), static_cast<int>(chain.size())));
    if (!bio) {
        if (err) *err = "BIO_new_mem_buf failed";
        return nullptr;
    }
    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
        if (err) *err = "response cert is not a valid X.509 PEM chain";
        return nullptr;
    }
    return std::unique_ptr<X509, X509Del>(cert);
}

// Lowercase hex leaf serial (even length), for log correlation only.
std::string leaf_serial_hex(X509* cert)
{
    const ASN1_INTEGER* sn = X509_get_serialNumber(cert);
    if (!sn) return {};
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> bn(
        ASN1_INTEGER_to_BN(sn, nullptr), BN_free);
    if (!bn) return {};
    char* hex = BN_bn2hex(bn.get());
    if (!hex) return {};
    std::string out(hex);
    OPENSSL_free(hex);
    for (char& c : out)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    if (out.size() % 2) out.insert(out.begin(), '0');
    return out;
}

// iv || ct || tag (12 || len || 16), Python AESGCM().encrypt layout.
bool aes_gcm_seal(const unsigned char key[32], const std::string& plain,
                  std::string* out, std::string* err)
{
    unsigned char iv[kGcmIvLen];
    if (RAND_bytes(iv, static_cast<int>(kGcmIvLen)) != 1) {
        if (err) *err = "RAND_bytes(iv) failed";
        return false;
    }
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDel> ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        if (err) *err = "EVP_CIPHER_CTX_new failed";
        return false;
    }
    int len = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(kGcmIvLen), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1) {
        if (err) *err = "GCM init failed";
        return false;
    }
    std::string ct(plain.size() + kGcmTagLen, '\0');
    if (EVP_EncryptUpdate(ctx.get(),
                          reinterpret_cast<unsigned char*>(&ct[0]), &len,
                          reinterpret_cast<const unsigned char*>(plain.data()),
                          static_cast<int>(plain.size())) != 1) {
        if (err) *err = "GCM encrypt failed";
        return false;
    }
    int total = len;
    if (EVP_EncryptFinal_ex(ctx.get(),
                            reinterpret_cast<unsigned char*>(&ct[0]) + total,
                            &len) != 1) {
        if (err) *err = "GCM final failed";
        return false;
    }
    total += len;
    ct.resize(static_cast<std::size_t>(total));
    unsigned char tag[kGcmTagLen];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(kGcmTagLen), tag) != 1) {
        if (err) *err = "GCM tag retrieval failed";
        return false;
    }
    out->assign(reinterpret_cast<const char*>(iv), kGcmIvLen);
    out->append(ct);
    out->append(reinterpret_cast<const char*>(tag), kGcmTagLen);
    return true;
}

// RSA-PKCS#1 v1.5 encrypt under the embedded server wrap key -> raw bytes.
bool rsa_wrap_session_key(const std::string& session_key, std::string* out,
                          std::string* err)
{
    std::string pem(server_wrap_key_pem());
    std::unique_ptr<BIO, BioDel> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        if (err) *err = "wrap-key BIO failed";
        return false;
    }
    std::unique_ptr<EVP_PKEY, PkeyDel> pub(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if (!pub) {
        if (err) *err = "embedded server wrap key does not parse";
        return false;
    }
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDel> ctx(
        EVP_PKEY_CTX_new(pub.get(), nullptr));
    if (!ctx ||
        EVP_PKEY_encrypt_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1) {
        if (err) *err = "RSA wrap init failed";
        return false;
    }
    std::size_t outlen = 0;
    const auto* p = reinterpret_cast<const unsigned char*>(session_key.data());
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, p,
                         session_key.size()) != 1 ||
        outlen == 0) {
        if (err) *err = "RSA wrap size query failed";
        return false;
    }
    std::string wrapped(outlen, '\0');
    if (EVP_PKEY_encrypt(ctx.get(),
                         reinterpret_cast<unsigned char*>(&wrapped[0]),
                         &outlen, p, session_key.size()) != 1) {
        if (err) *err = "RSA wrap failed";
        return false;
    }
    wrapped.resize(outlen);
    *out = std::move(wrapped);
    return true;
}

// Temp file + rename so a crash never leaves a half-written credential.
bool write_file_atomic(const std::string& path, const std::string& bytes,
                       std::string* err)
{
    const std::string tmp = path + ".tmp";
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) {
        if (err) *err = "cannot open " + tmp;
        return false;
    }
    const bool wrote = bytes.empty() ||
        std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    const bool closed = std::fclose(f) == 0;
    if (!wrote || !closed) {
        std::remove(tmp.c_str());
        if (err) *err = "short write: " + tmp;
        return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::remove(tmp.c_str());
        if (err) *err = "rename to " + path + " failed: " + ec.message();
        return false;
    }
    return true;
}

// Resolved path of the private key file (mirrors signing.cpp resolve_key_path).
std::string resolve_key_path_local()
{
    const auto& cfg = obn::config::current().slicer_key_pem;
    if (!cfg.empty()) return cfg;
    return obn::config::path_in_dir("slicer_key.pem");
}

std::string resolved_path_or(const std::string& cfg_value,
                             const char* basename)
{
    if (!cfg_value.empty()) return cfg_value;
    return obn::config::path_in_dir(basename);
}

// PEM blob of `pem` starting at `begin` (for modulus checks / leaf parse).
// Parses the private key PEM with OpenSSL and returns its modulus, or null.
BIGNUM* key_pem_modulus(const std::string& pem, std::string* err)
{
    std::unique_ptr<BIO, BioDel> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        if (err) *err = "BIO failed";
        return nullptr;
    }
    std::unique_ptr<EVP_PKEY, PkeyDel> pk(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (!pk) {
        if (err) *err = "private key PEM does not parse";
        return nullptr;
    }
    return pkey_modulus(pk.get());
}

} // namespace

bool material_consistent()
{
    const std::string cert_pem = obn::signing::slicer_cert_pem();
    if (cert_pem.empty()) return true; // absence is the callers' check
    const std::string key_path = resolve_key_path_local();
    if (key_path.empty()) return true;
    std::FILE* f = std::fopen(key_path.c_str(), "rb");
    if (!f) return true;
    std::string key_pem;
    char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        key_pem.append(buf, n);
    std::fclose(f);
    if (key_pem.empty()) return true;

    std::unique_ptr<BIO, BioDel> bio(
        BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())));
    if (!bio) return true;
    std::unique_ptr<X509, X509Del> x(PEM_read_bio_X509(bio.get(), nullptr,
                                                       nullptr, nullptr));
    if (!x) return true;
    std::unique_ptr<EVP_PKEY, PkeyDel> pub(X509_get_pubkey(x.get()));
    if (!pub) return true;
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> leaf_n(pkey_modulus(pub.get()),
                                                      BN_free);
    if (!leaf_n) return true;
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> key_n(
        key_pem_modulus(key_pem, nullptr), BN_free);
    if (!key_n) return true;
    return BN_cmp(leaf_n.get(), key_n.get()) == 0;
}

bool fetch_and_store(std::string* err)
{
    auto fail = [err](const std::string& e) -> bool {
        if (err) *err = e;
        OBN_ERROR("appcert fetch: %s", e.c_str());
        return false;
    };

    const std::string dir = obn::config::dir();
    if (dir.empty())
        return fail("config dir not set (set_config_dir not called)");
    // Secret resolution: OBN_CLIENT_AUTH_SECRET env, else an imported
    // <config_dir>/client_auth_secret.txt (one line, 43 ASCII bytes — the
    // install UI drop point for clean-room builds), else the embedded
    // default (compiled out under OBN_EMBED_SECRET=OFF).
    std::string secret;
    if (const char* v = std::getenv("OBN_CLIENT_AUTH_SECRET"); v && *v) {
        secret = v;
    } else {
        std::ifstream sf(dir + "/client_auth_secret.txt");
        if (sf && std::getline(sf, secret) && !secret.empty() &&
            secret.back() == '\r')
            secret.pop_back();
        if (secret.empty())
            secret = client_auth_secret();
    }
    if (secret.size() != 43)
        return fail(
            "client_auth_secret missing or wrong length (set "
            "OBN_CLIENT_AUTH_SECRET or add <config_dir>/"
            "client_auth_secret.txt)");

    // 1. Session key + wrapped secret.
    unsigned char session_key[32];
    if (RAND_bytes(session_key, static_cast<int>(sizeof(session_key))) != 1)
        return fail("RAND_bytes(session_key) failed");
    std::string gcm_err;
    std::string enc_raw;
    if (!aes_gcm_seal(session_key, secret, &enc_raw, &gcm_err))
        return fail("secret encryption failed: " + gcm_err);
    const std::string enc_secret = detail::b64url_encode(enc_raw);

    std::string wrap_err;
    std::string wrapped;
    if (!rsa_wrap_session_key(
            std::string(reinterpret_cast<const char*>(session_key),
                        sizeof(session_key)),
            &wrapped, &wrap_err))
        return fail("session-key wrap failed: " + wrap_err);
    const std::string aes256 = detail::b64url_encode(wrapped);

    // 2. Request. Any User-Agent satisfies the endpoint (live check 2026-07;
    // the default OBN/<version> from http_client is fine).
    const std::string host =
        obn::config::cloud_api_host_for(obn::config::current(), "GLOBAL");
    const std::string url =
        host + "/v1/iot-service/api/user/applications/" + enc_secret +
        "/cert?aes256=" + aes256 + "&ver=1";
    OBN_INFO("appcert fetch: GET %s/v1/iot-service/api/user/applications/"
             "{enc_secret}/cert (client_auth_secret=%zu bytes)",
             host.c_str(), secret.size());
    obn::http::global_init();
    const obn::http::Response resp = obn::http::get_json(url);
    if (!resp.error.empty())
        return fail("transport error: " + resp.error);
    if (resp.status_code != 200)
        return fail("HTTP " + std::to_string(resp.status_code) + ": " +
                    body_prefix(resp.body, 300));

    // 3. Response envelope.
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root)
        return fail("response is not JSON (" + perr + "): " +
                    body_prefix(resp.body, 200));
    const auto code_v = root->find("code");
    bool code_ok = true;
    if (code_v.is_number()) code_ok = code_v.as_int() == 0;
    else if (code_v.is_string())
        code_ok = code_v.as_string().empty() || code_v.as_string() == "0";
    const std::string msg = root->find("message").as_string();
    if (!code_ok && msg != "success")
        return fail("API error: " + body_prefix(resp.body, 300));

    const auto join_field = [&root](const char* name) -> std::string {
        const auto v = root->find(name);
        std::string out;
        if (v.is_string()) out = v.as_string();
        else if (v.is_array()) {
            for (const auto& e : v.as_array()) out += e.as_string();
        }
        return out;
    };
    const std::string cert_pem = join_field("cert");
    const std::string crl_pem  = join_field("crl");
    const std::string key_blob = root->find("key").as_string();
    if (cert_pem.empty())
        return fail("response carries no cert: " + body_prefix(resp.body, 300));
    if (crl_pem.empty())
        return fail("response carries no crl: " + body_prefix(resp.body, 300));
    if (key_blob.empty())
        return fail("response carries no key: " + body_prefix(resp.body, 300));

    // 4. Unwrap key, cross-check against the leaf BEFORE touching disk.
    std::array<std::string, 5> limbs;
    std::string unwrap_err;
    if (!detail::decode_key_blob(key_blob, &limbs, &unwrap_err))
        return fail("key unwrap failed: " + unwrap_err);
    std::string pem_err;
    const std::string key_pem = detail::rsa_pem_from_crt(limbs, &pem_err);
    if (key_pem.empty())
        return fail("RSA rebuild failed: " + pem_err);

    std::string leaf_err;
    auto leaf = parse_leaf(cert_pem, &leaf_err);
    if (!leaf) return fail(leaf_err);
    std::unique_ptr<EVP_PKEY, PkeyDel> leaf_pub(X509_get_pubkey(leaf.get()));
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> leaf_n(
        pkey_modulus(leaf_pub.get()), BN_free);
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> key_n(
        key_pem_modulus(key_pem, nullptr), BN_free);
    if (!leaf_n || !key_n)
        return fail("cannot compare leaf / key moduli");
    if (BN_cmp(leaf_n.get(), key_n.get()) != 0)
        return fail("reconstructed key modulus does not match leaf certificate");
    const std::string serial = leaf_serial_hex(leaf.get());

    // 5. Write: cert first, key last (a crash in between leaves old-key +
    // new-cert, which the next fetch rebuilds via material_consistent()).
    struct FileOut { const char* name; const std::string* bytes; };
    const FileOut files[] = {
        {"slicer_cert.pem", &cert_pem},
        {"slicer_crl.pem", &crl_pem},
        {"slicer_key.pem", &key_pem},
    };
    for (const auto& fo : files) {
        std::string werr;
        const std::string path =
            resolved_path_or({}, fo.name); // default config-dir location
        const std::string& body = *fo.bytes;
        const std::string data =
            (!body.empty() && body.back() == '\n') ? body : body + "\n";
        if (!write_file_atomic(path, data, &werr)) return fail(werr);
    }
    obn::signing::invalidate_cache();

    OBN_INFO("appcert fetch: ok — wrote slicer_cert/crl/key into %s "
             "(leaf serial %s)", dir.c_str(), serial.c_str());
    return true;
}

} // namespace obn::appcert