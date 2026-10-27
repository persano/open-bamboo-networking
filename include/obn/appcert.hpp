#pragma once

// Shared slicer app-credential fetch — the OBN implementation of stock
// bambu_network_update_cert (Studio GUI_App::check_cert, research/08.04-lan.md
// §8.4.6 and research/10.02-secrets.md).
//
// Stock Studio fetches the shared app certificate + CRL + private key on a
// background thread right after post_init and stores them in its config dir
// as slicer_cert.pem / slicer_crl.pem / slicer_key.pem; every secured-printer
// command is signed with that key. OBN provisions the same three files by
// calling Bambu's cert endpoint itself. The two bootstrap values the request
// needs (client_auth_secret, server wrap key) and their recovery procedure
// are documented in src/appcert_cipher.cpp.

#include <array>
#include <string>

namespace obn::appcert {

// The 43-byte client_auth_secret (app-cert CN prefix + fixed ASCII tail).
// Never logged or added to headers — only ever AES-GCM-encrypted into the
// request URL path segment. OBN_CLIENT_AUTH_SECRET (43 bytes) overrides the
// embedded default at runtime (rotation / no-embedded builds).
std::string client_auth_secret();

// PEM SubjectPublicKeyInfo of CN=service.bambulab.com — the public "server
// wrap key" published with the reverse-networking documentation (service.crt).
// Used to wrap the ephemeral AES session key; the private half lives only on
// Bambu's side.
const char* server_wrap_key_pem();

// GETs the shared app credentials from
//   <cloud api host>/v1/iot-service/api/user/applications/{enc}/cert?...
// validates that the returned private key matches the returned leaf
// certificate, and writes slicer_cert.pem / slicer_crl.pem / slicer_key.pem
// into config::dir() (atomic: temp file + rename, cert written first, key
// last). On success drops the cached parsed key/cert ids in obn::signing so
// the next signing call picks the new material up. Blocking — one HTTPS
// round trip. Returns false and fills *err on the first failure without
// touching any existing file.
bool fetch_and_store(std::string* err);

// True when the on-disk slicer_cert.pem leaf and slicer_key.pem share the
// same RSA modulus — a signature only verifies if the printer trusts the
// certificate paired with the signing key, so a mismatch (possible after a
// crash between the multi-file writes above) must trigger a refetch.
// Returns true (no opinion) when either file is missing or unparseable —
// the missing-material checks at the call sites cover that case.
bool material_consistent();

namespace detail {

// AES-256-CTR with the custom appcert S-box (NOT standard AES — SBOX[0] =
// 0xC5). Key schedule and block cipher are ported 1:1 from
// tools/fetch_slicer_credentials.py (KATs in tests/appcert_test.cpp).
// `nonce` must be 12 bytes; block i of the keystream uses counter 2 + i, so
// the first ciphertext block recovers with counter 2. Returns "" for a
// non-12-byte nonce.
std::string ctr_xor(const unsigned char key[32], const std::string& nonce,
                    const std::string& data);

// Unwraps the response `key` field: base64 blob framed as
//   nonce(12) || tag(16) || u32le(ct_len) || ciphertext
// whose plaintext is
//   SKEY-magic(4) || version(4) || bitlen(4) || 5 x u32le limb-len(20) ||
//   p || q || dp || dq || qinv        (equal-width big-endian limbs)
// Note the wire magic bytes 59 45 4b 53 are little-endian "SKEY" (ASCII
// "YEKS"). Fails on short frames, missing magic, or a body that is not five
// equal limbs.
bool decode_key_blob(const std::string& blob_b64,
                     std::array<std::string, 5>* limbs, std::string* err);

// Rebuilds an unencrypted PKCS#8 PEM RSA private key from CRT limbs
// (e = 65537, d = e^-1 mod lcm(p-1, q-1) — same construction as the Python
// reference). Fails on empty limbs or when the modular inverse does not
// exist. Sanity: the caller must still check the modulus against the leaf
// certificate (fetch_and_store does).
std::string rsa_pem_from_crt(const std::array<std::string, 5>& limbs,
                             std::string* err);

// URL-safe base64 (RFC 4648 §5) WITH padding — the encoding used in the
// request URL path segment and the aes256 query value.
std::string b64url_encode(const std::string& data);

} // namespace detail
} // namespace obn::appcert