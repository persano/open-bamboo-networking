#include "obn/cloud_auth.hpp"

#include "obn/config.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/signing.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <map>
#include <sstream>

namespace obn::cloud {

namespace {

std::string refresh_body(const std::string& refresh)
{
    std::ostringstream os;
    os << '{'
       << "\"refreshToken\":" << obn::json::escape(refresh)
       << '}';
    return os.str();
}

// Stock logout body uses the all-lowercase key `refreshtoken` (not
// camelCase) and always sends an empty string; Bearer alone is enough
// (research/08.05-auth.md gap_probe --do-logout).
std::string logout_body()
{
    return "{\"refreshtoken\":\"\"}";
}

// Extract the common "accessToken" shape. Fields that are absent stay
// empty; callers check `ok` first.
void fill_auth_fields(const obn::json::Value& root, AuthResult& r)
{
    r.access_token  = root.find("accessToken").as_string();
    r.refresh_token = root.find("refreshToken").as_string();
    r.expires_in    = root.find("expiresIn").as_int(0);
    r.refresh_expires_in = root.find("refreshExpiresIn").as_int(0);
    r.login_type    = root.find("loginType").as_string();
    // tfaKey is sometimes called "tfa_key"; check both.
    auto tfa1 = root.find("tfaKey").as_string();
    auto tfa2 = root.find("tfa_key").as_string();
    r.tfa_key = !tfa1.empty() ? tfa1 : tfa2;
}

std::string api_error(const obn::json::Value& root, long status)
{
    auto msg = root.find("message").as_string();
    if (msg.empty()) msg = root.find("error").as_string();
    if (msg.empty()) msg = "http " + std::to_string(status);
    return msg;
}

} // namespace

std::string api_host(const std::string& region)
{
    return obn::config::cloud_api_host_for(obn::config::current(), region);
}

std::string web_host(const std::string& region)
{
    return obn::config::cloud_web_host_for(obn::config::current(), region);
}

const char* os_type()
{
    // Host platform, the fallback identity in bbl_headers(). POST /my/task
    // rejects an OS mismatch with the leaf that signed the upload, so when a
    // slicer cert is in play bbl_headers() follows platform_for_leaf_pem()
    // instead and only reaches for this when there is no certificate.
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

const char* platform_for_leaf_pem(const std::string& pem)
{
    // research/10.02-secrets.md: the app identities split per client OS, and
    // the leaf CN/O is "<prefix>-<16 hex chars>0000" with the platform in the
    // first half. Our embedded client_auth_secret is the Windows one, so the
    // auto-provisioned leaf is the Windows leaf on every OS; a hand-placed
    // Linux chain has to keep reporting linux.
    if (pem.empty()) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    X509* leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!leaf) return nullptr;
    const char* result = nullptr;
    char field[256];
    const int nids[2] = {NID_commonName, NID_organizationName};
    for (int i = 0; !result && i < 2; ++i) {
        if (X509_NAME_get_text_by_NID(X509_get_subject_name(leaf), nids[i],
                                      field, sizeof(field)) <= 0)
            continue;
        const std::string value{field};
        const std::string suffix_windows = "-eed1e0410000";
        const std::string suffix_linux   = "-836763c70000";
        if (value.size() > suffix_windows.size() &&
            value.compare(value.size() - suffix_windows.size(),
                          suffix_windows.size(), suffix_windows) == 0)
            result = "windows";
        else if (value.size() > suffix_linux.size() &&
                 value.compare(value.size() - suffix_linux.size(),
                               suffix_linux.size(), suffix_linux) == 0)
            result = "linux";
    }
    X509_free(leaf);
    return result;
}

std::map<std::string, std::string> bbl_headers(const std::string& access_token,
                                               const std::string& user_id)
{
    const auto& cfg = obn::config::current();
    const auto& cfg_client_name = cfg.client_name;
    // Official BambuStudio EV code-signing attestation. The cloud validates
    // these contents (the PoP ablation in issue #112 shows a schema-valid
    // fake JSON still answers 403), so keep the real values and let obn.conf
    // override them when Bambu rotates.
    static constexpr const char* kStockExecutableInfo =
        R"({"cert_end_date":"2029-03-12","cert_start_date":"2025-12-23","hash_value":"3dca1e74c49cdcd6b6f551500f6f7667af28d8db","issue_name":"GlobalSign GCC R45 EV CodeSigning CA 2020","serial_number":"23009bd87d891a5405b02fbc","sign_date":"2026-08-14T09:50:51Z","subject_name":"Shanghai Lunkuo Technology Co., Ltd","verify_result":"0"})";
    std::map<std::string, std::string> h;
    h["Authorization"]        = "Bearer " + access_token;
    h["Content-Type"]         = "application/json";
    h["Accept"]               = "application/json";
    // BambuStudio is required, not cosmetic: /my/task and /user/ttcode
    // reject any other client name with HTTP 403 (research/
    // 06.06-cloud-rest.md).
    h["X-BBL-Client-Name"]    = cfg_client_name.empty() ? std::string{"BambuStudio"}
                                                        : cfg_client_name;
    h["X-BBL-Client-Type"]    = "slicer";
    // The cloud binds X-BBL-OS-Type to the signing leaf, and the leaf we hold
    // is provisioned from an embedded Windows client_auth_secret on every OS,
    // so the header follows the certificate rather than the host. Explicit
    // obn.conf cloud_os_type wins, then the leaf, then the host.
    std::string platform = cfg.cloud_os_type;
    if (platform.empty()) {
        if (const char* leaf = platform_for_leaf_pem(obn::signing::slicer_cert_pem()))
            platform = leaf;
    }
    if (platform.empty()) platform = os_type();
    OBN_DEBUG("bbl_headers: X-BBL-OS-Type=%s (config '%s')", platform.c_str(),
              cfg.cloud_os_type.c_str());
    h["X-BBL-OS-Type"]        = platform;
    h["X-BBL-Agent-OS-Type"]  = platform;
    h["X-BBL-Language"]       = "en-US";
    h["X-BBL-Executable-info"] = cfg.executable_info.empty()
                                     ? std::string{kStockExecutableInfo}
                                     : cfg.executable_info;
    if (!user_id.empty())
        h["X-BBL-Client-ID"] = "slicer:" + user_id + ":obn0";
    return h;
}

AuthResult login_with_ticket(const std::string& region,
                             const std::string& ticket)
{
    AuthResult r;
    if (ticket.empty()) {
        r.error_message = "empty ticket";
        return r;
    }
    // Endpoint confirmed from the original plugin's traffic:
    //   POST https://api.bambulab.com/v1/user-service/user/ticket/<TICKET>
    //   body: {"ticket":"<TICKET>"}
    // Response on success (HTTP 200):
    //   {"accessToken":"...","refreshToken":"...","expiresIn":31536000,
    //    "refreshExpiresIn":...,"tfaKey":"","accessMethod":"ticket",
    //    "loginType":"","firstAppLogin":false}
    // The ticket is single-use and short-lived; any failure here means
    // Studio will re-open the login dialog.
    std::string url  = api_host(region) + "/v1/user-service/user/ticket/" + ticket;
    std::string body = std::string("{\"ticket\":") + obn::json::escape(ticket) + "}";
    auto resp = obn::http::post_json(url, body);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    fill_auth_fields(*root, r);
    r.ok = !r.access_token.empty();
    if (!r.ok) r.error_message = api_error(*root, resp.status_code);
    return r;
}

AuthResult refresh_token(const std::string& region,
                         const std::string& access,
                         const std::string& refresh)
{
    AuthResult r;
    std::map<std::string, std::string> hdrs;
    if (!access.empty())
        hdrs["Authorization"] = "Bearer " + access;
    // Stock: POST /v1/user-service/user/refreshtoken + Bearer + refreshToken body.
    auto resp = obn::http::post_json(
        api_host(region) + "/v1/user-service/user/refreshtoken",
        refresh_body(refresh),
        hdrs);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) {
        r.error_message = "bad JSON: " + perr;
        return r;
    }
    fill_auth_fields(*root, r);
    r.ok = !r.access_token.empty();
    if (!r.ok) r.error_message = api_error(*root, resp.status_code);
    return r;
}

bool logout(const std::string& region,
            const std::string& access_token,
            const std::string& /*refresh*/)
{
    if (access_token.empty()) return true;
    std::map<std::string, std::string> hdrs{
        {"Authorization", "Bearer " + access_token},
    };
    // Evidence: MITM stock agent 02.08.01.53 — POST …/my/logout → 200
    // empty body. Failure must not block local session clear.
    auto resp = obn::http::post_json(
        api_host(region) + "/v1/user-service/my/logout",
        logout_body(),
        hdrs);
    if (!resp.error.empty()) {
        OBN_WARN("cloud logout: transport %s", resp.error.c_str());
        return false;
    }
    if (resp.status_code < 200 || resp.status_code >= 300) {
        OBN_WARN("cloud logout: http %ld", resp.status_code);
        return false;
    }
    return true;
}

ProfileResult get_profile(const std::string& region,
                          const std::string& access_token)
{
    ProfileResult r;
    std::map<std::string, std::string> hdrs{
        {"Authorization", "Bearer " + access_token},
    };
    auto resp = obn::http::get_json(api_host(region) + "/v1/user-service/my/profile", hdrs);
    r.http_status = resp.status_code;
    r.raw_body    = resp.body;
    if (!resp.error.empty()) {
        r.error_message = resp.error;
        return r;
    }
    if (resp.status_code != 200) {
        r.error_message = "http " + std::to_string(resp.status_code);
        return r;
    }
    std::string perr;
    auto root = obn::json::parse(resp.body, &perr);
    if (!root) { r.error_message = "bad JSON: " + perr; return r; }
    // The profile response looks like:
    //   {"uidStr":"...","name":"...","avatar":"...","account":"...","nickname":"..."}
    // (field names vary slightly across account regions; we accept a few
    // common spellings).
    r.user_id   = root->find("uidStr").as_string();
    if (r.user_id.empty()) {
        auto uid = root->find("uid").as_int(0);
        if (uid != 0) r.user_id = std::to_string(uid);
    }
    r.user_name = root->find("name").as_string();
    r.nick_name = root->find("nickname").as_string();
    if (r.nick_name.empty()) r.nick_name = root->find("nickName").as_string();
    r.avatar    = root->find("avatar").as_string();
    r.account   = root->find("account").as_string();
    // setting.isFirmwareBetaOpen controls whether the cloud firmware
    // endpoint returns beta firmware entries for this user's devices.
    r.firmware_beta_open = root->find("setting.isFirmwareBetaOpen").as_bool();
    r.ok = true;
    return r;
}

} // namespace obn::cloud
