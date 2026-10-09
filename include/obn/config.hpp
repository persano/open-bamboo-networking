#pragma once

// User-editable settings in <config_dir>/obn.conf (INI-like key = value).
// Loaded once from bambu_network_create_agent(log_dir). Environment
// variables override individual keys where documented (see log.hpp).

#include <string>

namespace obn::config {

inline constexpr const char* kConfigFileName = "obn.conf";

// Idle device-panel JPEG (MediaPlayCtrl downloads this slot).
inline constexpr const char* kCameraPreviewMemPath = "mem:/26";

// How start_local_print_with_record / start_print deliver the job.
// Orthogonal to block_cloud (background MQTT/REST).
enum class CloudPrintMode {
    CloudOnly,    // both ABIs → run_cloud_print_job (default)
    TryLanFirst,  // _with_record → local; fail lets Studio fall back to cloud
    LanOnly,      // _with_record → local; start_print always refused
};

struct Settings {
    // Logging (empty string = use built-in default for that key)
    std::string log_level;
    std::string log_stderr;
    std::string log_to_file;
    std::string log_file;

    // Cloud endpoints (per region; empty value falls back to production default)
    std::string cloud_global_api_host;
    std::string cloud_global_web_host;
    std::string cloud_global_mqtt_host;
    std::string cloud_cn_api_host;
    std::string cloud_cn_web_host;
    std::string cloud_cn_mqtt_host;

    // LAN / cloud networking
    bool lan_tls_skip_verify      = false;
    int  cloud_mqtt_port          = 8883;
    bool block_cloud              = true;

    // Print delivery for cloud-facing ABIs (see CloudPrintMode)
    CloudPrintMode cloud_print    = CloudPrintMode::CloudOnly;

    // When true, get_user_tasks returns an empty history envelope.
    bool cloud_hide_history       = false;

    // Ask each freshly subscribed cloud device for a full status snapshot
    // (pushing.pushall) once per session instead of waiting for the printer
    // to volunteer telemetry.
    bool cloud_pushall_on_connect = true;

    // Print behavior overrides
    bool force_timelapse_external = false;

    // File transfer
    bool force_ftps               = false;

    // Device panel: static "Printer Preview" JPEG (kCameraPreviewMemPath).
    bool disable_camera_preview      = false;

    // get_camera_url for a cloud-bound printer: prefer the LAN URL
    // (RTSP(S) / :6000) when the printer's video port answers a short TCP
    // probe; fall back to TUTK if LAN is down or LAN liveview is off and
    // credentials can be minted.
    // Off by default, matching the stock plugin.
    bool prefer_lan_over_tutk        = false;

    // MQTT connection persistence: Orca Slicer unconditionally tears down
    // and re-establishes the MQTT session after every print job, causing a
    // 5-30s reconnection delay.  Enabled by default to work around this.
    bool mqtt_keep_connection        = true;

    // Replace the LAN IP reported by the printer in push_status with the
    // IP used in connect_printer.  Needed for NAT / port-forwarding setups
    // where the printer advertises its internal LAN address but the slicer
    // must reach it via a different (public) IP.
    bool override_lan_ip             = false;

    // MQTT push_status patches (all off by default)
    bool patch_mqtt_home_flag        = false;
    bool patch_mqtt_ipcam_file       = false;
    bool patch_mqtt_internal_storage = false;
    // On by default in this fork: the banner fix ships enabled (upstream
    // default is false, opt-in). Set 0 to see the raw 65543 entries again.
    bool filter_mqtt_hms_65543       = true;

    // EXP-01 experiment mode: emit `sequence_id` as a JSON number on exactly
    // the frames the plugin builds AND signs (project_file, liveview prepare,
    // rescue republishes). Off (default) = byte-identical legacy string form.
    bool exp_numeric_sequence_id      = false;

    // Slicer signing key and app-cert provisioning files.
    // Empty = look for the corresponding file in config_dir:
    //   slicer_key_pem  -> slicer_key.pem
    //   slicer_cert_pem -> slicer_cert.pem   (app cert chain; MQTT/HTTP cert_id
    //                                         is derived from the leaf)
    //   slicer_crl_pem  -> slicer_crl.pem    (app CRL for app_cert_install)
    std::string slicer_key_pem;
    std::string slicer_cert_pem;
    std::string slicer_crl_pem;

    // Value sent in the `X-BBL-Client-Name` HTTP header on cloud REST calls.
    // The MakerWorld `POST /my/task` endpoint authorizes access to the
    // uploaded print content ONLY for the stock client name "BambuStudio",
    // and the `/user/ttcode` camera mint has the same requirement; any other
    // value is rejected with HTTP 403 ("no access rights to the content"),
    // which blocks cloud printing, "local print with record" and cloud
    // live view. Empty falls back to "BambuStudio" in bbl_headers().
    std::string client_name;

    // Value sent in `X-BBL-Executable-info` on cloud REST calls. Bambu's
    // cloud validates the JSON contents (hash_value, serial_number, ...) and
    // answers 403 when they do not match a known Studio build, so empty
    // falls back to the built-in copy of BambuStudio's EV code-signing
    // attestation. Override here if Bambu rotates the attestation and the
    // built-in value stops being accepted.
    std::string executable_info;

    // Attach proof-of-possession headers (`x-bbl-app-certification-id` +
    // `x-bbl-device-security-sign`) to POST /v1/user-service/my/task.
    // Default 0 keeps the historical behaviour (bearer token + client
    // identity only). Set 1 on the CN cloud, where the same account and
    // client name that 200 on api.bambulab.com answer 403 on
    // api.bambulab.cn (H2D report 2026-10-08, obn(2).log) and research
    // 10.05 lists /my/task as PoP-required on secured printers. add_pop_headers
    // silently sends nothing when the slicer key/cert material is absent or
    // mismatched, so 1 is safe on accounts without credentials.
    bool mytask_pop = false;

    // BambuSource logging — propagated to libBambuSource via obn.env
    std::string bambusource_log_level;
    std::string bambusource_log_stderr;
    std::string bambusource_log_to_file;
    std::string bambusource_log_file;
};

// Parse "0"/"1"/"true"/"false"/"yes"/"no" (case-insensitive) into a bool.
// Returns `fallback` for unrecognised values.
bool truthy(const std::string& val, bool fallback = false);

// Outcome of ensure_block_cloud_off(), doubled as the return value of the
// obn_ensure_conf_block_cloud() ABI (the plugin installer maps it to its
// install-message wording).
enum class EnsureOutcome {
    Error     = -1, // empty path, or the file could not be read/written
    Unchanged =  0, // block_cloud already off: file untouched
    Created   =  1, // obn.conf did not exist: template written with block_cloud = 0
    Set       =  2, // an existing block_cloud was truthy: rewritten to 0
    Appended  =  3, // no block_cloud key in an existing file: key appended
};

// Force `block_cloud = 0` in an existing or missing obn.conf, preserving
// every other line and the file's original line endings. This is the
// installer's job (see ensure_obn_conf() in open_bambu_networking.py);
// it lives here because OrcaSlicer's plugin audit hard-denies every Python
// open() of a path whose name contains "conf", so the plugin must delegate
// the write to the library that owns the file -- C++ writes are outside the
// Python audit hook. Returns Error when the path is empty or a write fails.
EnsureOutcome ensure_block_cloud_off(const std::string& conf_path);

// Load from <config_dir>/obn.conf; create a commented template if missing.
// Thread-safe; subsequent calls return the same cached Settings until
// load_or_create is called with a different non-empty directory.
Settings load_or_create(const std::string& config_dir);

// Parse an existing obn.conf without creating a template if absent.
// Returns default Settings when the file does not exist.
Settings load_if_exists(const std::string& config_dir);

// Valid only after load_or_create(); otherwise returns default Settings.
const Settings& current();

// The config_dir passed to the most recent load_or_create() call.
// All default file paths (key, cert, CRL, …) are relative to this.
const std::string& dir();

// Join `basename` onto the active config_dir() using the platform's native
// path separator (via std::filesystem). Returns "" when no config_dir has
// been set. Always use this for files living in the config directory instead
// of hand-concatenating "dir + \"/\" + name", which is not portable to
// Windows.
std::string path_in_dir(const std::string& basename);

// Resolve cloud endpoints for `region` ("CN"/"cn" = China, else global).
// Empty configured values fall back to production defaults.
std::string cloud_api_host_for(const Settings& s, const std::string& region);
std::string cloud_web_host_for(const Settings& s, const std::string& region);
std::string cloud_mqtt_host_for(const Settings& s, const std::string& region);

} // namespace obn::config
