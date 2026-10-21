// ensure_block_cloud_off(), ensure_conf_fixes() and their obn_ensure_conf_*
// exports the plugin installer calls once OrcaSlicer's audit hard-denies
// every Python open() of a "*.conf" path. The semantics mirror
// ensure_obn_conf() / ensure_log_to_file() / ensure_client_name() in
// open_bambu_networking.py: truthy key -> rewrite to 0, no key -> append the
// documented block, key already off -> file untouched, other lines preserved;
// log_to_file present -> value untouched (explicit 0 stays off), missing ->
// appended as 1; client_name only rewrites the shipped OpenBambooNetworking
// value.

#include "obn/config.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace fs = std::filesystem;

extern "C" int obn_ensure_conf_block_cloud(const char* conf_path);
extern "C" int obn_ensure_conf_fixes(const char* conf_path);

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__          \
                      << " " << #cond << "\n";                          \
            return 1;                                                   \
        }                                                               \
    } while (0)

static fs::path make_temp_dir()
{
    const fs::path base = fs::temp_directory_path() / "obn-conf-ensure-test";
    fs::create_directories(base);
    const fs::path dir = base / std::to_string(
        static_cast<unsigned long long>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(dir);
    return dir;
}

static void write_conf(const fs::path& path, const std::string& body)
{
    std::ofstream out(path, std::ios::binary);
    out << body;
}

static std::string read_conf(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

static int test_missing_file_created()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    CHECK(!fs::exists(path));
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Created);
    CHECK(fs::exists(path));
    const std::string body = read_conf(path);
    CHECK(body.find("block_cloud = 0") != std::string::npos);
    CHECK(body.find("block_cloud = 1") == std::string::npos);
    // Created from the full template, not a stub.
    CHECK(body.find("cloud_global_api_host = https://api.bambulab.com")
          != std::string::npos);
    return 0;
}

static int test_truthy_flipped_others_preserved()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path,
               "# my conf\n"
               "log_level = debug\n"
               "block_cloud = true\n"
               "lan_tls_skip_verify = 1\n");
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Set);
    const std::string body = read_conf(path);
    CHECK(body.find("block_cloud = 0\n") != std::string::npos);
    CHECK(body.find("block_cloud = true") == std::string::npos);
    CHECK(body.find("# my conf\n") == 0);
    CHECK(body.find("log_level = debug\n") != std::string::npos);
    CHECK(body.find("lan_tls_skip_verify = 1\n") != std::string::npos);
    return 0;
}

static int test_already_off_untouched()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "# header\nblock_cloud = 0\nlog_level = warn\n");
    const std::string before = read_conf(path);
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Unchanged);
    CHECK(read_conf(path) == before);
    return 0;
}

static int test_false_value_untouched()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "block_cloud = false\n");
    const std::string before = read_conf(path);
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Unchanged);
    CHECK(read_conf(path) == before);
    return 0;
}

static int test_missing_key_appended()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "log_level = debug\n");
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Appended);
    const std::string body = read_conf(path);
    CHECK(body.rfind("log_level = debug\n", 0) == 0);
    CHECK(body.find("block_cloud = 0\n") != std::string::npos);
    CHECK(body.find("talk to Bambu Cloud") != std::string::npos);
    return 0;
}

static int test_comment_is_not_the_key()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "# block_cloud = 1\nlog_level = debug\n");
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Appended);
    const std::string body = read_conf(path);
    CHECK(body.find("# block_cloud = 1\n") == 0);
    CHECK(body.find("\nblock_cloud = 0\n") != std::string::npos);
    return 0;
}

static int test_missing_final_newline_gains_one()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "block_cloud = 1");
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Set);
    const std::string body = read_conf(path);
    CHECK(body == "block_cloud = 0\n");
    return 0;
}

static int test_crlf_endings_preserved()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "log_level = debug\r\nblock_cloud = 1\r\n");
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Set);
    const std::string body = read_conf(path);
    CHECK(body.find("log_level = debug\r\n") != std::string::npos);
    CHECK(body.find("block_cloud = 0\r\n") != std::string::npos);
    CHECK(body.find("block_cloud = 1") == std::string::npos);
    return 0;
}

static int test_existing_empty_file_appended()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "");
    CHECK(obn::config::ensure_block_cloud_off(path.string())
          == obn::config::EnsureOutcome::Appended);
    CHECK(read_conf(path).find("block_cloud = 0\n") != std::string::npos);
    return 0;
}

static int test_empty_path_is_error()
{
    CHECK(obn::config::ensure_block_cloud_off("")
          == obn::config::EnsureOutcome::Error);
    CHECK(obn_ensure_conf_block_cloud(nullptr) == -1);
    CHECK(obn_ensure_conf_block_cloud("") == -1);
    return 0;
}

static int test_abi_export_roundtrip()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path, "block_cloud = 1\n");
    // 2 = Set, the same enum value the Python installer maps to its wording.
    CHECK(obn_ensure_conf_block_cloud(path.string().c_str()) == 2);
    CHECK(read_conf(path).find("block_cloud = 0\n") != std::string::npos);
    return 0;
}

// A pre-0.2.28 Python-installer conf: block already off, the shipped
// client_name value still there, no log_to_file key. All three fixes in one
// pass: block unchanged (0), log appended (1 byte), client rewritten (2 byte).
static int test_fixes_legacy_conf()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path,
               "# Open Bamboo Networking configuration\n"
               "block_cloud = 0\n"
               "client_name = OpenBambooNetworking\n");
    const int packed = obn_ensure_conf_fixes(path.string().c_str());
    CHECK(packed == (0 | (1 << 8) | (1 << 16)));
    const std::string body = read_conf(path);
    CHECK(body.find("client_name = BambuStudio\n") != std::string::npos);
    CHECK(body.find("log_to_file = 1\n") != std::string::npos);
    CHECK(body.find("# Open Bamboo Networking configuration\n") != std::string::npos);
    return 0;
}

// Values the user picked are never touched: block_cloud is forced off, but
// an explicit log_to_file = 0 stays off and a custom client_name stays.
static int test_fixes_user_values_kept()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    write_conf(path,
               "block_cloud = 1\n"
               "log_to_file = 0\n"
               "client_name = MyCustom\n");
    const int packed = obn_ensure_conf_fixes(path.string().c_str());
    CHECK(packed == 2); // Set, log untouched, client untouched
    const std::string body = read_conf(path);
    CHECK(body.find("block_cloud = 0\n") != std::string::npos);
    CHECK(body.find("log_to_file = 0\n") != std::string::npos);
    CHECK(body.find("client_name = MyCustom\n") != std::string::npos);
    return 0;
}

// Fresh file: the template (block_cloud = 1, log_to_file = 0,
// client_name = BambuStudio) is created and the block fix applied, reported
// as Created like ensure_block_cloud_off(); the template's log_to_file = 0
// becomes 1 (a fresh file means the user chose nothing, matching what the
// Python fresh path writes), client_name is already BambuStudio so byte 2
// stays 0.
static int test_fixes_fresh_file()
{
    const fs::path dir  = make_temp_dir();
    const fs::path path = dir / obn::config::kConfigFileName;
    CHECK(!fs::exists(path));
    const int packed = obn_ensure_conf_fixes(path.string().c_str());
    CHECK(packed == (1 | (1 << 8))); // Created, log enabled, client untouched
    CHECK(fs::exists(path));
    const std::string body = read_conf(path);
    CHECK(body.find("block_cloud = 0\n") != std::string::npos);
    CHECK(body.find("log_to_file = 1\n") != std::string::npos);
    CHECK(body.find("client_name = BambuStudio\n") != std::string::npos);
    return 0;
}

static int test_fixes_error_paths()
{
    CHECK(obn::config::ensure_conf_fixes("") == -1);
    CHECK(obn_ensure_conf_fixes(nullptr) == -1);
    CHECK(obn_ensure_conf_fixes("") == -1);
    return 0;
}

int main()
{
    if (test_missing_file_created() != 0) return 1;
    if (test_truthy_flipped_others_preserved() != 0) return 1;
    if (test_already_off_untouched() != 0) return 1;
    if (test_false_value_untouched() != 0) return 1;
    if (test_missing_key_appended() != 0) return 1;
    if (test_comment_is_not_the_key() != 0) return 1;
    if (test_missing_final_newline_gains_one() != 0) return 1;
    if (test_crlf_endings_preserved() != 0) return 1;
    if (test_existing_empty_file_appended() != 0) return 1;
    if (test_empty_path_is_error() != 0) return 1;
    if (test_abi_export_roundtrip() != 0) return 1;
    if (test_fixes_legacy_conf() != 0) return 1;
    if (test_fixes_user_values_kept() != 0) return 1;
    if (test_fixes_fresh_file() != 0) return 1;
    if (test_fixes_error_paths() != 0) return 1;

    std::cout << "conf_ensure_test: ok\n";
    return 0;
}
