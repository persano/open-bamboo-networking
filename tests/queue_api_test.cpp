// Queue integration API (issues #13/#16, stage 1+2): strict request
// validation, capability discovery, client/watch lifecycle, snapshots,
// event polling, session purge, and obn_read_text_file (issue #17).
//
// Framework: repo convention (int main() + fail_count + CHECK, as in
// push_status_merge_test.cpp). Fixtures load at runtime relative to the
// ctest WORKING_DIRECTORY (tests/fixtures, D-08).

#include "obn/obn_queue_api_v1.h"
#include "obn/queue_api.hpp"
#include "obn/json_lite.hpp"
#include "obn/os_compat.hpp"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

static int fail_count = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                         #cond);                                        \
            ++fail_count;                                               \
        }                                                               \
    } while (0)

namespace {

namespace json = obn::json;

// Call the C export and parse the envelope. rc must be 0 for every
// well-formed request (application errors still return 0 with ok=false).
struct Envelope {
    int         rc = -1;
    json::Value v;
    std::string text;
};

Envelope call(const std::string& req)
{
    Envelope e;
    char*    out  = nullptr;
    uint32_t n    = 0;
    e.rc          = obn_queue_call_v1(req.data(),
                                      static_cast<uint32_t>(req.size()), &out, &n);
    if (e.rc == 0 && out) {
        e.text.assign(out, n);
        auto p = json::parse(e.text);
        if (p) e.v = std::move(*p);
    }
    if (out) obn_queue_free_v1(out);
    return e;
}

bool ok(const Envelope& e)
{
    return e.rc == 0 && e.v.is_object() && e.v.find("ok").as_bool();
}

std::string err_code(const Envelope& e)
{
    return e.v.find("error.code").as_string();
}

// Minimal request builder: fixed envelope + op-specific body.
std::string req(const char* op, const std::string& body,
                const char* rid = "r1")
{
    std::string s = "{\"api\":1,\"request_id\":\"";
    s += rid;
    s += "\",\"op\":\"";
    s += op;
    s += "\"";
    s += body;
    s += "}";
    return s;
}

bool read_fixture(const char* rel, std::string& out)
{
    std::ifstream in(rel, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "FAIL cannot open fixture: %s\n", rel);
        ++fail_count;
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

const char* const kFrames[] = {
    "sequences/p1s-print-lifecycle/00-pushall.json",
    "sequences/p1s-print-lifecycle/01-delta-temps.json",
    "sequences/p1s-print-lifecycle/02-delta-progress.json",
    "sequences/p1s-print-lifecycle/03-delta-tray-switch.json",
    "sequences/p1s-print-lifecycle/04-delta-null-clears-wifi.json",
    "sequences/p1s-print-lifecycle/05-delta-pause.json",
    "sequences/p1s-print-lifecycle/06-delta-finish.json",
};

} // namespace

// ---------------------------------------------------------------------------
// Validation: UTF-8, duplicate keys, depth, NUL, oversize, unknown op.
// ---------------------------------------------------------------------------
static void test_validation()
{
    Envelope e;

    // Embedded NUL rejected before parsing.
    {
        std::string r = "{\"api\":1,\"request_id\":\"x\"}";
        r.insert(r.begin() + 5, '\0');
        e = call(r);
        CHECK(e.rc == 0);
        CHECK(!ok(e));
        CHECK(err_code(e) == "invalid_request");
    }

    // Oversize request.
    e = call(std::string(OBN_QUEUE_MAX_REQUEST_BYTES + 1, ' '));
    CHECK(e.rc == 0);
    CHECK(err_code(e) == "invalid_request");

    // Malformed UTF-8 (lone continuation byte).
    {
        std::string r = "{\"api\":1,\"request_id\":\"a\x80\"}";
        e = call(r);
        CHECK(err_code(e) == "invalid_request");
        CHECK(e.v.find("error.message").as_string() == "malformed UTF-8");
    }

    // Duplicate key.
    e = call("{\"api\":1,\"request_id\":\"a\",\"api\":1}");
    CHECK(err_code(e) == "invalid_request");
    CHECK(e.v.find("error.message").as_string().find("duplicate key") == 0);

    // Nesting deeper than 32.
    {
        std::string r = "{\"api\":1,\"request_id\":\"a\",\"x\":";
        for (int i = 0; i < 33; ++i) r += '[';
        r += "1";
        for (int i = 0; i < 33; ++i) r += ']';
        r += "}";
        e = call(r);
        CHECK(err_code(e) == "invalid_request");
        CHECK(e.v.find("error.message").as_string() == "nesting deeper than 32");
    }

    // api version + unknown op.
    e = call("{\"api\":2,\"request_id\":\"a\",\"op\":\"capabilities\"}");
    CHECK(err_code(e) == "unsupported_version");
    e = call("{\"api\":1,\"request_id\":\"a\",\"op\":\"print.submit\"}");
    CHECK(err_code(e) == "not_supported");
    CHECK(e.v.find("op").as_string() == "print.submit");
    CHECK(e.v.find("request_id").as_string() == "a");

    // Null C pointers.
    char* out  = nullptr;
    uint32_t n = 0;
    CHECK(obn_queue_call_v1(nullptr, 4, &out, &n) == -1);
    CHECK(obn_queue_call_v1("{\"api\":1}", 10, nullptr, &n) == -1);
    CHECK(obn_queue_call_v1("{\"api\":1}", 10, &out, nullptr) == -1);
}

// ---------------------------------------------------------------------------
// Capabilities shape + envelope fields.
// ---------------------------------------------------------------------------
static void test_capabilities()
{
    Envelope e = call(req("capabilities", ""));
    CHECK(ok(e));
    CHECK(e.v.find("api").as_number() == 1.0);
    CHECK(!e.v.find("instance_id").as_string().empty());
    CHECK(!e.v.find("session_epoch").as_string().empty());
    CHECK(e.v.find("capabilities_revision").as_string() == "stage3-draft-1");
    CHECK(e.v.find("op").as_string() == "capabilities");

    const json::Value res = e.v.find("result");
    CHECK(res.find("api_versions").as_array().size() == 1);
    CHECK(res.find("api_versions").as_array()[0].as_number() == 1.0);
    CHECK(res.find("operations").as_array().size() == 10);
    CHECK(res.find("command_kinds").as_array().size() == 4);
    CHECK(res.find("command_kinds").as_array()[0].as_string() == "print");
    CHECK(res.find("command_kinds").as_array()[3].as_string() == "stop");
    CHECK(res.find("command_protocol_revision").as_string() == "stage3-draft-1");
    const json::Value sub = res.find("submission");
    CHECK(sub.find("idempotency").as_string() == "durable_at_most_once_dispatch");
    CHECK(sub.find("max_pending_per_device").as_number() == 1.0);
    CHECK(res.find("features").as_array().size() == 2);
    CHECK(res.find("limits.max_clients").as_number() == 4);
    CHECK(res.find("limits.poll_min_interval_ms").as_number() == 500);
    CHECK(res.find("session_state").is_string());

    // Extra top-level field rejected.
    e = call("{\"api\":1,\"request_id\":\"a\",\"op\":\"capabilities\",\"x\":1}");
    CHECK(err_code(e) == "invalid_request");
}

// ---------------------------------------------------------------------------
// Client lifecycle: open/close, lease bounds, capacity, epoch echo.
// ---------------------------------------------------------------------------
static std::string g_epoch;   // epoch captured after client.open
static std::string g_client;  // open client_id

static void test_client_lifecycle()
{
    Envelope e;

    // Bad params.
    e = call(req("client.open", ",\"params\":{\"name\":\"\",\"lease_seconds\":60}"));
    CHECK(err_code(e) == "invalid_request");
    e = call(req("client.open", ",\"params\":{\"name\":\"x\",\"lease_seconds\":10}"));
    CHECK(err_code(e) == "invalid_request");
    e = call(req("client.open", ",\"params\":{\"name\":\"x\"}"));
    CHECK(err_code(e) == "invalid_request");

    // Valid open.
    e = call(req("client.open", ",\"params\":{\"name\":\"t\",\"lease_seconds\":60}", "o1"));
    CHECK(ok(e));
    g_client = e.v.find("result.client_id").as_string();
    g_epoch  = e.v.find("session_epoch").as_string();
    CHECK(!g_client.empty());
    CHECK(e.v.find("result.lease_seconds").as_number() == 60);

    // Capacity: fill to 4, 5th fails.
    std::vector<std::string> extra;
    for (int i = 0; i < 3; ++i) {
        Envelope c = call(req("client.open",
                              ",\"params\":{\"name\":\"x\",\"lease_seconds\":60}"));
        CHECK(ok(c));
        extra.push_back(c.v.find("result.client_id").as_string());
    }
    e = call(req("client.open", ",\"params\":{\"name\":\"x\",\"lease_seconds\":60}"));
    CHECK(err_code(e) == "capacity_exceeded");
    for (const auto& id : extra) {
        Envelope c = call(std::string("{\"api\":1,\"request_id\":\"c\",\"op\":\"client.close\",")
                          + "\"client_id\":\"" + id + "\",\"session_epoch\":\"" + g_epoch + "\"}");
        CHECK(ok(c));
    }

    // Wrong epoch -> session_changed.
    e = call(std::string("{\"api\":1,\"request_id\":\"c\",\"op\":\"devices.list\",")
             + "\"client_id\":\"" + g_client + "\",\"session_epoch\":\"nope\"}");
    CHECK(err_code(e) == "session_changed");

    // Unknown client -> client_expired.
    e = call(std::string("{\"api\":1,\"request_id\":\"c\",\"op\":\"devices.list\",")
             + "\"client_id\":\"c999999\",\"session_epoch\":\"" + g_epoch + "\"}");
    CHECK(err_code(e) == "client_expired");

    // devices.list works with a live client (empty inventory initially).
    e = call(std::string("{\"api\":1,\"request_id\":\"c\",\"op\":\"devices.list\",")
             + "\"client_id\":\"" + g_client + "\",\"session_epoch\":\"" + g_epoch + "\"}");
    CHECK(ok(e));
    CHECK(e.v.find("result.devices").is_array());
}

// ---------------------------------------------------------------------------
// Inventory, watch.set, snapshot.get, ingest of the 7 lifecycle frames.
// ---------------------------------------------------------------------------
static const char* kDev = "01P00C490800259";

static std::string client_op(const char* op, const std::string& params)
{
    return std::string("{\"api\":1,\"request_id\":\"c\",\"op\":\"") + op +
           "\",\"client_id\":\"" + g_client + "\",\"session_epoch\":\"" + g_epoch +
           "\"" + params + "}";
}

static void test_devices_watch_snapshot()
{
    // Authorized inventory from the cloud device list.
    obn::queue::note_devices_from_cloud(
        "{\"devices\":[{\"dev_id\":\"" + std::string(kDev) +
        "\",\"dev_name\":\"P1S\",\"dev_product_name\":\"Bambu Lab P1S\"}]}");

    Envelope e = call(client_op("devices.list", ""));
    CHECK(ok(e));
    const json::Array& devs = e.v.find("result.devices").as_array();
    CHECK(devs.size() == 1);
    CHECK(devs[0].find("device_id").as_string() == kDev);
    CHECK(devs[0].find("name").as_string() == "P1S");

    // watch.set: unknown device -> device_unavailable, watch unchanged.
    e = call(client_op("watch.set", ",\"params\":{\"device_ids\":[\"nope\"]}"));
    CHECK(err_code(e) == "device_unavailable");

    // Duplicate id rejected.
    e = call(client_op("watch.set",
                       ",\"params\":{\"device_ids\":[\"" + std::string(kDev) +
                       "\",\"" + kDev + "\"]}"));
    CHECK(err_code(e) == "invalid_request");

    // Valid watch: echo, cursor, one printer.
    e = call(client_op("watch.set",
                       ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));
    CHECK(e.v.find("result.cursor").as_string().find("e") == 0);
    CHECK(e.v.find("result.printers").as_array().size() == 1);

    // Ingest the 7 vendored frames for this device.
    for (const char* f : kFrames) {
        std::string body;
        if (!read_fixture(f, body)) continue;
        obn::queue::ingest_frame(kDev, body);
    }

    // Snapshot reflects merged state after 06 (FINISH, 100%).
    e = call(client_op("snapshot.get",
                       ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));
    const json::Value& p = e.v.find("result.printers").as_array()[0];
    CHECK(p.find("device_id").as_string() == kDev);
    CHECK(p.find("name").as_string() == "P1S");
    CHECK(p.find("online").as_bool() == true);
    CHECK(p.find("state").as_string() == "idle");
    CHECK(p.find("job.state").as_string() == "completed");
    CHECK(p.find("job.progress_percent").as_number() == 100);
    CHECK(p.find("temperature.nozzle_c").as_number() == 220.2);
    CHECK(p.find("nozzle_diameter").as_number() == 0.4);
    CHECK(p.find("status_age_ms").is_number());

    // Per-printer command support advertises the capability-gated
    // supply "none" mode alongside ams/external.
    const json::Array& sm = p.find("command_support.supply_modes").as_array();
    CHECK(sm.size() == 3);
    CHECK(sm[0].as_string() == "ams");
    CHECK(sm[2].as_string() == "none");

    // snapshot.get for a device outside the watch set.
    e = call(client_op("snapshot.get", ",\"params\":{\"device_ids\":[\"other\"]}"));
    CHECK(err_code(e) == "device_unavailable");

    // Non-push_status frames are ignored by ingest.
    obn::queue::ingest_frame(kDev, "{\"print\":{\"command\":\"other\"}}");
    e = call(client_op("snapshot.get",
                       ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));
}

// ---------------------------------------------------------------------------
// events.poll: cursor semantics, rate limit, watch filtering.
// ---------------------------------------------------------------------------
static std::string g_cursor; // cursor from watch.set (tail at that moment)

static void test_events_poll()
{
    // Fresh watch -> cursor at the current tail; poll rate limit resets.
    Envelope e = call(client_op("watch.set",
                                ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));
    g_cursor = e.v.find("result.cursor").as_string();

    // Two state changes -> at least two events (printer.status each,
    // job.state on the PAUSE transition).
    obn::queue::ingest_frame(kDev,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"mc_percent\":42}}");
    obn::queue::ingest_frame(kDev,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"gcode_state\":\"PAUSE\"}}");

    // limit=1 -> one event and has_more.
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + g_cursor + "\",\"limit\":1}"));
    CHECK(ok(e));
    CHECK(e.v.find("result.events").as_array().size() == 1);
    CHECK(e.v.find("result.has_more").as_bool() == true);
    const std::string next = e.v.find("result.next_cursor").as_string();
    CHECK(next != g_cursor);

    // Immediate second poll -> busy (retryable), poll_min_interval_ms.
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + next + "\",\"limit\":64}"));
    CHECK(err_code(e) == "busy");
    CHECK(e.v.find("error.retryable").as_bool() == true);

    // Reset the rate limit via watch.set, then drain the rest.
    e = call(client_op("watch.set",
                        ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + next + "\",\"limit\":64}"));
    CHECK(ok(e));
    CHECK(e.v.find("result.events").as_array().size() >= 1);
    CHECK(e.v.find("result.has_more").as_bool() == false);

    // watch.set also resets the rate limit before the establish poll.
    e = call(client_op("watch.set",
                        ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));

    // Establish (null cursor) -> empty live tail, no history.
    e = call(client_op("events.poll", ",\"params\":{\"cursor\":null,\"limit\":64}"));
    CHECK(ok(e));
    CHECK(e.v.find("result.events").as_array().empty());
    g_cursor = e.v.find("result.next_cursor").as_string();
    CHECK(g_cursor.find("e") == 0);

    // Cursor validation. Format errors are caught before the rate limit;
    // the ahead-of-stream check sits behind it, so reset first.
    e = call(client_op("events.poll", ",\"params\":{\"cursor\":\"bogus\",\"limit\":64}"));
    CHECK(err_code(e) == "invalid_request");
    e = call(client_op("events.poll", ",\"params\":{\"cursor\":\"e99999999999999999999999\",\"limit\":64}"));
    CHECK(err_code(e) == "invalid_request");
    e = call(client_op("watch.set",
                        ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(ok(e));
    e = call(client_op("events.poll", ",\"params\":{\"cursor\":\"e999999999\",\"limit\":64}"));
    CHECK(err_code(e) == "invalid_request");
    e = call(client_op("events.poll", ",\"params\":{\"cursor\":\"" + g_cursor + "\",\"limit\":0}"));
    CHECK(err_code(e) == "invalid_request");

    // Events for a device nobody watches are filtered: poll after a
    // non-watched device ingests must not surface them.
    e = call(client_op("watch.set", ",\"params\":{\"device_ids\":[]}"));
    CHECK(ok(e));
    obn::queue::ingest_frame("unwatched-dev",
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"gcode_state\":\"RUNNING\"}}");
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + g_cursor + "\",\"limit\":64}"));
    CHECK(ok(e));
    const json::Array& evs = e.v.find("result.events").as_array();
    for (const auto& ev : evs)
        CHECK(ev.find("data.device_id").as_string() != "unwatched-dev");
}

// ---------------------------------------------------------------------------
// Session purge (issue #13): epoch bump, inventory/watch cleared,
// stale epoch rejected, old cursor still delivers the session.changed event.
// ---------------------------------------------------------------------------
static void test_session_purge()
{
    // The purge under test: clears devices/inventory/events/watch sets,
    // bumps session_epoch, pushes session.changed(reason=logout).
    obn::queue::note_session_changed("logout");

    Envelope e = call(req("capabilities", "", "p1"));
    CHECK(ok(e));
    const std::string old_epoch = g_epoch;
    g_epoch = e.v.find("session_epoch").as_string();
    CHECK(g_epoch != old_epoch);

    // Stale epoch rejected on every client-scoped op.
    e = call(std::string("{\"api\":1,\"request_id\":\"c\",\"op\":\"devices.list\",")
             + "\"client_id\":\"" + g_client + "\",\"session_epoch\":\"" + old_epoch + "\"}");
    CHECK(err_code(e) == "session_changed");

    // Inventory purged.
    e = call(client_op("devices.list", ""));
    CHECK(ok(e));
    CHECK(e.v.find("result.devices").as_array().empty());

    // Watch set purged: re-watch needs a known device again.
    e = call(client_op("watch.set",
                       ",\"params\":{\"device_ids\":[\"" + std::string(kDev) + "\"]}"));
    CHECK(err_code(e) == "device_unavailable");

    // Empty watch is valid and resets the poll rate limit.
    e = call(client_op("watch.set", ",\"params\":{\"device_ids\":[]}"));
    CHECK(ok(e));

    // The cursor taken before the purge is exactly min_valid_seq, so it
    // still resolves and delivers the session.changed event.
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + g_cursor + "\",\"limit\":64}"));
    CHECK(ok(e));
    const json::Array& evs = e.v.find("result.events").as_array();
    CHECK(evs.size() == 1);
    CHECK(evs[0].find("kind").as_string() == "session.changed");
    CHECK(evs[0].find("data.reason").as_string() == "logout");

    // Reset the rate limit; the poll checks it before cursor validation.
    e = call(client_op("watch.set", ",\"params\":{\"device_ids\":[]}"));
    CHECK(ok(e));

    // A cursor behind the purge point is expired.
    e = call(client_op("events.poll", ",\"params\":{\"cursor\":\"e1\",\"limit\":64}"));
    CHECK(err_code(e) == "cursor_expired");

    // Client close still works after the purge; a second close fails.
    e = call(client_op("client.close", ""));
    CHECK(ok(e));
    e = call(client_op("client.close", ""));
    CHECK(err_code(e) == "client_expired");
    g_client.clear();
}

// ---------------------------------------------------------------------------
// obn_read_text_file (issue #17): probe, read, offset, error codes.
// ---------------------------------------------------------------------------
extern "C" long long obn_read_text_file(const char* path,
                                        unsigned long long offset,
                                        char* out,
                                        unsigned int out_capacity);

static void test_read_text_file()
{
    namespace fs = std::filesystem;
    const fs::path p = fs::temp_directory_path() / "obn_queue_api_read_test.txt";
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f << "hello queue api";
    }
    const std::string path = p.string();

    // Probe: null out -> size.
    CHECK(obn_read_text_file(path.c_str(), 0, nullptr, 0) == 15);
    // Read prefix.
    {
        char buf[16] = {};
        CHECK(obn_read_text_file(path.c_str(), 0, buf, 5) == 5);
        CHECK(std::string(buf, 5) == "hello");
    }
    // Read from offset.
    {
        char buf[16] = {};
        CHECK(obn_read_text_file(path.c_str(), 6, buf, 16) == 9);
        CHECK(std::string(buf, 9) == "queue api");
    }
    // Offset at/past EOF -> 0, not an error.
    {
        char buf[4] = {};
        CHECK(obn_read_text_file(path.c_str(), 15, buf, 4) == 0);
        CHECK(obn_read_text_file(path.c_str(), 99, buf, 4) == 0);
    }
    // Missing file -> -2; bad args -> -1.
    CHECK(obn_read_text_file("no/such/file.conf", 0, nullptr, 0) == -2);
    CHECK(obn_read_text_file(nullptr, 0, nullptr, 0) == -1);
    CHECK(obn_read_text_file("", 0, nullptr, 0) == -1);

    std::error_code ec;
    fs::remove(p, ec);
}

// Full print command JSON for the mapping-shape checks below.
static std::string map_cmd(const std::string& supply,
                           const std::string& materials)
{
    return "{\"kind\":\"print\",\"device_id\":\"01P00C490800259\","
           "\"payload\":{\"file\":{\"path\":\"C:/map.3mf\",\"sha256\":\"" +
           std::string(64, '0') +
           "\",\"plate_index\":1},\"task_tag\":\"map\","
           "\"supply\":\"" + supply + "\",\"materials\":" + materials +
           ",\"options\":{\"bed_leveling\":false,"
           "\"flow_calibration\":false,\"timelapse\":false}}}";
}

// Legacy mapping shapes (ChenLei's stock-bridge compare fixtures): one
// amsDetailMapping element per project filament, holes stay -1 in the
// flat array and become {255,255} in amsMapping2, with {255,0}
// reserved for a real external selection.
static void test_mapping_outputs()
{
    std::string flat, snake, detail, err;

    // Real external selection: -1 flat, {255,0} snake, full detail.
    CHECK(obn::queue::test_build_mapping(
        map_cmd("external",
                "[{\"source_filament_id\":\"0\",\"slot_id\":\"external\","
                "\"type\":\"PETG\",\"profile_id\":\"GFG99\","
                "\"source_color\":\"#FAFAFAFF\","
                "\"target_color\":\"#FAFAFAFF\"}]"),
        &flat, &snake, &detail, &err));
    CHECK(flat == "[-1]");
    CHECK(snake == "[{\"ams_id\":255,\"slot_id\":0}]");
    CHECK(detail ==
          "[{\"ams\":-1,\"targetColor\":\"FAFAFAFF\","
          "\"filamentId\":\"GFG99\",\"filamentType\":\"PETG\","
          "\"sourceColor\":\"FAFAFAFF\"}]");

    // Single AMS tray: flat carries the linear slot ams*4+tray.
    CHECK(obn::queue::test_build_mapping(
        map_cmd("ams",
                "[{\"source_filament_id\":\"0\",\"slot_id\":\"ams-0-slot-3\","
                "\"type\":\"PETG\",\"profile_id\":\"GFG99\","
                "\"source_color\":\"#FAFAFAFF\","
                "\"target_color\":\"#FAFAFAFF\"}]"),
        &flat, &snake, &detail, &err));
    CHECK(flat == "[3]");
    CHECK(snake == "[{\"ams_id\":0,\"slot_id\":3}]");
    CHECK(detail ==
          "[{\"ams\":3,\"targetColor\":\"FAFAFAFF\","
          "\"filamentId\":\"GFG99\",\"filamentType\":\"PETG\","
          "\"sourceColor\":\"FAFAFAFF\"}]");

    // Sparse plate: only source filament 8 is selected. The 8 leading
    // holes stay -1 in flat, map to {255,255} (never the external
    // {255,0}) in snake, and each gets an empty detail element with no
    // sourceColor key.
    CHECK(obn::queue::test_build_mapping(
        map_cmd("ams",
                "[{\"source_filament_id\":\"8\",\"slot_id\":\"ams-0-slot-3\","
                "\"type\":\"PETG\",\"profile_id\":\"GFG99\","
                "\"source_color\":\"#FAFAFAFF\","
                "\"target_color\":\"#FAFAFAFF\"}]"),
        &flat, &snake, &detail, &err));
    CHECK(flat == "[-1,-1,-1,-1,-1,-1,-1,-1,3]");
    CHECK(snake ==
          "[{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":255,\"slot_id\":255},"
          "{\"ams_id\":0,\"slot_id\":3}]");
    std::string want = "[";
    for (int i = 0; i < 8; ++i) {
        if (i) want += ',';
        want += "{\"ams\":-1,\"targetColor\":\"\","
                "\"filamentId\":\"\",\"filamentType\":\"\"}";
    }
    want += ",{\"ams\":3,\"targetColor\":\"FAFAFAFF\","
            "\"filamentId\":\"GFG99\",\"filamentType\":\"PETG\","
            "\"sourceColor\":\"FAFAFAFF\"}]";
    CHECK(detail == want);
}

// ---------------------------------------------------------------------------
// Stage-3 command.submit / command.get / job.get (issue #16): validation,
// signed-out fail-closed, durable dedup/replay/conflict, lane serialization,
// job binding, and worker pre-dispatch file failures.
// ---------------------------------------------------------------------------
#include <chrono>
#include <thread>

static std::string print_cmd(const std::string& dev, const std::string& path,
                             const std::string& sha, const char* tag = "t-queue-test")
{
    return "{\"kind\":\"print\",\"device_id\":\"" + dev + "\",\"payload\":{"
           "\"file\":{\"path\":\"" + path + "\",\"sha256\":\"" + sha +
           "\",\"plate_index\":1},"
           "\"task_tag\":\"" + std::string(tag) + "\",\"supply\":\"external\","
           "\"materials\":[{\"source_filament_id\":\"0\",\"slot_id\":\"external\","
           "\"type\":\"PLA\",\"profile_id\":\"p0\","
           "\"source_color\":\"#FF0000\",\"target_color\":\"#FF0000\"}],"
           "\"options\":{\"bed_leveling\":false,\"flow_calibration\":false,"
           "\"timelapse\":false}}}";
}

// command.submit for supply "none": empty materials, options false.
static std::string none_cmd(const std::string& dev, const std::string& path,
                            const std::string& sha, bool bad_opt = false)
{
    return "{\"kind\":\"print\",\"device_id\":\"" + dev + "\",\"payload\":{"
           "\"file\":{\"path\":\"" + path + "\",\"sha256\":\"" + sha +
           "\",\"plate_index\":1},"
           "\"task_tag\":\"t-none\",\"supply\":\"none\",\"materials\":[],"
           "\"options\":{\"bed_leveling\":" +
           std::string(bad_opt ? "true" : "false") +
           ",\"flow_calibration\":false,\"timelapse\":false}}}";
}

static std::uint32_t crc32_bytes(const std::string& s)
{
    std::uint32_t crc = 0xFFFFFFFFu;
    for (unsigned char c : s) {
        crc ^= c;
        for (int i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

// Minimal single-entry STORED zip carrying one plate gcode entry: local
// header, central directory, EOCD (sizes always from the central
// directory; zip::read_entry verifies the CRC-32 below).
static void write_min_plate_zip(const std::filesystem::path& p,
                                const std::string&           entry,
                                const std::string&           body)
{
    const std::uint32_t crc  = crc32_bytes(body);
    const std::uint32_t size = static_cast<std::uint32_t>(body.size());
    const std::uint16_t nlen = static_cast<std::uint16_t>(entry.size());
    std::string out;
    auto u16 = [&](std::uint16_t v) {
        out.push_back(static_cast<char>(v & 0xFF));
        out.push_back(static_cast<char>((v >> 8) & 0xFF));
    };
    auto u32 = [&](std::uint32_t v) {
        u16(static_cast<std::uint16_t>(v & 0xFFFF));
        u16(static_cast<std::uint16_t>((v >> 16) & 0xFFFF));
    };
    u32(0x04034b50); u16(20); u16(0); u16(0); u16(0); u16(0);
    u32(crc); u32(size); u32(size); u16(nlen); u16(0);
    out += entry;
    out += body;
    const std::uint32_t cd_off = static_cast<std::uint32_t>(out.size());
    u32(0x02014b50); u16(20); u16(20); u16(0); u16(0); u16(0); u16(0);
    u32(crc); u32(size); u32(size); u16(nlen); u16(0); u16(0); u16(0);
    u16(0); u32(0); u32(0);
    out += entry;
    const std::uint32_t cd_size =
        static_cast<std::uint32_t>(out.size()) - cd_off;
    u32(0x06054b50); u16(0); u16(0); u16(1); u16(1);
    u32(cd_size); u32(cd_off); u16(0);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(out.data(), static_cast<std::streamsize>(out.size()));
}

// Poll command.get until the receipt leaves "accepted" (worker threads run
// detached); returns the last observed state, "" on timeout.
static std::string wait_receipt_state(const std::string& key,
                                      const std::string& scope, int max_ms)
{
    std::string last;
    for (int waited = 0; waited < max_ms; waited += 25) {
        Envelope e = call(client_op(
            "command.get",
            ",\"params\":{\"submission_scope\":\"" + scope +
                "\",\"idempotency_key\":\"" + key + "\"}"));
        if (ok(e)) {
            last = e.v.find("result.state").as_string();
            if (last != "accepted") return last;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return last;
}

static void test_commands()
{
    namespace fs = std::filesystem;
    const fs::path cdir = fs::temp_directory_path() / "obn_queue_cmd_test";
    std::error_code ec;
    fs::remove_all(cdir, ec);
    fs::create_directories(cdir, ec);

    // Live client (the purge test closed the previous one).
    Envelope e = call(req("client.open",
                          ",\"params\":{\"name\":\"q3\",\"lease_seconds\":60}", "q1"));
    CHECK(ok(e));
    g_client = e.v.find("result.client_id").as_string();
    g_epoch  = e.v.find("session_epoch").as_string();
    CHECK(!g_client.empty());

    obn::queue::note_devices_from_cloud(
        "{\"devices\":[{\"dev_id\":\"" + std::string(kDev) +
        "\",\"dev_name\":\"P1S\",\"dev_product_name\":\"Bambu Lab P1S\"},"
        "{\"dev_id\":\"01P00C490800260\",\"dev_name\":\"P1S-2\","
        "\"dev_product_name\":\"Bambu Lab P1S\"}]}");

    // Deterministic busy state for the accept-path checks below.
    obn::queue::ingest_frame(kDev,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"gcode_state\":\"RUNNING\"}}");

    const std::string kDev2 = "01P00C490800260";
    const std::string sha0(64, '0');
    const std::string key1 = "stage3-key-00000001";
    const std::string key2 = "stage3-key-00000002";
    const std::string key4 = "stage3-key-00000004";
    const std::string key5 = "stage3-key-00000005";
    const std::string key6 = "stage3-key-00000006";

    auto submit = [&](const std::string& params) {
        return call(client_op("command.submit", ",\"params\":" + params));
    };

    // --- Request validation (no store needed). ---
    e = submit("{\"submission_scope\":\"s\",\"command\":{}}");
    CHECK(err_code(e) == "invalid_request"); // missing idempotency_key
    e = submit("{\"submission_scope\":\"s\",\"idempotency_key\":\"short\","
               "\"command\":{}}");
    CHECK(err_code(e) == "invalid_request"); // key < 16 chars
    e = submit("{\"submission_scope\":\"s\",\"idempotency_key\":\"" + key1 +
               "\",\"command\":{\"kind\":\"skip_objects\",\"device_id\":\"" +
               kDev + "\"}}");
    CHECK(err_code(e) == "not_supported");
    {
        // supply "none" now parses; print_cmd's non-empty materials
        // fails the empty-materials rule instead of not_supported.
        std::string cmd = print_cmd(kDev, "C:/none.gcode", sha0);
        const auto pos  = cmd.find("\"supply\":\"external\"");
        cmd.replace(pos, 19, "\"supply\":\"none\"");
        e = submit("{\"submission_scope\":\"s\",\"idempotency_key\":\"" + key1 +
                   "\",\"command\":" + cmd + "}");
        CHECK(err_code(e) == "invalid_request");
    }
    e = submit("{\"submission_scope\":\"s\",\"idempotency_key\":\"" + key1 +
               "\",\"command\":" + print_cmd("ghost-dev", "C:/none.gcode", sha0) + "}");
    CHECK(err_code(e) == "invalid_request"); // unknown device

    // --- Signed out: submission scope is null, submit fails closed. ---
    e = call(req("capabilities", "", "q2"));
    CHECK(ok(e));
    CHECK(e.v.find("result.submission.scope").is_null());
    e = submit("{\"submission_scope\":\"s\",\"idempotency_key\":\"" + key1 +
               "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0) + "}");
    CHECK(err_code(e) == "signed_out");
    CHECK(e.v.find("error.retryable").as_bool() == true);

    // --- Session injected, dispatch suppressed for accept-path checks. ---
    obn::queue::test_set_command_session("u_queue_test", cdir.string());
    obn::queue::test_set_dispatch_enabled(false);

    e = call(req("capabilities", "", "q3"));
    CHECK(ok(e));
    const std::string scope = e.v.find("result.submission.scope").as_string();
    CHECK(!scope.empty());

    // Busy printer (RUNNING frame above) rejected before reserving.
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               key1 + "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0) + "}");
    CHECK(err_code(e) == "busy");
    CHECK(e.v.find("error.retryable").as_bool() == true);

    // Wrong scope.
    e = submit("{\"submission_scope\":\"wrong-scope-1\",\"idempotency_key\":\"" +
               key1 + "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0) + "}");
    CHECK(err_code(e) == "submission_scope_changed");

    // IDLE now: first acceptance.
    obn::queue::ingest_frame(kDev,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"gcode_state\":\"IDLE\"}}");
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               key1 + "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0) + "}");
    CHECK(ok(e));
    const std::string cid = e.v.find("result.command_id").as_string();
    const std::string jid = e.v.find("result.job_id").as_string();
    CHECK(!cid.empty());
    CHECK(jid.rfind("job-", 0) == 0);
    CHECK(e.v.find("result.state").as_string() == "accepted");
    CHECK(e.v.find("result.dispatch").as_string() == "not_sent");
    CHECK(e.v.find("result.kind").as_string() == "print");
    CHECK(e.v.find("result.device_id").as_string() == kDev);
    CHECK(!e.v.find("result.accepted_at").as_string().empty());
    CHECK(e.v.find("result.accepted_at").as_string() ==
          e.v.find("result.updated_at").as_string());
    CHECK(e.v.find("result.error").is_null());

    // Replay: identical payload returns the original identity.
    Envelope r = submit("{\"submission_scope\":\"" + scope +
                        "\",\"idempotency_key\":\"" + key1 +
                        "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0) + "}");
    CHECK(ok(r));
    CHECK(r.v.find("result.command_id").as_string() == cid);
    CHECK(r.v.find("result.job_id").as_string() == jid);

    // Same key, different payload -> conflict, no new receipt.
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               key1 + "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0, "other-tag") + "}");
    CHECK(err_code(e) == "idempotency_conflict");

    // Lane held by key1: a second print for the same device is busy.
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               key2 + "\",\"command\":" + print_cmd(kDev, "C:/none.gcode", sha0) + "}");
    CHECK(err_code(e) == "busy");

    // command.get: the receipt, an unknown key, and a wrong scope.
    e = call(client_op("command.get",
                       ",\"params\":{\"submission_scope\":\"" + scope +
                           "\",\"idempotency_key\":\"" + key1 + "\"}"));
    CHECK(ok(e));
    CHECK(e.v.find("result.command_id").as_string() == cid);
    CHECK(e.v.find("result.state").as_string() == "accepted");
    e = call(client_op("command.get",
                       ",\"params\":{\"submission_scope\":\"" + scope +
                           "\",\"idempotency_key\":\"stage3-key-99999999\"}"));
    CHECK(err_code(e) == "not_found");
    e = call(client_op("command.get",
                       ",\"params\":{\"submission_scope\":\"nope-scope-x\","
                       "\"idempotency_key\":\"" + key1 + "\"}"));
    CHECK(err_code(e) == "submission_scope_changed");

    // job.get binds the print receipt through its job id.
    e = call(client_op("job.get",
                       ",\"params\":{\"submission_scope\":\"" + scope +
                           "\",\"device_id\":\"" + kDev +
                           "\",\"job_id\":\"" + jid + "\"}"));
    CHECK(ok(e));
    CHECK(e.v.find("result.job.job_id").as_string() == jid);
    CHECK(e.v.find("result.job.state").as_string() == "pending");
    CHECK(e.v.find("result.job.terminal").is_null());
    e = call(client_op("job.get",
                       ",\"params\":{\"submission_scope\":\"" + scope +
                           "\",\"device_id\":\"" + kDev +
                           "\",\"job_id\":\"job-nonexistent\"}"));
    CHECK(err_code(e) == "not_found");

    // Controls bind expected_job_id to the live print receipt.
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               "stage3-key-00000003\",\"command\":{\"kind\":\"pause\","
               "\"device_id\":\"" + kDev + "\",\"expected_job_id\":\"" + jid + "\"}}");
    CHECK(ok(e));
    CHECK(e.v.find("result.kind").as_string() == "pause");
    CHECK(e.v.find("result.state").as_string() == "accepted");
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               "stage3-key-00000007\",\"command\":{\"kind\":\"stop\","
               "\"device_id\":\"" + kDev +
               "\",\"expected_job_id\":\"job-nonexistent\"}}");
    CHECK(err_code(e) == "job_mismatch");

    // --- Worker pre-dispatch failures (dispatch on, detached threads). ---
    obn::queue::test_set_dispatch_enabled(true);

    // Missing file -> unsafe_file, not_sent, lane released.
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               key4 + "\",\"command\":" + print_cmd(kDev2, "C:/obn-no-such/no.gcode", sha0) + "}");
    CHECK(ok(e));
    CHECK(wait_receipt_state(key4, scope, 5000) == "failed");
    e = call(client_op("command.get",
                       ",\"params\":{\"submission_scope\":\"" + scope +
                           "\",\"idempotency_key\":\"" + key4 + "\"}"));
    CHECK(e.v.find("result.dispatch").as_string() == "not_sent");
    CHECK(e.v.find("result.error.code").as_string() == "unsafe_file");
    CHECK(e.v.find("result.error.retryable").as_bool() == false);

    // Existing file, wrong hash -> file_changed, lane released.
    {
        std::string fpath = (cdir / "payload.gcode").string();
        for (char& c : fpath)
            if (c == '\\') c = '/';
        {
            std::ofstream f(cdir / "payload.gcode", std::ios::binary | std::ios::trunc);
            f << "gcode content";
        }
        e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
                   key5 + "\",\"command\":" + print_cmd(kDev2, fpath, sha0) + "}");
        CHECK(ok(e));
        CHECK(wait_receipt_state(key5, scope, 5000) == "failed");
        e = call(client_op("command.get",
                           ",\"params\":{\"submission_scope\":\"" + scope +
                               "\",\"idempotency_key\":\"" + key5 + "\"}"));
        CHECK(e.v.find("result.error.code").as_string() == "file_changed");
    }

    // --- supply "none": validation + container integrity only. ---
    auto none_err = [&](const std::string& key) {
        Envelope g = call(client_op(
            "command.get",
            ",\"params\":{\"submission_scope\":\"" + scope +
                "\",\"idempotency_key\":\"" + key + "\"}"));
        return g.v.find("result.error.code").as_string();
    };
    auto submit_none = [&](const std::string& key, const std::string& path,
                           bool bad_opt) {
        return submit("{\"submission_scope\":\"" + scope +
                      "\",\"idempotency_key\":\"" + key +
                      "\",\"command\":" + none_cmd(kDev2, path, sha0, bad_opt) +
                      "}");
    };
    const std::string kKey9  = "stage3-key-00000009";
    const std::string kKey10 = "stage3-key-00000010";
    const std::string kKey11 = "stage3-key-00000011";
    const std::string kKey12 = "stage3-key-00000012";
    const std::string kKey13 = "stage3-key-00000013";
    const std::string kKey14 = "stage3-key-00000014";

    // Non-empty materials and a true calibration option reject at
    // validation (schema: empty materials, options all false).
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               kKey9 + "\",\"command\":{\"kind\":\"print\",\"device_id\":\"" +
               kDev2 + "\",\"payload\":{\"file\":{\"path\":\"C:/none/x.3mf\","
               "\"sha256\":\"" + sha0 + "\",\"plate_index\":1},"
               "\"task_tag\":\"t9\",\"supply\":\"none\","
               "\"materials\":[{\"source_filament_id\":\"0\","
               "\"slot_id\":\"external\",\"type\":\"PLA\",\"profile_id\":\"p0\","
               "\"source_color\":\"#FF0000\",\"target_color\":\"#FF0000\"}],"
               "\"options\":{\"bed_leveling\":false,\"flow_calibration\":false,"
               "\"timelapse\":false}}}}");
    CHECK(err_code(e) == "invalid_request");
    e = submit_none(kKey10, "C:/none/x.3mf", true);
    CHECK(err_code(e) == "invalid_request");

    std::string paypath = (cdir / "payload.gcode").string();
    for (char& c : paypath)
        if (c == '\\') c = '/';

    // A valid container (the plate gcode entry the printer extracts)
    // passes the container check and fails only at the byte check, as
    // file_changed: the sha0 above is wrong for these bytes.
    std::string zipok = (cdir / "plate_ok.3mf").string();
    for (char& c : zipok)
        if (c == '\\') c = '/';
    write_min_plate_zip(cdir / "plate_ok.3mf", "Metadata/plate_1.gcode",
                        "G1 X10 Y10 F3000\n");
    e = submit_none(kKey11, zipok, false);
    CHECK(ok(e));
    CHECK(wait_receipt_state(kKey11, scope, 5000) == "failed");
    CHECK(none_err(kKey11) == "file_changed");

    // An existing non-archive and an archive without this plate's entry
    // fail the container check closed (content is never inspected).
    e = submit_none(kKey12, paypath, false);
    CHECK(ok(e));
    CHECK(wait_receipt_state(kKey12, scope, 5000) == "failed");
    CHECK(none_err(kKey12) == "unsafe_gcode");

    std::string zipp2 = (cdir / "plate_only2.3mf").string();
    for (char& c : zipp2)
        if (c == '\\') c = '/';
    write_min_plate_zip(cdir / "plate_only2.3mf", "Metadata/plate_2.gcode",
                        "G1 X10 Y10 F3000\n");
    e = submit_none(kKey13, zipp2, false);
    CHECK(ok(e));
    CHECK(wait_receipt_state(kKey13, scope, 5000) == "failed");
    CHECK(none_err(kKey13) == "unsafe_gcode");

    // An unreadable archive fails closed the same way.
    e = submit_none(kKey14, "C:/obn-no-such/no.gcode", false);
    CHECK(ok(e));
    CHECK(wait_receipt_state(kKey14, scope, 5000) == "failed");
    CHECK(none_err(kKey14) == "unsafe_gcode");

    // UTF-8 file paths: a narrow open misses non-ACP names and would
    // fail closed as unsafe_file, so reaching file_changed proves the
    // wide open (sha256_file_hex / zip::read_entry) found the file.
    const std::string kKey15 = "stage3-key-00000015";
    const std::string kKey16 = "stage3-key-00000016";
    const std::string kKey17 = "stage3-key-00000017";
    {
        const fs::path up = cdir / std::filesystem::u8path(
                              "\xe6\x8d\xa2\xe7\x9b\x98\xf0\x9f\x8c\xb8.gcode");
        {
            std::ofstream f(up, std::ios::binary | std::ios::trunc);
            f << "unicode gcode";
        }
        std::string upath = up.u8string();
        for (char& c : upath)
            if (c == '\\') c = '/';
        e = submit("{\"submission_scope\":\"" + scope +
                   "\",\"idempotency_key\":\"" + kKey15 +
                   "\",\"command\":" + print_cmd(kDev2, upath, sha0) + "}");
        CHECK(ok(e));
        CHECK(wait_receipt_state(kKey15, scope, 5000) == "failed");
        CHECK(none_err(kKey15) == "file_changed");

        // Same through the zip container check (supply "none").
        const fs::path uz = cdir / std::filesystem::u8path(
                             "plate-\xe6\xb5\x8b\xe8\xaf\x95\xf0\x9f\x8c\xb8.3mf");
        write_min_plate_zip(uz, "Metadata/plate_1.gcode", "G1 X10 Y10 F3000\n");
        std::string uzpath = uz.u8string();
        for (char& c : uzpath)
            if (c == '\\') c = '/';
        e = submit("{\"submission_scope\":\"" + scope +
                   "\",\"idempotency_key\":\"" + kKey16 +
                   "\",\"command\":" + none_cmd(kDev2, uzpath, sha0, false) + "}");
        CHECK(ok(e));
        CHECK(wait_receipt_state(kKey16, scope, 5000) == "failed");
        CHECK(none_err(kKey16) == "file_changed");

        // MAX_PATH: a >260-char absolute path only opens behind the
        // \\?\ prefix os::open_path adds.
        fs::path longp = cdir / "obn_long_path";
        for (int i = 0; i < 8; ++i)
            longp /= "seg" + std::to_string(i) + std::string(30, 'x');
        std::error_code lec;
        fs::create_directories(obn::os::open_path(longp.u8string()), lec);
        CHECK(!lec);
        {
            std::ofstream f(obn::os::open_path((longp / "deep.gcode").u8string()),
                            std::ios::binary | std::ios::trunc);
            f << "deep gcode";
        }
        std::string lpath = (longp / "deep.gcode").u8string();
        for (char& c : lpath)
            if (c == '\\') c = '/';
        e = submit("{\"submission_scope\":\"" + scope +
                   "\",\"idempotency_key\":\"" + kKey17 +
                   "\",\"command\":" + print_cmd(kDev2, lpath, sha0) + "}");
        CHECK(ok(e));
        CHECK(wait_receipt_state(kKey17, scope, 5000) == "failed");
        CHECK(none_err(kKey17) == "file_changed");
        fs::remove_all(obn::os::open_path((cdir / "obn_long_path").u8string()),
                       lec);
    }

    // Both worker failures released the kDev2 lane: a fresh key accepts.
    obn::queue::test_set_dispatch_enabled(false);
    e = submit("{\"submission_scope\":\"" + scope + "\",\"idempotency_key\":\"" +
               key6 + "\",\"command\":" + print_cmd(kDev2, "C:/none.gcode", sha0) + "}");
    CHECK(ok(e));

    obn::queue::test_clear_command_session();
    obn::queue::test_set_dispatch_enabled(true);
    fs::remove_all(cdir, ec);
}

// ---------------------------------------------------------------------------
// Stage-3 job correlation: receipt job id bound to printer frame evidence
// (docs/queue-api-v1-stage3 README "Job lifecycle and evidence").
// Dispatch is simulated through test_mark_dispatched (no SDK).
// ---------------------------------------------------------------------------
static void test_job_correlation()
{
    namespace fs = std::filesystem;
    const fs::path cdir = fs::temp_directory_path() / "obn_queue_corr_test";
    std::error_code ec;
    fs::remove_all(cdir, ec);
    fs::create_directories(cdir, ec);

    // Reuse the live client from test_commands (never closed).
    CHECK(!g_client.empty());

    const std::string kDevC = "01P00C490800270";
    obn::queue::note_devices_from_cloud(
        "{\"devices\":[{\"dev_id\":\"" + kDevC +
        "\",\"dev_name\":\"P1S-C\",\"dev_product_name\":\"Bambu Lab P1S\"}]}");
    obn::queue::ingest_frame(kDevC,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"gcode_state\":\"IDLE\"}}");

    obn::queue::test_set_command_session("u_queue_corr", cdir.string());
    obn::queue::test_set_dispatch_enabled(false);

    Envelope e = call(req("capabilities", "", "q5"));
    CHECK(ok(e));
    const std::string scope = e.v.find("result.submission.scope").as_string();
    CHECK(!scope.empty());

    e = call(client_op("watch.set",
                       ",\"params\":{\"device_ids\":[\"" + kDevC + "\"]}"));
    CHECK(ok(e));
    std::string cursor = e.v.find("result.cursor").as_string();

    const std::string sha0(64, '0');
    const std::string keyA = "stage3-corr-key-0001";
    const std::string keyB = "stage3-corr-key-0002";

    auto submit = [&](const std::string& key) {
        return call(client_op(
            "command.submit",
            ",\"params\":{\"submission_scope\":\"" + scope +
                "\",\"idempotency_key\":\"" + key + "\",\"command\":" +
                print_cmd(kDevC, "C:/none.gcode", sha0) + "}"));
    };
    auto job_get = [&](const std::string& jid) {
        return call(client_op(
            "job.get",
            ",\"params\":{\"submission_scope\":\"" + scope +
                "\",\"device_id\":\"" + kDevC + "\",\"job_id\":\"" + jid +
                "\"}"));
    };
    auto snapshot = [&]() {
        return call(client_op(
            "snapshot.get", ",\"params\":{\"device_ids\":[\"" + kDevC + "\"]}"));
    };

    // Job A: accepted, then a confirmed dispatch (simulated).
    e = submit(keyA);
    CHECK(ok(e));
    const std::string jidA = e.v.find("result.job_id").as_string();
    CHECK(jidA.rfind("job-", 0) == 0);
    obn::queue::test_mark_dispatched(kDevC, keyA);

    // Dispatch acknowledged, no frame yet: receipt-derived, no job_key.
    e = job_get(jidA);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "printing");
    CHECK(e.v.find("result.job.job_key").is_null());
    CHECK(e.v.find("result.job.terminal").is_null());

    // A frame with the printer's native task_id correlates.
    obn::queue::ingest_frame(kDevC,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,"
        "\"gcode_state\":\"RUNNING\",\"mc_percent\":42,"
        "\"task_id\":\"task-corr-a\"}}");
    e = job_get(jidA);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "printing");
    CHECK(e.v.find("result.job.job_key").as_string() == "task-corr-a");
    CHECK(e.v.find("result.job.started_at").is_string());
    CHECK(e.v.find("result.job.terminal").is_null());

    // Terminal frame: correlated completed outcome.
    obn::queue::ingest_frame(kDevC,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,"
        "\"gcode_state\":\"FINISH\",\"mc_percent\":100,"
        "\"task_id\":\"task-corr-a\"}}");
    e = job_get(jidA);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "completed");
    CHECK(e.v.find("result.job.job_key").as_string() == "task-corr-a");
    CHECK(e.v.find("result.job.terminal.state").as_string() == "completed");
    CHECK(e.v.find("result.job.terminal.correlation").as_string() == "matched");
    CHECK(e.v.find("result.job.terminal.source").as_string() == "printer_report");
    CHECK(e.v.find("result.job.terminal.quiescent").as_bool() == false);
    CHECK(e.v.find("result.job.terminal.observed_at").is_string());

    // Post-release snapshot still correlates through the native task_id.
    e = snapshot();
    CHECK(ok(e));
    {
        const json::Value& p = e.v.find("result.printers").as_array()[0];
        CHECK(p.find("job.job_id").as_string() == jidA);
        CHECK(p.find("job.state").as_string() == "completed");
        CHECK(p.find("job.terminal.correlation").as_string() == "matched");
    }

    // Job B on the freed lane: a second, independent correlation.
    e = submit(keyB);
    CHECK(ok(e));
    const std::string jidB = e.v.find("result.job_id").as_string();
    CHECK(jidB != jidA);
    obn::queue::test_mark_dispatched(kDevC, keyB);
    obn::queue::ingest_frame(kDevC,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,"
        "\"gcode_state\":\"RUNNING\",\"mc_percent\":7,"
        "\"task_id\":\"task-corr-b\"}}");

    e = job_get(jidB);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "printing");
    CHECK(e.v.find("result.job.job_key").as_string() == "task-corr-b");
    // Job A never regresses to job B's frames.
    e = job_get(jidA);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "completed");

    // One poll carries every correlated job.state / printer.status.
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + cursor +
                           "\",\"limit\":64}"));
    CHECK(ok(e));
    {
        int  seen_a_print = 0, seen_a_done = 0, seen_b_print = 0;
        bool a_print_no_terminal = false, a_done_matched = false;
        int  seen_b_status = 0;
        for (const json::Value& ev : e.v.find("result.events").as_array()) {
            const std::string kind = ev.find("kind").as_string();
            if (kind == "job.state") {
                const json::Value& job = ev.find("data.job");
                const std::string  jid = job.find("job_id").as_string();
                const std::string  st  = job.find("state").as_string();
                if (jid == jidA && st == "printing") {
                    ++seen_a_print;
                    a_print_no_terminal = job.find("terminal").is_null();
                } else if (jid == jidA && st == "completed") {
                    ++seen_a_done;
                    a_done_matched =
                        job.find("terminal.correlation").as_string() == "matched";
                } else if (jid == jidB && st == "printing") {
                    ++seen_b_print;
                }
            } else if (kind == "printer.status") {
                if (ev.find("data.job.job_id").as_string() == jidB)
                    ++seen_b_status;
            }
        }
        CHECK(seen_a_print == 1);
        CHECK(seen_a_done == 1);
        CHECK(seen_b_print == 1);
        CHECK(a_print_no_terminal);
        CHECK(a_done_matched);
        CHECK(seen_b_status >= 1);
    }

    // IDLE after a seen job releases the lane with an unknown outcome.
    obn::queue::ingest_frame(kDevC,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,\"gcode_state\":\"IDLE\"}}");
    e = job_get(jidB);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "unknown");
    CHECK(e.v.find("result.job.terminal").is_null());

    // An uncorrelated (external) job never carries a job id.
    e = call(client_op("watch.set",
                       ",\"params\":{\"device_ids\":[\"" + kDevC + "\"]}"));
    CHECK(ok(e));
    cursor = e.v.find("result.cursor").as_string();
    obn::queue::ingest_frame(kDevC,
        "{\"print\":{\"command\":\"push_status\",\"msg\":1,"
        "\"gcode_state\":\"RUNNING\",\"mc_percent\":3,"
        "\"task_id\":\"task-ext-9\"}}");
    e = snapshot();
    CHECK(ok(e));
    {
        const json::Value& p = e.v.find("result.printers").as_array()[0];
        CHECK(p.find("job.state").as_string() == "printing");
        CHECK(!p.find("job.job_id").is_string());
    }
    e = call(client_op("events.poll",
                       ",\"params\":{\"cursor\":\"" + cursor +
                           "\",\"limit\":64}"));
    CHECK(ok(e));
    {
        bool ext_job_event = false, ext_uncorrelated = false;
        for (const json::Value& ev : e.v.find("result.events").as_array()) {
            if (ev.find("kind").as_string() != "job.state") continue;
            ext_job_event      = true;
            ext_uncorrelated   = !ev.find("data.job.job_id").is_string();
        }
        CHECK(ext_job_event);
        CHECK(ext_uncorrelated);
    }

    // The external frame never touches job A or B.
    e = job_get(jidA);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "completed");
    e = job_get(jidB);
    CHECK(ok(e));
    CHECK(e.v.find("result.job.state").as_string() == "unknown");

    obn::queue::test_clear_command_session();
    obn::queue::test_set_dispatch_enabled(true);
    fs::remove_all(cdir, ec);
}

int main()
{
    test_validation();
    test_capabilities();
    test_client_lifecycle();
    test_devices_watch_snapshot();
    test_events_poll();
    test_session_purge();
    test_read_text_file();
    test_mapping_outputs();
    test_commands();
    test_job_correlation();

    if (fail_count) {
        std::fprintf(stderr, "%d check(s) failed\n", fail_count);
        return 1;
    }
    std::printf("queue_api_test: all checks passed\n");
    return 0;
}
