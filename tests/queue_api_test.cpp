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

#include <cstdio>
#include <cstring>
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
    CHECK(e.v.find("capabilities_revision").as_string() == "c1");
    CHECK(e.v.find("op").as_string() == "capabilities");

    const json::Value res = e.v.find("result");
    CHECK(res.find("api_versions").as_array().size() == 1);
    CHECK(res.find("api_versions").as_array()[0].as_number() == 1.0);
    CHECK(res.find("operations").as_array().size() == 7);
    CHECK(res.find("command_kinds").as_array().empty());
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
    CHECK(p.find("status_age_ms").is_number());

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

int main()
{
    test_validation();
    test_capabilities();
    test_client_lifecycle();
    test_devices_watch_snapshot();
    test_events_poll();
    test_session_purge();
    test_read_text_file();

    if (fail_count) {
        std::fprintf(stderr, "%d check(s) failed\n", fail_count);
        return 1;
    }
    std::printf("queue_api_test: all checks passed\n");
    return 0;
}
