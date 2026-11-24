// Versioned queue integration API (stage 2): capability discovery,
// read-only multi-printer snapshots and polled events behind the two C
// exports declared in include/obn/obn_queue_api_v1.h. Stage 3 adds the
// capability-gated command.submit / command.get / job.get operations
// backed by the durable per-account receipt store
// (docs/queue-api-v1-stage3/README.md).
// Design: persano/open-bambu-networking-plugin issue #16.

#define OBN_QUEUE_API_BUILD
#include "obn/obn_queue_api_v1.h"

#include "obn/queue_api.hpp"

#include "obn/agent.hpp"
#include "obn/auth.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"
#include "obn/mqtt_seq.hpp"
#include "obn/receipt_store.hpp"
#include "obn/zip_read.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <initializer_list>
#include <map>
#include <mutex>
#include <new>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace obn::queue {

namespace {

using Clock = std::chrono::steady_clock;
namespace json = obn::json;

constexpr std::size_t kMaxClients          = 4;
constexpr std::size_t kMaxDevicesPerClient = 32;
constexpr std::size_t kMaxInventory        = 1024;
constexpr std::size_t kEventCapacity       = 4096;
constexpr int         kEventRetentionSec   = 900;
constexpr int         kPollMinMs           = 500;
constexpr int         kMaxPollEvents       = 256;
constexpr std::size_t kMaxMergedBytes      = 65536;
constexpr std::size_t kMaxRequestBytes     = 65536;
constexpr std::size_t kMaxResponseBudget   = 1900000; // headroom under 2 MiB
constexpr int         kMaxRequestDepth     = 32;
constexpr char        kCapRev[]            = "stage3-draft-1";

// --- Stage-3 command submission state (see docs/queue-api-v1-stage3) ------
// One physical print lane per device: an accepted queue print owns the
// device until its receipt fails/cancels before dispatch or a device
// frame shows the job ended (or no job at all, once dispatched).
struct LaneEntry {
    std::string key;       // owning idempotency key
    bool        dispatched = false; // may_have_been_sent durably recorded
};
// Serializes dedup + lane check + reservation + lane claim so two keys
// cannot both claim one device's lane between check and reserve.
// Lock order: ingest_frame takes reg().mu then g_submit_mu; command
// submission never takes reg().mu while holding g_submit_mu.
std::mutex g_submit_mu;
std::map<std::string, LaneEntry> g_print_lanes; // device_id -> lane

#ifdef OBN_TESTING
// Test seams (queue_api.hpp): inject session/config for the receipt
// store and suppress worker dispatch. Absent from production builds.
auth::Session g_test_session;
std::string   g_test_config_dir;
bool          g_test_session_set = false;
bool          g_test_dispatch_on = true;
#endif

bool dispatch_enabled()
{
#ifdef OBN_TESTING
    return g_test_dispatch_on;
#else
    return true;
#endif
}

// Stage-3 advertised command surface (global capabilities and per-printer
// command_support): skip_objects stays unadvertised until its validation
// subset exists (README: keep unsupported until agreed). supply "none"
// ships capability-gated behind the motion-only subset scan below.
json::Array command_kinds_array()
{
    json::Array a;
    for (const char* k : {"print", "pause", "resume", "stop"})
        a.push_back(json::Value(k));
    return a;
}
json::Array print_options_array()
{
    json::Array a;
    for (const char* k : {"bed_leveling", "flow_calibration", "timelapse"})
        a.push_back(json::Value(k));
    return a;
}
json::Array supply_modes_array()
{
    json::Array a;
    for (const char* k : {"ams", "external", "none"})
        a.push_back(json::Value(k));
    return a;
}

// ---------------------------------------------------------------------------
// Request pre-validation: malformed UTF-8, embedded NUL (checked by caller),
// nesting past 32 and duplicate keys are rejected before any semantic work.
// json_lite itself allows depth 128 and silently collapses duplicate keys,
// so the strict rules live here instead of in the shared parser.
// ---------------------------------------------------------------------------

bool utf8_ok(const char* data, std::size_t n, std::string* err)
{
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c < 0x80) { ++i; continue; }
        int         extra   = 0;
        std::uint32_t cp_min = 0;
        std::uint32_t cp     = 0;
        if ((c & 0xE0) == 0xC0) { extra = 1; cp_min = 0x80; cp = c & 0x1F; if (c < 0xC2) { *err = "malformed UTF-8"; return false; } }
        else if ((c & 0xF0) == 0xE0) { extra = 2; cp_min = 0x800; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { extra = 3; cp_min = 0x10000; cp = c & 0x07; if (c > 0xF4) { *err = "malformed UTF-8"; return false; } }
        else { *err = "malformed UTF-8"; return false; }
        if (n - i <= static_cast<std::size_t>(extra)) { *err = "malformed UTF-8"; return false; }
        for (int k = 1; k <= extra; ++k) {
            const unsigned char cc = static_cast<unsigned char>(data[i + k]);
            if ((cc & 0xC0) != 0x80) { *err = "malformed UTF-8"; return false; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (cp < cp_min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            *err = "malformed UTF-8";
            return false;
        }
        i += static_cast<std::size_t>(extra) + 1;
    }
    return true;
}

// Recursive JSON walker: structure, string escapes, depth cap, duplicate keys.
struct Scanner {
    const char*     p;
    const char*     end;
    std::string     err;
    std::int32_t    depth = 0;

    bool fail(const std::string& e) { if (err.empty()) err = e; return false; }

    void skip_ws()
    {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    }

    // Validates one JSON string. When `out` is non-null the decoded text is
    // collected (used for object keys); escapes must be well formed.
    bool scan_string(std::string* out)
    {
        if (p >= end || *p != '"') return fail("expected string");
        ++p;
        if (out) out->clear();
        while (p < end) {
            const char c = *p++;
            if (c == '"') return true;
            if (c == '\\') {
                if (p >= end) return fail("bad escape");
                const char e = *p++;
                switch (e) {
                case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
                    if (out) out->push_back(e);
                    break;
                case 'u': {
                    if (end - p < 4) return fail("bad \\u escape");
                    unsigned cpv = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = p[k];
                        cpv <<= 4;
                        if (h >= '0' && h <= '9') cpv |= static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') cpv |= static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cpv |= static_cast<unsigned>(h - 'A' + 10);
                        else return fail("bad hex in \\u escape");
                    }
                    p += 4;
                    if (cpv >= 0xD800 && cpv <= 0xDBFF) {
                        if (end - p < 6 || p[0] != '\\' || p[1] != 'u') return fail("unpaired surrogate");
                        unsigned lo = 0;
                        for (int k = 0; k < 4; ++k) {
                            const char h = p[2 + k];
                            lo <<= 4;
                            if (h >= '0' && h <= '9') lo |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') lo |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') lo |= static_cast<unsigned>(h - 'A' + 10);
                            else return fail("bad hex in \\u escape");
                        }
                        if (lo < 0xDC00 || lo > 0xDFFF) return fail("unpaired surrogate");
                        p += 6;
                    } else if (cpv >= 0xDC00 && cpv <= 0xDFFF) {
                        return fail("unpaired surrogate");
                    }
                    break;
                }
                default: return fail("bad escape character");
                }
            } else if (static_cast<unsigned char>(c) < 0x20) {
                return fail("control character in string");
            } else if (out) {
                out->push_back(c);
            }
        }
        return fail("unterminated string");
    }

    bool scan_value()
    {
        skip_ws();
        if (p >= end) return fail("unexpected end of input");
        const char c = *p;
        if (c == '"') return scan_string(nullptr);
        if (c == '{') {
            if (++depth > kMaxRequestDepth) return fail("nesting deeper than 32");
            ++p;
            std::vector<std::string> keys;
            skip_ws();
            if (p < end && *p == '}') { ++p; --depth; return true; }
            while (true) {
                skip_ws();
                std::string key;
                if (!scan_string(&key)) return false;
                for (const auto& seen : keys)
                    if (seen == key) return fail("duplicate key: " + key);
                keys.push_back(key);
                skip_ws();
                if (p >= end || *p != ':') return fail("expected ':'");
                ++p;
                if (!scan_value()) return false;
                skip_ws();
                if (p < end && *p == ',') { ++p; continue; }
                if (p < end && *p == '}') { ++p; --depth; return true; }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            if (++depth > kMaxRequestDepth) return fail("nesting deeper than 32");
            ++p;
            skip_ws();
            if (p < end && *p == ']') { ++p; --depth; return true; }
            while (true) {
                if (!scan_value()) return false;
                skip_ws();
                if (p < end && *p == ',') { ++p; continue; }
                if (p < end && *p == ']') { ++p; --depth; return true; }
                return fail("expected ',' or ']'");
            }
        }
        if (c == 't') { if (end - p >= 4 && std::strncmp(p, "true", 4) == 0) { p += 4; return true; } return fail("bad literal"); }
        if (c == 'f') { if (end - p >= 5 && std::strncmp(p, "false", 5) == 0) { p += 5; return true; } return fail("bad literal"); }
        if (c == 'n') { if (end - p >= 4 && std::strncmp(p, "null", 4) == 0) { p += 4; return true; } return fail("bad literal"); }
        if (c == '-' || (c >= '0' && c <= '9')) {
            const char* start = p;
            if (*p == '-') ++p;
            while (p < end && *p >= '0' && *p <= '9') ++p;
            if (p < end && *p == '.') { ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
            if (p < end && (*p == 'e' || *p == 'E')) {
                ++p;
                if (p < end && (*p == '+' || *p == '-')) ++p;
                while (p < end && *p >= '0' && *p <= '9') ++p;
            }
            if (p == start) return fail("bad number");
            return true;
        }
        return fail("unexpected character");
    }
};

// Returns "" when the request is acceptable, else the rejection reason.
std::string scan_request(const std::string& text)
{
    std::string uerr;
    if (!utf8_ok(text.data(), text.size(), &uerr)) return uerr;
    Scanner s{text.data(), text.data() + text.size()};
    s.skip_ws();
    if (!s.scan_value()) return s.err;
    s.skip_ws();
    if (s.p != s.end) return "trailing characters";
    return "";
}

// ---------------------------------------------------------------------------
// 3-rule push_status delta merge, same semantics as the executable spec in
// tests/push_status_merge_test.cpp (PandaSpy merge.rs): absent keeps, present
// null clears (key retained), objects merge recursively, everything else
// replaces wholesale. Presence is checked at map level, never Value::find.
// ---------------------------------------------------------------------------
void deep_merge(json::Value& base, const json::Value& delta)
{
    if (!base.is_object() || !delta.is_object()) {
        base = delta;
        return;
    }
    json::Object b = base.as_object();
    const json::Object& d = delta.as_object();
    for (const auto& kv : d) {
        auto it = b.find(kv.first);
        if (it == b.end()) {
            b.emplace(kv.first, kv.second);
        } else if (it->second.is_object() && kv.second.is_object()) {
            deep_merge(it->second, kv.second);
        } else {
            it->second = kv.second;
        }
    }
    base = json::Value(std::move(b));
}

// ---------------------------------------------------------------------------
// Registry: one process-wide instance guarded by a single mutex. Ingest runs
// on mosquitto network threads, calls run on host threads; queue code never
// calls back into Agent while holding this lock (the session probe runs
// before locking), so the agent->queue lock direction stays one-way.
// ---------------------------------------------------------------------------

struct DeviceState {
    json::Value        merged{json::Object{}};
    bool               online = false;
    std::uint64_t      conn_seq = 0;
    bool               has_frame = false;
    Clock::time_point  last_frame{};
    std::string        job_state; // last emitted job state; "" = none yet
};

struct InventoryEntry {
    std::string name;
    std::string model;
};

struct Client {
    std::string        name;
    std::uint32_t      lease_seconds = 120;
    Clock::time_point  deadline{};
    std::vector<std::string> watch;
    Clock::time_point  last_poll{};
    bool               poll_seen = false;
};

struct Event {
    std::uint64_t       seq = 0;
    std::string         epoch;
    std::string         kind;
    std::string         device_id; // empty = global (session.changed)
    json::Value         data;
    std::size_t         size_hint = 0;
    Clock::time_point   ts{};
};

struct Registry {
    std::mutex                          mu;
    std::map<std::string, DeviceState>  devices;
    std::map<std::string, InventoryEntry> inventory;
    std::map<std::string, Client>       clients;
    std::deque<Event>                   events;
    std::uint64_t                       next_seq = 1;
    std::uint64_t                       min_valid_seq = 0; // highest evicted seq
    std::uint64_t                       client_seq = 1;
    std::uint64_t                       epoch_seq = 1;
    std::string                         epoch = "s1";
};

Registry& reg()
{
    static Registry r;
    return r;
}

std::string make_instance_id()
{
    const auto nanos = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd;
    const std::uint64_t mix = static_cast<std::uint64_t>(nanos) ^
                              (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    char buf[24];
    std::snprintf(buf, sizeof(buf), "i%016llx", static_cast<unsigned long long>(mix));
    return std::string(buf);
}

const std::string& instance_id()
{
    static const std::string id = make_instance_id();
    return id;
}

std::string current_epoch()
{
    std::lock_guard<std::mutex> lk(reg().mu);
    return reg().epoch;
}

bool watched_by_any_locked(const Registry& r, const std::string& dev_id)
{
    for (const auto& [id, c] : r.clients)
        if (std::find(c.watch.begin(), c.watch.end(), dev_id) != c.watch.end())
            return true;
    return false;
}

void evict_events_locked(Registry& r, Clock::time_point now)
{
    while (!r.events.empty()) {
        const bool over_cap = r.events.size() > kEventCapacity;
        const auto age = std::chrono::duration_cast<std::chrono::seconds>(now - r.events.front().ts).count();
        const bool too_old = age > kEventRetentionSec;
        if (!over_cap && !too_old) break;
        r.min_valid_seq = r.events.front().seq;
        r.events.pop_front();
    }
}

void push_event_locked(Registry& r, std::string kind, std::string device_id, json::Value data)
{
    Event e;
    e.seq       = r.next_seq++;
    e.epoch     = r.epoch;
    e.kind      = std::move(kind);
    e.device_id = std::move(device_id);
    e.size_hint = data.dump().size();
    e.data      = std::move(data);
    e.ts        = Clock::now();
    r.events.push_back(std::move(e));
    evict_events_locked(r, Clock::now());
}

std::string tail_cursor_locked(const Registry& r)
{
    return "e" + std::to_string(r.next_seq - 1);
}

// ---------------------------------------------------------------------------
// Snapshot rendering: merged cached status -> the schema's printer object.
// ---------------------------------------------------------------------------

std::string conn_generation(const DeviceState* d)
{
    return "g" + std::to_string(d ? d->conn_seq : 0);
}

std::string printer_state_of(bool online, const std::string& gcode)
{
    if (!online) return "offline";
    if (gcode.empty()) return "unknown";
    if (gcode == "RUNNING" || gcode == "RUN" || gcode == "PAUSE" ||
        gcode == "PAUSED" || gcode == "PREPARE" || gcode == "SLICING")
        return "busy";
    if (gcode == "IDLE" || gcode == "FINISH" || gcode == "FAILED" ||
        gcode == "CANCELED" || gcode == "CANCELLED")
        return "idle";
    return "unknown";
}

// "" means "no job object"; anything else is a job.state enum value.
std::string job_state_of(const std::string& gcode)
{
    if (gcode == "RUNNING" || gcode == "RUN") return "printing";
    if (gcode == "PAUSE" || gcode == "PAUSED") return "paused";
    if (gcode == "FINISH") return "completed";
    if (gcode == "FAILED") return "failed";
    if (gcode == "CANCELED" || gcode == "CANCELLED") return "cancelled";
    if (gcode == "PREPARE" || gcode == "SLICING") return "preparing";
    if (gcode == "IDLE" || gcode.empty()) return "";
    return "unknown";
}

json::Value build_job(const json::Value& print_v, const std::string& gcode)
{
    const std::string jstate = job_state_of(gcode);
    if (jstate.empty()) return json::Value(nullptr);

    json::Object j;
    std::string  task_id = print_v.find("task_id").as_string();
    if (task_id.size() > 128) task_id.resize(128);
    j["job_key"] = task_id.empty() ? json::Value(nullptr) : json::Value(task_id);

    std::string tag = print_v.find("subtask_name").as_string();
    if (tag.size() > 80) tag.resize(80);
    j["task_tag"] = tag.empty() ? json::Value(nullptr) : json::Value(tag);

    j["origin"] = json::Value("unknown");
    j["state"]  = json::Value(jstate);

    json::Value pct(nullptr);
    const json::Value& pv = print_v.find("mc_percent");
    if (pv.is_number()) {
        double v = pv.as_number();
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        pct = json::Value(v);
    }
    j["progress_percent"] = pct;
    return json::Value(std::move(j));
}

// "#RRGGBB" / "#RRGGBBAA" from a Bambu 6- or 8-hex color, else null.
json::Value color_from_tray(const std::string& hex)
{
    if (hex.size() != 6 && hex.size() != 8) return json::Value(nullptr);
    for (const char c : hex) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return json::Value(nullptr);
    }
    return json::Value("#" + hex);
}

void append_slot(json::Array& out, const std::string& slot_id, const char* source,
                 const std::string& type, json::Value color, json::Value present)
{
    json::Object s;
    s["slot_id"] = json::Value(slot_id);
    s["source"]  = json::Value(source);
    s["type"]    = json::Value(type);
    s["color"]   = std::move(color);
    s["present"] = std::move(present);
    out.push_back(json::Value(std::move(s)));
}

json::Array build_slots(const json::Value& print_v)
{
    json::Array slots;
    const json::Value& ams = print_v.find("ams");

    // Presence bitmask shared by the whole AMS system in some frames.
    std::string exist_bits = ams.find("tray_exist_bits").as_string();

    const json::Value& ams_list = ams.find("ams");
    if (ams_list.is_array()) {
        for (std::size_t i = 0; i < ams_list.as_array().size() && slots.size() < 128; ++i) {
            const json::Value& unit = ams_list.as_array()[i];
            std::string ams_id = unit.find("id").as_string();
            if (ams_id.empty()) ams_id = std::to_string(i);
            const json::Value& trays = unit.find("tray");
            if (trays.is_array()) {
                for (std::size_t t = 0; t < trays.as_array().size() && slots.size() < 128; ++t) {
                    const json::Value& tray = trays.as_array()[t];
                    std::string tid = tray.find("id").as_string();
                    if (tid.empty()) tid = std::to_string(t);
                    std::string type = tray.find("tray_type").as_string();
                    std::string hex  = tray.find("tray_color").as_string();
                    const bool known  = !type.empty();
                    append_slot(slots, "ams-" + ams_id + "-slot-" + tid, "ams",
                                type, color_from_tray(hex),
                                json::Value(known ? json::Value(true) : json::Value(nullptr)));
                }
            } else {
                // String-form trays carry no per-slot detail; fall back to the
                // presence bitmask when present, else the slot chars. Unknown
                // telemetry stays unknown (type "", color null).
                const std::string presence = trays.is_string() ? trays.as_string() : std::string();
                if (!exist_bits.empty()) {
                    unsigned long bits = 0;
                    try { bits = std::stoul(exist_bits, nullptr, 16); } catch (...) { bits = 0; }
                    for (int t = 0; t < 16 && slots.size() < 128; ++t) {
                        if ((bits >> t) & 1UL) {
                            append_slot(slots, "ams-" + ams_id + "-slot-" + std::to_string(t), "ams",
                                        "", json::Value(nullptr), json::Value(true));
                        }
                    }
                } else {
                    for (std::size_t t = 0; t < presence.size() && slots.size() < 128; ++t) {
                        if (presence[t] == ' ') continue;
                        append_slot(slots, "ams-" + ams_id + "-slot-" + std::to_string(t), "ams",
                                    "", json::Value(nullptr), json::Value(true));
                    }
                }
            }
        }
    }

    const json::Value& vt = print_v.find("vt_tray");
    if (vt.is_object() && slots.size() < 128) {
        std::string type = vt.find("tray_type").as_string();
        std::string hex  = vt.find("tray_color").as_string();
        const bool known = !type.empty();
        append_slot(slots, "external", "external", type, color_from_tray(hex),
                    json::Value(known ? json::Value(true) : json::Value(nullptr)));
    }
    return slots;
}

json::Value build_printer_locked(const std::string& dev_id,
                                 const DeviceState*  d,
                                 const InventoryEntry* inv,
                                 Clock::time_point    now)
{
    const json::Value empty(json::Object{});
    const json::Value& merged = d ? d->merged : empty;
    const json::Value& print_v = merged.find("print");
    const std::string  gcode = print_v.find("gcode_state").as_string();

    const bool online = d && d->online;
    json::Object p;
    p["device_id"]            = json::Value(dev_id);
    p["name"]                 = json::Value(inv ? inv->name : std::string());
    p["model"]                = json::Value(inv ? inv->model : std::string());
    p["online"]               = json::Value(online);
    p["connection_generation"] = json::Value(conn_generation(d));

    json::Value age(nullptr);
    if (d && d->has_frame) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - d->last_frame).count();
        age = json::Value(static_cast<double>(ms < 0 ? 0 : ms));
    }
    p["status_age_ms"] = age;
    p["state"]         = json::Value(printer_state_of(online, gcode));
    p["job"]           = d ? build_job(print_v, gcode) : json::Value(nullptr);
    p["slots"]         = json::Value(build_slots(print_v));

    p["commands"]      = json::Value(json::Array{});
    p["print_options"] = json::Value(json::Array{});

    json::Object temp;
    const json::Value& noz = print_v.find("nozzle_temper");
    const json::Value& bed = print_v.find("bed_temper");
    temp["nozzle_c"] = noz.is_number() ? json::Value(noz.as_number()) : json::Value(nullptr);
    temp["bed_c"]    = bed.is_number() ? json::Value(bed.as_number()) : json::Value(nullptr);
    p["temperature"] = json::Value(std::move(temp));

    // Push status carries the diameter as a string ("0.4"); expose it as a
    // number and stay null until a frame reports it (issue #16 stage 3
    // contract request).
    json::Value nozzle_d(nullptr);
    const std::string nd = print_v.find("nozzle_diameter").as_string();
    if (!nd.empty()) {
        try { nozzle_d = json::Value(std::stod(nd)); } catch (...) {}
    }
    p["nozzle_diameter"] = std::move(nozzle_d);

    // Per-printer command support (stage-3 additive field): what the
    // queue may submit to this printer right now.
    json::Object cs;
    cs["command_kinds"]  = json::Value(command_kinds_array());
    cs["print_options"]  = json::Value(print_options_array());
    cs["supply_modes"]   = json::Value(supply_modes_array());
    p["command_support"] = json::Value(std::move(cs));

    return json::Value(std::move(p));
}

// ---------------------------------------------------------------------------
// Envelope construction. Every response carries instance_id, session_epoch
// and capabilities_revision, errors included.
// ---------------------------------------------------------------------------

struct Meta {
    std::string request_id;
    bool        has_request_id = false;
    std::string op;
    bool        has_op = false;
    std::string epoch;
};

json::Object base_env(const Meta& m, bool ok)
{
    json::Object o;
    o["api"]                  = json::Value(1.0);
    o["request_id"]           = m.has_request_id ? json::Value(m.request_id) : json::Value(nullptr);
    o["instance_id"]          = json::Value(instance_id());
    o["session_epoch"]        = json::Value(m.epoch);
    o["capabilities_revision"] = json::Value(kCapRev);
    o["op"]                   = m.has_op ? json::Value(m.op) : json::Value(nullptr);
    o["ok"]                   = json::Value(ok);
    return o;
}

std::string error_env(const Meta& m, const char* code, const std::string& message, bool retryable)
{
    json::Object o = base_env(m, false);
    json::Object e;
    e["code"]      = json::Value(code);
    std::string msg = message.size() > 1024 ? message.substr(0, 1024) : message;
    e["message"]   = json::Value(msg);
    e["retryable"] = json::Value(retryable);
    o["error"]     = json::Value(std::move(e));
    return json::Value(std::move(o)).dump();
}

std::string success_env(const Meta& m, json::Value result)
{
    json::Object o = base_env(m, true);
    o["result"] = std::move(result);
    return json::Value(std::move(o)).dump();
}

// ---------------------------------------------------------------------------
// Session state probe: reads the active agent OUTSIDE the registry lock.
// ---------------------------------------------------------------------------

const char* session_state()
{
    Agent* a = Agent::active_instance();
    if (!a) return "unavailable";
    const auth::Session s = a->user_session_snapshot();
    return s.logged_in() ? "ready" : "signed_out";
}

// ---------------------------------------------------------------------------
// Strict field helpers over the parsed request object.
// ---------------------------------------------------------------------------

const json::Value& gv(const json::Object& o, const char* k)
{
    static const json::Value null_v;
    const auto it = o.find(k);
    return it == o.end() ? null_v : it->second;
}

bool exact_keys(const json::Object& o, std::initializer_list<const char*> allowed, std::string& err)
{
    for (const auto& kv : o) {
        bool ok = false;
        for (const char* a : allowed)
            if (kv.first == a) { ok = true; break; }
        if (!ok) { err = "unexpected field: " + kv.first; return false; }
    }
    return true;
}

bool bounded_string(const json::Value& v, std::size_t lo, std::size_t hi)
{
    if (!v.is_string()) return false;
    const std::size_t n = v.as_string().size();
    return n >= lo && n <= hi;
}

bool int_in(const json::Value& v, double lo, double hi, long long* out)
{
    if (!v.is_number()) return false;
    const double d = v.as_number();
    if (d != std::floor(d) || d < lo || d > hi) return false;
    *out = static_cast<long long>(d);
    return true;
}

bool valid_device_id(const json::Value& v)
{
    return bounded_string(v, 1, 128);
}

// Validates params.device_ids as a whole (array, <=32, unique, bounded ids).
bool parse_device_ids(const json::Value& params, std::vector<std::string>* out, std::string& err)
{
    const json::Value& ids = gv(params.as_object(), "device_ids");
    if (!ids.is_array()) { err = "device_ids must be an array"; return false; }
    if (ids.as_array().size() > kMaxDevicesPerClient) { err = "device_ids longer than 32"; return false; }
    std::vector<std::string> seen;
    for (const auto& v : ids.as_array()) {
        if (!valid_device_id(v)) { err = "device id must be a string of 1..128 bytes"; return false; }
        const std::string& id = v.as_string();
        if (std::find(seen.begin(), seen.end(), id) != seen.end()) {
            err = "duplicate device id: " + id;
            return false;
        }
        seen.push_back(id);
    }
    if (out) *out = std::move(seen);
    return true;
}

bool known_device_locked(const Registry& r, const std::string& id)
{
    return r.inventory.count(id) != 0 || r.devices.count(id) != 0;
}

} // namespace (file-local helpers)

// ---------------------------------------------------------------------------
// Ingest and lifecycle taps (called from agent.cpp / abi_user.cpp /
// abi_lifecycle.cpp / abi_http.cpp).
// ---------------------------------------------------------------------------

void ingest_frame(const std::string& dev_id, const std::string& json_text)
{
    if (dev_id.empty() || dev_id.size() > 128 || json_text.empty()) return;

    auto parsed = json::parse(json_text, nullptr);
    if (!parsed || !parsed->is_object()) return;
    json::Value root = std::move(*parsed);

    // Canonical status shape (same gate as production paths, agent.cpp
    // print.command check): {"print":{"command":"push_status", ...}}.
    const json::Value& print_v = root.find("print");
    if (!print_v.is_object() || print_v.find("command").as_string() != "push_status") return;

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto now = Clock::now();

    DeviceState& d = r.devices[dev_id];
    if (!d.online) {
        d.online = true;
        ++d.conn_seq;
    }
    d.has_frame = true;
    d.last_frame = now;

    const json::Value before = d.merged;
    deep_merge(d.merged, root);
    if (d.merged.dump().size() > kMaxMergedBytes) {
        // Oversized telemetry is rejected, not normalized: keep the previous
        // cache and the fresh timestamp, but do not emit from it.
        d.merged = before;
        return;
    }

    const json::Value& merged_print = d.merged.find("print");
    const std::string  gcode = merged_print.find("gcode_state").as_string();

    // Release the stage-3 print lane on job-end evidence: any terminal
    // job state, or an explicit IDLE frame once the receipt crossed the
    // dispatch marker (an uncertain dispatch that never started shows
    // IDLE forever). Accepted-but-undispatched lanes stay: the worker
    // owns those releases. Lock order: reg().mu then g_submit_mu.
    {
        const std::string jst = job_state_of(gcode);
        const bool terminal = jst == "completed" || jst == "failed" || jst == "cancelled";
        if (terminal || gcode == "IDLE") {
            std::lock_guard<std::mutex> sl(g_submit_mu);
            auto lit = g_print_lanes.find(dev_id);
            if (lit != g_print_lanes.end() &&
                (terminal || lit->second.dispatched))
                g_print_lanes.erase(lit);
        }
    }

    const bool         watched = watched_by_any_locked(r, dev_id);
    if (!watched) return;

    const InventoryEntry* inv = nullptr;
    if (auto it = r.inventory.find(dev_id); it != r.inventory.end()) inv = &it->second;

    // job.state on first sight of a job or any transition; never for a null
    // job (the completed end is already visible in printer.status).
    const json::Value job = build_job(merged_print, gcode);
    const std::string jstate = job.is_object() ? job.find("state").as_string() : std::string();
    if (job.is_object() && jstate != d.job_state) {
        json::Object data;
        data["device_id"]            = json::Value(dev_id);
        data["connection_generation"] = json::Value(conn_generation(&d));
        data["job"]                  = job;
        data["evidence"]             = json::Value("printer_report");
        push_event_locked(r, "job.state", dev_id, json::Value(std::move(data)));
    }
    d.job_state = jstate;

    json::Value printer = build_printer_locked(dev_id, &d, inv, now);
    push_event_locked(r, "printer.status", dev_id, std::move(printer));
}

void note_connected(const std::string& dev_id)
{
    if (dev_id.empty()) return;
    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    DeviceState& d = r.devices[dev_id];
    if (!d.online) {
        d.online = true;
        ++d.conn_seq;
    }
}

void note_disconnected(const std::string& dev_id)
{
    if (dev_id.empty()) return;
    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto it = r.devices.find(dev_id);
    if (it != r.devices.end()) it->second.online = false;
}

void note_session_changed(const char* reason)
{
    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);

    // Purge everything the old account/session produced: snapshots,
    // inventory, event history and watch interests. Clients themselves stay
    // open; their next call carries the new epoch and they must watch again.
    r.devices.clear();
    r.inventory.clear();
    while (!r.events.empty()) {
        r.min_valid_seq = r.events.front().seq;
        r.events.pop_front();
    }
    for (auto& [id, c] : r.clients) {
        c.watch.clear();
        c.poll_seen = false;
    }

    ++r.epoch_seq;
    r.epoch = "s" + std::to_string(r.epoch_seq);

    std::string why = reason ? reason : "login";
    if (why != "login" && why != "logout" && why != "agent_replaced" && why != "library_restart")
        why = "login";
    json::Object data;
    data["reason"] = json::Value(why);
    push_event_locked(r, "session.changed", std::string(), json::Value(std::move(data)));
}

void note_devices_from_cloud(const std::string& raw_body)
{
    auto parsed = json::parse(raw_body, nullptr);
    if (!parsed || !parsed->is_object()) return;
    const json::Value& devs = parsed->find("devices");
    if (!devs.is_array()) return;

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    for (const auto& d : devs.as_array()) {
        if (r.inventory.size() >= kMaxInventory) break;
        const std::string id = d.find("dev_id").as_string();
        if (id.empty() || id.size() > 128) continue;
        InventoryEntry e;
        e.name  = d.find("dev_name").as_string();
        if (e.name.empty()) e.name = d.find("name").as_string();
        if (e.name.size() > 256) e.name.resize(256);
        e.model = d.find("dev_product_name").as_string();
        if (e.model.empty()) e.model = d.find("dev_model_name").as_string();
        if (e.model.size() > 128) e.model.resize(128);
        r.inventory[id] = std::move(e);
    }
}

namespace { // dispatch internals

// ---------------------------------------------------------------------------
// Stage-3 command plumbing (docs/queue-api-v1-stage3): receipt-store
// access, canonical fingerprints, response mapping, strict request
// validation, and the worker threads that cross the dispatch boundary
// off the calling thread.
// ---------------------------------------------------------------------------

// Fresh-frame bound for dispatch-time device checks: push_status cadence
// is seconds, so a two-minute-old frame means the printer is not
// reporting (contract: stale_status before dispatch).
constexpr std::chrono::milliseconds kFreshFrameMs{120000};

// Opens the durable receipt store for the currently authorized account.
// *err receives a contract error code ("signed_out" when no session,
// "submission_store_unavailable" otherwise) when this returns nullptr.
std::unique_ptr<ReceiptStore> open_store(std::string* err)
{
#ifdef OBN_TESTING
    if (g_test_session_set) {
        if (!g_test_session.logged_in()) {
            *err = "signed_out";
            return nullptr;
        }
        std::string oerr;
        auto st = ReceiptStore::open(g_test_config_dir, g_test_session.user_id, &oerr);
        if (!st) *err = "submission_store_unavailable";
        return st;
    }
#endif
    Agent* a = Agent::active_instance();
    if (!a) {
        *err = "signed_out";
        return nullptr;
    }
    const auth::Session s = a->user_session_snapshot();
    if (!s.logged_in()) {
        *err = "signed_out";
        return nullptr;
    }
    if (config::dir().empty()) {
        *err = "submission_store_unavailable";
        return nullptr;
    }
    std::string oerr;
    auto st = ReceiptStore::open(config::dir(), s.user_id, &oerr);
    if (!st) *err = "submission_store_unavailable";
    return st;
}

bool valid_idem_key(const json::Value& v)
{
    if (!bounded_string(v, 16, 128)) return false;
    for (const char c : v.as_string()) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') || c == '.' || c == '_' ||
                        c == ':' || c == '-';
        if (!ok) return false;
    }
    return true;
}

std::string to_hex_lower(const unsigned char* d, unsigned n)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out(n * 2, '\0');
    for (unsigned i = 0; i < n; ++i) {
        out[2 * i]     = kHex[(d[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[d[i] & 0xF];
    }
    return out;
}

std::string sha256_hex(const std::string& data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    std::string out;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned      len = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, md, &len) == 1 && len > 0)
        out = to_hex_lower(md, len);
    EVP_MD_CTX_free(ctx);
    return out;
}

// Streaming SHA-256 over a file: stage-3 verifies the consumer's hash
// before crossing the dispatch boundary. Returns "" on any failure and
// sets *exists=false when the file cannot be opened at all.
std::string sha256_file_hex(const std::string& path, bool* exists)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (exists) *exists = false;
        return {};
    }
    if (exists) *exists = true;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    std::string out;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) {
        bool bad = false;
        char buf[64 * 1024];
        while (in) {
            in.read(buf, sizeof(buf));
            const auto n = in.gcount();
            if (n > 0 && EVP_DigestUpdate(ctx, buf, static_cast<std::size_t>(n)) != 1) {
                bad = true;
                break;
            }
        }
        if (!in.eof()) bad = true; // short read that is not EOF
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned      len = 0;
        if (!bad && EVP_DigestFinal_ex(ctx, md, &len) == 1 && len > 0)
            out = to_hex_lower(md, len);
    }
    EVP_MD_CTX_free(ctx);
    return out;
}

// --- supply "none" motion-only subset (docs/queue-api-v1-stage3/README) --
// A "none" submission carries no material mapping, so the library must
// itself prove the archive cannot extrude, heat or change filament before
// dispatch: the scan is an allowlist and fails closed on anything unknown.

// Test-only plain-text redirect (queue_api_test); empty = scan the archive.
std::string g_none_gcode_override;

constexpr std::size_t kMaxNoneGcodeBytes = 1024 * 1024;

std::string ascii_upper(std::string s)
{
    for (char& c : s)
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return s;
}

struct GWord {
    std::size_t b = 0;
    std::size_t e = 0;
};

// Next whitespace-delimited word at/after `from`; b == e at the end.
GWord gword(const std::string& s, std::size_t from)
{
    std::size_t b = from;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t')) ++b;
    std::size_t e = b;
    while (e < s.size() && s[e] != ' ' && s[e] != '\t') ++e;
    return {b, e};
}

// True when the word list after a motion word carries a positive E
// (extrusion). A signed negative E (retract) passes; a malformed value
// fails closed.
bool has_positive_e(const std::string& line, std::size_t from)
{
    for (;;) {
        const GWord    w = gword(line, from);
        if (w.b == w.e) return false;
        const std::string t = line.substr(w.b, w.e - w.b);
        if (!t.empty() && (t[0] == 'E' || t[0] == 'e')) {
            if (t.size() == 1) return true;
            char*        end = nullptr;
            const double d   = std::strtod(t.c_str() + 1, &end);
            if (end == t.c_str() + 1 || *end != '\0') return true;
            if (d > 0.0) return true;
        }
        from = w.e;
    }
}

// Returns nullptr when the text is inside the accepted motion-only
// subset, else a short reason (contract: unknown macros fail closed).

// A full token must parse as a finite number.
bool numeric_word(const char* s)
{
    if (!*s) return false;
    char*        end = nullptr;
    const double d   = std::strtod(s, &end);
    return end != s && *end == '\0' && std::isfinite(d);
}

// G28/M17 argument check: bare, or axis selection words only (X/Y/Z).
// An E word here would be meaningless, so it fails.
bool axis_words_only(const std::string& line, std::size_t from)
{
    for (;;) {
        const GWord w = gword(line, from);
        if (w.b == w.e) return true;
        const std::string t = ascii_upper(line.substr(w.b, w.e - w.b));
        if (t[0] != 'X' && t[0] != 'Y' && t[0] != 'Z') return false;
        from = w.e;
    }
}

// M73 progress: P/R/S with finite numeric values only.
bool m73_words(const std::string& line, std::size_t from)
{
    for (;;) {
        const GWord w = gword(line, from);
        if (w.b == w.e) return true;
        const std::string t = ascii_upper(line.substr(w.b, w.e - w.b));
        if (t.size() < 2 || (t[0] != 'P' && t[0] != 'R' && t[0] != 'S'))
            return false;
        if (!numeric_word(t.c_str() + 1)) return false;
        from = w.e;
    }
}

// M104/M140 accept exactly one word: S with value 0 (heater off). No
// target, a non-numeric target or any trailing word fails closed.
bool heater_off_words(const std::string& line, std::size_t from)
{
    const GWord w = gword(line, from);
    if (w.b == w.e) return false;
    const std::string t = ascii_upper(line.substr(w.b, w.e - w.b));
    if (t.size() < 2 || t[0] != 'S' || !numeric_word(t.c_str() + 1))
        return false;
    if (std::strtod(t.c_str() + 1, nullptr) != 0.0) return false;
    const GWord w2 = gword(line, w.e);
    return w2.b == w2.e;
}

const char* gcode_motion_only(const std::string& text)
{
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::size_t star = line.find('*'); // trailing checksum
        if (star != std::string::npos) line.erase(star);

        GWord w = gword(line, 0);
        if (w.b == w.e) continue;
        std::string word = ascii_upper(line.substr(w.b, w.e - w.b));
        if (word.size() > 1 && word[0] == 'N' &&
            word.find_first_not_of("0123456789", 1) == std::string::npos) {
            w = gword(line, w.e); // N<line number> prefix
            if (w.b == w.e) continue;
            word = ascii_upper(line.substr(w.b, w.e - w.b));
        }
        if (word.empty()) continue;
        if (word[0] == ';' || word[0] == '(') continue;

        if (word == "G0" || word == "G1" || word == "G2" || word == "G3") {
            if (has_positive_e(line, w.e)) return "positive extrusion move";
            continue;
        }
        if (word == "G28") {
            if (!axis_words_only(line, w.e)) return "unsupported G28 argument";
            continue;
        }
        if (word == "G4" || word == "G90" || word == "G91" || word == "G92" ||
            word == "M400" || word == "M117" || word == "M84" || word == "M18")
            continue;
        if (word == "M17") {
            if (!axis_words_only(line, w.e)) return "unsupported M17 argument";
            continue;
        }
        if (word == "M73") {
            if (!m73_words(line, w.e)) return "unsupported M73 argument";
            continue;
        }
        if (word == "M104" || word == "M140") {
            if (!heater_off_words(line, w.e))
                return "heater target must be S0";
            continue;
        }
        if (word[0] == 'T') return "tool change command";
        if (word == "M620" || word == "M621" || word == "M600")
            return "filament change command";
        if (word == "M109" || word == "M190" || word == "M141" ||
            word == "M191" || word == "M106" || word == "M107")
            return "heater or fan command";
        return "unsupported command";
    }
    return nullptr;
}

// The archive entry the printer itself extracts for this plate:
// build_project_file_json writes param = Metadata/plate_<N>.gcode
// (print_job.cpp), so the validator reads exactly what the printer reads.
std::string none_gcode_entry(int plate)
{
    return "Metadata/plate_" + std::to_string(plate) + ".gcode";
}

// Full pre-dispatch check for a supply "none" submission: parse the
// submitted archive (or the test override) and scan its plate gcode.
bool none_gcode_motion_only(const std::string& path, int plate,
                            const char** err)
{
    std::string text;
    if (!g_none_gcode_override.empty()) {
        std::ifstream in(g_none_gcode_override, std::ios::binary);
        if (!in) {
            *err = "gcode override unreadable";
            return false;
        }
        in.seekg(0, std::ios::end);
        const std::streamoff n = in.tellg();
        if (n < 0 || static_cast<std::size_t>(n) > kMaxNoneGcodeBytes) {
            *err = "gcode exceeds motion-only size bound";
            return false;
        }
        in.seekg(0, std::ios::beg);
        text.resize(static_cast<std::size_t>(n));
        if (n > 0) in.read(&text[0], n);
        if (!in && !in.eof()) {
            *err = "gcode override unreadable";
            return false;
        }
    } else {
        std::vector<std::uint8_t> bytes;
        const std::string          entry = none_gcode_entry(plate);
        if (!obn::zip::read_entry(path, entry, kMaxNoneGcodeBytes, &bytes)) {
            *err = "cannot read plate gcode from archive";
            return false;
        }
        text.assign(bytes.begin(), bytes.end());
    }
    const char* bad = gcode_motion_only(text);
    if (bad) {
        *err = bad;
        return false;
    }
    return true;
}

// Canonical fingerprint: SHA-256 over the re-dumped command object.
// json::Object is an ordered map, so member order and whitespace
// normalize away; array order and values stay significant (contract
// rule 2).
std::string command_fingerprint(const json::Value& command)
{
    return sha256_hex(command.dump());
}

json::Value capabilities_result()
{
    json::Object res;

    json::Array api_versions;
    api_versions.push_back(json::Value(1.0));
    res["api_versions"] = json::Value(std::move(api_versions));

    json::Array ops;
    for (const char* o : {"capabilities", "client.open", "client.close", "devices.list",
                          "watch.set", "snapshot.get", "events.poll",
                          "command.submit", "command.get", "job.get"})
        ops.push_back(json::Value(o));
    res["operations"] = json::Value(std::move(ops));

    res["command_kinds"] = json::Value(command_kinds_array());
    res["command_protocol_revision"] = json::Value("stage3-draft-1");

    // Durable submission contract (capability-additions.schema.json).
    // scope is null while signed out or when the store cannot open;
    // consumers must re-read capabilities after session changes.
    json::Object sub;
    {
        std::string err;
        auto st = open_store(&err);
        sub["scope"] = st ? json::Value(st->scope()) : json::Value(nullptr);
    }
    sub["idempotency"]           = json::Value("durable_at_most_once_dispatch");
    sub["receipt_retention"]     = json::Value("until_explicit_store_reset");
    sub["max_retained_keys"]     = json::Value(static_cast<double>(ReceiptStore::kMaxKeys));
    sub["max_pending_per_device"] = json::Value(1.0);
    res["submission"] = json::Value(std::move(sub));

    json::Array features;
    features.push_back(json::Value("multi_printer"));
    features.push_back(json::Value("event_polling"));
    res["features"] = json::Value(std::move(features));

    json::Object limits;
    limits["max_devices_per_client"]       = json::Value(static_cast<double>(kMaxDevicesPerClient));
    limits["max_clients"]                  = json::Value(static_cast<double>(kMaxClients));
    limits["max_pending_commands"]         = json::Value(8.0);
    // Legacy per-client cap, retained for backward compatibility (PR #7).
    // Authoritative durable capacity is submission.max_retained_keys above.
    limits["max_command_receipts_per_client"] = json::Value(4096.0);
    limits["event_capacity"]               = json::Value(static_cast<double>(kEventCapacity));
    limits["event_retention_seconds"]      = json::Value(static_cast<double>(kEventRetentionSec));
    limits["poll_min_interval_ms"]         = json::Value(static_cast<double>(kPollMinMs));
    limits["max_request_bytes"]            = json::Value(static_cast<double>(kMaxRequestBytes));
    limits["max_response_bytes"]           = json::Value(2097152.0);
    res["limits"] = json::Value(std::move(limits));

    res["session_state"] = json::Value(session_state());
    return json::Value(std::move(res));
}

// Read-only view of a device's latest status for the command path.
struct DeviceSnap {
    bool          known = false;
    bool          have_frame = false;
    bool          busy = false;
    long long     age_ms = 0;
    std::uint64_t conn_seq = 0;
    json::Value   print{json::Object{}};
};

DeviceSnap snapshot_device(const std::string& dev)
{
    DeviceSnap s;
    Registry&  r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto it = r.devices.find(dev);
    if (it == r.devices.end()) return s;
    s.known = true;
    const DeviceState& d = it->second;
    s.conn_seq = d.conn_seq;
    if (!d.has_frame) return s;
    s.have_frame = true;
    s.age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                   Clock::now() - d.last_frame).count();
    if (s.age_ms < 0) s.age_ms = 0;
    const json::Value& pv = d.merged.find("print");
    s.print = pv.is_object() ? pv : json::Value(json::Object{});
    s.busy  = printer_state_of(d.online, s.print.find("gcode_state").as_string()) == "busy";
    return s;
}

std::string rec_str(const json::Object& rec, const char* k, const char* fb = "")
{
    const auto it = rec.find(k);
    return (it != rec.end() && it->second.is_string()) ? it->second.as_string()
                                                       : std::string(fb);
}

// command.submit / command.get result: the receipt shape from
// response.schema.json ($defs/receipt).
json::Value receipt_result(const std::string& scope, const json::Object& rec)
{
    json::Object o;
    o["submission_scope"] = json::Value(scope);
    o["idempotency_key"]  = json::Value(rec_str(rec, "k"));
    o["command_id"]       = json::Value(rec_str(rec, "cid"));
    o["device_id"]        = json::Value(rec_str(rec, "dev"));
    o["kind"]             = json::Value(rec_str(rec, "kind"));
    o["job_id"]           = json::Value(rec_str(rec, "jid"));
    o["state"]            = json::Value(rec_str(rec, "state", "accepted"));
    o["dispatch"]         = json::Value(rec_str(rec, "dispatch", "not_sent"));
    const std::string ts  = rec_str(rec, "ts");
    o["accepted_at"]      = json::Value(rec_str(rec, "acc", ts.c_str()));
    o["updated_at"]       = json::Value(ts);
    const auto err = rec.find("err");
    o["error"] = (err != rec.end() && err->second.is_object()) ? err->second
                                                               : json::Value(nullptr);
    return json::Value(std::move(o));
}

// job.get result (response.schema.json $defs/job). Receipt -> job state
// mapping without printer correlation yet: only a not_sent failure or
// cancellation proves the job never ran; anything past the dispatch
// marker stays "unknown" until frame evidence lands (shortcut: live
// frame correlation is a later step, covered by acceptance).
json::Value job_result(const std::string& scope, const json::Object& rec,
                       const DeviceSnap& snap)
{
    const std::string state    = rec_str(rec, "state", "accepted");
    const std::string dispatch = rec_str(rec, "dispatch", "not_sent");
    const std::string ts       = rec_str(rec, "ts");

    std::string js;
    if (state == "accepted")       js = "pending";
    else if (state == "working")   js = "preparing";
    else if (state == "succeeded") js = "printing"; // dispatch acknowledged
    else if (state == "failed")
        js = dispatch == "not_sent" ? "failed" : "unknown";
    else if (state == "cancelled")
        js = dispatch == "not_sent" ? "cancelled" : "unknown";
    else js = "unknown";

    json::Object j;
    j["job_id"]     = json::Value(rec_str(rec, "jid"));
    j["device_id"]  = json::Value(rec_str(rec, "dev"));
    j["state"]      = json::Value(js);
    j["started_at"] = (js == "printing" && !ts.empty()) ? json::Value(ts)
                                                        : json::Value(nullptr);
    if (js == "failed" || js == "cancelled") {
        json::Object t;
        t["state"]                 = json::Value(js);
        t["error_code"]            = json::Value(nullptr); // no printer code observed
        t["observed_at"]           = json::Value(ts);
        t["source"]                = json::Value("unknown");
        t["correlation"]           = json::Value("unverified");
        t["connection_generation"] =
            json::Value("connection-" + std::to_string(snap.conn_seq));
        // quiescent needs native end-of-execution proof, never receipt
        // evidence alone (contract quiescent gate): stay false.
        t["quiescent"] = json::Value(false);
        j["terminal"]  = json::Value(std::move(t));
    } else {
        j["terminal"] = json::Value(nullptr);
    }
    const std::string tag = rec_str(rec, "tag");
    j["task_tag"]         = tag.empty() ? json::Value(nullptr) : json::Value(tag);
    j["origin"]           = json::Value("unknown");
    j["progress_percent"] = json::Value(nullptr);

    json::Object res;
    res["submission_scope"] = json::Value(scope);
    res["job"]              = json::Value(std::move(j));
    return json::Value(std::move(res));
}

bool receipt_update(ReceiptStore* st, const std::string& key,
                    json::Object patch, const char* what)
{
    std::string e;
    if (!st->update(key, patch, &e)) {
        OBN_WARN("queue: receipt update (%s) failed key=%s: %s",
                 what, key.c_str(), e.c_str());
        return false;
    }
    return true;
}

// g_submit_mu must be held by the caller.
void lane_release_if_own(const std::string& dev, const std::string& key)
{
    const auto it = g_print_lanes.find(dev);
    if (it != g_print_lanes.end() && it->second.key == key)
        g_print_lanes.erase(it);
}

// One validated command.submit payload. `command` keeps the as-parsed
// object: it is the fingerprint source.
struct SubmitCommand {
    std::string kind; // print | pause | resume | stop
    std::string device_id;
    json::Value command;
    // print payload
    std::string file_path;
    std::string file_sha256;
    int         plate_index = 1;
    std::string task_tag;
    std::string supply;
    json::Value materials{json::Array{}};
    bool        bed_leveling     = false;
    bool        flow_calibration = false;
    bool        timelapse        = false;
    // control
    std::string expected_job_id;
};

bool valid_color(const json::Value& v)
{
    if (!v.is_string()) return false;
    const std::string& s = v.as_string();
    if ((s.size() != 7 && s.size() != 9) || s[0] != '#') return false;
    for (std::size_t i = 1; i < s.size(); ++i) {
        const char c = s[i];
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

// "ams-<N>-slot-<M>" with N in 0..255 and M in 0..3 (four trays per
// unit: the flat mapping's linear index is ams*4+tray).
bool parse_slot_id(const std::string& s, int* ams, int* tray)
{
    if (s.rfind("ams-", 0) != 0) return false;
    const auto pos = s.find("-slot-", 4);
    if (pos == std::string::npos) return false;
    const std::string a = s.substr(4, pos - 4);
    const std::string t = s.substr(pos + 6);
    if (a.empty() || t.empty()) return false;
    for (const char c : a) if (c < '0' || c > '9') return false;
    for (const char c : t) if (c < '0' || c > '9') return false;
    try {
        *ams  = std::stoi(a);
        *tray = std::stoi(t);
    } catch (...) {
        return false;
    }
    return *ams >= 0 && *ams <= 255 && *tray >= 0 && *tray <= 3;
}

// Strict stage-3 request validation (request.schema.json): exact key
// sets everywhere, bounded strings, pattern checks. Returns false with
// *err/*code for the error envelope; *code is "not_supported" for a
// shape that parses but is not advertised.
bool parse_command(const json::Value& cmd, SubmitCommand* out,
                   std::string* err, const char** code)
{
    *code = "invalid_request";
    if (!cmd.is_object()) {
        *err = "command must be an object";
        return false;
    }
    const json::Object& co   = cmd.as_object();
    const std::string   kind = gv(co, "kind").as_string();
    if (kind == "skip_objects") {
        *code = "not_supported";
        *err  = "command kind skip_objects is not advertised";
        return false;
    }
    if (kind != "print" && kind != "pause" && kind != "resume" && kind != "stop") {
        *err = "command.kind must be print, pause, resume or stop";
        return false;
    }
    out->kind = kind;

    std::string e;
    if (kind != "print") {
        if (!exact_keys(co, {"kind", "device_id", "expected_job_id"}, e)) {
            *err = e;
            return false;
        }
        const json::Value& dev = gv(co, "device_id");
        if (!valid_device_id(dev)) {
            *err = "device_id must be a string of 1..128 bytes";
            return false;
        }
        out->device_id = dev.as_string();
        const json::Value& exp = gv(co, "expected_job_id");
        if (!bounded_string(exp, 1, 128)) {
            *err = "expected_job_id must be a string of 1..128 bytes";
            return false;
        }
        out->expected_job_id = exp.as_string();
        out->command         = cmd;
        return true;
    }

    if (!exact_keys(co, {"kind", "device_id", "payload"}, e)) {
        *err = e;
        return false;
    }
    const json::Value& dev = gv(co, "device_id");
    if (!valid_device_id(dev)) {
        *err = "device_id must be a string of 1..128 bytes";
        return false;
    }
    out->device_id = dev.as_string();

    const json::Value& payload = gv(co, "payload");
    if (!payload.is_object()) {
        *err = "payload must be an object";
        return false;
    }
    const json::Object& po = payload.as_object();
    if (!exact_keys(po, {"file", "task_tag", "supply", "materials", "options"}, e)) {
        *err = e;
        return false;
    }

    const json::Value& file = gv(po, "file");
    if (!file.is_object()) {
        *err = "payload.file must be an object";
        return false;
    }
    if (!exact_keys(file.as_object(), {"path", "sha256", "plate_index"}, e)) {
        *err = e;
        return false;
    }
    const json::Value& path = gv(file.as_object(), "path");
    if (!bounded_string(path, 1, 32767)) {
        *err = "file.path must be a string of 1..32767 bytes";
        return false;
    }
    out->file_path = path.as_string();
    const json::Value& sha = gv(file.as_object(), "sha256");
    if (!bounded_string(sha, 64, 64)) {
        *err = "file.sha256 must be 64 lowercase hex chars";
        return false;
    }
    for (const char c : sha.as_string()) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            *err = "file.sha256 must be 64 lowercase hex chars";
            return false;
        }
    }
    out->file_sha256 = sha.as_string();
    long long plate  = 0;
    if (!int_in(gv(file.as_object(), "plate_index"), 1, 1024, &plate)) {
        *err = "file.plate_index must be an integer in 1..1024";
        return false;
    }
    out->plate_index = static_cast<int>(plate);

    if (!bounded_string(gv(po, "task_tag"), 1, 128)) {
        *err = "task_tag must be a string of 1..128 bytes";
        return false;
    }
    out->task_tag = gv(po, "task_tag").as_string();

    const std::string supply = gv(po, "supply").as_string();
    if (supply != "ams" && supply != "external" && supply != "none") {
        *err = "supply must be \"ams\", \"external\" or \"none\"";
        return false;
    }
    out->supply = supply;

    const json::Value& mats = gv(po, "materials");
    if (supply == "none") {
        if (!mats.is_array() || !mats.as_array().empty()) {
            *err = "supply \"none\" requires an empty materials array";
            return false;
        }
    } else if (!mats.is_array() || mats.as_array().size() < 1 ||
               mats.as_array().size() > 64) {
        *err = "materials must be an array of 1..64 entries";
        return false;
    }
    std::vector<int> seen_ids;
    for (const auto& m : mats.as_array()) {
        if (!m.is_object()) {
            *err = "materials entries must be objects";
            return false;
        }
        if (!exact_keys(m.as_object(),
                        {"source_filament_id", "slot_id", "type", "profile_id",
                         "source_color", "target_color"}, e)) {
            *err = e;
            return false;
        }
        const json::Value& sid = gv(m.as_object(), "source_filament_id");
        if (!bounded_string(sid, 1, 8)) {
            *err = "source_filament_id must be a digit string of 1..8 chars";
            return false;
        }
        int id_num = 0;
        for (const char c : sid.as_string()) {
            if (c < '0' || c > '9') {
                *err = "source_filament_id must be a digit string of 1..8 chars";
                return false;
            }
            id_num = id_num * 10 + (c - '0');
        }
        if (id_num > 1023) {
            *err = "source_filament_id must be <= 1023";
            return false;
        }
        if (std::find(seen_ids.begin(), seen_ids.end(), id_num) != seen_ids.end()) {
            *err = "duplicate source_filament_id: " + sid.as_string();
            return false;
        }
        seen_ids.push_back(id_num);
        if (!bounded_string(gv(m.as_object(), "slot_id"), 1, 128)) {
            *err = "slot_id must be a string of 1..128 bytes";
            return false;
        }
        if (!bounded_string(gv(m.as_object(), "type"), 1, 64)) {
            *err = "type must be a string of 1..64 bytes";
            return false;
        }
        if (!bounded_string(gv(m.as_object(), "profile_id"), 0, 128)) {
            *err = "profile_id must be a string of at most 128 bytes";
            return false;
        }
        if (!valid_color(gv(m.as_object(), "source_color")) ||
            !valid_color(gv(m.as_object(), "target_color"))) {
            *err = "colors must match #RRGGBB or #RRGGBBAA";
            return false;
        }
        if (supply == "ams") {
            int ams = 0, tray = 0;
            if (!parse_slot_id(gv(m.as_object(), "slot_id").as_string(), &ams, &tray)) {
                *err = "slot_id must be ams-<N>-slot-<M> with N in 0..255, M in 0..3";
                return false;
            }
        }
    }
    out->materials = mats;

    const json::Value& opts = gv(po, "options");
    if (!opts.is_object()) {
        *err = "options must be an object";
        return false;
    }
    if (!exact_keys(opts.as_object(), {"bed_leveling", "flow_calibration", "timelapse"}, e)) {
        *err = e;
        return false;
    }
    for (const char* k : {"bed_leveling", "flow_calibration", "timelapse"}) {
        if (!gv(opts.as_object(), k).is_bool()) {
            *err = std::string(k) + " must be a boolean";
            return false;
        }
    }
    out->bed_leveling     = gv(opts.as_object(), "bed_leveling").as_bool();
    out->flow_calibration = gv(opts.as_object(), "flow_calibration").as_bool();
    out->timelapse        = gv(opts.as_object(), "timelapse").as_bool();
    if (supply == "none" &&
        (out->bed_leveling || out->flow_calibration || out->timelapse)) {
        *err = "supply \"none\" requires options bed_leveling, flow_calibration "
               "and timelapse false";
        return false;
    }

    out->command = cmd;
    return true;
}

// materials -> per-source-id slot values: index = sliced source filament
// id, value = linear AMS slot (ams*4+tray) or -1 for external. Sparse
// ids are not list positions (contract): holes stay -1.
bool build_mapping_values(const SubmitCommand& sc, std::vector<int>* vals,
                          std::string* err)
{
    int                 max_id = -1;
    std::map<int, int>  by_id;
    for (const auto& m : sc.materials.as_array()) {
        const std::string sid = gv(m.as_object(), "source_filament_id").as_string();
        const int         id  = std::atoi(sid.c_str());
        int               v   = -1;
        if (sc.supply == "ams") {
            int ams = 0, tray = 0;
            if (!parse_slot_id(gv(m.as_object(), "slot_id").as_string(), &ams, &tray)) {
                *err = "invalid slot_id: " + gv(m.as_object(), "slot_id").as_string();
                return false;
            }
            v = ams * 4 + tray;
        }
        by_id[id] = v;
        if (id > max_id) max_id = id;
    }
    vals->assign(static_cast<std::size_t>(max_id + 1), -1);
    for (const auto& kv : by_id)
        (*vals)[static_cast<std::size_t>(kv.first)] = kv.second;
    return true;
}

std::string flat_mapping_json(const std::vector<int>& vals)
{
    std::string s = "[";
    for (std::size_t i = 0; i < vals.size(); ++i) {
        if (i) s += ',';
        s += std::to_string(vals[i]);
    }
    return s + "]";
}

// Snake_case ams_mapping2 the way the printer's MQTT schema wants it
// (PrintParams::ams_mapping2 is passed verbatim on the LAN path);
// -1/external maps to the {255,0} sentinel, same as the cloud
// conversion in cloud_print.cpp.
std::string snake_mapping2_json(const std::vector<int>& vals)
{
    std::string s     = "[";
    bool        first = true;
    for (const int v : vals) {
        if (!first) s += ',';
        first       = false;
        const int ams  = v < 0 ? 255 : v / 4;
        const int slot = v < 0 ? 0 : v % 4;
        s += "{\"ams_id\":" + std::to_string(ams) +
             ",\"slot_id\":" + std::to_string(slot) + "}";
    }
    return s + "]";
}

// Every material slot must still exist in the device's latest frame
// (contract: a slot removed after acceptance fails before dispatch).
bool slots_present(const json::Value& print_v, const json::Value& materials)
{
    const json::Array slots = build_slots(print_v);
    std::vector<std::string> ids;
    ids.reserve(slots.size());
    for (const auto& s : slots) ids.push_back(s.find("slot_id").as_string());
    for (const auto& m : materials.as_array()) {
        const std::string want = gv(m.as_object(), "slot_id").as_string();
        if (std::find(ids.begin(), ids.end(), want) == ids.end()) return false;
    }
    return true;
}

bool build_print_params(const SubmitCommand& sc, Agent* a, BBL::PrintParams* p,
                        std::string* err)
{
    std::vector<int> vals;
    if (!build_mapping_values(sc, &vals, err)) return false;

    *p                    = BBL::PrintParams{};
    p->dev_id             = sc.device_id;
    p->task_name          = sc.task_tag;
    p->project_name       = sc.task_tag;
    p->filename           = sc.file_path;
    p->plate_index        = sc.plate_index;
    p->dev_ip             = a->lan_ip_for(sc.device_id);
    p->password           = a->lan_access_code_for(sc.device_id);
    p->use_ssl_for_ftp    = true;
    p->use_ssl_for_mqtt   = true;
    p->task_bed_leveling      = sc.bed_leveling;
    p->task_flow_cali         = sc.flow_calibration;
    p->task_record_timelapse  = sc.timelapse;
    p->task_vibration_cali    = false;
    p->task_layer_inspect     = false;
    p->task_use_ams           = sc.supply == "ams";
    p->task_ext_change_assist = false;
    p->try_emmc_print         = false;
#if ABI_VERSION >= 0x020503
    p->task_timelapse_use_internal = false;
#endif
    // Resolved policy ints mirror the user toggles (research/08.08:
    // 0=off, 1=on; the booleans stay the user toggles).
    p->auto_bed_leveling = sc.bed_leveling ? 1 : 0;
    p->auto_flow_cali    = sc.flow_calibration ? 1 : 0;
    p->auto_offset_cali  = 0;
    p->ams_mapping  = flat_mapping_json(vals);
    p->ams_mapping2 = snake_mapping2_json(vals);
    return true;
}

// Mode selection mirrors abi_print.cpp's Studio entries: LanOnly stays
// LAN, CloudOnly goes through /my/task, TryLanFirst (and the
// MakerWorld-only mode, which a queue file never satisfies) tries LAN
// first and falls back to the cloud.
int run_print_job(Agent* a, const BBL::PrintParams& p)
{
    BBL::OnUpdateStatusFn ub = [](int, int, std::string) {};
    BBL::WasCancelledFn   cb = [] { return false; };
    using CPM = obn::config::CloudPrintMode;
    const CPM mode = obn::config::current().cloud_print;
    if (mode == CPM::LanOnly)
        return a->run_local_print_job(p, ub, cb);
    if (mode == CPM::CloudOnly)
        return a->run_cloud_print_job(p, ub, cb, /*use_lan_channel=*/false);
    int rc = a->run_local_print_job(p, ub, cb);
    if (rc != 0)
        rc = a->run_cloud_print_job(p, ub, cb, /*use_lan_channel=*/false);
    return rc;
}

// A control's expected_job_id binds only to a live queued print receipt
// for the same device (a failed/cancelled pre-dispatch job never ran
// physically). Controls share the target's jid, so kind=="print" filters
// them out.
bool binds_job(ReceiptStore* st, const std::string& dev, const std::string& jid)
{
    json::Object found;
    std::string  err;
    return st->find_if(
        [&](const json::Object& o) {
            if (rec_str(o, "kind") != "print") return false;
            if (rec_str(o, "dev") != dev) return false;
            if (rec_str(o, "jid") != jid) return false;
            const std::string s = rec_str(o, "state", "accepted");
            return s != "failed" && s != "cancelled";
        },
        &found, &err);
}

// Field-level gate shared by every client-scoped op: exact top-level key
// set, bounded client_id/session_epoch strings, and the epoch echo check.
// Returns an error envelope or ""; the caller then does the locked lookup.
std::string gate_client_fields(const json::Object& root, Meta& m,
                               std::initializer_list<const char*> top_keys,
                               std::string* client_id_out)
{
    std::string err;
    if (!exact_keys(root, top_keys, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& cid = gv(root, "client_id");
    if (!bounded_string(cid, 1, 128))
        return error_env(m, "invalid_request", "client_id must be a string of 1..128 bytes", false);

    const json::Value& ep = gv(root, "session_epoch");
    if (!bounded_string(ep, 1, 128))
        return error_env(m, "invalid_request", "session_epoch must be a string of 1..128 bytes", false);
    if (ep.as_string() != m.epoch)
        return error_env(m, "session_changed", "Refresh capabilities and reconcile before dispatch.", false);

    *client_id_out = cid.as_string();
    return "";
}

// Locked lookup; erases an expired lease. Renewal stays with the caller so
// only successful calls renew.
Client* find_client_locked(Registry& r, const std::string& cid, Clock::time_point now, std::string* err)
{
    const auto it = r.clients.find(cid);
    if (it == r.clients.end()) {
        *err = "client_id is unknown or already closed";
        return nullptr;
    }
    if (now >= it->second.deadline) {
        r.clients.erase(it);
        *err = "client lease expired";
        return nullptr;
    }
    return &it->second;
}

std::string op_capabilities(const json::Object& root, Meta& m)
{
    std::string err;
    if (!exact_keys(root, {"api", "request_id", "op"}, err))
        return error_env(m, "invalid_request", err, false);
    return success_env(m, capabilities_result());
}

std::string op_client_open(const json::Object& root, Meta& m)
{
    std::string err;
    if (!exact_keys(root, {"api", "request_id", "op", "params"}, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    if (!exact_keys(params.as_object(), {"name", "lease_seconds"}, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& name = gv(params.as_object(), "name");
    if (!bounded_string(name, 1, 80))
        return error_env(m, "invalid_request", "name must be a string of 1..80 bytes", false);

    long long lease = 0;
    if (!int_in(gv(params.as_object(), "lease_seconds"), 30, 300, &lease))
        return error_env(m, "invalid_request", "lease_seconds must be an integer in 30..300", false);

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto now = Clock::now();
    for (auto it = r.clients.begin(); it != r.clients.end();) {
        if (now >= it->second.deadline) it = r.clients.erase(it);
        else ++it;
    }
    if (r.clients.size() >= kMaxClients)
        return error_env(m, "capacity_exceeded", "too many open clients", false);

    const std::string id = "c" + std::to_string(r.client_seq++);
    Client c;
    c.name          = name.as_string();
    c.lease_seconds = static_cast<std::uint32_t>(lease);
    c.deadline      = now + std::chrono::seconds(lease);
    r.clients.emplace(id, std::move(c));

    json::Object res;
    res["client_id"]     = json::Value(id);
    res["lease_seconds"] = json::Value(static_cast<double>(lease));
    return success_env(m, json::Value(std::move(res)));
}

std::string op_client_close(const json::Object& root, Meta& m)
{
    std::string cid;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch"}, &cid);
        !gate.empty())
        return gate;

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    std::string err;
    Client* c = find_client_locked(r, cid, Clock::now(), &err);
    if (!c) return error_env(m, "client_expired", err, false);
    r.clients.erase(cid);

    json::Object res;
    res["closed"] = json::Value(true);
    return success_env(m, json::Value(std::move(res)));
}

std::string op_devices_list(const json::Object& root, Meta& m)
{
    std::string cid;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch"}, &cid);
        !gate.empty())
        return gate;

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto now = Clock::now();
    std::string err;
    Client* c = find_client_locked(r, cid, now, &err);
    if (!c) return error_env(m, "client_expired", err, false);

    std::size_t total = r.inventory.size();
    for (const auto& [id, st] : r.devices)
        if (r.inventory.count(id) == 0) ++total;
    if (total > kMaxInventory)
        return error_env(m, "capacity_exceeded", "device inventory exceeds 1024 devices", false);

    json::Array devs;
    for (const auto& [id, e] : r.inventory) {
        json::Object d;
        d["device_id"] = json::Value(id);
        d["name"]      = json::Value(e.name);
        d["model"]     = json::Value(e.model);
        devs.push_back(json::Value(std::move(d)));
    }
    for (const auto& [id, st] : r.devices) {
        if (r.inventory.count(id) != 0) continue;
        json::Object d;
        d["device_id"] = json::Value(id);
        d["name"]      = json::Value(std::string());
        d["model"]     = json::Value(std::string());
        devs.push_back(json::Value(std::move(d)));
    }

    c->deadline = now + std::chrono::seconds(c->lease_seconds);

    json::Object res;
    res["devices"] = json::Value(std::move(devs));
    return success_env(m, json::Value(std::move(res)));
}

// Builds printer snapshots for `ids` under the caller's lock. Returns an
// error envelope when the response would blow the byte budget, else "".
std::string build_printers_locked(const Registry& r, const std::vector<std::string>& ids,
                                  Clock::time_point now, json::Array* out, const Meta& m)
{
    std::size_t bytes = 0;
    for (const auto& id : ids) {
        const DeviceState*    d   = nullptr;
        const InventoryEntry* inv = nullptr;
        if (const auto it = r.devices.find(id); it != r.devices.end()) d = &it->second;
        if (const auto it = r.inventory.find(id); it != r.inventory.end()) inv = &it->second;
        json::Value p = build_printer_locked(id, d, inv, now);
        bytes += p.dump().size() + 64;
        if (bytes > kMaxResponseBudget)
            return error_env(m, "capacity_exceeded", "snapshot response exceeds max_response_bytes", false);
        out->push_back(std::move(p));
    }
    return "";
}

std::string op_watch_set(const json::Object& root, Meta& m)
{
    std::string cid;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch", "params"}, &cid);
        !gate.empty())
        return gate;

    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    std::vector<std::string> ids;
    std::string err;
    if (!parse_device_ids(params, &ids, err))
        return error_env(m, "invalid_request", err, false);

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto now = Clock::now();
    Client* c = find_client_locked(r, cid, now, &err);
    if (!c) return error_env(m, "client_expired", err, false);

    // Validate the whole set before changing anything: no partial watch.
    for (const auto& id : ids)
        if (!known_device_locked(r, id))
            return error_env(m, "device_unavailable", "unknown device: " + id, false);

    json::Array printers;
    if (const std::string berr = build_printers_locked(r, ids, now, &printers, m); !berr.empty())
        return berr;

    c->watch      = ids;
    c->poll_seen  = false; // a new stream may be polled immediately
    c->deadline   = now + std::chrono::seconds(c->lease_seconds);

    json::Object res;
    json::Array  echo;
    for (const auto& id : ids) echo.push_back(json::Value(id));
    res["device_ids"] = json::Value(std::move(echo));
    res["cursor"]     = json::Value(tail_cursor_locked(r));
    res["printers"]   = json::Value(std::move(printers));
    return success_env(m, json::Value(std::move(res)));
}

std::string op_snapshot_get(const json::Object& root, Meta& m)
{
    std::string cid;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch", "params"}, &cid);
        !gate.empty())
        return gate;

    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    std::vector<std::string> ids;
    std::string err;
    if (!parse_device_ids(params, &ids, err))
        return error_env(m, "invalid_request", err, false);

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto now = Clock::now();
    Client* c = find_client_locked(r, cid, now, &err);
    if (!c) return error_env(m, "client_expired", err, false);

    for (const auto& id : ids) {
        if (std::find(c->watch.begin(), c->watch.end(), id) == c->watch.end())
            return error_env(m, "device_unavailable", "device not in this client's watch set: " + id, false);
    }

    json::Array printers;
    if (const std::string berr = build_printers_locked(r, ids, now, &printers, m); !berr.empty())
        return berr;

    c->deadline = now + std::chrono::seconds(c->lease_seconds);

    json::Object res;
    res["cursor"]   = json::Value(tail_cursor_locked(r));
    res["printers"] = json::Value(std::move(printers));
    return success_env(m, json::Value(std::move(res)));
}

// Strict cursor: "e" followed by decimal digits, fitting uint64.
bool parse_cursor(const json::Value& v, std::uint64_t* out)
{
    if (!v.is_string()) return false;
    const std::string& s = v.as_string();
    if (s.size() < 2 || s.size() > 20 || s[0] != 'e') return false;
    std::uint64_t acc = 0;
    for (std::size_t i = 1; i < s.size(); ++i) {
        const char ch = s[i];
        if (ch < '0' || ch > '9') return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
        if (acc > (UINT64_MAX - digit) / 10) return false;
        acc = acc * 10 + digit;
    }
    *out = acc;
    return true;
}

std::string op_events_poll(const json::Object& root, Meta& m)
{
    std::string cid;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch", "params"}, &cid);
        !gate.empty())
        return gate;

    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    std::string err;
    if (!exact_keys(params.as_object(), {"cursor", "limit"}, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& cur = gv(params.as_object(), "cursor");
    const bool         establish = cur.is_null();
    std::uint64_t      cursor_seq = 0;
    if (!establish) {
        if (!bounded_string(cur, 1, 128) || !parse_cursor(cur, &cursor_seq))
            return error_env(m, "invalid_request", "cursor must be null or an opaque cursor string", false);
    }
    long long limit = 0;
    if (!int_in(gv(params.as_object(), "limit"), 1, 256, &limit))
        return error_env(m, "invalid_request", "limit must be an integer in 1..256", false);

    Registry& r = reg();
    std::lock_guard<std::mutex> lk(r.mu);
    const auto now = Clock::now();
    Client* c = find_client_locked(r, cid, now, &err);
    if (!c) return error_env(m, "client_expired", err, false);

    if (c->poll_seen &&
        std::chrono::duration_cast<std::chrono::milliseconds>(now - c->last_poll).count() < kPollMinMs)
        return error_env(m, "busy", "poll no faster than poll_min_interval_ms", true);

    const std::uint64_t tail = r.next_seq - 1;
    std::uint64_t start = tail;
    if (!establish) {
        if (cursor_seq < r.min_valid_seq)
            return error_env(m, "cursor_expired",
                             "cursor expired; take a fresh snapshot/cursor and reconcile", false);
        if (cursor_seq > tail)
            return error_env(m, "invalid_request", "cursor is ahead of the event stream", false);
        start = cursor_seq;
    }

    json::Array  events;
    std::size_t  bytes = 0;
    int          count = 0;
    bool         more  = false;
    std::uint64_t last = start;
    for (const auto& e : r.events) {
        if (e.seq <= start) continue;
        if (!e.device_id.empty() &&
            std::find(c->watch.begin(), c->watch.end(), e.device_id) == c->watch.end())
            continue;
        if (count >= static_cast<int>(limit) ||
            bytes + e.size_hint + 160 > kMaxResponseBudget) {
            more = true;
            break;
        }
        json::Object ev;
        ev["cursor"]               = json::Value("e" + std::to_string(e.seq));
        ev["session_epoch"]        = json::Value(e.epoch);
        ev["capabilities_revision"] = json::Value(kCapRev);
        ev["kind"]                 = json::Value(e.kind);
        ev["data"]                 = e.data;
        events.push_back(json::Value(std::move(ev)));
        bytes += e.size_hint + 160;
        ++count;
        last = e.seq;
    }

    c->last_poll  = now;
    c->poll_seen  = true;
    c->deadline   = now + std::chrono::seconds(c->lease_seconds);

    json::Object res;
    res["next_cursor"] = json::Value("e" + std::to_string(last));
    res["has_more"]    = json::Value(more);
    res["events"]      = json::Value(std::move(events));
    return success_env(m, json::Value(std::move(res)));
}

// Print worker: verifies the intent, then crosses the dispatch boundary
// on this thread (contract: submit returns promptly; hashing, upload and
// printer acknowledgement never run on the calling thread).
void worker_print(std::string key, SubmitCommand sc, std::string epoch)
{
    std::string err;
    auto store = open_store(&err);
    if (!store) {
        OBN_WARN("queue: print worker cannot open receipt store key=%s: %s",
                 key.c_str(), err.c_str());
        return; // stays accepted/not_sent: nothing dispatched
    }
    json::Object rec;
    if (!store->get(key, &rec, &err)) {
        // Another account or a reset store owns this directory now:
        // never dispatch work the current session cannot account for.
        OBN_WARN("queue: print worker receipt missing key=%s: %s",
                 key.c_str(), err.c_str());
        return;
    }

    auto release_lane = [&] {
        std::lock_guard<std::mutex> lk(g_submit_mu);
        lane_release_if_own(sc.device_id, key);
    };
    auto fail_pre = [&](const char* code, bool retryable, const char* what) {
        json::Object errv;
        errv["code"]      = json::Value(code);
        errv["retryable"] = json::Value(retryable);
        json::Object patch;
        patch["state"]    = json::Value("failed");
        patch["dispatch"] = json::Value("not_sent");
        patch["err"]      = json::Value(std::move(errv));
        receipt_update(store.get(), key, std::move(patch), what);
        release_lane();
    };
    auto cancel_pre = [&](const char* what) {
        json::Object patch;
        patch["state"]    = json::Value("cancelled");
        patch["dispatch"] = json::Value("not_sent");
        receipt_update(store.get(), key, std::move(patch), what);
        release_lane();
    };

    if (current_epoch() != epoch) {
        cancel_pre("session replaced before dispatch");
        return;
    }

    // File verification before any dispatch boundary: file errors are
    // retained receipt failures, never uploads (contract). supply "none"
    // additionally proves the archive stays inside the motion-only subset
    // before the hash: a conforming-but-changed file still fails below as
    // file_changed, anything outside the subset never reaches dispatch.
    if (sc.supply == "none") {
        const char* sub_err = nullptr;
        if (!none_gcode_motion_only(sc.file_path, sc.plate_index, &sub_err)) {
            fail_pre("unsafe_gcode", false,
                     sub_err ? sub_err : "gcode outside motion-only subset");
            return;
        }
    }
    bool               exists = false;
    const std::string  digest = sha256_file_hex(sc.file_path, &exists);
    if (!exists || digest.empty()) {
        fail_pre("unsafe_file", false, "file missing or unreadable");
        return;
    }
    if (digest != sc.file_sha256) {
        fail_pre("file_changed", false, "file hash mismatch");
        return;
    }

    Agent* a = Agent::active_instance();
    if (!a || !a->user_session_snapshot().logged_in() || current_epoch() != epoch) {
        cancel_pre("session replaced before dispatch");
        return;
    }

    const DeviceSnap snap = snapshot_device(sc.device_id);
    if (!snap.known || !snap.have_frame || snap.age_ms > kFreshFrameMs.count()) {
        fail_pre("stale_status", true, "no fresh device status");
        return;
    }
    if (snap.busy) {
        fail_pre("busy", true, "printer busy at dispatch");
        return;
    }
    if (sc.supply == "ams" && !slots_present(snap.print, sc.materials)) {
        fail_pre("invalid_mapping", false, "material slot not present on device");
        return;
    }

    // Lane recheck immediately before dispatch: the accept-time claim
    // can be released by frame evidence while this worker was hashing.
    bool lane_ok = true;
    {
        std::lock_guard<std::mutex> lk(g_submit_mu);
        auto it = g_print_lanes.find(sc.device_id);
        if (it == g_print_lanes.end())
            g_print_lanes[sc.device_id] = LaneEntry{key, false};
        else if (it->second.key != key)
            lane_ok = false;
    }
    if (!lane_ok) {
        fail_pre("busy", true, "print lane taken by another submission");
        return;
    }

    BBL::PrintParams p{};
    if (!build_print_params(sc, a, &p, &err)) {
        fail_pre("invalid_mapping", false, err.c_str());
        return;
    }

    // Dispatch boundary: durably record uncertainty BEFORE the SDK call;
    // after this point nothing may retransmit this key (contract rule 4).
    json::Object mark;
    mark["state"]    = json::Value("working");
    mark["dispatch"] = json::Value("may_have_been_sent");
    if (!receipt_update(store.get(), key, std::move(mark), "dispatch marker")) {
        release_lane(); // fail closed: no dispatch without a durable marker
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_submit_mu);
        auto it = g_print_lanes.find(sc.device_id);
        if (it != g_print_lanes.end() && it->second.key == key)
            it->second.dispatched = true;
        else
            g_print_lanes[sc.device_id] = LaneEntry{key, true};
    }

    const int rc = run_print_job(a, p);
    if (rc == BAMBU_NETWORK_SUCCESS) {
        json::Object patch;
        patch["state"]    = json::Value("succeeded");
        patch["dispatch"] = json::Value("confirmed");
        receipt_update(store.get(), key, std::move(patch), "dispatch confirmed");
        // Lane stays: the physical job owns the device until ingest_frame
        // sees terminal/jobless evidence.
    } else {
        // The SDK reported failure but cannot prove the boundary was not
        // crossed: retain uncertainty (never retransmit) and keep the
        // lane until frame evidence releases it.
        json::Object errv;
        errv["code"]      = json::Value("result_unknown");
        errv["retryable"] = json::Value(true);
        json::Object patch;
        patch["state"] = json::Value("unknown");
        patch["err"]   = json::Value(std::move(errv));
        receipt_update(store.get(), key, std::move(patch), "dispatch failed");
    }
}

// Control worker (pause/resume/stop): same boundary discipline as the
// print worker, minus the lane (controls never own the device).
void worker_control(std::string key, SubmitCommand sc, std::string epoch)
{
    std::string err;
    auto store = open_store(&err);
    if (!store) {
        OBN_WARN("queue: control worker cannot open receipt store key=%s: %s",
                 key.c_str(), err.c_str());
        return;
    }
    json::Object rec;
    if (!store->get(key, &rec, &err)) {
        OBN_WARN("queue: control worker receipt missing key=%s: %s",
                 key.c_str(), err.c_str());
        return;
    }

    auto fail_pre = [&](const char* code, bool retryable, const char* what) {
        json::Object errv;
        errv["code"]      = json::Value(code);
        errv["retryable"] = json::Value(retryable);
        json::Object patch;
        patch["state"]    = json::Value("failed");
        patch["dispatch"] = json::Value("not_sent");
        patch["err"]      = json::Value(std::move(errv));
        receipt_update(store.get(), key, std::move(patch), what);
    };
    auto cancel_pre = [&](const char* what) {
        json::Object patch;
        patch["state"]    = json::Value("cancelled");
        patch["dispatch"] = json::Value("not_sent");
        receipt_update(store.get(), key, std::move(patch), what);
    };

    if (current_epoch() != epoch) {
        cancel_pre("session replaced before dispatch");
        return;
    }
    // Controls recheck expected_job_id at dispatch (contract): the job
    // may have failed/cancelled between acceptance and send.
    if (!binds_job(store.get(), sc.device_id, sc.expected_job_id)) {
        fail_pre("job_mismatch", false, "expected_job_id no longer binds a live job");
        return;
    }
    Agent* a = Agent::active_instance();
    if (!a || !a->user_session_snapshot().logged_in() || current_epoch() != epoch) {
        cancel_pre("session replaced before dispatch");
        return;
    }

    json::Object mark;
    mark["state"]    = json::Value("working");
    mark["dispatch"] = json::Value("may_have_been_sent");
    if (!receipt_update(store.get(), key, std::move(mark), "dispatch marker")) return;

    obn::json::Object po;
    po["sequence_id"] = obn::seq_json_value(obn::next_mqtt_seq_id());
    po["command"]     = json::Value(sc.kind);
    po["param"]       = json::Value("");
    obn::json::Object root;
    root["print"] = obn::json::Value(std::move(po));
    const int rc = a->send_message(sc.device_id,
                                   obn::json::Value(std::move(root)).dump(),
                                   /*qos=*/0);
    if (rc == BAMBU_NETWORK_SUCCESS) {
        json::Object patch;
        patch["state"]    = json::Value("succeeded");
        patch["dispatch"] = json::Value("confirmed");
        receipt_update(store.get(), key, std::move(patch), "control published");
    } else {
        // A QoS 0 publish can fail after the frame left: retain
        // uncertainty, never auto-retry a control.
        json::Object errv;
        errv["code"]      = json::Value("result_unknown");
        errv["retryable"] = json::Value(true);
        json::Object patch;
        patch["state"] = json::Value("unknown");
        patch["err"]   = json::Value(std::move(errv));
        receipt_update(store.get(), key, std::move(patch), "control publish failed");
    }
}

std::string op_command_submit(const json::Object& root, Meta& m)
{
    std::string client_id;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch", "params"},
            &client_id);
        !gate.empty())
        return gate;

    std::string err;
    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    if (!exact_keys(params.as_object(), {"submission_scope", "idempotency_key", "command"}, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& scope_v = gv(params.as_object(), "submission_scope");
    if (!bounded_string(scope_v, 1, 128))
        return error_env(m, "invalid_request",
                         "submission_scope must be a string of 1..128 bytes", false);
    const std::string scope = scope_v.as_string();

    const json::Value& key_v = gv(params.as_object(), "idempotency_key");
    if (!valid_idem_key(key_v))
        return error_env(m, "invalid_request",
                         "idempotency_key must be 16..128 chars of [A-Za-z0-9._:-]",
                         false);
    const std::string key = key_v.as_string();

    SubmitCommand sc;
    const char*    pcode = "invalid_request";
    if (!parse_command(gv(params.as_object(), "command"), &sc, &err, &pcode))
        return error_env(m, pcode, err, false);

    const std::string fp = command_fingerprint(sc.command);

    // Client lease + device existence (registry lock, released before
    // any store I/O).
    {
        Registry& r = reg();
        std::lock_guard<std::mutex> lk(r.mu);
        const auto  now  = Clock::now();
        std::string cerr;
        Client* c = find_client_locked(r, client_id, now, &cerr);
        if (!c) return error_env(m, "client_expired", cerr, false);
        c->deadline = now + std::chrono::seconds(c->lease_seconds);
        if (!known_device_locked(r, sc.device_id))
            return error_env(m, "invalid_request",
                             "unknown device_id: " + sc.device_id, false);
    }

    std::string serr;
    auto store = open_store(&serr);
    if (!store)
        return error_env(m, serr.c_str(),
                         serr == "signed_out"
                             ? "no authorized session for command submission"
                             : "receipt store unavailable; no actions accepted",
                         true);
    if (scope != store->scope())
        return error_env(m, "submission_scope_changed",
                         "submission_scope does not match the current store scope",
                         false);

    // Dedup first (contract): an existing key answers before the
    // printer-busy check and before any occupied-lane rejection.
    {
        json::Object rec;
        std::string  gerr;
        if (store->get(key, &rec, &gerr)) {
            auto fpit = rec.find("fp");
            const std::string stored =
                (fpit != rec.end() && fpit->second.is_string())
                    ? fpit->second.as_string() : std::string();
            if (stored != fp)
                return error_env(m, "idempotency_conflict",
                                 "idempotency_key reused with a different command payload",
                                 false);
            std::lock_guard<std::mutex> sub(g_submit_mu);
            if (sc.kind == "print" &&
                g_print_lanes.find(sc.device_id) == g_print_lanes.end())
                g_print_lanes[sc.device_id] = LaneEntry{key, false};
            return success_env(m, receipt_result(scope, rec));
        }
        if (gerr != "not_found")
            return error_env(m, "submission_store_unavailable",
                             "receipt store unavailable; no actions accepted", true);
    }

    // New key: a busy printer is rejected before reserving anything.
    if (sc.kind == "print") {
        const DeviceSnap snap = snapshot_device(sc.device_id);
        if (snap.have_frame && snap.busy)
            return error_env(m, "busy", "printer is busy with another job", true);
    }

    std::lock_guard<std::mutex> sub(g_submit_mu);

    // Re-check under the submit lock: another thread or process may
    // have reserved the same key while we were checking the printer.
    json::Object rec;
    std::string  gerr;
    if (store->get(key, &rec, &gerr)) {
        auto fpit = rec.find("fp");
        const std::string stored =
            (fpit != rec.end() && fpit->second.is_string())
                ? fpit->second.as_string() : std::string();
        if (stored != fp)
            return error_env(m, "idempotency_conflict",
                             "idempotency_key reused with a different command payload",
                             false);
        if (sc.kind == "print" &&
            g_print_lanes.find(sc.device_id) == g_print_lanes.end())
            g_print_lanes[sc.device_id] = LaneEntry{key, false};
        return success_env(m, receipt_result(scope, rec));
    }
    if (gerr != "not_found")
        return error_env(m, "submission_store_unavailable",
                         "receipt store unavailable; no actions accepted", true);

    if (sc.kind == "print") {
        const auto lane = g_print_lanes.find(sc.device_id);
        if (lane != g_print_lanes.end() && lane->second.key != key)
            return error_env(m, "busy", "printer already has a queued print", true);
    } else if (!binds_job(store.get(), sc.device_id, sc.expected_job_id)) {
        return error_env(m, "job_mismatch",
                         "expected_job_id does not match an active queued job", false);
    }

    json::Object extra;
    extra["dev"]  = json::Value(sc.device_id);
    extra["kind"] = json::Value(sc.kind);
    if (sc.kind != "print")
        extra["jid"] = json::Value(sc.expected_job_id);
    else
        extra["tag"] = json::Value(sc.task_tag);

    const ReceiptStore::Reservation rsv = store->reserve(key, fp, &extra);
    if (!rsv.ok) {
        if (rsv.error == "idempotency_conflict")
            return error_env(m, "idempotency_conflict",
                             "idempotency_key reused with a different command payload",
                             false);
        if (rsv.error == "capacity_exceeded")
            return error_env(m, "capacity_exceeded", "receipt store is full", false);
        if (rsv.error == "invalid_argument")
            return error_env(m, "invalid_request",
                             "invalid idempotency key or fingerprint", false);
        return error_env(m, "submission_store_unavailable",
                         "receipt store unavailable; no actions accepted", true);
    }
    if (rsv.replay) {
        // Raced with another submit for the same key: return the
        // original identity; dispatch stays with the original owner.
        json::Object rrec;
        if (!store->get(key, &rrec, &gerr))
            return error_env(m, "submission_store_unavailable",
                             "receipt store unavailable; no actions accepted", true);
        if (sc.kind == "print" &&
            g_print_lanes.find(sc.device_id) == g_print_lanes.end())
            g_print_lanes[sc.device_id] = LaneEntry{key, false};
        return success_env(m, receipt_result(scope, rrec));
    }
    if (sc.kind == "print") g_print_lanes[sc.device_id] = LaneEntry{key, false};

    const std::string epoch = m.epoch;
    if (dispatch_enabled()) {
        if (sc.kind == "print")
            std::thread(worker_print, key, sc, epoch).detach();
        else
            std::thread(worker_control, key, sc, epoch).detach();
    }

    json::Object frec;
    if (!store->get(key, &frec, &gerr))
        return error_env(m, "submission_store_unavailable",
                         "receipt store unavailable; no actions accepted", true);
    return success_env(m, receipt_result(scope, frec));
}

std::string op_command_get(const json::Object& root, Meta& m)
{
    std::string client_id;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch", "params"},
            &client_id);
        !gate.empty())
        return gate;

    std::string err;
    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    if (!exact_keys(params.as_object(), {"submission_scope", "idempotency_key"}, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& scope_v = gv(params.as_object(), "submission_scope");
    if (!bounded_string(scope_v, 1, 128))
        return error_env(m, "invalid_request",
                         "submission_scope must be a string of 1..128 bytes", false);
    const std::string scope = scope_v.as_string();
    const json::Value& key_v = gv(params.as_object(), "idempotency_key");
    if (!valid_idem_key(key_v))
        return error_env(m, "invalid_request",
                         "idempotency_key must be 16..128 chars of [A-Za-z0-9._:-]",
                         false);
    const std::string key = key_v.as_string();

    {
        Registry& r = reg();
        std::lock_guard<std::mutex> lk(r.mu);
        const auto  now  = Clock::now();
        std::string cerr;
        Client* c = find_client_locked(r, client_id, now, &cerr);
        if (!c) return error_env(m, "client_expired", cerr, false);
        c->deadline = now + std::chrono::seconds(c->lease_seconds);
    }

    std::string serr;
    auto store = open_store(&serr);
    if (!store)
        return error_env(m, serr.c_str(),
                         serr == "signed_out"
                             ? "no authorized session for receipt lookup"
                             : "receipt store unavailable",
                         true);
    if (scope != store->scope())
        return error_env(m, "submission_scope_changed",
                         "submission_scope does not match the current store scope",
                         false);

    json::Object rec;
    std::string  gerr;
    if (!store->get(key, &rec, &gerr)) {
        if (gerr == "not_found")
            return error_env(m, "not_found",
                             "no receipt for this idempotency key", false);
        return error_env(m, "submission_store_unavailable",
                         "receipt store unavailable", true);
    }
    return success_env(m, receipt_result(scope, rec));
}

std::string op_job_get(const json::Object& root, Meta& m)
{
    std::string client_id;
    if (const std::string gate = gate_client_fields(
            root, m, {"api", "request_id", "op", "client_id", "session_epoch", "params"},
            &client_id);
        !gate.empty())
        return gate;

    std::string err;
    const json::Value& params = gv(root, "params");
    if (!params.is_object())
        return error_env(m, "invalid_request", "params must be an object", false);
    if (!exact_keys(params.as_object(), {"submission_scope", "device_id", "job_id"}, err))
        return error_env(m, "invalid_request", err, false);

    const json::Value& scope_v = gv(params.as_object(), "submission_scope");
    if (!bounded_string(scope_v, 1, 128))
        return error_env(m, "invalid_request",
                         "submission_scope must be a string of 1..128 bytes", false);
    const std::string scope = scope_v.as_string();
    const json::Value& dev_v = gv(params.as_object(), "device_id");
    if (!valid_device_id(dev_v))
        return error_env(m, "invalid_request",
                         "device_id must be a string of 1..128 bytes", false);
    const std::string device_id = dev_v.as_string();
    const json::Value& job_v = gv(params.as_object(), "job_id");
    if (!bounded_string(job_v, 1, 128))
        return error_env(m, "invalid_request",
                         "job_id must be a string of 1..128 bytes", false);
    const std::string job_id = job_v.as_string();

    {
        Registry& r = reg();
        std::lock_guard<std::mutex> lk(r.mu);
        const auto  now  = Clock::now();
        std::string cerr;
        Client* c = find_client_locked(r, client_id, now, &cerr);
        if (!c) return error_env(m, "client_expired", cerr, false);
        c->deadline = now + std::chrono::seconds(c->lease_seconds);
    }

    std::string serr;
    auto store = open_store(&serr);
    if (!store)
        return error_env(m, serr.c_str(),
                         serr == "signed_out"
                             ? "no authorized session for job lookup"
                             : "receipt store unavailable",
                         true);
    if (scope != store->scope())
        return error_env(m, "submission_scope_changed",
                         "submission_scope does not match the current store scope",
                         false);

    json::Object rec;
    std::string  gerr;
    const bool found = store->find_if(
        [&](const json::Object& o) {
            return rec_str(o, "kind") == "print" &&
                   rec_str(o, "dev") == device_id &&
                   rec_str(o, "jid") == job_id;
        },
        &rec, &gerr);
    if (!found) {
        if (gerr == "not_found")
            return error_env(m, "not_found",
                             "no job for this device_id/job_id", false);
        return error_env(m, "submission_store_unavailable",
                         "receipt store unavailable", true);
    }
    return success_env(m, job_result(scope, rec, snapshot_device(device_id)));
}

std::string dispatch(const json::Object& root)
{
    Meta m;
    m.epoch = current_epoch();

    // Best-effort echo fields first so every later error can carry them.
    const json::Value& api_v = gv(root, "api");
    const json::Value& rid_v = gv(root, "request_id");
    const json::Value& op_v  = gv(root, "op");
    if (bounded_string(rid_v, 1, 128)) {
        m.request_id      = rid_v.as_string();
        m.has_request_id  = true;
    }
    if (op_v.is_string() && !op_v.as_string().empty() && op_v.as_string().size() <= 128) {
        m.op     = op_v.as_string();
        m.has_op = true;
    }

    if (!api_v.is_number())
        return error_env(m, "invalid_request", "api must be 1", false);
    if (api_v.as_number() != 1.0)
        return error_env(m, "unsupported_version", "only api version 1 is supported", false);
    if (!m.has_request_id)
        return error_env(m, "invalid_request", "request_id must be a string of 1..128 bytes", false);
    if (!m.has_op)
        return error_env(m, "invalid_request", "op must be a non-empty string", false);

    if (m.op == "capabilities")  return op_capabilities(root, m);
    if (m.op == "client.open")   return op_client_open(root, m);
    if (m.op == "client.close")  return op_client_close(root, m);
    if (m.op == "devices.list")  return op_devices_list(root, m);
    if (m.op == "watch.set")     return op_watch_set(root, m);
    if (m.op == "snapshot.get")  return op_snapshot_get(root, m);
    if (m.op == "events.poll")   return op_events_poll(root, m);
    if (m.op == "command.submit") return op_command_submit(root, m);
    if (m.op == "command.get")    return op_command_get(root, m);
    if (m.op == "job.get")        return op_job_get(root, m);
    return error_env(m, "not_supported", "unknown op: " + m.op, false);
}

std::string handle_request(const char* req, std::uint32_t len)
{
    Meta m;
    m.epoch = current_epoch();
    if (len > kMaxRequestBytes)
        return error_env(m, "invalid_request", "request exceeds max_request_bytes", false);
    if (std::memchr(req, 0, len) != nullptr)
        return error_env(m, "invalid_request", "embedded NUL in request", false);

    const std::string text(req, len);
    if (const std::string serr = scan_request(text); !serr.empty())
        return error_env(m, "invalid_request", serr, false);

    auto parsed = json::parse(text, nullptr);
    if (!parsed || !parsed->is_object())
        return error_env(m, "invalid_request", "request body must be a JSON object", false);
    return dispatch(parsed->as_object());
}

} // namespace (dispatch internals)

std::int32_t call_v1(const char* request_utf8, std::uint32_t request_bytes,
                     char** response_utf8, std::uint32_t* response_bytes)
{
    if (!request_utf8 || !response_utf8 || !response_bytes) return -1;
    *response_utf8  = nullptr;
    *response_bytes = 0;

    std::string resp;
    try {
        resp = handle_request(request_utf8, request_bytes);
    } catch (const std::bad_alloc&) {
        return -2;
    } catch (const std::exception& ex) {
        try {
            Meta m;
            m.epoch = current_epoch();
            resp    = error_env(m, "internal_error", ex.what(), false);
        } catch (...) {
            return -3;
        }
    } catch (...) {
        try {
            Meta m;
            m.epoch = current_epoch();
            resp    = error_env(m, "internal_error", "unexpected failure", false);
        } catch (...) {
            return -3;
        }
    }

    char* buf = static_cast<char*>(std::malloc(resp.size() + 1));
    if (!buf) return -2;
    std::memcpy(buf, resp.data(), resp.size());
    buf[resp.size()] = '\0';
    *response_utf8  = buf;
    *response_bytes = static_cast<std::uint32_t>(resp.size());
    return 0;
}

void free_v1(char* response_utf8)
{
    std::free(response_utf8);
}

#ifdef OBN_TESTING
void test_set_command_session(const std::string& user_id,
                              const std::string& config_dir)
{
    g_test_session       = auth::Session{};
    g_test_session.user_id      = user_id;
    g_test_session.access_token = "test-token"; // logged_in() checks both
    g_test_config_dir   = config_dir;
    g_test_session_set  = true;
}

void test_clear_command_session()
{
    g_test_session      = auth::Session{};
    g_test_config_dir.clear();
    g_test_session_set = false;
}

void test_set_dispatch_enabled(bool enabled)
{
    g_test_dispatch_on = enabled;
}

void test_set_none_gcode_override(const std::string& path)
{
    g_none_gcode_override = path;
}
#endif

} // namespace obn::queue

// Exports exactly as declared in obn_queue_api_v1.h (extern "C" comes from
// the header; dllexport from OBN_QUEUE_API_BUILD defined above it).
int32_t OBNQ_CALL obn_queue_call_v1(const char* request_utf8, uint32_t request_bytes,
                                    char** response_utf8, uint32_t* response_bytes)
{
    return obn::queue::call_v1(request_utf8, request_bytes, response_utf8, response_bytes);
}

void OBNQ_CALL obn_queue_free_v1(char* response_utf8)
{
    obn::queue::free_v1(response_utf8);
}
