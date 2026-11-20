// Versioned queue integration API (stage 2): capability discovery,
// read-only multi-printer snapshots and polled events behind the two C
// exports declared in include/obn/obn_queue_api_v1.h.
// Design: persano/open-bambu-networking-plugin issue #16.

#define OBN_QUEUE_API_BUILD
#include "obn/obn_queue_api_v1.h"

#include "obn/queue_api.hpp"

#include "obn/agent.hpp"
#include "obn/auth.hpp"
#include "obn/json_lite.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <initializer_list>
#include <map>
#include <mutex>
#include <new>
#include <random>
#include <string>
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
constexpr char        kCapRev[]            = "c1";

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

json::Value capabilities_result()
{
    json::Object res;

    json::Array api_versions;
    api_versions.push_back(json::Value(1.0));
    res["api_versions"] = json::Value(std::move(api_versions));

    json::Array ops;
    for (const char* o : {"capabilities", "client.open", "client.close", "devices.list",
                          "watch.set", "snapshot.get", "events.poll"})
        ops.push_back(json::Value(o));
    res["operations"] = json::Value(std::move(ops));

    res["command_kinds"] = json::Value(json::Array{});

    json::Array features;
    features.push_back(json::Value("multi_printer"));
    features.push_back(json::Value("event_polling"));
    res["features"] = json::Value(std::move(features));

    json::Object limits;
    limits["max_devices_per_client"]       = json::Value(static_cast<double>(kMaxDevicesPerClient));
    limits["max_clients"]                  = json::Value(static_cast<double>(kMaxClients));
    limits["max_pending_commands"]         = json::Value(8.0);
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
