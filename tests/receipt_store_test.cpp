// Stage-3 durable receipt store (docs/queue-api-v1-stage3/README.md):
// per-account append-only JSONL log, cross-process reservation atomicity,
// torn-line recovery, fail-closed corruption handling, capacity,
// compaction and scope rules. Files live under a temp directory that is
// wiped before and after the run.
//
// Framework: repo convention (main + fail_count + CHECK, as in
// queue_api_test.cpp).

#include "obn/receipt_store.hpp"
#include "obn/json_lite.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
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

namespace fs = std::filesystem;
namespace json = obn::json;
namespace rs   = obn::queue;

fs::path g_root;

std::string read_file(const fs::path& p)
{
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void append_raw(const fs::path& p, const std::string& bytes)
{
    std::ofstream out(p, std::ios::binary | std::ios::app);
    out << bytes;
}

std::size_t count_lines(const fs::path& p)
{
    const std::string data = read_file(p);
    std::size_t n = 0;
    for (char c : data)
        if (c == '\n') ++n;
    return n;
}

fs::path log_of(const std::string& user)
{
    return g_root / "queue_receipts" / user / "receipts.jsonl";
}

// ---------------------------------------------------------------------------
// open / scope
// ---------------------------------------------------------------------------

void test_open_creates_store_and_scope()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_open");
    CHECK(s != nullptr);
    if (!s) return;
    CHECK(!s->scope().empty());
    CHECK(s->keys() == 0);
    CHECK(fs::exists(g_root / "queue_receipts" / "u_open" / "scope"));
    CHECK(fs::exists(g_root / "queue_receipts" / "u_open" / "receipts.lock"));

    // Reopen: same scope, receipts persist.
    auto s2 = rs::ReceiptStore::open(g_root.string(), "u_open");
    CHECK(s2 != nullptr);
    if (s2) CHECK(s2->scope() == s->scope());

    // A different account gets its own namespace.
    auto s3 = rs::ReceiptStore::open(g_root.string(), "u_other");
    CHECK(s3 != nullptr);
    if (s3 && s2) CHECK(s3->scope() != s2->scope());
}

void test_user_id_validation()
{
    std::string err;
    CHECK(rs::ReceiptStore::open(g_root.string(), "", &err) == nullptr);
    CHECK(err == "invalid_argument");
    CHECK(rs::ReceiptStore::open(g_root.string(), "../evil", &err) == nullptr);
    CHECK(err == "invalid_argument");
    CHECK(rs::ReceiptStore::open(g_root.string(), "a/b", &err) == nullptr);
    CHECK(err == "invalid_argument");
}

void test_scope_missing_with_receipts_fails_closed()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_scope");
    CHECK(s != nullptr);
    if (!s) return;
    auto r = s->reserve("k1", "fp1");
    CHECK(r.ok);
    s.reset();

    fs::remove(g_root / "queue_receipts" / "u_scope" / "scope");
    std::string err;
    CHECK(rs::ReceiptStore::open(g_root.string(), "u_scope", &err) == nullptr);
    CHECK(err == "submission_store_unavailable");
}

void test_scope_regenerated_for_empty_store()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_scope_empty");
    CHECK(s != nullptr);
    if (!s) return;
    const std::string old_scope = s->scope();
    s.reset();

    // Never issued anything: a missing scope file may be recreated.
    fs::remove(g_root / "queue_receipts" / "u_scope_empty" / "scope");
    auto s2 = rs::ReceiptStore::open(g_root.string(), "u_scope_empty");
    CHECK(s2 != nullptr);
    if (s2) CHECK(!s2->scope().empty() && s2->scope() != old_scope);
}

// ---------------------------------------------------------------------------
// reserve / replay / conflict / get / update
// ---------------------------------------------------------------------------

void test_reserve_replay_conflict_get()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_basic");
    CHECK(s != nullptr);
    if (!s) return;

    auto r = s->reserve("key1", "fpA");
    CHECK(r.ok);
    CHECK(!r.replay);
    CHECK(r.command_id == "command-000001");
    CHECK(count_lines(log_of("u_basic")) == 1);

    json::Object got;
    std::string err;
    CHECK(s->get("key1", &got, &err));
    CHECK(got["k"].as_string() == "key1");
    CHECK(got["fp"].as_string() == "fpA");
    CHECK(got["cid"].as_string() == r.command_id);
    CHECK(got["state"].as_string() == "accepted");
    CHECK(got["dispatch"].as_string() == "not_sent");
    CHECK(!got["ts"].as_string().empty());

    // Identical intent: one identity, no second line.
    auto r2 = s->reserve("key1", "fpA");
    CHECK(r2.ok);
    CHECK(r2.replay);
    CHECK(r2.command_id == r.command_id);
    CHECK(count_lines(log_of("u_basic")) == 1);

    // Same key, different intent: rejected, nothing written.
    auto r3 = s->reserve("key1", "fpB");
    CHECK(!r3.ok);
    CHECK(r3.error == "idempotency_conflict");
    CHECK(count_lines(log_of("u_basic")) == 1);

    // Unknown key lookups.
    CHECK(!s->get("nope", &got, &err));
    CHECK(err == "not_found");

    // Invalid arguments.
    CHECK(!s->reserve("", "fp").ok);
    CHECK(s->reserve("", "fp").error == "invalid_argument");
}

void test_update_merges_and_stamps()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_update");
    CHECK(s != nullptr);
    if (!s) return;
    auto r = s->reserve("key1", "fpA");
    CHECK(r.ok);

    json::Object patch;
    patch["state"]    = "working";
    patch["dispatch"] = "may_have_been_sent";
    patch["job_id"]   = "job-001";
    std::string err;
    CHECK(s->update("key1", patch, &err));
    CHECK(count_lines(log_of("u_update")) == 2);

    json::Object got;
    CHECK(s->get("key1", &got, &err));
    CHECK(got["state"].as_string() == "working");
    CHECK(got["dispatch"].as_string() == "may_have_been_sent");
    CHECK(got["job_id"].as_string() == "job-001");
    CHECK(got["cid"].as_string() == r.command_id); // identity untouched
    CHECK(!got["ts"].as_string().empty());

    // Identity fields are immutable.
    json::Object evil;
    evil["cid"] = "command-999999";
    CHECK(!s->update("key1", evil, &err));
    CHECK(err == "invalid_argument");

    // Unknown key.
    json::Object any;
    any["state"] = "working";
    CHECK(!s->update("nope", any, &err));
    CHECK(err == "not_found");
}

// ---------------------------------------------------------------------------
// durability: torn line, corruption, scope
// ---------------------------------------------------------------------------

void test_torn_line_truncated_on_open()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_torn");
    CHECK(s != nullptr);
    if (!s) return;
    auto r = s->reserve("key1", "fpA");
    CHECK(r.ok);
    s.reset();

    // A writer crashed mid-append: complete JSON, no trailing newline.
    append_raw(log_of("u_torn"), "{\"k\":\"zz\",\"fp\":\"fpZ\",\"cid\":\"command-000002\"");
    const std::string with_torn = read_file(log_of("u_torn"));
    CHECK(with_torn.find("\"zz\"") != std::string::npos);

    auto s2 = rs::ReceiptStore::open(g_root.string(), "u_torn");
    CHECK(s2 != nullptr);
    if (!s2) return;
    // Torn tail gone, complete receipts intact.
    const std::string after = read_file(log_of("u_torn"));
    CHECK(after.find("\"zz\"") == std::string::npos);
    CHECK(after.find("\"key1\"") != std::string::npos);

    json::Object got;
    std::string err;
    CHECK(s2->get("key1", &got, &err));
    // The dropped fragment never became a reservation: zz is a new key.
    auto rz = s2->reserve("zz", "fpZ");
    CHECK(rz.ok);
    CHECK(!rz.replay);
}

void test_corrupt_line_fails_closed_but_reads_survive()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_corrupt");
    CHECK(s != nullptr);
    if (!s) return;
    auto r = s->reserve("key1", "fpA");
    CHECK(r.ok);
    s.reset();

    append_raw(log_of("u_corrupt"), "garbage not json\n");

    auto s2 = rs::ReceiptStore::open(g_root.string(), "u_corrupt");
    CHECK(s2 != nullptr);
    if (!s2) return;

    // Reservations and updates are refused...
    auto r2 = s2->reserve("key2", "fpB");
    CHECK(!r2.ok);
    CHECK(r2.error == "submission_store_unavailable");
    json::Object patch;
    patch["state"] = "working";
    std::string err;
    CHECK(!s2->update("key1", patch, &err));
    CHECK(err == "submission_store_unavailable");

    // ...but observation keeps serving what parses.
    json::Object got;
    CHECK(s2->get("key1", &got, &err));
    CHECK(got["cid"].as_string() == r.command_id);
}

// ---------------------------------------------------------------------------
// capacity, compaction, concurrency
// ---------------------------------------------------------------------------

void test_capacity_is_per_account()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_cap");
    CHECK(s != nullptr);
    if (!s) return;

    for (std::size_t i = 0; i < rs::ReceiptStore::kMaxKeys; ++i) {
        auto r = s->reserve("k" + std::to_string(i), "fp");
        if (!r.ok) {
            std::fprintf(stderr, "FAIL capacity: key %zu rejected: %s\n", i,
                         r.error.c_str());
            ++fail_count;
            break;
        }
    }
    CHECK(s->keys() == rs::ReceiptStore::kMaxKeys);

    // New keys are refused at the limit...
    auto over = s->reserve("one-too-many", "fp");
    CHECK(!over.ok);
    CHECK(over.error == "capacity_exceeded");

    // ...existing keys keep replaying and updating (no eviction).
    auto replay = s->reserve("k0", "fp");
    CHECK(replay.ok);
    CHECK(replay.replay);
    json::Object patch;
    patch["state"] = "working";
    std::string err;
    CHECK(s->update("k0", patch, &err));
    json::Object got;
    CHECK(s->get("k" + std::to_string(rs::ReceiptStore::kMaxKeys - 1), &got, &err));

    // Capacity is per account: a second account starts empty.
    auto other = rs::ReceiptStore::open(g_root.string(), "u_cap2");
    CHECK(other != nullptr);
    if (other) CHECK(other->keys() == 0);
}

void test_compaction_preserves_last_state()
{
    auto s = rs::ReceiptStore::open(g_root.string(), "u_compact");
    CHECK(s != nullptr);
    if (!s) return;
    auto r = s->reserve("key1", "fpA");
    CHECK(r.ok);

    const char* last_state = nullptr;
    for (int i = 0; i < 40; ++i) {
        json::Object patch;
        last_state = (i % 2) ? "working" : "accepted";
        patch["state"] = last_state;
        patch["seq"]   = static_cast<double>(i);
        std::string err;
        CHECK(s->update("key1", patch, &err));
    }

    // Replayed transitions doubled the log past live content, so it must
    // have compacted down to roughly one line per key.
    const std::size_t lines = count_lines(log_of("u_compact"));
    CHECK(lines >= 1 && lines <= 32);

    // The last state survived compaction, on disk and after reopen.
    json::Object got;
    std::string err;
    CHECK(s->get("key1", &got, &err));
    CHECK(got["state"].as_string() == last_state);
    s.reset();

    auto s2 = rs::ReceiptStore::open(g_root.string(), "u_compact");
    CHECK(s2 != nullptr);
    if (s2) {
        json::Object got2;
        CHECK(s2->get("key1", &got2, &err));
        CHECK(got2["state"].as_string() == last_state);
        CHECK(got2["seq"].as_number() == 39.0);
    }
}

void test_concurrent_instances_one_identity()
{
    // Two store objects on one directory from concurrent threads stand
    // in for two Orca processes: the cross-process lock must make the
    // read-check-append-flush of one reservation atomic across both.
    constexpr int kThreads = 8;
    auto a = rs::ReceiptStore::open(g_root.string(), "u_conc");
    auto b = rs::ReceiptStore::open(g_root.string(), "u_conc");
    CHECK(a != nullptr && b != nullptr);
    if (!a || !b) return;

    std::vector<std::string> cids(kThreads);
    std::vector<bool>       oks(kThreads, false);
    std::vector<bool>       replays(kThreads, false);
    std::vector<std::thread> pool;
    for (int i = 0; i < kThreads; ++i) {
        pool.emplace_back([&, i] {
            auto* store = (i % 2) ? b.get() : a.get();
            auto  r     = store->reserve("shared", "fp-shared");
            oks[i]      = r.ok;
            replays[i]  = r.replay;
            cids[i]     = r.command_id;
        });
    }
    for (auto& t : pool) t.join();

    int ok_count = 0;
    int first_count = 0;
    std::string first_cid;
    for (int i = 0; i < kThreads; ++i) {
        CHECK(oks[i]);
        if (oks[i]) ++ok_count;
        if (oks[i] && !replays[i]) {
            ++first_count;
            first_cid = cids[i];
        }
    }
    CHECK(ok_count == kThreads);
    CHECK(first_count == 1);      // exactly one reservation created it
    CHECK(!first_cid.empty());
    CHECK(count_lines(log_of("u_conc")) == 1);

    json::Object got;
    std::string err;
    CHECK(a->get("shared", &got, &err));
    CHECK(got["cid"].as_string() == first_cid);
}

} // namespace

int main()
{
    g_root = fs::temp_directory_path() / "obn_receipt_store_test";
    std::error_code ec;
    fs::remove_all(g_root, ec);
    fs::create_directories(g_root, ec);

    test_open_creates_store_and_scope();
    test_user_id_validation();
    test_scope_missing_with_receipts_fails_closed();
    test_scope_regenerated_for_empty_store();
    test_reserve_replay_conflict_get();
    test_update_merges_and_stamps();
    test_torn_line_truncated_on_open();
    test_corrupt_line_fails_closed_but_reads_survive();
    test_capacity_is_per_account();
    test_compaction_preserves_last_state();
    test_concurrent_instances_one_identity();

    fs::remove_all(g_root, ec);
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stderr, "receipt_store_test: ok\n");
    return 0;
}
