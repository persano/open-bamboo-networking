// SPDX-License-Identifier: AGPL-3.0-or-later
// Durable command receipt store: append-only JSON Lines, one directory
// per account, exclusive lock across processes around every
// read-check-append-flush. Design and guarantees: include/obn/receipt_store.hpp.

#include "obn/receipt_store.hpp"

#include "obn/log.hpp"
#include "obn/os_compat.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace obn::queue {

namespace {

namespace fs = std::filesystem;
namespace json = obn::json;

constexpr const char* kLogName    = "receipts.jsonl";
constexpr const char* kLockName   = "receipts.lock";
constexpr const char* kScopeName  = "scope";
constexpr std::size_t kMaxKeyLen  = 256;
constexpr std::size_t kMaxFpLen   = 1024;
constexpr std::size_t kMaxLineLen = 64 * 1024;

std::string utc_stamp()
{
    const auto t = std::time(nullptr);
    std::tm    tm{};
    obn::os::gmtime_safe(t, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                  tm.tm_min, tm.tm_sec);
    return buf;
}

// Opaque, UUID-shaped, generated once per store. Not a secret: it only
// namespaces deduplication (contract submission.scope).
std::string make_scope()
{
    std::random_device rd;
    const std::uint64_t a =
        (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    const std::uint64_t b =
        (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    char buf[40];
    std::snprintf(buf, sizeof(buf),
                  "%08x-%04x-4%03x-8%03x-%012llx",
                  static_cast<unsigned>(a & 0xffffffffu),
                  static_cast<unsigned>((a >> 32) & 0xffffu),
                  static_cast<unsigned>((b >> 16) & 0x0fffu),
                  static_cast<unsigned>(b & 0x0fffu),
                  static_cast<unsigned long long>(b >> 20 & 0xffffffffffffull));
    return buf;
}

// fflush + fsync: the bytes must be on stable storage before the caller
// is told the reservation exists.
bool durable_flush(std::FILE* f)
{
    if (std::fflush(f) != 0) return false;
#ifdef _WIN32
    if (_commit(_fileno(f)) != 0) return false;
#else
    if (fsync(fileno(f)) != 0) return false;
#endif
    return true;
}

// Exclusive cross-process lock, blocking. Opened with share modes that
// allow concurrent opens: exclusion comes from the lock itself, so a
// second holder waits instead of failing on a sharing violation.
class FileLock {
public:
    explicit FileLock(const fs::path& path)
    {
#ifdef _WIN32
        h_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) {
            h_ = nullptr;
            return;
        }
        OVERLAPPED ov{};
        // No LOCKFILE_FAIL_IMMEDIATELY: block until the peer releases.
        if (!LockFileEx(h_, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD,
                        &ov)) {
            CloseHandle(h_);
            h_ = nullptr;
        }
#else
        fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
        if (fd_ < 0) return;
        if (::flock(fd_, LOCK_EX) != 0) {
            ::close(fd_);
            fd_ = -1;
        }
#endif
    }
    ~FileLock() { release(); }
    FileLock(const FileLock&)            = delete;
    FileLock& operator=(const FileLock&) = delete;

    bool held() const
    {
#ifdef _WIN32
        return h_ != nullptr;
#else
        return fd_ >= 0;
#endif
    }

private:
    void release()
    {
#ifdef _WIN32
        if (h_) {
            OVERLAPPED ov{};
            UnlockFileEx(h_, 0, MAXDWORD, MAXDWORD, &ov);
            CloseHandle(h_);
            h_ = nullptr;
        }
#else
        if (fd_ >= 0) {
            ::flock(fd_, LOCK_UN);
            ::close(fd_);
            fd_ = -1;
        }
#endif
    }
#ifdef _WIN32
    HANDLE h_ = nullptr;
#else
    int fd_ = -1;
#endif
};

bool valid_user_id(const std::string& id)
{
    if (id.empty() || id.size() > 128) return false;
    for (char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool valid_key(const std::string& k)
{
    return !k.empty() && k.size() <= kMaxKeyLen;
}

} // namespace

// ---------------------------------------------------------------------------
// open
// ---------------------------------------------------------------------------

std::unique_ptr<ReceiptStore> ReceiptStore::open(const std::string& config_dir,
                                                 const std::string& user_id,
                                                 std::string* err)
{
    auto fail = [err](const char* e) {
        if (err) *err = e;
        return std::unique_ptr<ReceiptStore>{};
    };
    if (config_dir.empty()) return fail("invalid_argument");
    if (!valid_user_id(user_id)) return fail("invalid_argument");

    auto store             = std::unique_ptr<ReceiptStore>(new ReceiptStore());
    store->dir_            = (fs::path(config_dir) / "queue_receipts" / user_id).string();

    std::error_code ec;
    fs::create_directories(store->dir_, ec);
    if (ec && !fs::is_directory(store->dir_)) return fail("submission_store_unavailable");

    const fs::path log_path  = fs::path(store->dir_) / kLogName;
    const fs::path lock_path = fs::path(store->dir_) / kLockName;
    const fs::path scope_path = fs::path(store->dir_) / kScopeName;

    FileLock lock(lock_path);
    if (!lock.held()) return fail("submission_store_unavailable");

    // Load (and truncate any torn tail) before touching the scope: the
    // decision whether an invalid scope may be regenerated depends on
    // whether receipts already exist.
    store->reload_locked();

    std::string scope;
    {
        std::ifstream in(scope_path, std::ios::binary);
        if (in) {
            std::getline(in, scope);
            if (scope.empty() || scope.size() > 128) scope.clear();
        }
    }
    if (scope.empty()) {
        std::error_code ec2;
        const bool receipts_exist =
            fs::exists(log_path, ec2) && fs::file_size(log_path, ec2) > 0;
        if (receipts_exist) {
            // Receipts exist but the scope that issued them is gone or
            // invalid: fail closed, never silently mint a new namespace
            // (contract: no automatic scope reset).
            OBN_ERROR("receipt_store: scope missing/invalid with existing receipts in %s; refusing to open",
                      store->dir_.c_str());
            return fail("submission_store_unavailable");
        }
        scope = make_scope();
        const fs::path tmp = fs::path(store->dir_) / "scope.tmp";
        std::FILE* f = std::fopen(tmp.string().c_str(), "wb");
        if (!f) return fail("submission_store_unavailable");
        const bool wrote = std::fwrite(scope.data(), 1, scope.size(), f) == scope.size() &&
                           durable_flush(f);
        std::fclose(f);
        if (!wrote) return fail("submission_store_unavailable");
        fs::rename(tmp, scope_path, ec);
        if (ec) return fail("submission_store_unavailable");
        OBN_INFO("receipt_store: created scope %s for %s", scope.c_str(),
                 store->dir_.c_str());
    }
    store->scope_ = scope;
    return store;
}

// ---------------------------------------------------------------------------
// log loading
// ---------------------------------------------------------------------------

void ReceiptStore::reload_locked()
{
    const fs::path path = fs::path(dir_) / kLogName;
    std::error_code ec;
    const std::uintmax_t size = fs::exists(path, ec) ? fs::file_size(path, ec) : 0;
    if (ec) {
        // Unreadable file: treat as absent-but-poisoned so reserve fails
        // closed while the object still exists for diagnostics.
        corrupt_ = true;
        known_size_ = static_cast<std::uintmax_t>(-1);
        return;
    }
    if (known_size_ != static_cast<std::uintmax_t>(-1) && size == known_size_) {
        return; // no writer touched the log since our last op
    }

    std::string data;
    {
        std::ifstream in(path, std::ios::binary);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            data = ss.str();
        }
    }

    bool corrupt = false;

    // A trailing fragment with no newline is a torn append: drop it.
    // Safe because a complete line is the unit of durability. If the
    // file cannot be truncated the store is poisoned instead: appending
    // after a torn tail would glue the next reservation onto it.
    if (!data.empty() && data.back() != '\n') {
        const std::size_t cut = data.rfind('\n');
        const std::size_t keep = (cut == std::string::npos) ? 0 : cut + 1;
        OBN_WARN("receipt_store: truncating torn trailing line in %s (%zu -> %zu bytes)",
                 path.string().c_str(), data.size(), keep);
        data.resize(keep);
        std::FILE* f = std::fopen(path.string().c_str(), "r+b");
        bool truncated = false;
        if (f) {
#ifdef _WIN32
            const int r = _chsize_s(_fileno(f), static_cast<__int64>(keep));
#else
            const int r = ftruncate(fileno(f), static_cast<off_t>(keep));
#endif
            truncated = (r == 0);
            std::fclose(f);
        }
        if (!truncated) {
            OBN_ERROR("receipt_store: cannot truncate torn line in %s",
                      path.string().c_str());
            corrupt = true;
        }
    }

    std::map<std::string, json::Object> next;
    std::size_t lines = 0;
    std::size_t start = 0;
    while (start < data.size()) {
        const std::size_t nl = data.find('\n', start);
        const std::size_t end = (nl == std::string::npos) ? data.size() : nl;
        const std::string line = data.substr(start, end - start);
        start = end + 1;

        if (line.empty()) {
            corrupt = true; // blank line: malformed complete record
            continue;
        }
        std::string perr;
        auto parsed = json::parse(line, &perr);
        if (!parsed || !parsed->is_object()) {
            corrupt = true;
            continue;
        }
        json::Object obj = parsed->as_object();
        auto it = obj.find("k");
        if (it == obj.end() || !it->second.is_string() ||
            it->second.as_string().empty()) {
            corrupt = true;
            continue;
        }
        next[it->second.as_string()] = std::move(obj);
        ++lines;
    }

    cache_      = std::move(next);
    lines_      = lines;
    corrupt_    = corrupt;
    known_size_ = data.size();
    if (corrupt)
        OBN_ERROR("receipt_store: malformed complete line(s) in %s; reservations disabled",
                  path.string().c_str());
}

bool ReceiptStore::append_locked(const std::string& line, std::string* error)
{
    const fs::path path = fs::path(dir_) / kLogName;
    std::FILE* f = std::fopen(path.string().c_str(), "ab");
    if (!f) {
        if (error) *error = "submission_store_unavailable";
        return false;
    }
    const bool wrote =
        std::fwrite(line.data(), 1, line.size(), f) == line.size() &&
        durable_flush(f);
    const bool closed = std::fclose(f) == 0;
    if (!wrote || !closed) {
        // Not proof the reservation was rejected: the bytes may be on
        // disk. The caller recovers with the identical key.
        if (error) *error = "submission_store_unavailable";
        return false;
    }
    known_size_ += line.size();
    ++lines_;
    return true;
}

std::string ReceiptStore::next_command_id_locked() const
{
    unsigned long long max_id = 0;
    for (const auto& kv : cache_) {
        auto it = kv.second.find("cid");
        if (it == kv.second.end() || !it->second.is_string()) continue;
        const std::string& cid = it->second.as_string();
        unsigned long long id = 0;
        if (std::sscanf(cid.c_str(), "command-%llu", &id) == 1 && id > max_id)
            max_id = id;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "command-%06llu", max_id + 1);
    return buf;
}

void ReceiptStore::maybe_compact_locked()
{
    // Rewrites only when replayed transitions have doubled the log past
    // its live content. Crash-safe: full tmp file, fsync, atomic replace
    // of the old log, so a crash mid-compaction can neither lose keys nor
    // leave a fresh-looking store.
    if (lines_ <= cache_.size() * 2 + 16) return;

    const fs::path path  = fs::path(dir_) / kLogName;
    const fs::path tmp   = fs::path(dir_) / "receipts.jsonl.tmp";
    std::FILE* f = std::fopen(tmp.string().c_str(), "wb");
    if (!f) {
        OBN_WARN("receipt_store: compaction skipped, cannot write %s",
                 tmp.string().c_str());
        return;
    }
    std::string blob;
    for (const auto& kv : cache_) {
        blob += json::Value(kv.second).dump();
        blob += '\n';
    }
    const bool wrote =
        std::fwrite(blob.data(), 1, blob.size(), f) == blob.size() &&
        durable_flush(f);
    std::fclose(f);
    if (!wrote) {
        OBN_WARN("receipt_store: compaction failed writing %s", tmp.string().c_str());
        std::error_code ec;
        fs::remove(tmp, ec);
        return;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec); // replaces the existing log atomically
    if (ec) {
        OBN_WARN("receipt_store: compaction rename failed: %s", ec.message().c_str());
        fs::remove(tmp, ec);
        return;
    }
    lines_ = cache_.size();
    known_size_ = fs::file_size(path, ec);
    if (ec) known_size_ = static_cast<std::uintmax_t>(-1);
    OBN_DEBUG("receipt_store: compacted %s to %zu lines", path.string().c_str(),
              lines_);
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

ReceiptStore::Reservation ReceiptStore::reserve(const std::string& idempotency_key,
                                                const std::string& fingerprint,
                                                const json::Object* extra)
{
    Reservation r;
    if (!valid_key(idempotency_key) || fingerprint.empty() ||
        fingerprint.size() > kMaxFpLen) {
        r.error = "invalid_argument";
        return r;
    }

    std::lock_guard<std::mutex> lk(mu_);
    const fs::path lock_path = fs::path(dir_) / kLockName;
    FileLock lock(lock_path);
    if (!lock.held()) {
        r.error = "submission_store_unavailable";
        return r;
    }
    reload_locked();
    if (corrupt_) {
        r.error = "submission_store_unavailable";
        return r;
    }

    auto it = cache_.find(idempotency_key);
    if (it != cache_.end()) {
        auto fp = it->second.find("fp");
        const std::string stored_fp =
            (fp != it->second.end() && fp->second.is_string())
                ? fp->second.as_string()
                : std::string();
        if (stored_fp != fingerprint) {
            r.error = "idempotency_conflict";
            return r;
        }
        auto cid = it->second.find("cid");
        if (cid == it->second.end() || !cid->second.is_string() ||
            cid->second.as_string().empty()) {
            r.error = "submission_store_unavailable"; // identity missing: corrupt
            return r;
        }
        r.ok       = true;
        r.replay   = true;
        r.command_id = cid->second.as_string();
        return r;
    }

    if (cache_.size() >= kMaxKeys) {
        r.error = "capacity_exceeded";
        return r;
    }

    json::Object obj;
    obj["k"]        = idempotency_key;
    obj["fp"]       = fingerprint;
    obj["cid"]      = next_command_id_locked();
    // Job ID shares the command counter so receipt + command + job
    // identity land on one durable line (stage-3 contract rule 3).
    obj["jid"]      = "job-" + obj["cid"].as_string().substr(std::strlen("command-"));
    obj["state"]    = "accepted";
    obj["dispatch"] = "not_sent";
    const std::string stamp = utc_stamp();
    obj["ts"]       = stamp;
    obj["acc"]      = stamp; // accepted_at; preserved by later updates
    if (extra) {
        for (const auto& kv : *extra) {
            if (kv.first == "k" || kv.first == "fp" || kv.first == "cid") continue;
            obj[kv.first] = kv.second;
        }
    }
    const std::string line = json::Value(obj).dump() + "\n";

    std::string err;
    if (!append_locked(line, &err)) {
        r.error = err;
        return r;
    }
    cache_[idempotency_key] = std::move(obj);
    maybe_compact_locked();

    r.ok         = true;
    r.command_id = cache_[idempotency_key]["cid"].as_string();
    return r;
}

bool ReceiptStore::get(const std::string& idempotency_key, json::Object* out,
                       std::string* error)
{
    if (!out || !valid_key(idempotency_key)) {
        if (error) *error = "invalid_argument";
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    const fs::path lock_path = fs::path(dir_) / kLockName;
    FileLock lock(lock_path);
    if (!lock.held()) {
        if (error) *error = "submission_store_unavailable";
        return false;
    }
    reload_locked();
    auto it = cache_.find(idempotency_key);
    if (it == cache_.end()) {
        if (error) *error = "not_found";
        return false;
    }
    *out = it->second;
    return true;
}

bool ReceiptStore::find_if(const std::function<bool(const json::Object&)>& pred,
                           json::Object* out, std::string* error)
{
    if (!out || !pred) {
        if (error) *error = "invalid_argument";
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    const fs::path lock_path = fs::path(dir_) / kLockName;
    FileLock lock(lock_path);
    if (!lock.held()) {
        if (error) *error = "submission_store_unavailable";
        return false;
    }
    reload_locked();
    for (const auto& kv : cache_) {
        if (pred(kv.second)) {
            *out = kv.second;
            return true;
        }
    }
    if (error) *error = "not_found";
    return false;
}

bool ReceiptStore::update(const std::string& idempotency_key,
                          const json::Object& patch, std::string* error)
{
    if (!valid_key(idempotency_key)) {
        if (error) *error = "invalid_argument";
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    const fs::path lock_path = fs::path(dir_) / kLockName;
    FileLock lock(lock_path);
    if (!lock.held()) {
        if (error) *error = "submission_store_unavailable";
        return false;
    }
    reload_locked();
    if (corrupt_) {
        if (error) *error = "submission_store_unavailable";
        return false;
    }
    auto it = cache_.find(idempotency_key);
    if (it == cache_.end()) {
        if (error) *error = "not_found";
        return false;
    }

    json::Object merged = it->second;
    for (const auto& kv : patch) {
        if (kv.first == "k" || kv.first == "fp" || kv.first == "cid") {
            auto cur = merged.find(kv.first);
            if (cur == merged.end() || cur->second.dump() != kv.second.dump()) {
                if (error) *error = "invalid_argument"; // identity is immutable
                return false;
            }
            continue;
        }
        merged[kv.first] = kv.second;
    }
    if (merged.find("acc") == merged.end()) {
        // accepted_at: keep the reservation's timestamp across updates.
        auto old = it->second.find("ts");
        if (old != it->second.end()) merged["acc"] = old->second;
    }
    merged["ts"] = utc_stamp(); // native observation time of this transition
    const std::string line = json::Value(merged).dump() + "\n";
    if (line.size() > kMaxLineLen) {
        if (error) *error = "invalid_argument";
        return false;
    }

    std::string err;
    if (!append_locked(line, &err)) {
        if (error) *error = err;
        return false;
    }
    it->second = std::move(merged);
    maybe_compact_locked();
    return true;
}

std::size_t ReceiptStore::keys()
{
    std::lock_guard<std::mutex> lk(mu_);
    const fs::path lock_path = fs::path(dir_) / kLockName;
    FileLock lock(lock_path);
    if (!lock.held()) return cache_.size();
    reload_locked();
    return cache_.size();
}

} // namespace obn::queue
