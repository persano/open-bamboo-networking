#pragma once
// SPDX-License-Identifier: AGPL-3.0-or-later
// Durable command receipt store for the stage-3 queue contract
// (docs/queue-api-v1-stage3/README.md).
//
// One directory per authorized account, created under the host data
// directory that already holds obn.conf (config::dir()):
//   <config_dir>/queue_receipts/<user_id>/receipts.jsonl  append-only log
//   <config_dir>/queue_receipts/<user_id>/receipts.lock   cross-process lock
//   <config_dir>/queue_receipts/<user_id>/scope           submission scope
//
// receipts.jsonl holds one JSON object per line, UTF-8, '\n' terminated.
// The last line per idempotency key is that key's current receipt;
// earlier lines are its history. A trailing fragment without a newline
// is a torn append from a crashed writer: it is truncated on open. That
// is safe because a reservation only becomes durable once its complete
// line is on disk, so a torn line was never returned to a caller and
// dropping it cannot resurrect an action. A malformed COMPLETE line
// marks the store corrupt: reserve/update fail closed with
// submission_store_unavailable while get() keeps serving the lines that
// parse.
//
// The store never advances state, dispatches or redispatches on its
// own: every line after the reservation is appended by an explicit
// update() call, and compaction only rewrites existing lines. A receipt
// left at "accepted"/"not_sent" across a restart stays exactly that, so
// an uncertain dispatch can never become automatically replayable.
//
// Concurrency: every operation takes an exclusive cross-process lock on
// receipts.lock (and an in-process mutex) around read-check-append-
// flush, so duplicate detection and the durable reservation are atomic
// across instances and processes sharing the account directory.

#include "obn/json_lite.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace obn::queue {

class ReceiptStore {
public:
    // Distinct idempotency keys retained per account, advertised to
    // consumers as submission.max_retained_keys. Capacity is per account,
    // shared by every client and process: reopening a client does not
    // reset it. No automatic eviction; at the limit only NEW keys are
    // rejected, lookups, replays and updates of existing keys continue.
    static constexpr std::size_t kMaxKeys = 4096;

    // Opens, creating on first use, the store for one account. Returns
    // nullptr and sets *err when user_id is not a safe path component,
    // the directory cannot be created, an existing scope file is invalid
    // while receipts already exist (fail closed, no automatic scope
    // reset), or the log has a malformed complete line.
    static std::unique_ptr<ReceiptStore> open(const std::string& config_dir,
                                              const std::string& user_id,
                                              std::string* err = nullptr);

    struct Reservation {
        bool        ok     = false;
        std::string error;  // submission_store_unavailable | capacity_exceeded
                            // | idempotency_conflict | invalid_argument
        bool        replay = false; // key existed with the same fingerprint
        std::string command_id;     // allocated once, stable across replays
    };

    // Atomically dedups by idempotency_key under the store lock: an
    // existing key with the same fingerprint returns the original
    // identity (replay=true); a different fingerprint fails with
    // idempotency_conflict; a new key appends its durable reservation
    // (receipt + command id, flushed to stable storage) before returning.
    // If the flush fails the reservation may still exist on disk: the
    // error is not proof of rejection, and retrying the identical key is
    // the recovery path (replay or a fresh reservation).
    Reservation reserve(const std::string& idempotency_key,
                        const std::string& fingerprint);

    // Current receipt for the key (last line wins), copied into *out.
    // Fails with not_found for an unknown key or invalid_argument for a
    // bad key. Best-effort on a corrupt store: lines that parse are still
    // served. Read-only observation never reserves or changes anything.
    bool get(const std::string& idempotency_key, json::Object* out,
             std::string* error = nullptr);

    // Appends a full snapshot line for an existing key: patch fields are
    // merged over the current receipt (identity fields k/fp/cid must not
    // change) and the store stamps ts with the UTC observation time.
    // Fails with not_found for an unknown key, invalid_argument for a
    // bad patch or oversized line, submission_store_unavailable on a
    // corrupt store or failed flush. Recording dispatch evidence
    // (may_have_been_sent/confirmed) is the CALLER's decision at the
    // contract's dispatch boundary; this call itself never sends.
    bool update(const std::string& idempotency_key, const json::Object& patch,
                std::string* error = nullptr);

    // Opaque per-store deduplication namespace (contract submission.scope).
    const std::string& scope() const { return scope_; }
    // Distinct keys currently retained.
    std::size_t keys();

private:
    ReceiptStore() = default;

    // All of these run with the cross-process lock held (except scope_,
    // which is immutable after open()).
    void reload_locked();
    bool append_locked(const std::string& line, std::string* error);
    void maybe_compact_locked();
    std::string next_command_id_locked() const;

    std::string  dir_;   // account directory, native separators
    std::string  scope_; // immutable after open()
    std::mutex   mu_;

    // Cached log state, validated against the file size after every
    // reload: every content change happens under the lock we hold, so an
    // unchanged size means no other process wrote since our last op and
    // the cache can be reused (avoids reparsing the log on every call).
    std::map<std::string, json::Object> cache_;
    std::uintmax_t known_size_ = static_cast<std::uintmax_t>(-1);
    bool          corrupt_     = false;
    std::size_t   lines_       = 0;
};

} // namespace obn::queue
