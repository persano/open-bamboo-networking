# Stage 3: asynchronous commands and correlated jobs (draft for review)

**Contract and tests only. Nothing here enables commands or changes printer behavior.**

Target repository: `persano/open-bamboo-networking`, branch `option-b-cloud-rescue`.
Reviewed base: `08f9b2fa0fbab03f51950cd0e57d91065a944900` (2026-11-21).
The author owns the native implementation; Orca Plate Queue owns its consumer and
A1/P1S hardware acceptance. This proposal is not a claim that stage 3 is shipped.

## Changes and compatibility

Keep both C exports and all seven stage-2 operations unchanged. The header change
is comments only. Add capability-gated `command.submit`, `command.get`, `job.get`;
command kinds are `print`, `pause`, `resume`, `stop`, `skip_objects`. A stage-2
library still advertises an empty `command_kinds` and rejects unsupported operations.
Do not change current default capabilities, source files, build configuration, or
Orca callbacks in this PR.

The JSON schemas in this directory validate **only stage-3 operations and additive
fragments**, not the entire stage-2 API. Keep stage-2 validation/tests as they are.
No stage-2 field is removed or redefined. Response readers accept additive fields
and unknown event kinds; unknown states never imply success. Requests reject
unrecognized fields. The existing 64 KiB request, UTF-8/NUL/duplicate-key/depth
validation and originating-module buffer ownership still apply.

`capability-additions.schema.json` describes additional fields in the capabilities
result; `printer-additions.schema.json` describes additions to printer snapshots.
Use existing `operations`, `command_kinds`, `features`, and `limits` alongside
these additions. Check global AND per-printer command support before submitting.
Advertise print options and supply modes separately; unsupported settings must
fail before dispatch, never be silently ignored. Existing limits stay intact;
new durable storage capacity is `submission.max_retained_keys`.

No new DLL, listener, login, exposed credentials/tokens, or replacement host
callback. No changes to LAN/cloud mode or AMS refill configuration.

## Identifiers: RPCs, commands and print jobs

| Field | Meaning |
|---|---|
| `request_id` | Correlates one request/response exchange; may change on retry. |
| `idempotency_key` | Consumer-generated persistent key for one intended action. |
| `command_id` | Native receipt ID allocated once when that action is accepted. |
| `job_id` | Native correlated print-job ID; allocated at print acceptance, before upload. |
| `job_key` | Existing stage-2 printer identity; retain its meaning and nullable behavior. |
| `submission_scope` | Opaque native-issued durable deduplication namespace, not a credential. |

Every accepted submit, including a replay, returns the same receipt and `job_id`.
Print controls refer to the target `expected_job_id`; their receipts return that
same job ID, not a newly invented print job. For external/Orca-started jobs,
controls are allowed only if native code can assign and reliably bind a job ID;
otherwise reject `job_mismatch`. Do not use filenames, percentages, a previous
job's terminal state, or temperatures as identity.

## Uncertain outcomes and idempotency (decision requested)

The original draft used `request_id` and client/session lifetime for deduplication.
That is insufficient for a retry after client expiry or Orca restart. This draft
proposes a **durable at-most-once dispatch** guarantee, not exactly-once printing.
Please confirm this persistence scope before native implementation.

1. The consumer journals the scope, key, device, complete immutable intent and
   file hash **before** submit. Every submit, including controls, requires a key.
2. Native code deduplicates by `(submission_scope, idempotency_key)` independently
   of `client_id`, `request_id`, `session_epoch`, or `instance_id`. Device and all
   command payload fields are part of the canonical fingerprint. JSON member order
   and whitespace are irrelevant; array order and values are significant. Reuse
   with any changed device/path/hash/mapping/options returns `idempotency_conflict`.
3. Atomically reserve durable receipt + command ID + print job ID before returning
   acceptance or starting work. Concurrent identical submissions receive one
   identity and cause at most one dispatch attempt.
4. Before crossing the potentially effective dispatch boundary, durably record
   `may_have_been_sent`. A crash, lost reply, timeout, or ambiguous SDK result after
   this point must NEVER cause retransmission of that action. Reconcile, otherwise
   retain `unknown`. Acknowledged dispatch becomes `confirmed`.
5. An upload may be retried only when it cannot itself start printing. Keep one
   dispatch owner and recheck the journal before any SDK retry that could act.
6. The namespace is scoped internally to the installation and authorized account;
   it exposes no account identifier. It survives library upgrades, process restarts,
   observer close/expiry and same-account re-login. A different account cannot query
   its receipts. Session epochs still gate every request and prevent stale-session
   dispatch; no undispatched work is automatically replayed into a new session.
7. Native storage unavailable/corrupt: fail closed, accept no actions. An explicitly
   reset store gets a new scope; the caller's old scope is rejected with
   `submission_scope_changed`, not silently mapped to the new one. No automatic
   scope reset, receipt eviction, TTL expiry, or migration of old uncertain actions
   to a new scope/key. Scope values are UUID-like opaque handles, not secrets.
8. For this first contract, retain durable keys/receipts until explicit store reset;
   advertise a finite capacity and reject NEW keys with `capacity_exceeded` before
   acceptance. Existing-key recovery still works when full. A future retention/GC
   protocol needs separate agreement; this draft has no reset/forget API.

This trades availability for duplicate prevention: an action might not execute
after a crash around dispatch, but automatic retry cannot print it twice. If durable
native storage is too broad for the first implementation, agree on a narrower,
explicitly non-resumable guarantee first; do not advertise this stronger capability.

## Submission, receipts and recovery

`command.submit` validates syntax, authorization, scope, capabilities and capacity,
then durably accepts asynchronous work. It must return promptly; file hashing,
upload and printer acknowledgements do not run on the calling/UI thread.

Receipt states: `accepted`, `working`, `succeeded`, `failed`, `cancelled`, `unknown`.
Dispatch evidence: `not_sent`, `may_have_been_sent`, `confirmed`. For a print command,
`succeeded` means acknowledged print dispatch, **never completion of the print**.
For a control it means acknowledgement or reliable correlated resulting-state
confirmation. `accepted` does not mean the printer received anything.

`command.get(scope, key)` finds the original receipt even if the submit reply was
lost. A fresh authorized observer may recover it after restart. A lookup failure,
`busy`, transport failure, missing event, or `retryable:true` is not permission to
invent a new key. `not_found` means no record in the given intact scope; retrying
the identical intent under the SAME key is safe. A different client cannot cancel
or change an accepted intent by replacing its payload.

Reserve one physical-job submission lane per printer until the correlated job is
terminal; reject a different print while occupied. Controls for that job remain
available. Other printers have independent lanes, subject to advertised global
capacity. Query/dedup an existing key before occupied-lane rejection. Immediately
before dispatch, recheck account/session, fresh device state, faults, capability
revision, job ownership, and materials. Do not replace an Orca/Handy-started job.

Client close/expiry releases observation only. Native command ownership and receipts
survive; closing/reopening the queue cannot cancel or replay a print. This replaces
the old unimplemented draft's client-close cancellation idea; stage 2 has no command
side effects to preserve. Host exit/account change never sends an implicit physical
stop. Undispatched work is cancelled on session replacement; ambiguous dispatched
work stays unknown until positively reconciled. Receipt access requires current
authorization. Polling watches remain the existing per-client, atomic, independent
watch sets; never take over Orca's subscriptions or selected device.

## Job lifecycle and evidence

`job.get(scope, device_id, job_id)` is the durable recovery path when events are lost.
Return an additive `job_id` on correlated job snapshots/events while retaining the
existing `job_key`. A newly accepted job may have `job_key:null`; fill it only after
reliable native correlation. Stage-2 fields such as progress and task tag remain.

States: `pending`, `preparing`, `printing`, `paused`, `completed`, `failed`,
`cancelled`, `unknown`. The response and `job.state` event use the same job ID from
acceptance to start to terminal outcome. Unknown correlation produces no guessed
successful terminal event. Receipts and jobs have different lifecycles.

Terminal evidence includes state, nullable numeric error code, UTC receipt timestamp
`observed_at`, evidence source, correlation, connection generation and `quiescent`.
Timestamps use UTC `YYYY-MM-DDTHH:MM:SS[.fraction]Z`. The timestamp records native receipt/observation, not a fabricated printer clock;
ordering comes from cursors, not wall-clock comparisons. Unknown error is null,
not zero. `quiescent:true` means native evidence says this job has ended execution,
including end G-code; 100% or the last layer is insufficient. If the firmware cannot
establish that condition, leave it false and prohibit automatic continuation.

Never carry an old job's error/finish/identity into a new job. Authoritative late
evidence may resolve `unknown`; repeated terminal events remain idempotent. A
correlated terminal outcome must not regress because a stale progress frame arrives.
Conflicting evidence requires reconciliation and must not trigger another action.

On `cursor_expired`, reconnect or session change, fetch fresh capabilities, rebuild
watches, then query the persisted receipt/job. Do not reconstruct success from a
snapshot with another job, idle state, a missing job, or a filename match.

## File and material contract

Print a local, authorized, sliced single-plate 3MF. `plate_index` is the one-based
plate identifier from that file, not a queue index. Use UTF-8 paths and preserve
Windows long paths/Unicode. After acceptance, asynchronously verify SHA-256 and
retain immutable bytes/a suitable locked handle; do not hash and then reopen a
potentially changed path for upload. File errors become retained receipt failures
before dispatch. This API grants no additional host file permissions.

For normal printing, supply must explicitly be `ams` or `external`, with a complete
mapping of used sliced filament IDs to opaque snapshot slot IDs. Reject duplicate
source IDs, unknown/foreign slots, missing used materials, incompatible types/options,
or unsupported nozzle topology. Sparse source IDs are not list positions. Never
fall back from AMS to external. If the selected source becomes unusable before
dispatch, fail; the queue must explicitly choose a new intent after confirming the
old one was not dispatched. Cross-plate refill selection remains queue policy.

An external row is configured metadata, never proof of loaded filament. Presence,
active source and configured type/color must remain distinct. Do not invent an
active-source field from existing metadata. `nozzle_diameter` is already added in
the reviewed upstream revision; null remains unknown. Active-source exposure, if
needed later, should be a separate nullable field with documented evidence.

Mechanical A1 plate changing uses **the same print operation**, a separate ordinary
3MF and a fresh idempotency key/job ID. The proposed optional `supply:"none"` payload
requires capability support, empty materials, disabled calibration/timelapse/leveling,
and native validation of a bounded supported G-code subset with no extrusion or
filament loading. Unknown macros/commands or an unverifiable file fail before
dispatch. Mere user labeling or empty mapping is not proof. The accepted subset and
firmware constraints must be agreed before advertising `none`; keep it unsupported
until then. This is a print capability, not a special plate-changer API.

Automatic sequencing requires matched, quiescent `completed` evidence with error 0,
then a fresh available/idle, fault-free printer check. Failed/cancelled jobs do not
automatically authorize a swap; explicit user stop-and-continue policy is separate.
The mechanical job needs its own terminal evidence before the next model submission.
No software terminal event claims that a physical replacement plate is seated.
P1S retains manual plate confirmation. A pause-after marker blocks new submissions
after the target job, including the plate-change file, without pausing that job.

Controls recheck `expected_job_id` at dispatch. Object IDs come from the existing
native/sliced identification, never list order. An all-remaining-objects request
returns `would_end_job`; explicit stop-and-continue intent uses a separate keyed
stop command. No implicit conversion from skip to stop.

## Errors and decisions for review

Retain existing errors. Proposed additions: `idempotency_conflict`,
`submission_scope_changed`, `submission_store_unavailable`, `not_found`,
`signed_out`, `not_authorized`, `stale_status`, `invalid_mapping`, `file_changed`,
`job_mismatch`, `would_end_job`, `result_unknown`, `unsafe_file`. Only an `ok:true`
receipt acknowledges library acceptance. Generic/internal/transport failure is
ambiguous; recover by key. Errors must not include credentials or file contents.

Please review in particular:

1. Durable scope/store ownership, capacity and recovery after Orca restart.
2. Where the native SDK's potentially effective dispatch boundary is, and whether
   internal SDK retries can honor at-most-once dispatch.
3. Correlation of the returned job ID to printer start/end identifiers, including
   external jobs and trustworthy end-G-code/quiescence evidence on A1/P1S.
4. The optional `supply:none` validation subset (safe to defer separately).
5. Whether metadata needed for native material validation should be read entirely
   from 3MF, reducing the proposed redundant material fields before implementation.

## Tests and PR boundaries

Run `python -m pip install jsonschema` in a development environment, then
`python tests/queue_api_stage3_contract_test.py`. Tests read synthetic fixtures only,
never load the library, access user account files, or contact printers. They check
schema validity, examples, rejected shapes and cross-field fixture invariants.
See `acceptance.md` for native fake-transport/fault-injection cases and later hardware
acceptance. These schema tests **do not prove native deduplication or real printing**.

Examples are independent illustrative exchanges except the explicitly linked
submit/retry/recovery/completion sequence. IDs, paths and hashes are synthetic.
Merge only the contract/tests first; implement/enable commands separately after review.
