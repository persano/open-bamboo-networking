# Native implementation acceptance plan (not yet executed)

These tests are obligations for the implementation PR, not claims made by the
standalone schema test. Use a fake transport with a counted, externally observable
dispatch boundary and a temporary durable journal. Never use a real printer in CI.
Inject failures on both sides of each durable write and dispatch boundary.

| Case | Required result |
|---|---|
| Same key, identical payload, different RPC IDs | Same command/job IDs; dispatch counter at most 1. |
| Two clients submit the same key concurrently | One reservation; same receipt; dispatch at most 1. |
| Same key, altered device/hash/path/options/mapping | `idempotency_conflict`; no second dispatch. |
| Acceptance reply lost | `command.get` and same-key retry recover original identity. |
| Crash before journal reservation | No dispatch; same-key retry may accept once. |
| Crash after reservation, before dispatch marker | Recover without duplicate ownership or automatic session replay. |
| Crash after dispatch marker, before SDK call | Preserve uncertainty; no retry dispatch, even if print never started. |
| Crash after SDK send, before acknowledgement persistence | Preserve same job; reconcile or unknown; dispatch stays at most 1. |
| Client expiry/close/reopen, same-account re-login, process restart | Dedup keys/identities persist; no implicit physical stop/replay. |
| Different account or wrong session/scope | Reject; no old data leak or physical action in the new session. |
| Journal corrupt/unavailable, disk full at reservation/dispatch marker | Fail closed before crossing affected side-effect boundary. |
| Receipt store full | New keys fail before dispatch; old-key lookup/replay still works. |
| Explicit store reset | New scope; old-scope request rejected, never accepted as fresh. |
| SDK auto-retry after uncertain send | Cannot duplicate dispatch; otherwise keep capability disabled. |
| Print accepted/uploaded but not acknowledged | Must not report printing/completed or authorize swap. |
| Two printers + Orca live callbacks | Independent lanes/status/events; no callback replacement or selection changes. |
| One printer busy, second available | First new print fails busy; second unaffected; existing-key lookup works. |
| Job replaced between control validation and send | `job_mismatch`; no control sent to replacement job. |
| Stop/skip reply lost and same-key retry | No second control; especially no stop targeting the next job. |
| All remaining objects selected | `would_end_job`; no implicit stop. |
| Event duplication/out-of-order frames | One logical terminal result; no regression or repeated swap. |
| Cursor expiry/reconnect during completion | Recover same job via journal and reliable evidence, otherwise unknown. |
| Progress 100%, idle, old FINISH, missing job, filename match | None alone can establish matched quiescent completion. |
| Terminal fields missing/conflicting, error null, correlation unverified | No automatic next submission. |
| Positive correlated completion and fresh idle/fault-free state | Queue may submit exactly one distinct mechanical job. |
| Mechanical job finishes vs merely uploads | Only its own matched terminal evidence permits next model. |
| Pause after selected plate | Current print continues; neither swap nor next model is submitted. |
| AMS sparse IDs, multiple AMS units, external spool | Explicit exact mapping; no positional guess or external fallback. |
| Configured external metadata with AMS active | Do not label external loaded or use it for routing. |
| Slot removed/type changes after acceptance | Fail before dispatch; no silently substituted source. |
| File modified after hash, Unicode/long path, missing/denied file | Immutable upload or retained failure; never upload mismatched bytes. |
| supply none unsupported / extrusion / unknown macro | Reject before dispatch; no claim of a safe plate-change job. |
| Old stage-2 library / feature partially implemented | Consumer disables missing commands; existing observation remains. |

Hardware acceptance AFTER native implementation and explicit test authorization:
one small A1 AMS print, one P1S AMS print, external-spool print, pause/resume,
single-object skip, explicit stop, concurrent A1/P1S observation, controlled reconnect,
and inspected mechanical A1 swap plus next model. Validate against Orca/Handy and
physical behavior, not only transport success. Keep the currently working bridge
available until those checks pass. Never automatically perform destructive fault
injection or a mechanical swap on a user's ongoing job.
