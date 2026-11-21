// SPDX-License-Identifier: AGPL-3.0-or-later
// Versioned C integration API for third-party print queue plugins.
// Design: https://github.com/persano/open-bambu-networking-plugin/issues/16
#ifndef OBN_QUEUE_API_V1_H
#define OBN_QUEUE_API_V1_H
#include <stdint.h>
#if defined(_WIN32)
#define OBNQ_CALL __cdecl
#if defined(OBN_QUEUE_API_BUILD)
#define OBNQ_EXPORT __declspec(dllexport)
#else
#define OBNQ_EXPORT
#endif
#else
#define OBNQ_CALL
#define OBNQ_EXPORT __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define OBN_QUEUE_MAX_REQUEST_BYTES 65536u
#define OBN_QUEUE_MAX_RESPONSE_BYTES 2097152u
// Resolve BOTH exports on the networking module already loaded by the host.
// Missing export => unsupported. Do not load a second networking library.
// JSON op="capabilities" is the capability query; it needs no client/session.
// Lengths are UTF-8 byte counts excluding NUL; embedded NULs are rejected.
// 0: valid response envelope (success OR application error).
// -1: invalid C arguments; -2: allocation failure; -3: internal failure.
// Initialize output pointers to NULL/0 on nonzero return.
// Null output pointers are invalid arguments and must not be dereferenced.
// Never let C++ exceptions cross this boundary. Never call from DllMain.
// A transport/internal failure is NOT proof that a command was not accepted.
// Stage-3 DRAFT contract: see docs/queue-api-v1-stage3/README.md.
// request_id correlates one RPC, NOT a physical action. command.submit carries
// a separate submission_scope + idempotency_key. Recover with command.get;
// retry only the identical command under that same scope/key. A new client,
// session, or process does not grant permission to dispatch that key again.
// This header adds no exports, changes no ABI, and enables no command kinds.
// Calls copy input, enqueue commands, and return cached JSON; no network wait.
// Returned memory belongs to this module. Free it exactly once below, never
// with the caller's CRT. Keep the module alive through the call and free.
OBNQ_EXPORT int32_t OBNQ_CALL obn_queue_call_v1(
    const char *request_utf8, uint32_t request_bytes,
    char **response_utf8, uint32_t *response_bytes);
OBNQ_EXPORT void OBNQ_CALL obn_queue_free_v1(char *response_utf8);
// Signatures for consumers that dynamically resolve the exports.
typedef int32_t (OBNQ_CALL *obn_queue_call_v1_fn)(
    const char *, uint32_t, char **, uint32_t *);
typedef void (OBNQ_CALL *obn_queue_free_v1_fn)(char *);
#ifdef __cplusplus
}
#endif
#endif
