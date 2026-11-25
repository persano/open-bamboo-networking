#pragma once

// Internal C++ interface of the versioned queue integration API
// (obn_queue_api_v1.h is the public C contract; this is its engine).
// Stage 2 scope: capability discovery, read-only multi-printer snapshots
// and polled events. Stage 3 adds the capability-gated command.submit /
// command.get / job.get operations backed by the durable receipt store
// (docs/queue-api-v1-stage3/).

#include <cstdint>
#include <string>

namespace obn::queue {

// One host-delivered MQTT frame, post-normalization, exactly as the host
// callback receives it (agent.cpp taps this beside the existing dispatch).
void ingest_frame(const std::string& dev_id, const std::string& json);

// Transport edges for per-device connection_generation / online state.
void note_connected(const std::string& dev_id);
void note_disconnected(const std::string& dev_id);

// Session lifecycle: reason = "login" | "logout" | "agent_replaced".
// Bumps session_epoch, purges snapshots/inventory/events and watch sets.
void note_session_changed(const char* reason);

// Authorized device inventory from the cloud /user/print or /user/bind
// response body (abi_http.cpp calls this after a successful fetch).
void note_devices_from_cloud(const std::string& raw_body);

// C ABI bodies behind obn_queue_call_v1 / obn_queue_free_v1 (abi_queue.cpp).
std::int32_t call_v1(const char* request_utf8, std::uint32_t request_bytes,
                     char** response_utf8, std::uint32_t* response_bytes);
void free_v1(char* response_utf8);

#ifdef OBN_TESTING
// Test seams for the stage-3 command path (tests only; absent from
// production builds). Inject the authorized session + config dir the
// receipt store opens with (tests have no live Agent), and suppress
// worker-thread dispatch so accept/replay/lane assertions stay
// deterministic.
void test_set_command_session(const std::string& user_id,
                              const std::string& config_dir);
void test_clear_command_session();
void test_set_dispatch_enabled(bool enabled);
// Parse a full print command and return the flat / snake / detail
// mapping strings build_print_params would set (no Agent, no store).
bool test_build_mapping(const std::string& cmd_json, std::string* flat,
                        std::string* snake, std::string* detail,
                        std::string* err);
#endif

} // namespace obn::queue
