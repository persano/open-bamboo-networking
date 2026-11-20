#pragma once

// Internal C++ interface of the versioned queue integration API
// (obn_queue_api_v1.h is the public C contract; this is its engine).
// Stage 2 scope: capability discovery, read-only multi-printer snapshots
// and polled events. Commands/print submission arrive in a later stage.

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

} // namespace obn::queue
