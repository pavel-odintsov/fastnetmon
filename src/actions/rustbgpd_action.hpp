#pragma once

#include "../fastnetmon_types.hpp"

#include "../attack_details.hpp"

#include <atomic>
#include <string>

#include <sys/stat.h>

bool rustbgpd_action_init();

// Stops worker thread. Safe to call more than once
void rustbgpd_action_shutdown();

// Stops worker from signal handler: only async-signal-safe operations, never locks or joins. Waits up to 6 seconds
// for worker to finish. Returns false if it is still running: then caller must leave with _exit(), as exit() would
// destroy objects worker uses. rustbgpd_action_shutdown does nothing after it. This covers only this action: code
// which runs in signal handler before it must be async-signal-safe on its own
bool rustbgpd_action_signal_shutdown();

// Test hook called by action at named points, never set in FastNetMon. Tests change it while worker runs
using rustbgpd_test_checkpoint_t = void (*)(const char* point);
extern std::atomic<rustbgpd_test_checkpoint_t> rustbgpd_test_checkpoint;

// Only changes desired state, gRPC calls are made by worker thread. Call it in order of ban and unban events
void rustbgpd_ban_manage(const std::string& action,
                         bool ipv6,
                         uint32_t client_ip,
                         const subnet_ipv6_cidr_mask_t& client_ipv6,
                         const attack_details_t& current_attack);

// Shared metadata check for credential files: regular file owned by effective_uid or root. Secret files (bearer
// token, TLS private key) allow no access for group or others; CA and certificate files allow no write access for
// them. Returns empty string or reason to reject it
std::string rustbgpd_check_token_file_metadata(const struct stat& file_stat, uid_t effective_uid, bool secret = true);
