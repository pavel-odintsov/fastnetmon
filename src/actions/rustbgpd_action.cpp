#include "rustbgpd_action.hpp"
#include "../fastnetmon_actions.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <tuple>

#include <grpcpp/grpcpp.h>

#include <boost/algorithm/string.hpp>

#include "../bgp_protocol.hpp"

#include "../rustbgpd_client/rustbgpd_injection.grpc.pb.h"

#include "../fastnetmon_configuration_scheme.hpp"

#include "../ban_list.hpp"

extern fastnetmon_configuration_t fastnetmon_global_configuration;

extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;
extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

// rustbgpd action: announces and withdraws blackholes through rustbgpd's InjectionService
// https://github.com/lance0/rustbgpd/blob/main/docs/reference/api.md#injectionservice
//
// Ban and unban only change desired state here, synchronously and in the order FastNetMon calls them.
// Single worker thread makes all gRPC calls and moves rustbgpd towards desired state. Each change of desired
// state for prefix gets new version and worker marks prefix as done only when rustbgpd confirmed exactly that
// version, so late answer for older state never hides newer one.
//
// Routes injected into rustbgpd live only as long as the rustbgpd process. Worker announces all wanted routes
// again when rustbgpd becomes reachable after failed liveness probe (as after rustbgpd restart), when our lease
// generation changes and on periodic pass.

// Deadline for AddPath, DeletePath and RenewLease calls
unsigned int rustbgpd_call_timeout = 5;

// How often we probe rustbgpd with ControlService.CheckLiveness
const std::chrono::milliseconds rustbgpd_probe_interval(500);

using rustbgpd_clock_t = std::chrono::steady_clock;

class rustbgpd_route_t {
    public:
    std::string prefix;
    uint32_t prefix_length = 0;
    std::string next_hop;
    std::vector<uint32_t> communities;

    std::string key() const {
        return prefix + "/" + std::to_string(prefix_length);
    }
};

class rustbgpd_route_state_t {
    public:
    rustbgpd_route_t route;

    // Banned hosts which need this route. Host route has only host itself, subnet route has all banned hosts from
    // this subnet. Route must be announced while this set is not empty
    std::set<std::string> contributors;

    // Version of desired state and last version which rustbgpd confirmed
    uint64_t version        = 0;
    uint64_t synced_version = 0;

    // Do not retry failed call before this time
    rustbgpd_clock_t::time_point retry_after{};

    // Failed calls in a row for current version
    unsigned int failures = 0;

    // Status of last failed call, -1 for answer we did not recognise, 0 if last call succeeded
    int last_error = 0;

    // Desired state changed since rustbgpd confirmed it, as opposed to resending in full pass
    bool changed = false;

    // Last call for this route: routes which waited longest go first within their class
    rustbgpd_clock_t::time_point last_attempt{};
};

// Copy of route state which worker uses for gRPC call without holding lock
class rustbgpd_job_t {
    public:
    rustbgpd_route_t route;
    bool announce    = false;
    uint64_t version = 0;
    bool changed     = false;
    rustbgpd_clock_t::time_point last_attempt{};

    // Status of previous failed call for this route: same failure again is logged at DEBUG only
    int last_error = 0;

    // Set by call: status of this call when it failed and whether rustbgpd changed its routes
    int error          = 0;
    bool route_changed = false;
};

enum class rustbgpd_call_result_t { success, transient_failure, failure };

std::unique_ptr<rustbgpd::v1::InjectionService::Stub> rustbgpd_injection_stub;
std::unique_ptr<rustbgpd::v1::ControlService::Stub> rustbgpd_control_stub;

std::string rustbgpd_token;

// Protects all variables below. Never held during gRPC calls
// Never destroyed: after stop from signal handler worker may still wait on them while exit() destroys globals
std::mutex& rustbgpd_mutex                      = *new std::mutex;
std::condition_variable& rustbgpd_worker_wakeup = *new std::condition_variable;

std::map<std::string, rustbgpd_route_state_t> rustbgpd_routes;
uint64_t rustbgpd_last_version = 0;

// Lease generation returned by the last leased add
bool rustbgpd_lease_generation_known = false;
rustbgpd::v1::LeaseGeneration rustbgpd_lease_generation;

// Our lease is valid at least until this time: start of last successful leased add or renewal plus lease time.
// Used by worker thread only, empty when unknown
rustbgpd_clock_t::time_point rustbgpd_lease_valid_until{};

// Allocated on start and deleted after join. After stop from signal handler we never join and leave it allocated
boost::thread* rustbgpd_worker = nullptr;
bool rustbgpd_worker_running   = false;
bool rustbgpd_worker_stop      = false;

// Stop requested from signal handler. Lock free, signal handler may only touch these two
std::atomic<bool> rustbgpd_signal_stop{ false };
std::atomic<bool> rustbgpd_worker_exited{ true };

// Desired state changed, worker should not wait for next probe interval
bool rustbgpd_work_pending = false;

// Full pass is copying ban lists: hosts with ban or unban calls since copy started go to rustbgpd_hosts_changed_in_copy
bool rustbgpd_copy_in_progress = false;
std::set<std::string> rustbgpd_hosts_changed_in_copy;

// Full pass needed because rustbgpd lost our routes (new lease generation), worker also checks ban lists then
bool rustbgpd_full_pass_requested = false;

// Disagreements with ban lists which last full pass saw: host, then route key, then +1 when ban list has host and
// route does not, -1 for the other way round
std::map<std::string, std::map<std::string, int>> rustbgpd_disagreement_marks;

// We keep channel to check its state before each liveness probe
std::shared_ptr<grpc::Channel> rustbgpd_channel;

// Test hook, never set in FastNetMon
std::atomic<rustbgpd_test_checkpoint_t> rustbgpd_test_checkpoint{ nullptr };

// Calls test hook if set. We load it once, as test may clear it between check and call
void rustbgpd_run_test_checkpoint(const char* point) {
    rustbgpd_test_checkpoint_t checkpoint = rustbgpd_test_checkpoint.load();

    if (checkpoint != nullptr) {
        checkpoint(point);
    }
}

// Call in progress, we cancel it on shutdown
grpc::ClientContext* rustbgpd_current_call = nullptr;

void rustbgpd_prepare_context(grpc::ClientContext& context, unsigned int timeout_seconds) {
    std::chrono::milliseconds timeout = std::chrono::seconds(timeout_seconds);

    // Call must end one second before our lease would expire, so that we can renew it after the call
    if (fastnetmon_global_configuration.rustbgpd_lease && rustbgpd_lease_valid_until != rustbgpd_clock_t::time_point{}) {
        auto until_expiry = std::chrono::duration_cast<std::chrono::milliseconds>(
            rustbgpd_lease_valid_until - rustbgpd_clock_t::now() - std::chrono::seconds(1));

        timeout = std::max(std::min(timeout, until_expiry), std::chrono::milliseconds(500));
    }

    context.set_deadline(std::chrono::system_clock::now() + timeout);

    // Call credentials are attached only to channels gRPC considers secure, so we add token directly to each call
    if (!rustbgpd_token.empty()) {
        context.AddMetadata("authorization", "Bearer " + rustbgpd_token);
    }
}

std::string rustbgpd_status_code_name(grpc::StatusCode code) {
    static const char* names[] = {
        "OK",        "CANCELLED",      "UNKNOWN",           "INVALID_ARGUMENT",   "DEADLINE_EXCEEDED",
        "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
        "ABORTED",   "OUT_OF_RANGE",   "UNIMPLEMENTED",     "INTERNAL",           "UNAVAILABLE",
        "DATA_LOSS", "UNAUTHENTICATED"
    };

    if (code >= 0 && size_t(code) < sizeof(names) / sizeof(names[0])) {
        return names[code];
    }

    return "code " + std::to_string(code);
}

std::string rustbgpd_describe_status(const grpc::Status& status) {
    return rustbgpd_status_code_name(status.error_code()) + ": " + status.error_message();
}

// Errors after which an immediate retry makes sense
bool rustbgpd_is_transient_error(const grpc::Status& status) {
    return status.error_code() == grpc::StatusCode::UNAVAILABLE || status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED;
}

// Must be called with rustbgpd_mutex held
void rustbgpd_schedule_full_pass() {
    for (auto& [key, state] : rustbgpd_routes) {
        state.synced_version = 0;
        state.retry_after    = rustbgpd_clock_t::time_point{};
    }

    rustbgpd_work_pending = true;
    rustbgpd_worker_wakeup.notify_all();
}

// Must be called with rustbgpd_mutex held
void rustbgpd_request_full_pass() {
    rustbgpd_schedule_full_pass();
    rustbgpd_full_pass_requested = true;
}

// Runs gRPC call with context which shutdown can cancel
template <typename Call> grpc::Status rustbgpd_run_call(grpc::ClientContext& context, Call call) {
    {
        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

        if (rustbgpd_worker_stop || rustbgpd_signal_stop) {
            return grpc::Status(grpc::StatusCode::CANCELLED, "FastNetMon is stopping");
        }

        rustbgpd_current_call = &context;
    }

    grpc::Status status = call();

    std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);
    rustbgpd_current_call = nullptr;

    return status;
}

// Same failure as previous call for this route is logged at DEBUG, first one at ERROR
log4cpp::Priority::Value rustbgpd_error_priority(const rustbgpd_job_t& job) {
    return job.error == job.last_error ? log4cpp::Priority::DEBUG : log4cpp::Priority::ERROR;
}

rustbgpd_call_result_t rustbgpd_add_route(rustbgpd_job_t& job) {
    const rustbgpd_route_t& route = job.route;
    rustbgpd::v1::AddPathRequest path;

    path.set_prefix(route.prefix);
    path.set_prefix_length(route.prefix_length);
    path.set_next_hop(route.next_hop);

    // Same origin as GoBGP action announces
    path.set_origin(BGP_ORIGIN_INCOMPLETE);

    for (auto community : route.communities) {
        path.add_communities(community);
    }

    grpc::ClientContext context;
    rustbgpd_prepare_context(context, rustbgpd_call_timeout);

    grpc::Status status;
    rustbgpd::v1::PathInjectOutcome outcome = rustbgpd::v1::PATH_INJECT_OUTCOME_UNSPECIFIED;

    if (fastnetmon_global_configuration.rustbgpd_lease) {
        rustbgpd::v1::AddLeasedPathRequest request;
        *request.mutable_path() = path;
        request.mutable_lease()->set_owner(fastnetmon_global_configuration.rustbgpd_lease_owner);
        request.mutable_lease()->set_lease_seconds(fastnetmon_global_configuration.rustbgpd_lease_time);

        rustbgpd::v1::AddLeasedPathResponse response;
        auto call_started = rustbgpd_clock_t::now();
        status            = rustbgpd_run_call(context,
                                              [&] { return rustbgpd_injection_stub->AddLeasedPath(&context, request, &response); });

        if (status.ok() && (!response.has_result() || !response.has_generation())) {
            job.error = -1;
            logger << rustbgpd_error_priority(job) << "rustbgpd answered leased announce of " << route.key()
                   << " without result or lease generation";
            return rustbgpd_call_result_t::failure;
        }

        if (status.ok()) {
            outcome = response.result().outcome();

            const auto& generation = response.generation();

            std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

            if (rustbgpd_lease_generation_known && (generation.incarnation() != rustbgpd_lease_generation.incarnation() ||
                                                    generation.sequence() != rustbgpd_lease_generation.sequence())) {
                // Our previous lease expired or rustbgpd restarted. Routes added under it, including ones added
                // earlier in the current pass, may be gone
                logger << log4cpp::Priority::WARN << "rustbgpd started new lease for owner "
                       << fastnetmon_global_configuration.rustbgpd_lease_owner << ", will announce all active bans again";
                rustbgpd_request_full_pass();
            }

            rustbgpd_lease_generation       = generation;
            rustbgpd_lease_generation_known = true;
            rustbgpd_lease_valid_until = call_started + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_lease_time);
        }
    } else {
        rustbgpd::v1::AddPathResponse response;
        status = rustbgpd_run_call(context, [&] { return rustbgpd_injection_stub->AddPath(&context, path, &response); });

        if (status.ok()) {
            outcome = response.outcome();
        }
    }

    rustbgpd_run_test_checkpoint("announce_returned");

    if (!status.ok()) {
        job.error = status.error_code();

        logger << rustbgpd_error_priority(job) << "rustbgpd rejected announce of " << route.key() << " next hop "
               << route.next_hop << ": " << rustbgpd_describe_status(status);

        if (status.error_code() == grpc::StatusCode::FAILED_PRECONDITION) {
            logger << rustbgpd_error_priority(job) << "Prefix " << route.key() << " is held in rustbgpd by another lease owner or "
                   << "without lease. Remove it with: rbgp rib delete " << route.key() << " --override-owner";
        }

        return rustbgpd_is_transient_error(status) ? rustbgpd_call_result_t::transient_failure : rustbgpd_call_result_t::failure;
    }

    if (outcome != rustbgpd::v1::PATH_INJECT_OUTCOME_CREATED && outcome != rustbgpd::v1::PATH_INJECT_OUTCOME_REPLACED &&
        outcome != rustbgpd::v1::PATH_INJECT_OUTCOME_UNCHANGED) {
        // rustbgpd older than 0.79.0 or newer one with outcome we do not know. We will try again
        job.error = -1;
        logger << rustbgpd_error_priority(job) << "rustbgpd answered announce of " << route.key()
               << " without recognised outcome (" << int(outcome) << "), will retry";
        return rustbgpd_call_result_t::failure;
    }

    // Full pass resends every route and most of them are unchanged
    job.route_changed = outcome != rustbgpd::v1::PATH_INJECT_OUTCOME_UNCHANGED;

    logger << (job.route_changed ? log4cpp::Priority::INFO : log4cpp::Priority::DEBUG) << "rustbgpd announced "
           << route.key() << " next hop " << route.next_hop << " outcome " << rustbgpd::v1::PathInjectOutcome_Name(outcome);

    return rustbgpd_call_result_t::success;
}

rustbgpd_call_result_t rustbgpd_delete_route(rustbgpd_job_t& job) {
    const rustbgpd_route_t& route = job.route;
    rustbgpd::v1::DeletePathRequest request;

    request.set_prefix(route.prefix);
    request.set_prefix_length(route.prefix_length);

    // rustbgpd may have restarted and lost this route already
    request.set_allow_missing(true);

    if (fastnetmon_global_configuration.rustbgpd_lease) {
        request.set_owner(fastnetmon_global_configuration.rustbgpd_lease_owner);
    }

    grpc::ClientContext context;
    rustbgpd_prepare_context(context, rustbgpd_call_timeout);

    rustbgpd::v1::DeletePathResponse response;
    grpc::Status status =
        rustbgpd_run_call(context, [&] { return rustbgpd_injection_stub->DeletePath(&context, request, &response); });

    if (!status.ok()) {
        job.error = status.error_code();

        logger << rustbgpd_error_priority(job) << "rustbgpd rejected withdrawal of " << route.key() << ": "
               << rustbgpd_describe_status(status);

        return rustbgpd_is_transient_error(status) ? rustbgpd_call_result_t::transient_failure : rustbgpd_call_result_t::failure;
    }

    if (response.outcome() != rustbgpd::v1::PATH_DELETE_OUTCOME_DELETED &&
        response.outcome() != rustbgpd::v1::PATH_DELETE_OUTCOME_NOT_PRESENT) {
        job.error = -1;
        logger << rustbgpd_error_priority(job) << "rustbgpd answered withdrawal of " << route.key()
               << " without recognised outcome (" << int(response.outcome()) << "), will retry";
        return rustbgpd_call_result_t::failure;
    }

    job.route_changed = response.outcome() == rustbgpd::v1::PATH_DELETE_OUTCOME_DELETED;

    logger << (job.route_changed ? log4cpp::Priority::INFO : log4cpp::Priority::DEBUG) << "rustbgpd withdrew "
           << route.key() << " outcome " << rustbgpd::v1::PathDeleteOutcome_Name(response.outcome());

    return rustbgpd_call_result_t::success;
}

void rustbgpd_renew_lease(const rustbgpd::v1::LeaseGeneration& generation) {
    rustbgpd_run_test_checkpoint("renewal_started");

    rustbgpd::v1::RenewLeaseRequest request;
    request.set_owner(fastnetmon_global_configuration.rustbgpd_lease_owner);
    *request.mutable_generation() = generation;
    request.set_lease_seconds(fastnetmon_global_configuration.rustbgpd_lease_time);

    grpc::ClientContext context;
    rustbgpd_prepare_context(context, rustbgpd_call_timeout);

    rustbgpd::v1::RenewLeaseResponse response;
    auto call_started = rustbgpd_clock_t::now();
    grpc::Status status =
        rustbgpd_run_call(context, [&] { return rustbgpd_injection_stub->RenewLease(&context, request, &response); });

    if (status.ok()) {
        rustbgpd_lease_valid_until = call_started + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_lease_time);
        return;
    }

    logger << log4cpp::Priority::ERROR << "rustbgpd lease renewal for owner "
           << fastnetmon_global_configuration.rustbgpd_lease_owner << " failed: " << rustbgpd_describe_status(status);

    if (status.error_code() == grpc::StatusCode::FAILED_PRECONDITION) {
        // Lease expired or rustbgpd restarted. First leased add will start new lease
        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);
        rustbgpd_lease_generation_known = false;
        rustbgpd_lease_valid_until      = rustbgpd_clock_t::time_point{};
        rustbgpd_request_full_pass();
    }
}

grpc::Status rustbgpd_check_liveness() {
    grpc::ClientContext context;
    rustbgpd_prepare_context(context, 1);

    // Wait for connection up to deadline instead of failing at once. Without call in progress gRPC
    // makes progress on new connections only from its backup poller every 5 seconds and we would see
    // restarted rustbgpd up to 5 seconds late
    context.set_wait_for_ready(true);

    rustbgpd::v1::CheckLivenessRequest request;
    rustbgpd::v1::CheckLivenessResponse response;

    return rustbgpd_run_call(context, [&] { return rustbgpd_control_stub->CheckLiveness(&context, request, &response); });
}

// Applies result of call made for job. Must be called with rustbgpd_mutex held
void rustbgpd_apply_result(const std::string& key, const rustbgpd_job_t& job, rustbgpd_call_result_t result) {
    auto it = rustbgpd_routes.find(key);

    if (it == rustbgpd_routes.end()) {
        return;
    }

    auto& state = it->second;

    state.last_attempt = rustbgpd_clock_t::now();

    // Desired state changed while call was in progress. Worker applies newer version next, result of older one
    // must not delay it, whatever it was
    if (state.version != job.version) {
        return;
    }

    if (result != rustbgpd_call_result_t::success) {
        // Rejected call or answer we do not understand: retry after rustbgpd_reconcile_interval but not later than
        // in 10 seconds, operator may fix cause in meantime. Call which failed as unreachable while liveness probes
        // succeed: retry after 0.5, 1, 2, 4... seconds up to the same limit. When rustbgpd comes back after failed
        // probe, full pass retries everything at once
        auto max_delay = std::min(std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval)),
                                  std::chrono::milliseconds(10000));

        state.failures++;

        auto delay = max_delay;

        if (result == rustbgpd_call_result_t::transient_failure) {
            delay = std::min(std::chrono::milliseconds(500) * (1u << std::min(state.failures - 1, 5u)), max_delay);
        } else if (job.error == state.last_error) {
            // Same rejection again, operator has not fixed it yet: retry on reconcile interval only
            delay = std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval);
        }

        state.last_error  = job.error;
        state.retry_after = rustbgpd_clock_t::now() + delay;
        return;
    }

    state.synced_version = job.version;
    state.failures       = 0;
    state.last_error     = 0;
    state.changed        = false;

    if (state.contributors.empty()) {
        rustbgpd_routes.erase(it);
    }
}

std::vector<rustbgpd_route_t> rustbgpd_routes_for_host(bool ipv6,
                                                       uint32_t client_ip,
                                                       const subnet_ipv6_cidr_mask_t& client_ipv6,
                                                       const attack_details_t& current_attack,
                                                       std::string& host,
                                                       bool log_errors);

// Starts new version after contributors of route changed, when route became wanted or unwanted or is new. Must be
// called with rustbgpd_mutex held. Returns true when version changed
bool rustbgpd_contributors_changed(rustbgpd_route_state_t& state, const rustbgpd_route_t& route, bool wanted_before) {
    bool wanted_now = !state.contributors.empty();

    // New entry or change between announce and withdrawal. Unban of route we do not know still sends withdrawal:
    // rustbgpd may keep it from before FastNetMon restart
    if (state.version != 0 && wanted_before == wanted_now) {
        return false;
    }

    state.route       = route;
    state.version     = ++rustbgpd_last_version;
    state.retry_after = rustbgpd_clock_t::time_point{};
    state.failures    = 0;
    state.last_error  = 0;
    state.changed     = true;

    return true;
}

// Sets contributors of route, see rustbgpd_contributors_changed. Must be called with rustbgpd_mutex held
bool rustbgpd_set_contributors(rustbgpd_route_state_t& state, const rustbgpd_route_t& route, const std::set<std::string>& contributors) {
    bool wanted_before = !state.contributors.empty();
    state.contributors = contributors;

    return rustbgpd_contributors_changed(state, route, wanted_before);
}

// FastNetMon's ban lists are the source of truth: ban and unban calls may reach us in other order than FastNetMon
// changed its ban lists, so on every full pass we make wanted routes match ban lists in both directions.
// Lock order: we copy ban lists under their own locks and release them, only then we take rustbgpd_mutex. We never
// hold both
void rustbgpd_converge_with_ban_lists() {
    rustbgpd_run_test_checkpoint("converge_starting");

    {
        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);
        rustbgpd_copy_in_progress = true;
        rustbgpd_hosts_changed_in_copy.clear();
    }

    {
        std::map<uint32_t, attack_details_t> banned_ipv4;
        std::map<subnet_ipv6_cidr_mask_t, attack_details_t> banned_ipv6;

        ban_list_ipv4.get_whole_banlist(banned_ipv4);
        ban_list_ipv6.get_whole_banlist(banned_ipv6);

        rustbgpd_run_test_checkpoint("converge_copied");

        // Wanted routes and banned hosts which need them
        std::map<std::string, std::pair<rustbgpd_route_t, std::set<std::string>>> wanted;
        std::string host;

        for (const auto& [client_ip, attack] : banned_ipv4) {
            for (const auto& route : rustbgpd_routes_for_host(false, client_ip, subnet_ipv6_cidr_mask_t{}, attack, host, false)) {
                wanted[route.key()].first = route;
                wanted[route.key()].second.insert(host);
            }
        }

        for (const auto& [client_ipv6, attack] : banned_ipv6) {
            for (const auto& route : rustbgpd_routes_for_host(true, 0, client_ipv6, attack, host, false)) {
                wanted[route.key()].first = route;
                wanted[route.key()].second.insert(host);
            }
        }

        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

        // Ban or unban of a host while we copied ban lists: our copy may be older than its change, so we neither
        // act on nor mark disagreements of that host. Rest of the copy is used
        rustbgpd_copy_in_progress                   = false;
        const std::set<std::string> changed_in_copy = std::move(rustbgpd_hosts_changed_in_copy);
        rustbgpd_hosts_changed_in_copy.clear();

        // Disagreements between our routes and ban lists: host which ban list has and route lacks (+1), or route
        // has and ban list does not (-1)
        std::vector<std::tuple<std::string, std::string, int>> disagreements;

        for (const auto& [key, state] : rustbgpd_routes) {
            auto it = wanted.find(key);

            for (const auto& contributor : state.contributors) {
                if (it == wanted.end() || it->second.second.count(contributor) == 0) {
                    disagreements.push_back({ contributor, key, -1 });
                }
            }
        }

        for (const auto& [key, route_and_hosts] : wanted) {
            auto it = rustbgpd_routes.find(key);

            for (const auto& banned_host : route_and_hosts.second) {
                if (it == rustbgpd_routes.end() || it->second.contributors.count(banned_host) == 0) {
                    disagreements.push_back({ banned_host, key, +1 });
                }
            }
        }

        // We act only on disagreement which previous full pass saw too and no ban or unban of that host touched since.
        // Single pass may fall between ban list change and its action call, as unban of expired bans calls actions
        // before it removes hosts from ban list. Agreements drop their marks
        std::map<std::string, std::map<std::string, int>> marks;

        for (const auto& [disagreeing_host, key, direction] : disagreements) {
            if (changed_in_copy.count(disagreeing_host) > 0) {
                continue;
            }

            auto host_marks = rustbgpd_disagreement_marks.find(disagreeing_host);

            bool seen_before = host_marks != rustbgpd_disagreement_marks.end() && host_marks->second.count(key) > 0 &&
                               host_marks->second.at(key) == direction;

            if (!seen_before) {
                marks[disagreeing_host][key] = direction;
                continue;
            }

            auto& state        = rustbgpd_routes[key];
            bool wanted_before = !state.contributors.empty();

            if (direction > 0) {
                state.contributors.insert(disagreeing_host);
            } else {
                state.contributors.erase(disagreeing_host);
            }

            const rustbgpd_route_t& route = direction > 0 ? wanted[key].first : state.route;

            if (rustbgpd_contributors_changed(state, route, wanted_before)) {
                logger << log4cpp::Priority::WARN << "rustbgpd " << (direction > 0 ? "announces " : "withdraws ") << key
                       << " because FastNetMon ban list " << (direction > 0 ? "had " : "did not have ")
                       << disagreeing_host << " in two full passes in a row";
            }
        }

        rustbgpd_disagreement_marks = marks;
    }
}

// Must be called with rustbgpd_mutex held. Returns true with generation to renew when renewal is due
bool rustbgpd_take_due_renewal(rustbgpd_clock_t::time_point& next_renewal, rustbgpd::v1::LeaseGeneration& generation) {
    auto now = rustbgpd_clock_t::now();

    if (!fastnetmon_global_configuration.rustbgpd_lease || !rustbgpd_lease_generation_known || now < next_renewal) {
        return false;
    }

    next_renewal = now + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_lease_time / 3);

    bool any_wanted = false;

    for (const auto& [key, state] : rustbgpd_routes) {
        any_wanted = any_wanted || !state.contributors.empty();
    }

    if (!any_wanted) {
        // Nothing to keep, let lease expire
        rustbgpd_lease_generation_known = false;
        rustbgpd_lease_valid_until      = rustbgpd_clock_t::time_point{};
        return false;
    }

    generation = rustbgpd_lease_generation;
    return true;
}

void rustbgpd_worker_thread() {
    // Lets signal handler see that we do not use anything anymore
    class exit_flag_t {
        public:
        ~exit_flag_t() {
            rustbgpd_worker_exited = true;
        }
    } exit_flag;

    bool reachable                    = true;
    grpc::StatusCode last_probe_error = grpc::StatusCode::OK;

    // Changed withdrawals go first, unless one of them stalled last round: then changed announces get their turn
    bool announces_first = false;

    // Channel was ready once. New channel starts idle, which is not reconnect
    bool was_ready = false;

    auto next_full_pass =
        rustbgpd_clock_t::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval);
    auto next_renewal = rustbgpd_clock_t::now() + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_lease_time / 3);

    while (true) {
        {
            std::unique_lock<std::mutex> lock(rustbgpd_mutex);
            rustbgpd_worker_wakeup.wait_for(lock, rustbgpd_probe_interval, [] {
                return rustbgpd_worker_stop || rustbgpd_signal_stop || rustbgpd_work_pending;
            });

            if (rustbgpd_worker_stop || rustbgpd_signal_stop) {
                return;
            }

            rustbgpd_work_pending = false;
        }

        // Channel which is not ready lost its connection since last probe: rustbgpd may have restarted faster than
        // our probe could fail, so we handle it as reconnect and resend everything
        if (was_ready && rustbgpd_channel->GetState(false) != GRPC_CHANNEL_READY) {
            reachable = false;
        }

        grpc::Status probe = rustbgpd_check_liveness();

        if (rustbgpd_signal_stop) {
            return;
        }

        if (!probe.ok()) {
            if (reachable || probe.error_code() != last_probe_error) {
                logger << log4cpp::Priority::ERROR << "rustbgpd at " << fastnetmon_global_configuration.rustbgpd_target
                       << " did not answer liveness probe: " << rustbgpd_describe_status(probe);
            }

            reachable        = false;
            last_probe_error = probe.error_code();
            continue;
        }

        was_ready = true;

        std::vector<std::pair<std::string, rustbgpd_job_t>> jobs;
        bool renew_lease = false;
        bool full_pass   = !reachable || rustbgpd_clock_t::now() >= next_full_pass;
        rustbgpd::v1::LeaseGeneration generation;

        {
            std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

            if (rustbgpd_full_pass_requested) {
                full_pass                    = true;
                rustbgpd_full_pass_requested = false;
            }
        }

        if (full_pass) {
            rustbgpd_converge_with_ban_lists();
        }

        {
            std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

            auto now = rustbgpd_clock_t::now();

            if (full_pass) {
                if (!reachable && !rustbgpd_routes.empty()) {
                    logger << log4cpp::Priority::INFO << "rustbgpd is reachable, will announce all "
                           << rustbgpd_routes.size() << " routes again";
                }

                rustbgpd_schedule_full_pass();
                next_full_pass = now + std::chrono::seconds(fastnetmon_global_configuration.rustbgpd_reconcile_interval);
            }

            renew_lease = rustbgpd_take_due_renewal(next_renewal, generation);

            for (const auto& [key, state] : rustbgpd_routes) {
                if (state.synced_version != state.version && state.retry_after <= now) {
                    rustbgpd_job_t job;
                    job.route        = state.route;
                    job.announce     = !state.contributors.empty();
                    job.version      = state.version;
                    job.changed      = state.changed;
                    job.last_error   = state.last_error;
                    job.last_attempt = state.last_attempt;

                    jobs.push_back({ key, job });
                }
            }

            // Changed withdrawals, then changed announces (or the other way round, see announces_first), then
            // resending of unchanged routes. Within each class route which waited longest goes first, so route which
            // failed goes to the back. Routes in backoff are not in this list at all
            auto job_class = [&](const rustbgpd_job_t& job) {
                if (!job.changed) {
                    return 2;
                }

                return job.announce == announces_first ? 0 : 1;
            };

            std::stable_sort(jobs.begin(), jobs.end(), [&](const auto& a, const auto& b) {
                if (job_class(a.second) != job_class(b.second)) {
                    return job_class(a.second) < job_class(b.second);
                }

                return a.second.last_attempt < b.second.last_attempt;
            });

            // We took all work pending so far, only changes after this point should interrupt this round
            rustbgpd_work_pending = false;
        }

        reachable        = true;
        last_probe_error = grpc::StatusCode::OK;

        if (renew_lease) {
            rustbgpd_renew_lease(generation);
        }

        unsigned int sent = 0, route_changes = 0, failed = 0;
        const rustbgpd_job_t* stalled = nullptr;

        for (auto& [key, job] : jobs) {
            // Many slow calls in one batch must not let our lease expire
            {
                std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);
                renew_lease = rustbgpd_take_due_renewal(next_renewal, generation);
            }

            if (renew_lease) {
                rustbgpd_renew_lease(generation);
            }

            // Ban or unban changed this route after we copied the job: its newer version goes in next round,
            // older one must not reach rustbgpd. Checked after renewal, which can take a whole call timeout
            {
                std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);
                auto it = rustbgpd_routes.find(key);

                if (it == rustbgpd_routes.end() || it->second.version != job.version) {
                    continue;
                }
            }

            rustbgpd_call_result_t result = job.announce ? rustbgpd_add_route(job) : rustbgpd_delete_route(job);

            if (rustbgpd_signal_stop) {
                return;
            }

            std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

            if (rustbgpd_worker_stop) {
                return;
            }

            rustbgpd_apply_result(key, job, result);

            sent++;
            route_changes += job.route_changed;
            failed += result != rustbgpd_call_result_t::success;

            // rustbgpd does not answer in time: probe and back off instead of waiting on every other route.
            // New ban or unban during resending of unchanged routes: handle it first, rest waits for next round. We
            // do not stop sending changed routes for it: collecting next round looks at every route, and doing it
            // for each ban of a burst would cost quadratic time
            if (result == rustbgpd_call_result_t::transient_failure) {
                stalled = &job;
                break;
            }

            if (rustbgpd_work_pending && !job.changed) {
                break;
            }
        }

        // Stalled changed withdrawal lets changed announces go first next round, and stalled announce the other way
        announces_first = stalled != nullptr && stalled->changed && !stalled->announce;

        // Connection may have dropped during this round and the last call may have reconnected to restarted
        // rustbgpd already, then channel would look ready at next probe. Check it now as well
        if (rustbgpd_channel->GetState(false) != GRPC_CHANNEL_READY) {
            reachable = false;
        }

        if (full_pass && !jobs.empty()) {
            logger << log4cpp::Priority::INFO << "rustbgpd full pass sent " << sent << " of " << jobs.size()
                   << " routes: " << route_changes << " changed in rustbgpd, " << failed << " failed"
                   << (sent < jobs.size() ? ", others in next round" : "");
        }
    }
}

void rustbgpd_action_shutdown() {
    // FastNetMon's signal handler calls exit(), which runs us from atexit inside that handler. Signal handler
    // already stopped worker with rustbgpd_action_signal_shutdown and we must not lock or join here
    if (rustbgpd_signal_stop) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

        if (!rustbgpd_worker_running) {
            return;
        }

        rustbgpd_worker_stop = true;

        if (rustbgpd_current_call != nullptr) {
            rustbgpd_current_call->TryCancel();
        }
    }

    rustbgpd_worker_wakeup.notify_all();
    rustbgpd_worker->join();

    delete rustbgpd_worker;
    rustbgpd_worker = nullptr;

    std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

    rustbgpd_worker_running = false;
    rustbgpd_worker_stop    = false;

    rustbgpd_routes.clear();
    rustbgpd_disagreement_marks.clear();
    rustbgpd_lease_generation_known = false;
    rustbgpd_lease_valid_until      = rustbgpd_clock_t::time_point{};
    rustbgpd_injection_stub.reset();
    rustbgpd_control_stub.reset();
    rustbgpd_channel.reset();
    rustbgpd_token.clear();

    logger << log4cpp::Priority::INFO << "rustbgpd action stopped";
}

bool rustbgpd_action_signal_shutdown() {
    // Only async-signal-safe operations: lock free atomics and nanosleep
    rustbgpd_signal_stop = true;

    // Worker does not get this signal, so we never run on it. It stops before its next call; call in progress ends
    // by its deadline. If this signal interrupted thread which holds rustbgpd_mutex, worker may wait for that lock
    // forever, so we wait for call deadline plus one second only: 6 seconds
    for (unsigned int i = 0; i < (rustbgpd_call_timeout + 1) * 100 && !rustbgpd_worker_exited; i++) {
        struct timespec delay = { 0, 10 * 1000 * 1000 };
        nanosleep(&delay, nullptr);
    }

    return rustbgpd_worker_exited;
}

void rustbgpd_read_bool(const std::string& name, bool& value) {
    if (configuration_map.count(name)) {
        value = configuration_map[name] == "on";
    }
}

void rustbgpd_read_string(const std::string& name, std::string& value) {
    if (configuration_map.count(name)) {
        value = configuration_map[name];
    }
}

bool rustbgpd_read_number(const std::string& name, unsigned int& value, unsigned int min, unsigned int max) {
    if (configuration_map.count(name) == 0) {
        return true;
    }

    const std::string& text = configuration_map[name];
    int parsed              = 0;

    // FastNetMon's parser accepts leading number of longer string, as 30 of 30x: we require decimal digits only
    bool decimal = !text.empty() && text.size() <= 9 && text.find_first_not_of("0123456789") == std::string::npos;

    if (!decimal || !convert_string_to_positive_integer_safe(text, parsed) || parsed < int(min) || parsed > int(max)) {
        logger << log4cpp::Priority::ERROR << name << " must be a number from " << min << " to " << max << ", got "
               << configuration_map[name];
        return false;
    }

    value = parsed;
    return true;
}

bool rustbgpd_read_next_hop(const std::string& name, std::string& value, int family) {
    rustbgpd_read_string(name, value);

    unsigned char buffer[sizeof(struct in6_addr)];

    if (inet_pton(family, value.c_str(), buffer) != 1) {
        logger << log4cpp::Priority::ERROR << "Cannot parse " << name << " as IP" << (family == AF_INET ? "v4" : "v6")
               << " address: " << value;
        return false;
    }

    return true;
}

// ASN:value with decimal parts from 0 to 65535. FastNetMon's parser would read 65535:0x29a as 65535:0
bool rustbgpd_valid_community(const std::string& value) {
    auto colon = value.find(':');

    if (colon == std::string::npos || value.find(':', colon + 1) != std::string::npos) {
        return false;
    }

    for (const auto& part : { value.substr(0, colon), value.substr(colon + 1) }) {
        if (part.empty() || part.size() > 5 || part.find_first_not_of("0123456789") != std::string::npos || std::stoul(part) > 65535) {
            return false;
        }
    }

    return true;
}

bool rustbgpd_read_community(const std::string& name, std::string& value) {
    rustbgpd_read_string(name, value);

    bgp_community_attribute_element_t community;

    if (!rustbgpd_valid_community(value) || !read_bgp_community_from_string(value, community)) {
        logger << log4cpp::Priority::ERROR << "Cannot parse " << name << " as BGP community: " << value;
        return false;
    }

    return true;
}

// Accepts unix:///absolute/path, or literal loopback address with port: 127.0.0.0/8 as 127.0.0.1:50051 or ::1 as
// [::1]:50051. We never accept host names: bearer token must not leave this host. Sets target for gRPC which
// does not use DNS resolver
bool rustbgpd_parse_target(const std::string& target, std::string& grpc_target, bool& unix_socket) {
    unix_socket = false;

    if (target.rfind("unix:", 0) == 0) {
        std::string path = target.substr(strlen("unix:"));

        if (path.rfind("//", 0) == 0) {
            path = path.substr(2);
        }

        if (path.empty() || path[0] != '/') {
            return false;
        }

        unix_socket = true;
        grpc_target = "unix:" + path;
        return true;
    }

    std::string host;
    std::string port;

    if (!target.empty() && target[0] == '[') {
        auto end = target.find("]:");

        if (end == std::string::npos) {
            return false;
        }

        host = target.substr(1, end - 1);
        port = target.substr(end + 2);

        struct in6_addr address;

        if (inet_pton(AF_INET6, host.c_str(), &address) != 1 || !IN6_IS_ADDR_LOOPBACK(&address)) {
            return false;
        }

        grpc_target = "ipv6:[" + host + "]:";
    } else {
        auto separator = target.rfind(':');

        if (separator == std::string::npos) {
            return false;
        }

        host = target.substr(0, separator);
        port = target.substr(separator + 1);

        // inet_pton accepts only four decimal octets, never names
        struct in_addr address;

        if (inet_pton(AF_INET, host.c_str(), &address) != 1 || (ntohl(address.s_addr) >> 24) != 127) {
            return false;
        }

        grpc_target = "ipv4:" + host + ":";
    }

    if (port.empty() || port.size() > 5 || port.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }

    int port_number = std::stoi(port);

    if (port_number < 1 || port_number > 65535) {
        return false;
    }

    grpc_target += port;
    return true;
}

std::string rustbgpd_check_token_file_metadata(const struct stat& file_stat, uid_t effective_uid) {
    if (!S_ISREG(file_stat.st_mode)) {
        return "it is not a regular file";
    }

    if (file_stat.st_uid != effective_uid && file_stat.st_uid != 0) {
        return "it must be owned by the user who runs FastNetMon or by root";
    }

    if ((file_stat.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return "it must not be accessible by group or others, use chmod 600";
    }

    return "";
}

// Reads bearer token. File must be regular file of user who runs FastNetMon or root, without access for group
// and others. We never log token itself
bool rustbgpd_read_token_file(const std::string& path, std::string& token) {
    const size_t max_token_file_size = 4096;

    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

    if (fd < 0) {
        logger << log4cpp::Priority::ERROR << "Cannot open rustbgpd_token_file " << path << ": " << strerror(errno)
               << (errno == ELOOP || errno == EMLINK ? " (symbolic links are not allowed)" : "");
        return false;
    }

    struct stat file_stat;
    std::string error;

    if (fstat(fd, &file_stat) != 0) {
        error = std::string("cannot stat it: ") + strerror(errno);
    } else {
        error = rustbgpd_check_token_file_metadata(file_stat, geteuid());
    }

    std::string content;

    if (error.empty()) {
        char buffer[max_token_file_size + 1];
        size_t total = 0;

        while (total < sizeof(buffer)) {
            ssize_t got = read(fd, buffer + total, sizeof(buffer) - total);

            if (got < 0 && errno == EINTR) {
                continue;
            }

            if (got < 0) {
                error = std::string("cannot read it: ") + strerror(errno);
                break;
            }

            if (got == 0) {
                break;
            }

            total += got;
        }

        if (error.empty() && total > max_token_file_size) {
            error = "it is larger than " + std::to_string(max_token_file_size) + " bytes";
        }

        content.assign(buffer, error.empty() ? total : 0);
    }

    close(fd);

    if (error.empty()) {
        boost::algorithm::trim(content);

        if (content.empty()) {
            error = "it is empty";
        } else if (std::any_of(content.begin(), content.end(), [](char c) { return c < 0x21 || c > 0x7e; })) {
            // Token goes to HTTP/2 header
            error = "token must consist of printable ASCII characters without spaces";
        }
    }

    if (!error.empty()) {
        logger << log4cpp::Priority::ERROR << "Cannot use rustbgpd_token_file " << path << ": " << error;
        return false;
    }

    token = content;
    return true;
}

// rustbgpd's rule for lease owner: 1-64 bytes of [A-Za-z0-9._-]
bool rustbgpd_valid_lease_owner(const std::string& owner) {
    return !owner.empty() && owner.size() <= 64 && std::all_of(owner.begin(), owner.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}

bool rustbgpd_action_init() {
    logger << log4cpp::Priority::INFO << "rustbgpd action module loaded";

    if (rustbgpd_worker_running) {
        logger << log4cpp::Priority::ERROR << "rustbgpd action is already running";
        return false;
    }

    auto& configuration = fastnetmon_global_configuration;

    rustbgpd_read_string("rustbgpd_target", configuration.rustbgpd_target);
    rustbgpd_read_string("rustbgpd_token_file", configuration.rustbgpd_token_file);
    rustbgpd_read_bool("rustbgpd_announce_host", configuration.rustbgpd_announce_host);
    rustbgpd_read_bool("rustbgpd_announce_whole_subnet", configuration.rustbgpd_announce_whole_subnet);
    rustbgpd_read_bool("rustbgpd_announce_host_ipv6", configuration.rustbgpd_announce_host_ipv6);
    rustbgpd_read_bool("rustbgpd_lease", configuration.rustbgpd_lease);
    rustbgpd_read_string("rustbgpd_lease_owner", configuration.rustbgpd_lease_owner);

    bool valid =
        rustbgpd_read_next_hop("rustbgpd_next_hop_host_ipv4", configuration.rustbgpd_next_hop_host_ipv4, AF_INET) &&
        rustbgpd_read_next_hop("rustbgpd_next_hop_subnet_ipv4", configuration.rustbgpd_next_hop_subnet_ipv4, AF_INET) &&
        rustbgpd_read_next_hop("rustbgpd_next_hop_host_ipv6", configuration.rustbgpd_next_hop_host_ipv6, AF_INET6) &&
        rustbgpd_read_community("rustbgpd_community_host", configuration.rustbgpd_community_host) &&
        rustbgpd_read_community("rustbgpd_community_subnet", configuration.rustbgpd_community_subnet) &&
        rustbgpd_read_community("rustbgpd_community_host_ipv6", configuration.rustbgpd_community_host_ipv6) &&
        rustbgpd_read_number("rustbgpd_reconcile_interval", configuration.rustbgpd_reconcile_interval, 1, 3600) &&
        rustbgpd_read_number("rustbgpd_lease_time", configuration.rustbgpd_lease_time, 5, 3600);

    if (!valid) {
        return false;
    }

    // rustbgpd accepts plaintext gRPC only from its owner-only Unix socket or with bearer token
    // We do not send token in plaintext anywhere but loopback
    std::string grpc_target;
    bool unix_socket = false;

    if (!rustbgpd_parse_target(configuration.rustbgpd_target, grpc_target, unix_socket)) {
        logger << log4cpp::Priority::ERROR << "rustbgpd_target must be unix:///absolute/path or literal loopback address "
               << "with port such as 127.0.0.1:50051 or [::1]:50051, got " << configuration.rustbgpd_target;
        return false;
    }

    std::string token;

    if (!configuration.rustbgpd_token_file.empty() && !rustbgpd_read_token_file(configuration.rustbgpd_token_file, token)) {
        return false;
    }

    if (!unix_socket && token.empty()) {
        logger << log4cpp::Priority::ERROR << "rustbgpd accepts TCP connections only with token, please set rustbgpd_token_file";
        return false;
    }

    if (configuration.rustbgpd_lease && !rustbgpd_valid_lease_owner(configuration.rustbgpd_lease_owner)) {
        logger << log4cpp::Priority::ERROR << "rustbgpd_lease_owner must be 1-64 characters of A-Z a-z 0-9 . _ -, got "
               << configuration.rustbgpd_lease_owner;
        return false;
    }

    if (configuration.rustbgpd_lease) {
        logger << log4cpp::Priority::WARN << "rustbgpd leases are enabled. Lease API is not part of rustbgpd's stable v1 API "
               << "and may change in future rustbgpd releases";
    }

    grpc::ChannelArguments channel_arguments;

    // Otherwise gRPC sends socket path as HTTP/2 authority and rustbgpd resets such streams
    if (unix_socket) {
        channel_arguments.SetString(GRPC_ARG_DEFAULT_AUTHORITY, "localhost");
    }

    // Reconnect quickly after rustbgpd restart. Default reconnect backoff grows up to 120 seconds
    // Retrying connection to absent Unix socket or closed loopback port is cheap
    // We keep default minimum connect timeout (GRPC_ARG_MIN_RECONNECT_BACKOFF_MS, 20 seconds) as it also limits time
    // for HTTP/2 handshake
    // gRPC sends even literal addresses through proxy from grpc_proxy, https_proxy or http_proxy. Our channel is
    // plaintext and carries bearer token, it must go to rustbgpd directly
    channel_arguments.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);

    channel_arguments.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS, 250);
    channel_arguments.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, 250);

    // Worker and threads gRPC starts for our channel inherit our signal mask. With SIGINT blocked FastNetMon's
    // shutdown handler never runs on them. We do not block other signals: synchronous faults as SIGSEGV must reach
    // FastNetMon's crash handler, and blocking them has undefined results
    sigset_t shutdown_signals;
    sigset_t previous_signals;
    sigemptyset(&shutdown_signals);
    sigaddset(&shutdown_signals, SIGINT);
    pthread_sigmask(SIG_BLOCK, &shutdown_signals, &previous_signals);

    auto channel = grpc::CreateCustomChannel(grpc_target, grpc::InsecureChannelCredentials(), channel_arguments);

    {
        std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

        rustbgpd_token          = token;
        rustbgpd_channel        = channel;
        rustbgpd_injection_stub = rustbgpd::v1::InjectionService::NewStub(channel);
        rustbgpd_control_stub   = rustbgpd::v1::ControlService::NewStub(channel);

        rustbgpd_worker_running = true;
        rustbgpd_worker_exited  = false;

        rustbgpd_worker = new boost::thread(rustbgpd_worker_thread);
        set_boost_process_name(rustbgpd_worker, "rustbgpd");
    }

    pthread_sigmask(SIG_SETMASK, &previous_signals, nullptr);

    // Stop worker before global variables are destroyed on any exit path
    static bool shutdown_registered = false;

    if (!shutdown_registered) {
        std::atexit(rustbgpd_action_shutdown);
        shutdown_registered = true;
    }

    logger << log4cpp::Priority::INFO << "rustbgpd action will use " << configuration.rustbgpd_target;

    return true;
}

rustbgpd_route_t
rustbgpd_build_route(const std::string& prefix, uint32_t prefix_length, const std::string& next_hop, const std::string& community_as_string) {
    rustbgpd_route_t route;

    route.prefix        = prefix;
    route.prefix_length = prefix_length;
    route.next_hop      = next_hop;

    // We validated it on start
    bgp_community_attribute_element_t community;

    if (read_bgp_community_from_string(community_as_string, community)) {
        route.communities.push_back(uint32_t(community.asn_number) << 16 | community.community_number);
    }

    return route;
}

std::vector<rustbgpd_route_t> rustbgpd_routes_for_host(bool ipv6,
                                                       uint32_t client_ip,
                                                       const subnet_ipv6_cidr_mask_t& client_ipv6,
                                                       const attack_details_t& current_attack,
                                                       std::string& host,
                                                       bool log_errors) {
    const auto& configuration = fastnetmon_global_configuration;

    std::vector<rustbgpd_route_t> routes;

    if (ipv6) {
        char address[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &client_ipv6.subnet_address, address, sizeof(address));
        host = address;

        if (configuration.rustbgpd_announce_host_ipv6) {
            routes.push_back(rustbgpd_build_route(host, 128, configuration.rustbgpd_next_hop_host_ipv6,
                                                  configuration.rustbgpd_community_host_ipv6));
        }
    } else {
        host = convert_ip_as_uint_to_string(client_ip);

        const subnet_cidr_mask_t& network = current_attack.customer_network;

        if (configuration.rustbgpd_announce_whole_subnet && (network.cidr_prefix_length == 0 || network.subnet_address == 0)) {
            // Attack without customer network would make us blackhole default route
            logger << (log_errors ? log4cpp::Priority::ERROR : log4cpp::Priority::DEBUG) << "rustbgpd will not announce customer subnet "
                   << convert_ipv4_subnet_to_string(network) << " for " << host << ", attack has no customer network";
        } else if (configuration.rustbgpd_announce_whole_subnet) {
            routes.push_back(rustbgpd_build_route(convert_ip_as_uint_to_string(network.subnet_address),
                                                  network.cidr_prefix_length, configuration.rustbgpd_next_hop_subnet_ipv4,
                                                  configuration.rustbgpd_community_subnet));
        }

        if (configuration.rustbgpd_announce_host) {
            routes.push_back(rustbgpd_build_route(host, 32, configuration.rustbgpd_next_hop_host_ipv4,
                                                  configuration.rustbgpd_community_host));
        }

        // Customer network /32 is the host itself: one route, host announce with its next hop and community wins
        if (routes.size() == 2 && routes[0].key() == routes[1].key()) {
            routes.erase(routes.begin());
        }
    }

    return routes;
}

void rustbgpd_ban_manage(const std::string& action,
                         bool ipv6,
                         uint32_t client_ip,
                         const subnet_ipv6_cidr_mask_t& client_ipv6,
                         const attack_details_t& current_attack) {
    std::string host;
    std::vector<rustbgpd_route_t> routes = rustbgpd_routes_for_host(ipv6, client_ip, client_ipv6, current_attack, host, true);

    std::lock_guard<std::mutex> lock_guard(rustbgpd_mutex);

    if (!rustbgpd_worker_running) {
        logger << log4cpp::Priority::ERROR << "rustbgpd action is not running, ignoring " << action << " for " << host;
        return;
    }

    // FastNetMon adds host to its ban list and may write attack details to disk before it calls us, and nothing
    // keeps these steps together with unban. Unban removes host from ban list before it calls actions (API) or
    // shortly after (unban of expired bans). Ban which reaches us after host left ban list was overtaken by its unban
    // and must not announce anything. We check while we hold our lock. Removing host from ban list does not take our
    // lock, but unban's own call of this function does: if host leaves ban list after this check, that call waits
    // for us and withdraws what this ban announced. We read FastNetMon's ban list because it is FastNetMon's own
    // record of current bans. It does not order everything: unban of expired bans changes it only after its action
    // calls, which full passes handle (see rustbgpd_converge_with_ban_lists)
    bool still_banned = ipv6 ? ban_list_ipv6.is_blackholed(client_ipv6) : ban_list_ipv4.is_blackholed(client_ip);

    if (action == "ban" && !still_banned) {
        logger << log4cpp::Priority::WARN << "rustbgpd ignores ban of " << host
               << ": host is not in FastNetMon ban list anymore, its unban came first";
        return;
    }

    if (rustbgpd_copy_in_progress) {
        rustbgpd_hosts_changed_in_copy.insert(host);
    }

    // Ban or unban of host is newer than anything full pass saw about it
    rustbgpd_disagreement_marks.erase(host);

    for (const auto& route : routes) {
        auto& state = rustbgpd_routes[route.key()];

        bool wanted_before = !state.contributors.empty();

        // In place: subnet route may have many contributors
        if (action == "ban") {
            state.contributors.insert(host);
        } else {
            state.contributors.erase(host);
        }

        rustbgpd_contributors_changed(state, route, wanted_before);

        bool wanted_now = !state.contributors.empty();

        logger << log4cpp::Priority::INFO << "rustbgpd " << (wanted_now ? "announce" : "withdrawal") << " of "
               << route.key() << " requested by " << action << " of " << host << ", " << state.contributors.size()
               << " banned hosts need it";
    }

    rustbgpd_run_test_checkpoint("ban_manage_locked");

    rustbgpd_work_pending = true;
    rustbgpd_worker_wakeup.notify_all();
}
