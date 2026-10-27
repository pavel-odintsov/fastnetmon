// Tests for rustbgpd action against in-process mock of rustbgpd's gRPC API
//
// cmake -DBUILD_TESTS=ON .. && make rustbgpd_action_tests && ./rustbgpd_action_tests

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "log4cpp/Category.hh"
#include "log4cpp/LayoutAppender.hh"
#include "log4cpp/Priority.hh"

#include "../actions/rustbgpd_action.hpp"
#include "../fastnetmon_configuration_scheme.hpp"

#include "../ban_list.hpp"
#include "../rustbgpd_client/rustbgpd_injection.grpc.pb.h"

log4cpp::Category& logger = log4cpp::Category::getRoot();
std::map<std::string, std::string> configuration_map;
fastnetmon_configuration_t fastnetmon_global_configuration;
blackhole_ban_list_t<uint32_t> ban_list_ipv4;
blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

using namespace std::chrono_literals;

// Keeps all log messages so tests can check them
class captured_log_t : public log4cpp::LayoutAppender {
    public:
    captured_log_t() : log4cpp::LayoutAppender("captured") {
    }

    void close() override {
    }

    std::string text() {
        std::lock_guard<std::mutex> lock_guard(mutex);
        return buffer;
    }

    void clear() {
        std::lock_guard<std::mutex> lock_guard(mutex);
        buffer.clear();
    }

    protected:
    void _append(const log4cpp::LoggingEvent& event) override {
        std::lock_guard<std::mutex> lock_guard(mutex);
        // Priority name first, so tests can check log level too
        buffer += log4cpp::Priority::getPriorityName(event.priority) + " " + event.message + "\n";
    }

    private:
    std::mutex mutex;
    std::string buffer;
};

captured_log_t* captured_log = nullptr;

// State of mock rustbgpd and knobs which change its behaviour
class mock_state_t {
    public:
    std::mutex mutex;
    std::map<std::string, rustbgpd::v1::AddPathRequest> routes;
    std::map<std::string, std::string> owners;

    std::atomic<int> adds_started{ 0 };
    std::atomic<int> deletes{ 0 };
    std::atomic<int> renewals{ 0 };

    std::atomic<int> add_delay_ms{ 0 };

    // Announces wait while it is set
    std::atomic<bool> hold_adds{ false };

    // Status for announces, OK means normal answer
    std::atomic<int> add_status_code{ grpc::StatusCode::OK };

    // Answer next announce without outcome
    std::atomic<bool> omit_next_add_outcome{ false };

    // Answer OK without outcome
    std::atomic<bool> omit_outcome{ false };

    // Answer leased add without generation
    std::atomic<bool> omit_generation{ false };

    // After answering next leased add, expire lease: drop owner's routes and start new generation on next add
    std::atomic<bool> expire_after_next_add{ false };

    std::atomic<int> liveness_code{ grpc::StatusCode::OK };

    bool lease_live = false;
    std::chrono::steady_clock::time_point lease_deadline{};

    // Lease expired at least once
    std::atomic<bool> lease_expired{ false };

    std::atomic<int> delete_delay_ms{ 0 };

    // Announces per route key, under mutex
    std::map<std::string, int> adds_per_key;

    int adds_of(const std::string& key) {
        std::lock_guard<std::mutex> lock_guard(mutex);
        return adds_per_key[key];
    }

    // Withdrawals per route key, under mutex
    std::map<std::string, int> deletes_per_key;

    int deletes_of(const std::string& key) {
        std::lock_guard<std::mutex> lock_guard(mutex);
        return deletes_per_key[key];
    }

    // Longest time to deadline seen on withdrawals, in milliseconds
    std::atomic<long> longest_delete_deadline_ms{ 0 };
    uint64_t incarnation = 7;
    uint64_t sequence    = 1;

    std::string last_authorization;

    // Expires lease as rustbgpd does when its deadline passed: drops owned routes
    void expire_if_due() {
        std::lock_guard<std::mutex> lock_guard(mutex);

        if (!lease_live || std::chrono::steady_clock::now() < lease_deadline) {
            return;
        }

        for (auto it = routes.begin(); it != routes.end();) {
            if (!owners[it->first].empty()) {
                it = routes.erase(it);
            } else {
                ++it;
            }
        }

        lease_live    = false;
        lease_expired = true;
    }

    bool has(const std::string& key) {
        std::lock_guard<std::mutex> lock_guard(mutex);
        return routes.count(key) > 0;
    }
};

std::string route_key(const std::string& prefix, uint32_t length) {
    return prefix + "/" + std::to_string(length);
}

class mock_injection_t final : public rustbgpd::v1::InjectionService::Service {
    public:
    explicit mock_injection_t(mock_state_t& state) : state(state) {
    }

    grpc::Status AddPath(grpc::ServerContext* context,
                         const rustbgpd::v1::AddPathRequest* request,
                         rustbgpd::v1::AddPathResponse* response) override {
        if (state.add_status_code != grpc::StatusCode::OK) {
            state.adds_started++;
            return grpc::Status(grpc::StatusCode(state.add_status_code.load()), "mock announce failure");
        }

        auto outcome = add(context, *request, "");
        set_outcome(response, outcome);
        return grpc::Status::OK;
    }

    grpc::Status AddLeasedPath(grpc::ServerContext* context,
                               const rustbgpd::v1::AddLeasedPathRequest* request,
                               rustbgpd::v1::AddLeasedPathResponse* response) override {
        state.expire_if_due();

        auto outcome = add(context, request->path(), request->lease().owner());
        set_outcome(response->mutable_result(), outcome);

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        if (!state.lease_live) {
            state.lease_live = true;
            state.sequence++;
        }

        state.lease_deadline = std::max(state.lease_deadline, std::chrono::steady_clock::now() +
                                                                  std::chrono::seconds(request->lease().lease_seconds()));

        if (!state.omit_generation) {
            response->mutable_generation()->set_incarnation(state.incarnation);
            response->mutable_generation()->set_sequence(state.sequence);
        }

        if (state.expire_after_next_add.exchange(false)) {
            for (auto it = state.routes.begin(); it != state.routes.end();) {
                if (state.owners[it->first] == request->lease().owner()) {
                    it = state.routes.erase(it);
                } else {
                    ++it;
                }
            }

            state.lease_live = false;
        }

        return grpc::Status::OK;
    }

    grpc::Status DeletePath(grpc::ServerContext* context,
                            const rustbgpd::v1::DeletePathRequest* request,
                            rustbgpd::v1::DeletePathResponse* response) override {
        long deadline_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(context->deadline() - std::chrono::system_clock::now())
                .count();
        state.longest_delete_deadline_ms = std::max(state.longest_delete_deadline_ms.load(), deadline_ms);

        state.expire_if_due();
        std::this_thread::sleep_for(std::chrono::milliseconds(state.delete_delay_ms.load()));
        state.expire_if_due();

        state.deletes++;

        std::lock_guard<std::mutex> lock_guard(state.mutex);
        state.deletes_per_key[route_key(request->prefix(), request->prefix_length())]++;

        if (state.routes.erase(route_key(request->prefix(), request->prefix_length())) > 0) {
            response->set_outcome(rustbgpd::v1::PATH_DELETE_OUTCOME_DELETED);
        } else if (request->allow_missing()) {
            response->set_outcome(rustbgpd::v1::PATH_DELETE_OUTCOME_NOT_PRESENT);
        } else {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "no such route");
        }

        if (state.omit_outcome) {
            response->clear_outcome();
        }

        return grpc::Status::OK;
    }

    grpc::Status RenewLease(grpc::ServerContext* context,
                            const rustbgpd::v1::RenewLeaseRequest* request,
                            rustbgpd::v1::RenewLeaseResponse* response) override {
        state.expire_if_due();
        state.renewals++;

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        if (!state.lease_live || request->generation().incarnation() != state.incarnation ||
            request->generation().sequence() != state.sequence) {
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "not the live lease");
        }

        state.lease_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(request->lease_seconds());
        *response->mutable_generation() = request->generation();
        return grpc::Status::OK;
    }

    private:
    rustbgpd::v1::PathInjectOutcome
    add(grpc::ServerContext* context, const rustbgpd::v1::AddPathRequest& request, const std::string& owner) {
        state.adds_started++;

        std::this_thread::sleep_for(std::chrono::milliseconds(state.add_delay_ms.load()));

        while (state.hold_adds) {
            std::this_thread::sleep_for(5ms);
        }

        std::lock_guard<std::mutex> lock_guard(state.mutex);

        auto authorization = context->client_metadata().find("authorization");

        if (authorization != context->client_metadata().end()) {
            state.last_authorization = std::string(authorization->second.data(), authorization->second.size());
        }

        auto key     = route_key(request.prefix(), request.prefix_length());
        bool existed = state.routes.count(key) > 0;

        state.routes[key] = request;
        state.adds_per_key[key]++;
        state.owners[key] = owner;

        return existed ? rustbgpd::v1::PATH_INJECT_OUTCOME_UNCHANGED : rustbgpd::v1::PATH_INJECT_OUTCOME_CREATED;
    }

    void set_outcome(rustbgpd::v1::AddPathResponse* response, rustbgpd::v1::PathInjectOutcome outcome) {
        if (!state.omit_outcome && !state.omit_next_add_outcome.exchange(false)) {
            response->set_outcome(outcome);
        }
    }

    mock_state_t& state;
};

class mock_control_t final : public rustbgpd::v1::ControlService::Service {
    public:
    explicit mock_control_t(mock_state_t& state) : state(state) {
    }

    grpc::Status CheckLiveness(grpc::ServerContext* context,
                               const rustbgpd::v1::CheckLivenessRequest* request,
                               rustbgpd::v1::CheckLivenessResponse* response) override {
        int code = state.liveness_code;

        if (code != grpc::StatusCode::OK) {
            return grpc::Status(grpc::StatusCode(code), "mock liveness failure");
        }

        return grpc::Status::OK;
    }

    private:
    mock_state_t& state;
};

bool wait_for(std::function<bool()> condition, std::chrono::milliseconds limit) {
    auto deadline = std::chrono::steady_clock::now() + limit;

    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) {
            return true;
        }

        std::this_thread::sleep_for(20ms);
    }

    return condition();
}

class RustbgpdActionTest : public ::testing::Test {
    protected:
    void SetUp() override {
        char directory_template[] = "/tmp/rustbgpd_action_tests.XXXXXX";
        directory                 = mkdtemp(directory_template);
        socket_path               = directory + "/grpc.sock";

        injection = std::make_unique<mock_injection_t>(state);
        control   = std::make_unique<mock_control_t>(state);

        grpc::ServerBuilder builder;
        builder.AddListeningPort("unix://" + socket_path, grpc::InsecureServerCredentials());
        builder.RegisterService(injection.get());
        builder.RegisterService(control.get());
        server = builder.BuildAndStart();
        ASSERT_TRUE(server);

        configuration_map.clear();
        fastnetmon_global_configuration = fastnetmon_configuration_t{};

        configuration_map["rustbgpd_target"]             = "unix://" + socket_path;
        configuration_map["rustbgpd_reconcile_interval"] = "30";

        captured_log->clear();

        // Ban lists outlive tests, and full passes announce what they hold
        std::vector<uint32_t> banned_ipv4;
        ban_list_ipv4.get_blackholed_hosts(banned_ipv4);

        for (auto host : banned_ipv4) {
            ban_list_ipv4.remove_from_blackhole(host);
        }

        std::vector<subnet_ipv6_cidr_mask_t> banned_ipv6;
        ban_list_ipv6.get_blackholed_hosts(banned_ipv6);

        for (auto host : banned_ipv6) {
            ban_list_ipv6.remove_from_blackhole(host);
        }
    }

    // Stops mock rustbgpd, forgets its routes as restarted rustbgpd does and starts it again on the same socket
    void restart_server(std::chrono::milliseconds gap) {
        server->Shutdown(std::chrono::system_clock::now() + 1s);
        server.reset();

        {
            std::lock_guard<std::mutex> lock_guard(state.mutex);
            state.routes.clear();
        }

        std::this_thread::sleep_for(gap);

        injection = std::make_unique<mock_injection_t>(state);
        control   = std::make_unique<mock_control_t>(state);

        grpc::ServerBuilder builder;
        builder.AddListeningPort("unix://" + socket_path, grpc::InsecureServerCredentials());
        builder.RegisterService(injection.get());
        builder.RegisterService(control.get());
        server = builder.BuildAndStart();
        ASSERT_TRUE(server);
    }

    size_t count_lines(const std::string& text) {
        std::string log = captured_log->text();
        size_t count    = 0;

        for (size_t position = log.find(text); position != std::string::npos; position = log.find(text, position + 1)) {
            count++;
        }

        return count;
    }

    void TearDown() override {
        rustbgpd_action_shutdown();
        rustbgpd_test_checkpoint = nullptr;
        server->Shutdown(std::chrono::system_clock::now() + 1s);
        std::filesystem::remove_all(directory);
    }

    void ipv4_action(const std::string& action,
                     const std::string& host,
                     subnet_cidr_mask_t customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24)) {
        attack_details_t attack;
        attack.customer_network = customer_network;

        // Same order as FastNetMon: ban list first, then actions. Unban as API does it
        if (action == "ban") {
            ban_list_ipv4.add_to_blackhole(inet_addr(host.c_str()), attack);
        } else {
            ban_list_ipv4.remove_from_blackhole(inet_addr(host.c_str()));
        }

        rustbgpd_ban_manage(action, false, inet_addr(host.c_str()), subnet_ipv6_cidr_mask_t{}, attack);
    }

    std::string write_file(const std::string& name, const std::string& content, mode_t mode) {
        auto path = directory + "/" + name;
        std::ofstream(path) << content;
        chmod(path.c_str(), mode);
        return path;
    }

    mock_state_t state;
    std::unique_ptr<mock_injection_t> injection;
    std::unique_ptr<mock_control_t> control;
    std::unique_ptr<grpc::Server> server;
    std::string directory;
    std::string socket_path;
};

TEST_F(RustbgpdActionTest, announces_and_withdraws_host) {
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    {
        std::lock_guard<std::mutex> lock_guard(state.mutex);
        const auto& route = state.routes["203.0.113.7/32"];

        EXPECT_EQ(route.next_hop(), "0.0.0.0");
        EXPECT_EQ(route.origin(), 2u);
        ASSERT_EQ(route.communities_size(), 1);
        EXPECT_EQ(route.communities(0), 65535u << 16 | 666u);
    }

    ipv4_action("unban", "203.0.113.7");
    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.7/32"); }, 3s));
    EXPECT_TRUE(
        wait_for([&] { return captured_log->text().find("outcome PATH_DELETE_OUTCOME_DELETED") != std::string::npos; }, 1s));
}

// Unban which arrives while announce is still in flight must win and must not wait for it
TEST_F(RustbgpdActionTest, unban_during_slow_announce_withdraws) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.add_delay_ms = 1000;

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started == 1; }, 3s));

    auto started = std::chrono::steady_clock::now();
    ipv4_action("unban", "203.0.113.7");
    EXPECT_LT(std::chrono::steady_clock::now() - started, 200ms) << "unban waited for announce in flight";

    // Announce lands first, then withdrawal must follow
    EXPECT_TRUE(wait_for([&] { return state.deletes >= 1 && !state.has("203.0.113.7/32"); }, 4s));

    std::this_thread::sleep_for(1500ms);
    EXPECT_FALSE(state.has("203.0.113.7/32")) << "route came back after unban";
}

// Ban thread adds host to ban list and stalls (attack file I/O) before it calls actions. Unban from API removes
// host and calls actions first. Late ban must not announce host which is not banned anymore
TEST_F(RustbgpdActionTest, late_ban_after_unban_is_ignored) {
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    // Ban thread: host into ban list, then it stalls
    ban_list_ipv4.add_to_blackhole(host, attack);

    // API unban: out of ban list, then actions
    ban_list_ipv4.remove_from_blackhole(host);
    rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    // Ban thread resumes and calls actions
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    ASSERT_TRUE(wait_for([&] { return state.deletes >= 1; }, 3s));
    std::this_thread::sleep_for(1s);
    EXPECT_FALSE(state.has("203.0.113.7/32")) << "late ban announced host which is not banned";
    EXPECT_NE(captured_log->text().find("rustbgpd ignores ban of 203.0.113.7"), std::string::npos);
}

// Unban of expired ban calls actions before host leaves ban list: delayed ban passes ban list check and announces
// again. Next full pass compares with ban list and withdraws it
TEST_F(RustbgpdActionTest, late_ban_in_expiry_window_withdrawn_by_full_pass) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    ban_list_ipv4.add_to_blackhole(host, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    // Unban of expired bans: actions first
    rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    // Delayed older ban arrives while host is still in ban list
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    // Then host leaves ban list
    ban_list_ipv4.remove_from_blackhole(host);

    // Second full pass after the disagreement acts on it
    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.7/32"); }, 4s)) << "expired ban stays announced";
}

// API unban takes host out of ban list, new ban adds it again and announces, then older unban arrives: next full
// pass compares with ban list and announces again
TEST_F(RustbgpdActionTest, older_unban_after_newer_ban_reannounced_by_full_pass) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    ban_list_ipv4.add_to_blackhole(host, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    // API unban removes host, its action call is delayed
    ban_list_ipv4.remove_from_blackhole(host);

    // New ban of the same host
    ban_list_ipv4.add_to_blackhole(host, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    // Delayed unban arrives
    rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    ASSERT_TRUE(wait_for([&] { return !state.has("203.0.113.7/32"); }, 3s));

    EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 4s)) << "banned host stays withdrawn";
    EXPECT_NE(captured_log->text().find(
                  "rustbgpd announces 203.0.113.7/32 because FastNetMon ban list had 203.0.113.7"),
              std::string::npos);
}

// Full pass builds routes from ban lists with the same announce settings as ban path: no host route when host
// announce is off, no IPv6 route when IPv6 announce is off, and no subnet from attack without customer network
TEST_F(RustbgpdActionTest, full_pass_from_ban_lists_respects_announce_settings) {
    configuration_map["rustbgpd_reconcile_interval"]    = "1";
    configuration_map["rustbgpd_announce_host"]         = "off";
    configuration_map["rustbgpd_announce_whole_subnet"] = "on";
    configuration_map["rustbgpd_announce_host_ipv6"]    = "off";
    ASSERT_TRUE(rustbgpd_action_init());

    // Bans only in ban lists, as after a missed ban call
    attack_details_t with_network;
    with_network.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);
    ban_list_ipv4.add_to_blackhole(inet_addr("203.0.113.7"), with_network);

    attack_details_t without_network;
    ban_list_ipv4.add_to_blackhole(inet_addr("198.51.100.7"), without_network);

    subnet_ipv6_cidr_mask_t ipv6_host;
    inet_pton(AF_INET6, "2001:db8:66::7", &ipv6_host.subnet_address);
    ipv6_host.cidr_prefix_length = 128;
    ban_list_ipv6.add_to_blackhole(ipv6_host, attack_details_t{});

    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.0/24"); }, 4s));
    std::this_thread::sleep_for(1500ms);

    std::lock_guard<std::mutex> lock_guard(state.mutex);
    std::string announced;

    for (const auto& [key, route] : state.routes) {
        announced += key + " ";
    }

    EXPECT_EQ(announced, "203.0.113.0/24 ") << "full pass announced routes which announce settings exclude";
}

// Full pass hooks: count passes and run scripted steps at their start (before ban lists are copied) or right
// after the copy (before it is used)
std::atomic<int> pass_starts{ 0 };
std::atomic<int> pass_copies{ 0 };
std::function<void(int)> on_pass_start;
std::function<void(int)> on_pass_copied;

void pass_checkpoint(const char* point) {
    if (strcmp(point, "converge_starting") == 0) {
        int pass = ++pass_starts;

        if (on_pass_start) {
            on_pass_start(pass);
        }
    } else if (strcmp(point, "converge_copied") == 0) {
        int pass = ++pass_copies;

        if (on_pass_copied) {
            on_pass_copied(pass);
        }
    }
}

void start_pass_script(std::function<void(int)> start, std::function<void(int)> copied) {
    on_pass_start            = start;
    on_pass_copied           = copied;
    pass_starts              = 0;
    pass_copies              = 0;
    rustbgpd_test_checkpoint = pass_checkpoint;
}

void stop_pass_script() {
    rustbgpd_test_checkpoint = nullptr;
    std::this_thread::sleep_for(100ms);
    on_pass_start  = nullptr;
    on_pass_copied = nullptr;
}

// Expiry order across a copy: unban call arrives while pass 1 copies ban lists, host stays in ban list during
// pass 2 and leaves it before pass 3. Pass 1 must ignore its copy for this host, otherwise pass 2 would see the
// same disagreement again and announce the unbanned host
TEST_F(RustbgpdActionTest, full_pass_ignores_host_changed_during_copy) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    ban_list_ipv4.add_to_blackhole(host, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    start_pass_script(
        [&](int pass) {
            if (pass == 3) {
                ban_list_ipv4.remove_from_blackhole(host);
            }
        },
        [&](int pass) {
            if (pass == 1) {
                rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
            }
        });

    ASSERT_TRUE(wait_for([&] { return pass_starts >= 4; }, 6s));
    stop_pass_script();

    EXPECT_FALSE(state.has("203.0.113.7/32"));
    EXPECT_EQ(captured_log->text().find("rustbgpd announces 203.0.113.7/32 because"), std::string::npos)
        << "unbanned host announced again from copy taken during its unban";
}

// Ban or unban of a host between passes makes earlier disagreement of that host obsolete: pass 1 sees expiry order
// disagreement, then host is banned and unbanned again before pass 2, which sees the same disagreement once more.
// It must count as first sighting
TEST_F(RustbgpdActionTest, ban_or_unban_clears_disagreement_mark) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    ban_list_ipv4.add_to_blackhole(host, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    // Unban call first, host stays in ban list: pass 1 marks the disagreement
    rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    std::this_thread::sleep_for(100ms);

    start_pass_script(
        [&](int pass) {
            if (pass == 2) {
                // New attack and its expiry, again in expiry order
                rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
                rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
            } else if (pass == 3) {
                ban_list_ipv4.remove_from_blackhole(host);
            }
        },
        nullptr);

    ASSERT_TRUE(wait_for([&] { return pass_starts >= 4; }, 6s));
    stop_pass_script();

    EXPECT_EQ(captured_log->text().find("rustbgpd announces 203.0.113.7/32 because"), std::string::npos)
        << "disagreement mark survived ban and unban of the host";
    EXPECT_FALSE(state.has("203.0.113.7/32"));
}

// Some other host is banned during every copy: backstop must still correct a host which its ban call missed, on
// the second pass which sees it
TEST_F(RustbgpdActionTest, backstop_works_while_other_hosts_change) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("10.0.0.0"), 8);

    std::atomic<uint32_t> index{ 1 };
    std::atomic<int> fixed_at_pass{ 0 };

    start_pass_script(nullptr, [&](int pass) {
        uint32_t other = htonl((10u << 24) | index++);
        ban_list_ipv4.add_to_blackhole(other, attack);
        rustbgpd_ban_manage("ban", false, other, subnet_ipv6_cidr_mask_t{}, attack);
    });

    // Ban call of this host was lost
    attack_details_t lost;
    lost.customer_network = subnet_cidr_mask_t(inet_addr("192.0.2.0"), 24);
    ban_list_ipv4.add_to_blackhole(inet_addr("192.0.2.77"), lost);
    int first_pass = pass_starts + 1;

    bool fixed = wait_for([&] { return state.has("192.0.2.77/32"); }, 6s);
    int passes = pass_starts - first_pass + 1;
    stop_pass_script();

    EXPECT_TRUE(fixed) << "backstop did not run while other hosts changed";
    EXPECT_LE(passes, 3) << "correction took " << passes << " passes";
}

// Unban of expired bans calls actions before it removes hosts from ban list: full pass which copies ban list in
// that window must not announce host again
TEST_F(RustbgpdActionTest, unban_before_ban_list_removal_never_reannounces) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    ban_list_ipv4.add_to_blackhole(host, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    int adds = state.adds_of("203.0.113.7/32");
    rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    // At least one full pass runs while host is still in ban list
    std::this_thread::sleep_for(1500ms);
    ban_list_ipv4.remove_from_blackhole(host);
    std::this_thread::sleep_for(2500ms);

    EXPECT_EQ(state.adds_of("203.0.113.7/32"), adds) << "unbanned host announced again";
    EXPECT_FALSE(state.has("203.0.113.7/32"));
}

// Bans keep coming while full passes copy ban lists: no ban may be withdrawn
TEST_F(RustbgpdActionTest, ban_churn_during_full_passes_withdraws_nothing) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("10.0.0.0"), 8);

    auto ban = [&](uint32_t index) {
        uint32_t host = htonl((10u << 24) | index);
        ban_list_ipv4.add_to_blackhole(host, attack);
        rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    };

    uint32_t index = 1;

    for (; index <= 5000; index++) {
        ban(index);
    }

    // Unique new bans for 5 seconds, several full passes
    auto end = std::chrono::steady_clock::now() + 5s;

    while (std::chrono::steady_clock::now() < end) {
        ban(index++);
        std::this_thread::sleep_for(1ms);
    }

    std::this_thread::sleep_for(2500ms);
    EXPECT_EQ(state.deletes, 0) << "live bans withdrawn while ban lists changed";
}

// Unban delivered before late ban: route is withdrawn, also when late ban got through
TEST_F(RustbgpdActionTest, late_ban_after_unban_withdrawn_by_full_pass) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    uint32_t host = inet_addr("203.0.113.7");
    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("203.0.113.0"), 24);

    ban_list_ipv4.add_to_blackhole(host, attack);
    ban_list_ipv4.remove_from_blackhole(host);
    rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);

    std::this_thread::sleep_for(3500ms);
    EXPECT_FALSE(state.has("203.0.113.7/32")) << "host which is not banned stays announced";
}

// Announces which always stall must not keep changed withdrawal waiting
TEST_F(RustbgpdActionTest, changed_withdrawal_not_starved_by_stalled_announces) {
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.9");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.9/32"); }, 3s));

    // Announces of hosts which sort before 203.0.113.9 take 6 seconds against 5 second deadline
    state.add_delay_ms = 6000;
    int adds           = state.adds_started;

    for (const auto& host : { "203.0.113.1", "203.0.113.2", "203.0.113.3" }) {
        ipv4_action("ban", host);
    }

    ASSERT_TRUE(wait_for([&] { return state.adds_started > adds; }, 3s));
    ipv4_action("unban", "203.0.113.9");

    // One stalled call in flight, then the withdrawal
    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.9/32"); }, 7s))
        << "withdrawal waited behind stalled announces";
}

// Withdrawals which always stall must not keep changed announce waiting either
TEST_F(RustbgpdActionTest, changed_announce_not_starved_by_stalled_withdrawals) {
    ASSERT_TRUE(rustbgpd_action_init());

    std::vector<std::string> hosts = { "203.0.113.1", "203.0.113.2", "203.0.113.3" };

    for (const auto& host : hosts) {
        ipv4_action("ban", host);
    }

    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.3/32"); }, 3s));

    // Withdrawals take 6 seconds against 5 second deadline
    state.delete_delay_ms = 6000;

    for (const auto& host : hosts) {
        ipv4_action("unban", host);
    }

    // First withdrawal is in flight now
    std::this_thread::sleep_for(1s);
    ipv4_action("ban", "203.0.113.9");

    // At most two stalled withdrawals, then the announce
    EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.9/32"); }, 12s))
        << "announce waited behind stalled withdrawals";
}

// Records connections to a local port, as HTTP proxy would see them
class connection_counter_t {
    public:
    connection_counter_t() {
        listener = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in address{};
        address.sin_family      = AF_INET;
        address.sin_addr.s_addr = inet_addr("127.0.0.1");
        bind(listener, (sockaddr*)&address, sizeof(address));
        listen(listener, 16);

        socklen_t length = sizeof(address);
        getsockname(listener, (sockaddr*)&address, &length);
        port = ntohs(address.sin_port);

        thread = std::thread([this] {
            while (true) {
                int connection = accept(listener, nullptr, nullptr);

                if (connection < 0) {
                    return;
                }

                connections++;
                close(connection);
            }
        });
    }

    ~connection_counter_t() {
        shutdown(listener, SHUT_RDWR);
        close(listener);
        thread.join();
    }

    int listener = -1;
    int port     = 0;
    std::atomic<int> connections{ 0 };
    std::thread thread;
};

// Proxy from environment must not get our plaintext channel with bearer token
TEST_F(RustbgpdActionTest, http_proxy_from_environment_is_not_used) {
    int port = 0;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(injection.get());
    builder.RegisterService(control.get());

    server->Shutdown(std::chrono::system_clock::now() + 1s);
    server = builder.BuildAndStart();
    ASSERT_TRUE(server);

    connection_counter_t proxy;
    std::string proxy_url = "http://127.0.0.1:" + std::to_string(proxy.port);

    unsetenv("grpc_proxy");
    unsetenv("https_proxy");
    unsetenv("no_proxy");
    unsetenv("no_grpc_proxy");
    setenv("http_proxy", proxy_url.c_str(), 1);

    configuration_map["rustbgpd_target"]     = "127.0.0.1:" + std::to_string(port);
    configuration_map["rustbgpd_token_file"] = write_file("token", "secret-token\n", 0600);
    bool started                             = rustbgpd_action_init();

    if (started) {
        ipv4_action("ban", "203.0.113.7");
        EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));
        rustbgpd_action_shutdown();
    }

    unsetenv("http_proxy");

    ASSERT_TRUE(started);
    EXPECT_EQ(proxy.connections, 0) << "channel went through proxy from http_proxy";
}

// Failed answer for announce which is already outdated must not delay withdrawal which replaced it
TEST_F(RustbgpdActionTest, failed_outdated_announce_does_not_delay_withdrawal) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.hold_adds = true;
    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started == 1; }, 3s));

    // Unban while announce is in flight, then announce gets answer which action does not accept
    ipv4_action("unban", "203.0.113.7");
    state.omit_next_add_outcome = true;
    state.hold_adds             = false;

    EXPECT_TRUE(wait_for([&] { return state.deletes >= 1 && !state.has("203.0.113.7/32"); }, 2s))
        << "withdrawal waited for retry delay of outdated announce";
}

// Announce fails as unavailable while liveness probes succeed: retries back off instead of running every probe
TEST_F(RustbgpdActionTest, unavailable_announce_backs_off) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.add_status_code = grpc::StatusCode::UNAVAILABLE;
    ipv4_action("ban", "203.0.113.7");
    std::this_thread::sleep_for(6s);

    // 0.5 s probe interval alone gives about 12 attempts in 6 s, backoff 0.5, 1, 2, 4 s gives 5 at most
    EXPECT_GE(state.adds_started, 3) << "announce was not retried";
    EXPECT_LE(state.adds_started, 6) << "announce retried without backoff";

    state.add_status_code = grpc::StatusCode::OK;
    EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 10s));
}

// Announces stall longer than call deadline during full pass, while liveness probes still answer: unban of other host
// must not wait behind all of them
TEST_F(RustbgpdActionTest, withdrawal_not_stuck_behind_stalled_announces) {
    ASSERT_TRUE(rustbgpd_action_init());

    std::vector<std::string> hosts = { "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.9" };

    for (const auto& host : hosts) {
        ipv4_action("ban", host);
    }

    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.9/32"); }, 3s));

    // Full pass after probe failure, every announce now takes 6 seconds against 5 second deadline
    state.add_delay_ms  = 6000;
    int adds            = state.adds_started;
    state.liveness_code = grpc::StatusCode::UNAVAILABLE;
    ASSERT_TRUE(wait_for([&] { return captured_log->text().find("did not answer liveness probe") != std::string::npos; }, 3s));
    state.liveness_code = grpc::StatusCode::OK;
    ASSERT_TRUE(wait_for([&] { return state.adds_started > adds; }, 3s));

    // Host which sorts last in the pass
    ipv4_action("unban", "203.0.113.9");

    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.9/32"); }, 8s))
        << "withdrawal waited behind stalled announces";
}

// New channel starts idle: start is not a reconnect, so no full pass and no reconnect message
TEST_F(RustbgpdActionTest, start_is_not_reconnect) {
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));
    std::this_thread::sleep_for(1s);

    EXPECT_EQ(captured_log->text().find("rustbgpd is reachable, will announce all"), std::string::npos);
    EXPECT_EQ(captured_log->text().find("rustbgpd full pass sent"), std::string::npos);
}

// rustbgpd restart shorter than our probe interval and its deadline: connection loss alone must trigger full pass
TEST_F(RustbgpdActionTest, short_restart_is_detected) {
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    for (auto gap : { 50ms, 300ms }) {
        restart_server(gap);
        EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 2s))
            << "route not announced again after restart with " << gap.count() << " ms gap";
    }
}

// Periodic pass resends every route: unchanged ones are logged at DEBUG, with one INFO summary per pass
TEST_F(RustbgpdActionTest, periodic_pass_logs_summary_not_every_route) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ipv4_action("ban", "203.0.113.8");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.8/32"); }, 3s));
    EXPECT_EQ(count_lines(
                  "INFO rustbgpd announced 203.0.113.7/32 next hop 0.0.0.0 outcome PATH_INJECT_OUTCOME_CREATED"),
              1u);

    captured_log->clear();
    std::this_thread::sleep_for(2500ms);

    EXPECT_GE(count_lines(
                  "DEBUG rustbgpd announced 203.0.113.7/32 next hop 0.0.0.0 outcome PATH_INJECT_OUTCOME_UNCHANGED"),
              1u);
    EXPECT_EQ(count_lines("INFO rustbgpd announced"), 0u) << "unchanged routes logged at INFO";
    EXPECT_GE(count_lines("INFO rustbgpd full pass sent 2 of 2 routes: 0 changed in rustbgpd, 0 failed"), 1u);
}

// Same rejection again and again: ERROR once, then DEBUG, and retries on reconcile interval
TEST_F(RustbgpdActionTest, repeated_rejection_logged_once) {
    configuration_map["rustbgpd_reconcile_interval"] = "1";
    ASSERT_TRUE(rustbgpd_action_init());

    state.add_status_code = grpc::StatusCode::FAILED_PRECONDITION;
    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started >= 3; }, 6s));

    EXPECT_EQ(count_lines("ERROR rustbgpd rejected announce of 203.0.113.7/32"), 1u);
    EXPECT_GE(count_lines("DEBUG rustbgpd rejected announce of 203.0.113.7/32"), 1u);
}

// Many banned hosts in one subnet: every ban must not copy the whole set of hosts which need the subnet route.
// With such copies 20000 bans take seconds, without them well under one
TEST_F(RustbgpdActionTest, many_hosts_in_one_subnet_ban_quickly) {
    configuration_map["rustbgpd_announce_whole_subnet"] = "on";
    ASSERT_TRUE(rustbgpd_action_init());

    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("10.20.0.0"), 16);

    std::vector<uint32_t> hosts;

    for (int i = 0; i < 20000; i++) {
        hosts.push_back(htonl((10u << 24) | (20u << 16) | (uint32_t(i / 250 + 1) << 8) | uint32_t(i % 250 + 1)));
        ban_list_ipv4.add_to_blackhole(hosts.back(), attack);
    }

    auto started = std::chrono::steady_clock::now();

    for (auto host : hosts) {
        rustbgpd_ban_manage("ban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    }

    auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_LT(elapsed, 1s) << "20000 bans took " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
}

// Customer network /32 is the host: host announce with its next hop wins over subnet announce
TEST_F(RustbgpdActionTest, host_announce_wins_over_subnet_of_same_host) {
    configuration_map["rustbgpd_announce_whole_subnet"] = "on";
    configuration_map["rustbgpd_next_hop_subnet_ipv4"]  = "192.0.2.1";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7", subnet_cidr_mask_t(inet_addr("203.0.113.7"), 32));
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    std::lock_guard<std::mutex> lock_guard(state.mutex);
    EXPECT_EQ(state.routes["203.0.113.7/32"].next_hop(), "0.0.0.0");
    EXPECT_EQ(state.routes.size(), 1u);
}

// Withdrawals of a round were copied before host is banned again: its outdated withdrawal must not be sent. This
// is the guard for sending changed routes without interruption during a burst
TEST_F(RustbgpdActionTest, outdated_withdrawal_not_sent_after_reban) {
    ASSERT_TRUE(rustbgpd_action_init());

    attack_details_t attack;
    attack.customer_network = subnet_cidr_mask_t(inet_addr("10.30.0.0"), 16);

    std::vector<uint32_t> hosts;

    for (uint32_t i = 1; i <= 40; i++) {
        hosts.push_back(htonl((10u << 24) | (30u << 16) | i));
        ban_list_ipv4.add_to_blackhole(hosts.back(), attack);
        rustbgpd_ban_manage("ban", false, hosts.back(), subnet_ipv6_cidr_mask_t{}, attack);
    }

    ASSERT_TRUE(wait_for([&] { return state.has("10.30.0.40/32") && state.has("10.30.0.1/32"); }, 3s));
    std::this_thread::sleep_for(300ms);

    // Withdrawals take 50 ms each, one round handles all 40
    state.delete_delay_ms = 50;
    int deletes_before    = state.deletes;

    for (auto host : hosts) {
        ban_list_ipv4.remove_from_blackhole(host);
        rustbgpd_ban_manage("unban", false, host, subnet_ipv6_cidr_mask_t{}, attack);
    }

    ASSERT_TRUE(wait_for([&] { return state.deletes >= deletes_before + 2; }, 3s));

    // Ban host 30 again while its withdrawal is still waiting in this round
    uint32_t again = hosts[29];
    ASSERT_TRUE(state.has("10.30.0.30/32"));
    ban_list_ipv4.add_to_blackhole(again, attack);
    rustbgpd_ban_manage("ban", false, again, subnet_ipv6_cidr_mask_t{}, attack);

    bool ever_missing = false;
    auto end          = std::chrono::steady_clock::now() + 4s;

    while (std::chrono::steady_clock::now() < end) {
        ever_missing = ever_missing || !state.has("10.30.0.30/32");
        std::this_thread::sleep_for(1ms);
    }

    EXPECT_FALSE(ever_missing) << "banned host withdrawn by outdated job of the same round";
}

// Shutdown cancels call in flight, joins worker and no calls happen after it
TEST_F(RustbgpdActionTest, shutdown_stops_worker_during_call) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.add_delay_ms = 3000;

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.adds_started == 1; }, 3s));

    auto started = std::chrono::steady_clock::now();
    rustbgpd_action_shutdown();
    EXPECT_LT(std::chrono::steady_clock::now() - started, 1500ms) << "shutdown waited for call in flight";

    int adds = state.adds_started;
    ipv4_action("ban", "203.0.113.8");
    std::this_thread::sleep_for(1500ms);
    EXPECT_EQ(state.adds_started, adds) << "worker made calls after shutdown";

    // Second call is harmless
    rustbgpd_action_shutdown();
}

// FastNetMon exits with exit() from several places. Worker must be stopped before global variables go away
TEST_F(RustbgpdActionTest, exit_without_shutdown_is_clean) {
    EXPECT_EXIT(
        {
            if (!rustbgpd_action_init()) {
                exit(2);
            }

            state.add_delay_ms = 2000;
            ipv4_action("ban", "203.0.113.7");
            wait_for([&] { return state.adds_started == 1; }, 3s);
            exit(0);
        },
        ::testing::ExitedWithCode(0), "");
}

std::atomic<pid_t> worker_thread_id{ 0 };

// Final steps of FastNetMon's interruption_signal_handler, the ones about this action. Steps which the real handler
// runs before them (logging, API server shutdown, joins of thread groups) are not covered by these tests. Exit code
// 3 if it ran on worker thread
void production_signal_handler(int signal_number) {
#ifdef __linux__
    bool on_worker = syscall(SYS_gettid) == worker_thread_id;
#else
    bool on_worker = false;
#endif

    if (!rustbgpd_action_signal_shutdown()) {
        _exit(2);
    }

    exit(on_worker ? 3 : 0);
}

// Checkpoints which tests set as rustbgpd_test_checkpoint
std::atomic<bool> raise_on_ban_manage{ false };
std::atomic<bool> hold_worker_after_announce{ false };
std::atomic<bool> worker_held{ false };

void test_checkpoint(const char* point) {
    if (strcmp(point, "ban_manage_locked") == 0 && raise_on_ban_manage.exchange(false)) {
        raise(SIGINT);
    }

    if (strcmp(point, "announce_returned") == 0) {
        while (hold_worker_after_announce) {
            worker_held = true;
            std::this_thread::sleep_for(1ms);
        }
    }
}

// Releases held worker after all other static objects of this program are destroyed: objects with init priority
// 101 are constructed first and destroyed last. Only exit() runs it
class teardown_release_t {
    public:
    ~teardown_release_t() {
        if (hold_worker_after_announce.exchange(false)) {
            std::this_thread::sleep_for(1s);
        }
    }
};

teardown_release_t teardown_release __attribute__((init_priority(101)));

#ifdef __linux__
// Thread id of action's worker thread, 0 if there is no such thread
pid_t find_worker_thread() {
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/task")) {
        std::ifstream comm(entry.path() / "comm");
        std::string name;

        if (std::getline(comm, name) && name == "rustbgpd") {
            return std::stoi(entry.path().filename());
        }
    }

    return 0;
}

// Signals blocked on thread, from SigBlk in /proc/self/task/<thread>/status
uint64_t blocked_signals(pid_t thread) {
    std::ifstream status("/proc/self/task/" + std::to_string(thread) + "/status");
    std::string line;

    while (std::getline(status, line)) {
        if (line.rfind("SigBlk:", 0) == 0) {
            return std::stoull(line.substr(strlen("SigBlk:")), nullptr, 16);
        }
    }

    return 0;
}

bool signal_in_mask(uint64_t mask, int signal_number) {
    return (mask >> (signal_number - 1)) & 1;
}

// Worker blocks SIGINT, which FastNetMon handles for shutdown, and no fault signals
TEST_F(RustbgpdActionTest, worker_blocks_only_shutdown_signal) {
    ASSERT_TRUE(rustbgpd_action_init());

    pid_t worker = find_worker_thread();
    ASSERT_NE(worker, 0);

    // New thread runs with all signals blocked until glibc sets mask it inherited, and we may find it by name before
    uint64_t mask = 0;

    wait_for(
        [&] {
            mask = blocked_signals(worker);
            return !signal_in_mask(mask, SIGSEGV);
        },
        5s);

    EXPECT_TRUE(signal_in_mask(mask, SIGINT));

    for (int fault_signal : { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT }) {
        EXPECT_FALSE(signal_in_mask(mask, fault_signal)) << "worker blocks signal " << fault_signal;
    }
}

// Signal sent to worker thread must not run handler there: handler would wait for or join the thread it runs on
TEST_F(RustbgpdActionTest, signal_is_never_handled_on_worker_thread) {
    EXPECT_EXIT(
        {
            // Hang is failure too
            alarm(20);
            signal(SIGINT, production_signal_handler);

            if (!rustbgpd_action_init()) {
                exit(2);
            }

            ipv4_action("ban", "203.0.113.7");
            wait_for([&] { return state.has("203.0.113.7/32"); }, 3s);

            worker_thread_id = find_worker_thread();

            if (worker_thread_id == 0) {
                exit(4);
            }

            syscall(SYS_tgkill, getpid(), worker_thread_id.load(), SIGINT);
            std::this_thread::sleep_for(1s);

            // Worker keeps it pending, so this thread handles it
            raise(SIGINT);
            std::this_thread::sleep_for(30s);
            exit(5);
        },
        ::testing::ExitedWithCode(0), "");
}
#endif

// Signal handler runs on thread which holds action's lock: shutdown from handler must not lock it again. Worker may
// stop in time (exit 0) or wait for that lock (exit 2 without cleanup), both are fine. Hang or crash are not
TEST_F(RustbgpdActionTest, signal_while_lock_is_held_does_not_deadlock) {
    EXPECT_EXIT(
        {
            alarm(20);
            signal(SIGINT, production_signal_handler);

            if (!rustbgpd_action_init()) {
                exit(2);
            }

            rustbgpd_test_checkpoint = test_checkpoint;
            raise_on_ban_manage      = true;
            ipv4_action("ban", "203.0.113.7");
            std::this_thread::sleep_for(30s);
            exit(5);
        },
        [](int status) { return WIFEXITED(status) && (WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 2); }, "");
}

// Worker does not stop within the bound: handler must leave without destroying objects worker still uses. With
// exit() the worker continues during teardown and uses destroyed objects
TEST_F(RustbgpdActionTest, worker_held_past_stop_timeout_exits_without_teardown) {
    EXPECT_EXIT(
        {
            alarm(30);
            signal(SIGINT, production_signal_handler);

            if (!rustbgpd_action_init()) {
                exit(2);
            }

            rustbgpd_test_checkpoint   = test_checkpoint;
            hold_worker_after_announce = true;
            ipv4_action("ban", "203.0.113.7");

            if (!wait_for([&] { return worker_held.load(); }, 3s)) {
                exit(4);
            }

            raise(SIGINT);
            std::this_thread::sleep_for(30s);
            exit(5);
        },
        ::testing::ExitedWithCode(2), "");
}

// Same as above with stderr going to a full pipe nobody reads: handler must still leave within its bound, so it
// must not write anything
TEST_F(RustbgpdActionTest, worker_held_past_stop_timeout_exits_with_blocked_stderr) {
    EXPECT_EXIT(
        {
            alarm(20);
            signal(SIGINT, production_signal_handler);

            int stderr_pipe[2];

            if (pipe(stderr_pipe) != 0) {
                exit(4);
            }

            // Fill the pipe, then make writes to it block
            fcntl(stderr_pipe[1], F_SETFL, O_NONBLOCK);
            char filler[4096] = {};

            while (write(stderr_pipe[1], filler, sizeof(filler)) > 0) {
            }

            fcntl(stderr_pipe[1], F_SETFL, 0);
            dup2(stderr_pipe[1], STDERR_FILENO);

            if (!rustbgpd_action_init()) {
                exit(4);
            }

            rustbgpd_test_checkpoint   = test_checkpoint;
            hold_worker_after_announce = true;
            ipv4_action("ban", "203.0.113.7");

            if (!wait_for([&] { return worker_held.load(); }, 3s)) {
                exit(4);
            }

            raise(SIGINT);
            std::this_thread::sleep_for(30s);
            exit(5);
        },
        ::testing::ExitedWithCode(2), "");
}

// Subnet announce stays while any banned host of that subnet needs it
TEST_F(RustbgpdActionTest, subnet_withdrawn_after_last_host) {
    configuration_map["rustbgpd_announce_whole_subnet"] = "on";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ipv4_action("ban", "203.0.113.8");
    ASSERT_TRUE(wait_for(
        [&] { return state.has("203.0.113.0/24") && state.has("203.0.113.7/32") && state.has("203.0.113.8/32"); }, 3s));

    ipv4_action("unban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return !state.has("203.0.113.7/32"); }, 3s));
    std::this_thread::sleep_for(1s);
    EXPECT_TRUE(state.has("203.0.113.0/24")) << "subnet withdrawn while 203.0.113.8 is still banned";

    ipv4_action("unban", "203.0.113.8");
    EXPECT_TRUE(wait_for([&] { return !state.has("203.0.113.0/24") && !state.has("203.0.113.8/32"); }, 3s));
}

// Ban from FastNetMon's API comes without customer network (0.0.0.0/0): we must not announce it
TEST_F(RustbgpdActionTest, subnet_announce_skipped_without_customer_network) {
    configuration_map["rustbgpd_announce_whole_subnet"] = "on";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7", subnet_cidr_mask_t{});
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));
    std::this_thread::sleep_for(500ms);

    {
        std::lock_guard<std::mutex> lock_guard(state.mutex);
        EXPECT_EQ(state.routes.size(), 1u) << "announced more than the host route";
        EXPECT_EQ(state.routes.count("0.0.0.0/0"), 0u) << "announced default route";
    }

    EXPECT_NE(captured_log->text().find("rustbgpd will not announce customer subnet 0.0.0.0/0 for 203.0.113.7"), std::string::npos);

    // Subnet with unspecified address is refused too
    ipv4_action("ban", "203.0.113.8", subnet_cidr_mask_t(0, 24));
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.8/32"); }, 3s));
    EXPECT_FALSE(state.has("0.0.0.0/24"));
}

// Batch of slow withdrawals takes longer than lease: lease must be renewed between them
TEST_F(RustbgpdActionTest, lease_renewed_during_long_batch) {
    configuration_map["rustbgpd_lease"]      = "on";
    configuration_map["rustbgpd_lease_time"] = "10";
    ASSERT_TRUE(rustbgpd_action_init());

    std::vector<std::string> hosts = { "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13" };

    ipv4_action("ban", "203.0.113.7");

    for (const auto& host : hosts) {
        ipv4_action("ban", host);
    }

    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32") && state.has("203.0.113.13/32"); }, 3s));

    // Four withdrawals of 2.5 seconds each, 10 seconds in total, against 10 second lease renewed every 3 seconds.
    // Renewal between calls keeps every call within its deadline; without it the last call would be cut short one
    // second before the lease expires
    state.delete_delay_ms = 2500;

    for (const auto& host : hosts) {
        ipv4_action("unban", host);
    }

    EXPECT_TRUE(wait_for([&] { return state.deletes >= 4; }, 20s));
    EXPECT_FALSE(state.lease_expired) << "lease expired during batch of withdrawals";
    EXPECT_TRUE(state.has("203.0.113.7/32"));
    EXPECT_EQ(captured_log->text().find("DEADLINE_EXCEEDED"), std::string::npos) << "call cut short by lease deadline";
}

// With leases call deadline ends one second before lease would expire: 5 second lease, at most 4 seconds per call
// instead of usual 5
TEST_F(RustbgpdActionTest, call_deadline_ends_before_lease_expiry) {
    configuration_map["rustbgpd_lease"]      = "on";
    configuration_map["rustbgpd_lease_time"] = "5";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ipv4_action("ban", "203.0.113.8");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.8/32"); }, 3s));

    ipv4_action("unban", "203.0.113.8");
    ASSERT_TRUE(wait_for([&] { return state.deletes >= 1; }, 3s));

    EXPECT_GT(state.longest_delete_deadline_ms, 0);
    EXPECT_LE(state.longest_delete_deadline_ms, 4000) << "call may outlive lease";
}

// Runs once in worker when lease renewal starts, if set
std::function<void()> on_renewal_started;

void renewal_checkpoint(const char* point) {
    if (strcmp(point, "renewal_started") == 0 && on_renewal_started) {
        auto action        = std::move(on_renewal_started);
        on_renewal_started = nullptr;
        action();
    }
}

// Renewal between calls can take a whole call timeout. A host banned again during it must not be withdrawn by the
// job copied before
TEST_F(RustbgpdActionTest, withdrawal_not_sent_after_reban_during_renewal) {
    configuration_map["rustbgpd_lease"]      = "on";
    configuration_map["rustbgpd_lease_time"] = "5";
    ASSERT_TRUE(rustbgpd_action_init());

    std::vector<std::string> hosts = { "203.0.113.10", "203.0.113.11", "203.0.113.12",
                                       "203.0.113.13", "203.0.113.14", "203.0.113.15" };

    // Stays banned, so lease is kept and renewed
    ipv4_action("ban", "203.0.113.7");

    for (const auto& host : hosts) {
        ipv4_action("ban", host);
    }

    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32") && state.has("203.0.113.15/32"); }, 3s));
    std::this_thread::sleep_for(300ms);

    // Six withdrawals of 600 ms each against renewal every second: renewal is due between calls of this round
    state.delete_delay_ms = 600;
    int deletes_before    = state.deletes;

    for (const auto& host : hosts) {
        ipv4_action("unban", host);
    }

    ASSERT_TRUE(wait_for([&] { return state.deletes > deletes_before; }, 3s));

    // Ban again every host whose withdrawal is still waiting, among them the next job of this round
    std::vector<std::string> banned_again;
    std::atomic<bool> renewal_seen{ false };

    on_renewal_started = [&] {
        for (const auto& host : hosts) {
            if (state.has(host + "/32")) {
                ipv4_action("ban", host);
                banned_again.push_back(host + "/32");
            }
        }

        renewal_seen = true;
    };

    rustbgpd_test_checkpoint = renewal_checkpoint;
    ASSERT_TRUE(wait_for([&] { return renewal_seen.load(); }, 5s));
    ASSERT_FALSE(banned_again.empty()) << "renewal came after all withdrawals";

    // Rest of this round and next one
    std::this_thread::sleep_for(4s);
    rustbgpd_test_checkpoint = nullptr;

    for (const auto& key : banned_again) {
        EXPECT_EQ(state.deletes_of(key), 0) << key << " banned again during renewal but withdrawn";
        EXPECT_TRUE(state.has(key));
    }
}

// Lease expires in the middle of full pass: routes added before we saw new generation must be added again
TEST_F(RustbgpdActionTest, lease_generation_change_during_pass_reannounces) {
    configuration_map["rustbgpd_lease"]      = "on";
    configuration_map["rustbgpd_lease_time"] = "60";
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ipv4_action("ban", "203.0.113.8");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32") && state.has("203.0.113.8/32"); }, 3s));

    // Force full pass: liveness probe fails and recovers. First add of the pass (203.0.113.7) still gets old
    // generation and then lease expires, second add (203.0.113.8) starts new generation
    state.expire_after_next_add = true;
    state.liveness_code         = grpc::StatusCode::UNAVAILABLE;
    ASSERT_TRUE(wait_for([&] { return captured_log->text().find("did not answer liveness probe") != std::string::npos; }, 3s));
    state.liveness_code = grpc::StatusCode::OK;

    // Lease expired after the first add of the pass
    ASSERT_TRUE(wait_for([&] { return !state.expire_after_next_add; }, 3s));

    EXPECT_TRUE(wait_for([&] { return state.has("203.0.113.7/32") && state.has("203.0.113.8/32"); }, 3s))
        << "route lost with expired lease was not announced again";
}

TEST_F(RustbgpdActionTest, rejects_targets_other_than_unix_socket_and_loopback_address) {
    configuration_map["rustbgpd_token_file"] = write_file("token", "secret-token\n", 0600);

    for (std::string target :
         std::vector<std::string>{ "127.attacker.example:50051", "localhost:50051", "10.0.0.1:50051", "[::2]:50051",
                                   "[::ffff:127.0.0.1]:50051", "127.1:50051", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536",
                                   "127.0.0.1:50051x", "unix:relative/path", "dns:///127.0.0.1:50051", "" }) {
        configuration_map["rustbgpd_target"] = target;
        EXPECT_FALSE(rustbgpd_action_init()) << "accepted target " << target;
        rustbgpd_action_shutdown();
    }

    for (std::string target : std::vector<std::string>{ "127.0.0.1:50051", "127.10.20.30:1", "[::1]:50051",
                                                        "unix:///run/rustbgpd/grpc.sock", "unix:/run/rustbgpd/grpc.sock" }) {
        configuration_map["rustbgpd_target"] = target;
        EXPECT_TRUE(rustbgpd_action_init()) << "rejected target " << target;
        rustbgpd_action_shutdown();
    }
}

// Numbers must be complete decimal strings: FastNetMon's parser alone reads 1e3 as 1 and 30x as 30
TEST_F(RustbgpdActionTest, numeric_options_must_be_decimal) {
    for (std::string name : std::vector<std::string>{ "rustbgpd_reconcile_interval", "rustbgpd_lease_time" }) {
        for (std::string text : std::vector<std::string>{ "1e3", "30x", " 30", "30 ", "+30", "-5", "3.0", "0x10", "", "99999999999" }) {
            configuration_map[name] = text;
            EXPECT_FALSE(rustbgpd_action_init()) << name << " accepted '" << text << "'";
            rustbgpd_action_shutdown();
        }

        configuration_map[name] = "30";
        EXPECT_TRUE(rustbgpd_action_init()) << name << " rejected 30";
        rustbgpd_action_shutdown();
        configuration_map.erase(name);
    }
}

// Communities must be ASN:value with decimal parts up to 65535: FastNetMon's parser alone reads 65535:0x29a as
// 65535:0, which is not BLACKHOLE
TEST_F(RustbgpdActionTest, community_options_must_be_complete) {
    for (std::string name :
         std::vector<std::string>{ "rustbgpd_community_host", "rustbgpd_community_subnet", "rustbgpd_community_host_ipv6" }) {
        for (std::string text : std::vector<std::string>{ "65535:0x29a", "65535:666x", "65535:666:1", "65536:666", "65535:65536",
                                                          ":666", "65535:", "65535 :666", "65535: 666", "blackhole", "" }) {
            configuration_map[name] = text;
            EXPECT_FALSE(rustbgpd_action_init()) << name << " accepted '" << text << "'";
            rustbgpd_action_shutdown();
        }

        configuration_map[name] = "65535:666";
        EXPECT_TRUE(rustbgpd_action_init()) << name << " rejected 65535:666";
        rustbgpd_action_shutdown();
        configuration_map.erase(name);
    }
}

TEST_F(RustbgpdActionTest, tcp_target_requires_token) {
    configuration_map["rustbgpd_target"] = "127.0.0.1:50051";
    EXPECT_FALSE(rustbgpd_action_init());
}

// Loopback TCP with token: token goes in authorization header of each call
TEST_F(RustbgpdActionTest, tcp_target_sends_token) {
    int port = 0;
    grpc::ServerBuilder builder;
    builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
    builder.RegisterService(injection.get());
    builder.RegisterService(control.get());

    // Services may be registered with one running server only
    server->Shutdown(std::chrono::system_clock::now() + 1s);
    server = builder.BuildAndStart();
    ASSERT_TRUE(server);
    ASSERT_GT(port, 0);

    configuration_map["rustbgpd_target"]     = "127.0.0.1:" + std::to_string(port);
    configuration_map["rustbgpd_token_file"] = write_file("token", "secret-token\n", 0600);
    ASSERT_TRUE(rustbgpd_action_init());

    ipv4_action("ban", "203.0.113.7");
    ASSERT_TRUE(wait_for([&] { return state.has("203.0.113.7/32"); }, 3s));

    std::lock_guard<std::mutex> lock_guard(state.mutex);
    EXPECT_EQ(state.last_authorization, "Bearer secret-token");
}

TEST_F(RustbgpdActionTest, token_file_checks) {
    auto good = write_file("good", "secret-token\n", 0600);

    configuration_map["rustbgpd_token_file"] = good;
    EXPECT_TRUE(rustbgpd_action_init());
    rustbgpd_action_shutdown();

    auto link = directory + "/link";
    ASSERT_EQ(symlink(good.c_str(), link.c_str()), 0);

    auto fifo = directory + "/fifo";
    ASSERT_EQ(mkfifo(fifo.c_str(), 0600), 0);

    std::map<std::string, std::string> bad_files = {
        { "symbolic link", link },
        { "group and world readable", write_file("open", "secret-token\n", 0644) },
        { "group readable", write_file("group", "secret-token\n", 0640) },
        { "directory", directory },
        { "missing", directory + "/missing" },
        { "empty", write_file("empty", "\n", 0600) },
        { "too large", write_file("large", std::string(5000, 'a'), 0600) },
        { "space in token", write_file("space", "secret token\n", 0600) },
        { "fifo", fifo },
    };

    for (const auto& [name, path] : bad_files) {
        configuration_map["rustbgpd_token_file"] = path;

        // Opening FIFO without O_NONBLOCK waits for writer forever
        auto result = std::async(std::launch::async, [] { return rustbgpd_action_init(); });

        if (result.wait_for(2s) != std::future_status::ready) {
            ADD_FAILURE() << "token file check blocked on " << name;

            // Unblock reader
            int writer = open(fifo.c_str(), O_WRONLY | O_NONBLOCK);
            close(writer);
        }

        EXPECT_FALSE(result.get()) << "accepted token file: " << name;
        rustbgpd_action_shutdown();
    }

    EXPECT_EQ(captured_log->text().find("secret"), std::string::npos) << "token content in log";
}

TEST(rustbgpd_token_file_metadata, owner_and_mode) {
    uid_t me = 1000;

    struct stat file_stat {};
    file_stat.st_mode = S_IFREG | 0600;

    file_stat.st_uid = me;
    EXPECT_EQ(rustbgpd_check_token_file_metadata(file_stat, me), "");

    file_stat.st_uid = 0;
    EXPECT_EQ(rustbgpd_check_token_file_metadata(file_stat, me), "");

    file_stat.st_uid = me + 1;
    EXPECT_NE(rustbgpd_check_token_file_metadata(file_stat, me), "") << "accepted file of another user";

    file_stat.st_uid  = me;
    file_stat.st_mode = S_IFREG | 0400;
    EXPECT_EQ(rustbgpd_check_token_file_metadata(file_stat, me), "");

    file_stat.st_mode = S_IFREG | 0604;
    EXPECT_NE(rustbgpd_check_token_file_metadata(file_stat, me), "");

    file_stat.st_mode = S_IFREG | 0610;
    EXPECT_NE(rustbgpd_check_token_file_metadata(file_stat, me), "");

    file_stat.st_mode = S_IFDIR | 0700;
    EXPECT_NE(rustbgpd_check_token_file_metadata(file_stat, me), "");

    file_stat.st_mode = S_IFIFO | 0600;
    EXPECT_NE(rustbgpd_check_token_file_metadata(file_stat, me), "");
}

TEST_F(RustbgpdActionTest, lease_owner_checked_when_leases_enabled) {
    configuration_map["rustbgpd_lease"] = "on";

    for (std::string owner : std::vector<std::string>{ "", "bad owner", "owner/1", std::string(65, 'a'), "fnm:1" }) {
        configuration_map["rustbgpd_lease_owner"] = owner;
        EXPECT_FALSE(rustbgpd_action_init()) << "accepted owner '" << owner << "'";
        rustbgpd_action_shutdown();
    }

    for (std::string owner : std::vector<std::string>{ "fastnetmon", "pop1.fastnetmon_a-B9", std::string(64, 'a') }) {
        configuration_map["rustbgpd_lease_owner"] = owner;
        EXPECT_TRUE(rustbgpd_action_init()) << "rejected owner '" << owner << "'";
        rustbgpd_action_shutdown();
    }
}

// OK without outcome means rustbgpd older than 0.79.0 or unknown outcome: we keep retrying. Periodic pass is
// every 30 seconds here, first retry of failed call is in 10 seconds
TEST_F(RustbgpdActionTest, unrecognised_outcome_is_retried) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.omit_outcome = true;
    ipv4_action("ban", "203.0.113.7");
    EXPECT_TRUE(wait_for([&] { return state.adds_started >= 2; }, 12s)) << "announce was not retried";
    EXPECT_NE(captured_log->text().find("rustbgpd answered announce of 203.0.113.7/32 without recognised outcome (0)"),
              std::string::npos);

    // Same failure again would wait for reconcile interval now. Unban changes desired state, so its withdrawal is
    // sent at once and retried in 10 seconds
    ipv4_action("unban", "203.0.113.7");
    EXPECT_TRUE(wait_for([&] { return state.deletes >= 2; }, 12s)) << "withdrawal was not retried";
    EXPECT_NE(captured_log->text().find(
                  "rustbgpd answered withdrawal of 203.0.113.7/32 without recognised outcome (0)"),
              std::string::npos);
}

TEST_F(RustbgpdActionTest, leased_answer_without_generation_is_failure) {
    configuration_map["rustbgpd_lease"] = "on";
    ASSERT_TRUE(rustbgpd_action_init());

    state.omit_generation = true;
    ipv4_action("ban", "203.0.113.7");
    EXPECT_TRUE(wait_for(
        [&] {
            return captured_log->text().find("rustbgpd answered leased announce of 203.0.113.7/32 without result or "
                                             "lease generation") != std::string::npos;
        },
        3s));
    EXPECT_EQ(captured_log->text().find("rustbgpd announced 203.0.113.7/32"), std::string::npos);
}

TEST_F(RustbgpdActionTest, liveness_failure_status_is_logged) {
    ASSERT_TRUE(rustbgpd_action_init());

    state.liveness_code = grpc::StatusCode::UNAUTHENTICATED;
    EXPECT_TRUE(wait_for(
        [&] {
            return captured_log->text().find("did not answer liveness probe: UNAUTHENTICATED: mock liveness failure") !=
                   std::string::npos;
        },
        3s));
}

// Sanitizer failure must not look like exit code 1 of a test
extern "C" const char* __asan_default_options() {
    return "exitcode=66";
}

int main(int argc, char** argv) {
    captured_log = new captured_log_t;
    logger.addAppender(captured_log);
    logger.setPriority(log4cpp::Priority::DEBUG);

    ::testing::InitGoogleTest(&argc, argv);

    // Death tests fork, we have gRPC threads running
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    return RUN_ALL_TESTS();
}
