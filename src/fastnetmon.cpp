/* Author: pavel.odintsov@gmail.com */
/* License: GPLv2 */

#include <new>
#include <signal.h>

// We have it on all non Windows platofms
#ifndef _WIN32
#include <sys/resource.h> // setrlimit
#endif

#include "fast_library.hpp"
#include "fastnetmon_types.hpp"
#include "libpatricia/patricia.hpp"
#include "packet_storage.hpp"

// Here we store variables which differs for different paltforms
#include "fast_platform.hpp"

#include "fastnetmon_logic.hpp"

#include "fast_endianless.hpp"

#ifdef FASTNETMON_API

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif // __GNUC__

#include "abstract_subnet_counters.hpp"

#include "fastnetmon.grpc.pb.h"
#include <grpc++/grpc++.h>

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__

#endif

// Plugins
#include "netflow_plugin/netflow_collector.hpp"

#ifdef ENABLE_PCAP
#include "pcap_plugin/pcap_collector.hpp"
#endif

#include "sflow_plugin/sflow_collector.hpp"

#ifdef NETMAP_PLUGIN
#include "netmap_plugin/netmap_collector.hpp"
#endif

#ifdef FASTNETMON_ENABLE_AF_XDP
#include "xdp_plugin/xdp_collector.hpp"
#endif

#ifdef FASTNETMON_ENABLE_AFPACKET
#include "afpacket_plugin/afpacket_collector.hpp"
#endif

#ifdef ENABLE_GOBGP
#include "actions/gobgp_action.hpp"
#endif

// Yes, maybe it's not an good idea but with this we can guarantee working code in example plugin
#include "example_plugin/example_collector.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>

#include <filesystem>
#include <sstream>
#include <utility>
#include <vector>

#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#include <boost/program_options.hpp>

#include "all_logcpp_libraries.hpp"

// We do not have syslog.h on Windows
#ifndef _WIN32
#include <log4cpp/RemoteSyslogAppender.hh>
#include <log4cpp/SyslogAppender.hh>
#endif

// Boost libs
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#if defined(__APPLE__)
#define _GNU_SOURCE
#endif
#include <boost/stacktrace.hpp>

#ifdef GEOIP
#include "GeoIP.h"
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

#include "packet_bucket.hpp"

#include "ban_list.hpp"

#include "metrics/graphite.hpp"
#include "metrics/influxdb.hpp"

#ifdef KAFKA
#include <cppkafka/cppkafka.h>
#endif

#ifdef FASTNETMON_API
using fastmitigation::BanListReply;
using fastmitigation::BanListRequest;
using fastmitigation::Fastnetmon;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

std::unique_ptr<Server> api_server;
bool enable_api = false;
#endif

#ifdef KAFKA
cppkafka::Producer* kafka_traffic_export_producer = nullptr;
#endif

// Traffic export to Kafka
bool kafka_traffic_export = false;

std::string kafka_traffic_export_topic                    = "fastnetmon";
kafka_traffic_export_format_t kafka_traffic_export_format = kafka_traffic_export_format_t::JSON;
std::vector<std::string> kafka_traffic_export_brokers;

std::chrono::steady_clock::time_point last_call_of_traffic_recalculation;

std::string cli_stats_file_path = "/tmp/fastnetmon.dat";

std::string cli_stats_ipv6_file_path = "/tmp/fastnetmon_ipv6.dat";

// How often we send usage data
unsigned int stats_thread_sleep_time = 3600;

// Delay before we send first report about usage
unsigned int stats_thread_initial_call_delay = 30;

std::string reporting_server = "community-stats.fastnetmon.com";

// Each this seconds we will check about available data in bucket
unsigned int check_for_availible_for_processing_packets_buckets = 1;

// Current time with pretty low precision, we use separate thread to update it
time_t current_inaccurate_time = 0;

// This is thread safe storage for captured from the wire packets for IPv4 traffic
packet_buckets_storage_t<uint32_t> packet_buckets_ipv4_storage;

// This is thread safe storage for captured from the wire packets for IPv6 traffic
packet_buckets_storage_t<subnet_ipv6_cidr_mask_t> packet_buckets_ipv6_storage;

unsigned int recalculate_speed_timeout = 1;

// We will remove all packet buckets which runs longer than this time. This value used only for one shot buckets.
// Infinite bucket's will not removed
unsigned int maximum_time_since_bucket_start_to_remove = 120;

FastnetmonPlatformConfigurtion fastnetmon_platform_configuration;

bool notify_script_enabled = true;

// We could collect attack dumps in pcap format
bool collect_attack_pcap_dumps = false;

bool unban_only_if_attack_finished = true;

logging_configuration_t logging_configuration;

// Global map with parsed config file
configuration_map_t configuration_map;

// Enable Prometheus
bool prometheus = false;

// Prometheus port
unsigned short prometheus_port = 9209;

// Prometheus host
std::string prometheus_host = "127.0.0.1";

// Every X seconds we will run ban list cleaner thread
// If customer uses ban_time smaller than this value we will use ban_time/2 as unban_iteration_sleep_time
int unban_iteration_sleep_time = 60;

bool unban_enabled = true;

#ifdef ENABLE_GOBGP
bool gobgp_enabled = false;
#endif

#ifdef MONGO
std::string mongodb_host  = "localhost";
unsigned int mongodb_port = 27017;
bool mongodb_enabled      = false;

std::string mongodb_database_name = "fastnetmon";
#endif

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
unsigned int redis_port = 6379;
std::string redis_host  = "127.0.0.1";

// redis key prefix
std::string redis_prefix = "";

// because it's additional and very specific feature we should disable it by default
bool redis_enabled = false;
#endif

bool monitor_local_ip_addresses = true;

// Enable monitoring for OpenVZ VPS IP addresses by reading their list from kernel
bool monitor_openvz_vps_ip_addresses = false;

// We will announce whole subnet instead single IP with BGP if this flag enabled
bool exabgp_announce_whole_subnet = false;

std::string exabgp_command_pipe = "";

// We will announce only /32 host
bool exabgp_announce_host = false;

ban_settings_t global_ban_settings;

void init_global_ban_settings() {
    // ban Configuration params
    global_ban_settings.enable_ban_for_pps              = false;
    global_ban_settings.enable_ban_for_bandwidth        = false;
    global_ban_settings.enable_ban_for_flows_per_second = false;

    // We must ban IP if it exceeed this limit in PPS
    global_ban_settings.ban_threshold_pps = 20000;

    // We must ban IP of it exceed this limit for number of flows in any direction
    global_ban_settings.ban_threshold_flows = 3500;

    // We must ban client if it exceed 1GBps
    global_ban_settings.ban_threshold_mbps = 1000;

    // Disable per protocol thresholds too
    global_ban_settings.enable_ban_for_tcp_pps       = false;
    global_ban_settings.enable_ban_for_tcp_bandwidth = false;

    global_ban_settings.enable_ban_for_udp_pps       = false;
    global_ban_settings.enable_ban_for_udp_bandwidth = false;

    global_ban_settings.enable_ban_for_icmp_pps       = false;
    global_ban_settings.enable_ban_for_icmp_bandwidth = false;

    // Ban enable/disable flag
    global_ban_settings.enable_ban = true;
}

bool enable_connection_tracking = true;

bool enable_afpacket_collection         = false;
bool enable_af_xdp_collection           = false;
bool enable_data_collection_from_mirror = false;
bool enable_netmap_collection           = false;
bool enable_sflow_collection            = false;
bool enable_netflow_collection          = false;
bool enable_pcap_collection             = false;

std::string speed_calculation_time_desc = "Time consumed by recalculation for all IPs";
struct timeval speed_calculation_time;

// Time consumed by drawing stats for all IPs
struct timeval drawing_thread_execution_time;

// Global thread group for packet capture threads
boost::thread_group packet_capture_plugin_thread_group;

// Global thread group for service processes (speed recalculation,
// screen updater and ban list cleaner)
boost::thread_group service_thread_group;

std::string total_number_of_hosts_in_our_networks_desc = "Total number of hosts in our networks";
unsigned int total_number_of_hosts_in_our_networks     = 0;

#ifdef GEOIP
GeoIP* geo_ip = NULL;
#endif

// IPv4 lookup trees
patricia_tree_t *lookup_tree_ipv4, *whitelist_tree_ipv4;

// IPv6 lookup trees
patricia_tree_t *lookup_tree_ipv6, *whitelist_tree_ipv6;

bool DEBUG = 0;

// flag about dumping all packets to log
bool DEBUG_DUMP_ALL_PACKETS = false;

// dump "other" packets
bool DEBUG_DUMP_OTHER_PACKETS = false;

// Period for update screen for console version of tool
unsigned int check_period = 3;

// Standard ban time in seconds for all attacks but you can tune this value
int global_ban_time = 1800;

// We calc average pps/bps for this time
double average_calculation_amount = 15;

// Key used for sorting clients in output.  Allowed sort params: packets/bytes/flows
std::string sort_parameter = "bytes";

// Number of lines in program output
unsigned int max_ips_in_list = 7;

// Number of lines for sending ben attack details to email
unsigned int ban_details_records_count = 50;

// We haven't option for configure it with configuration file
unsigned int number_of_packets_for_pcap_attack_dump = 500;

// log file
log4cpp::Category& logger = log4cpp::Category::getRoot();

/* Configuration block ends */

// We count total number of incoming/outgoing/internal and other traffic type packets/bytes
total_speed_counters_t total_counters_ipv4;
total_speed_counters_t total_counters_ipv6;

std::string total_unparsed_packets_desc = "Total number of packets we failed to parse";
uint64_t total_unparsed_packets         = 0;

std::string total_unparsed_packets_speed_desc = "Number of packets we fail to parse per second";
uint64_t total_unparsed_packets_speed         = 0;

std::string total_ipv4_packets_desc = "Total number of IPv4 simple packets processed";
uint64_t total_ipv4_packets         = 0;

std::string total_ipv6_packets_desc = "Total number of IPv6 simple packets processed";
uint64_t total_ipv6_packets         = 0;

std::string unknown_ip_version_packets_desc = "Non IPv4 and non IPv6 packets";
uint64_t unknown_ip_version_packets         = 0;

std::string total_simple_packets_processed_desc = "Total number of simple packets processed";
uint64_t total_simple_packets_processed         = 0;

// IPv6 traffic which belongs to our own networks
uint64_t our_ipv6_packets = 0;

uint64_t incoming_total_flows_speed = 0;
uint64_t outgoing_total_flows_speed = 0;

// Network counters for IPv6
abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_subnet_counters;

// Host counters for IPv6
abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_host_counters;

// Here we store traffic per subnet
abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;

// Host counters for IPv4
abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;

// Flow tracking structures
map_of_vector_counters_for_flow_t SubnetVectorMapFlow;

std::string netflow_ipfix_all_protocols_total_flows_speed_desc = "Number of IPFIX and Netflow per second";
int64_t netflow_ipfix_all_protocols_total_flows_speed          = 0;

std::string sflow_raw_packet_headers_total_speed_desc = "Number of sFlow headers per second";
int64_t sflow_raw_packet_headers_total_speed          = 0;

std::mutex flow_counter_mutex;

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

// Banned IPv6 hosts
blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

// Banned IPv4 hosts
blackhole_ban_list_t<uint32_t> ban_list_ipv4;

host_group_map_t host_groups;

// Here we store assignment from subnet to certain host group for fast lookup
subnet_to_host_group_map_t subnet_to_host_groups;

host_group_ban_settings_map_t host_group_ban_settings_map;

std::vector<subnet_cidr_mask_t> our_networks;
std::vector<subnet_cidr_mask_t> whitelist_networks;

// ExaBGP support flag
bool exabgp_enabled          = false;
std::string exabgp_community = "";

// We could use separate communities for subnet and host announces
std::string exabgp_community_subnet = "";
std::string exabgp_community_host   = "";


std::string exabgp_next_hop     = "";

// Graphite monitoring
bool graphite_enabled             = false;
std::string graphite_host         = "127.0.0.1";
unsigned short int graphite_port  = 2003;
unsigned int graphite_push_period = 1;

// Default graphite namespace
std::string graphite_prefix = "fastnetmon";

std::string influxdb_writes_total_desc = "Total number of InfluxDB writes";
uint64_t influxdb_writes_total         = 0;

std::string influxdb_writes_failed_desc = "Total number of failed InfluxDB writes";
uint64_t influxdb_writes_failed         = 0;

// InfluxDB
bool influxdb_enabled             = false;
std::string influxdb_database     = "fastnetmon";
std::string influxdb_host         = "127.0.0.1";
unsigned short int influxdb_port  = 8086;
bool influxdb_auth                = false;
std::string influxdb_user         = "";
std::string influxdb_password     = "";
unsigned int influxdb_push_period = 1;

bool process_incoming_traffic = true;
bool process_outgoing_traffic = true;

logging_configuration_t read_logging_settings(configuration_map_t configuration_map);
std::string get_amplification_attack_type(amplification_attack_type_t attack_type);
ban_settings_t read_ban_settings(configuration_map_t configuration_map, std::string host_group_name = "");
bool load_configuration_file();
void free_up_all_resources();
void interruption_signal_handler(int signal_number);

#ifdef FASTNETMON_API
void silent_logging_function(gpr_log_func_args* args) {
    // We do not want any logging here
}

// We could not define this variable in top of the file because we should define class before
FastnetmonApiServiceImpl api_service;

std::unique_ptr<Server> StartupApiServer() {
    std::string server_address("127.0.0.1:50052");
    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&api_service);

    // Finally assemble the server.
    std::unique_ptr<Server> current_api_server(builder.BuildAndStart());
    logger << log4cpp::Priority::INFO << "API server listening on " << server_address;

    return current_api_server;
}

void RunApiServer() {
    logger << log4cpp::Priority::INFO << "Launch API server";
    api_server = StartupApiServer();

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    api_server->Wait();
    logger << log4cpp::Priority::INFO << "API server got shutdown signal";
}
#endif

void sigpipe_handler_for_popen(int signo) {
    logger << log4cpp::Priority::ERROR << "Sorry but we experienced error with popen. "
           << "Please check your scripts. They must receive data on stdin";

    // Well, we do not need exit here because we have another options to notifying about atatck
    // exit(1);
}

#ifdef GEOIP
bool geoip_init() {
    // load GeoIP ASN database to memory
    geo_ip = GeoIP_open("/root/fastnetmon/GeoIPASNum.dat", GEOIP_MEMORY_CACHE);

    if (geo_ip == NULL) {
        return false;
    } else {
        return true;
    }
}
#endif

// TODO: move to lirbary
// read whole file to vector
std::vector<std::string> read_file_to_vector(std::string file_name) {
    std::vector<std::string> data;
    std::string line;

    std::ifstream reading_file;

    reading_file.open(file_name.c_str(), std::ifstream::in);
    if (reading_file.is_open()) {
        while (getline(reading_file, line)) {
            boost::algorithm::trim(line);
            data.push_back(line);
        }
    } else {
        logger << log4cpp::Priority::ERROR << "Can't open file: " << file_name;
    }

    return data;
}

void parse_hostgroups(std::string name, std::string value) {
    // We are creating new host group of subnets
    if (name != "hostgroup") {
        return;
    }

    std::vector<std::string> splitted_new_host_group;
    // We have new host groups in form:
    // hostgroup = new_host_group_name:11.22.33.44/32,....
    split(splitted_new_host_group, value, boost::is_any_of(":"), boost::token_compress_on);

    if (splitted_new_host_group.size() != 2) {
        logger << log4cpp::Priority::ERROR << "We can't parse new host group";
        return;
    }

    boost::algorithm::trim(splitted_new_host_group[0]);
    boost::algorithm::trim(splitted_new_host_group[1]);

    std::string host_group_name = splitted_new_host_group[0];

    if (host_groups.count(host_group_name) > 0) {
        logger << log4cpp::Priority::WARN << "We already have this host group (" << host_group_name << "). Please check!";
        return;
    }

    // Split networks
    std::vector<std::string> hostgroup_subnets = split_strings_to_vector_by_comma(splitted_new_host_group[1]);

    for (std::vector<std::string>::iterator itr = hostgroup_subnets.begin(); itr != hostgroup_subnets.end(); ++itr) {
        subnet_cidr_mask_t subnet;

        bool subnet_parse_result = convert_subnet_from_string_to_binary_with_cidr_format_safe(*itr, subnet);

        if (!subnet_parse_result) {
            logger << log4cpp::Priority::ERROR << "Cannot parse subnet " << *itr;
            continue;
        }

        host_groups[host_group_name].push_back(subnet);

        logger << log4cpp::Priority::WARN << "We add subnet " << convert_subnet_to_string(subnet) << " to host group " << host_group_name;

        // And add to subnet to host group lookup hash
        if (subnet_to_host_groups.count(subnet) > 0) {
            // Huston, we have problem! Subnet to host group mapping should map single subnet to single group!
            logger << log4cpp::Priority::WARN << "Seems you have specified single subnet " << *itr
                   << " to multiple host groups, please fix it, it's prohibited";
        } else {
            subnet_to_host_groups[subnet] = host_group_name;
        }
    }

    logger << log4cpp::Priority::INFO << "We have created host group " << host_group_name << " with "
           << host_groups[host_group_name].size() << " subnets";
}

// Load configuration
bool load_configuration_file() {
    std::ifstream config_file(fastnetmon_platform_configuration.global_config_path.c_str());
    std::string line;

    if (!config_file.is_open()) {
        logger << log4cpp::Priority::ERROR << "Can't open config file";
        return false;
    }

    while (getline(config_file, line)) {
        std::vector<std::string> parsed_config;
        boost::algorithm::trim(line);

        if (line.find("#") == 0 or line.empty()) {
            // Ignore comments line
            continue;
        }

        boost::split(parsed_config, line, boost::is_any_of("="), boost::token_compress_on);

        if (parsed_config.size() == 2) {
            boost::algorithm::trim(parsed_config[0]);
            boost::algorithm::trim(parsed_config[1]);

            configuration_map[parsed_config[0]] = parsed_config[1];

            // Well, we parse host groups here
            parse_hostgroups(parsed_config[0], parsed_config[1]);
        } else {
            logger << log4cpp::Priority::ERROR << "Can't parse config line: '" << line << "'";
        }
    }

    if (configuration_map.count("enable_connection_tracking")) {
        if (configuration_map["enable_connection_tracking"] == "on") {
            enable_connection_tracking = true;
        } else {
            enable_connection_tracking = false;
        }
    }

    if (configuration_map.count("ban_time") != 0) {
        global_ban_time = convert_string_to_integer(configuration_map["ban_time"]);

        // Completely disable unban option
        if (global_ban_time == 0) {
            unban_enabled = false;
        }
    }

    if (configuration_map.count("pid_path") != 0) {
        fastnetmon_platform_configuration.pid_path = configuration_map["pid_path"];
    }

    if (configuration_map.count("cli_stats_file_path") != 0) {
        cli_stats_file_path = configuration_map["cli_stats_file_path"];
    }

    if (configuration_map.count("cli_stats_ipv6_file_path") != 0) {
        cli_stats_ipv6_file_path = configuration_map["cli_stats_ipv6_file_path"];
    }

    if (configuration_map.count("unban_only_if_attack_finished") != 0) {
        if (configuration_map["unban_only_if_attack_finished"] == "on") {
            unban_only_if_attack_finished = true;
        } else {
            unban_only_if_attack_finished = false;
        }
    }

    if (configuration_map.count("graphite_prefix") != 0) {
        graphite_prefix = configuration_map["graphite_prefix"];
    }

    if (configuration_map.count("average_calculation_time") != 0) {
        average_calculation_amount = convert_string_to_integer(configuration_map["average_calculation_time"]);
    }

    if (configuration_map.count("speed_calculation_delay") != 0) {
        recalculate_speed_timeout = convert_string_to_integer(configuration_map["speed_calculation_delay"]);
    }

    if (configuration_map.count("monitor_local_ip_addresses") != 0) {
        monitor_local_ip_addresses = configuration_map["monitor_local_ip_addresses"] == "on" ? true : false;
    }

    if (configuration_map.count("monitor_openvz_vps_ip_addresses") != 0) {
        monitor_openvz_vps_ip_addresses = configuration_map["monitor_openvz_vps_ip_addresses"] == "on" ? true : false;
    }

#ifdef FASTNETMON_API
    if (configuration_map.count("enable_api") != 0) {
        enable_api = configuration_map["enable_api"] == "on";
    }
#endif

#ifdef ENABLE_GOBGP
    // GoBGP configuration
    if (configuration_map.count("gobgp") != 0) {
        gobgp_enabled = configuration_map["gobgp"] == "on";
    }
#endif

    // ExaBGP configuration

    if (configuration_map.count("exabgp") != 0) {
        if (configuration_map["exabgp"] == "on") {
            exabgp_enabled = true;
        } else {
            exabgp_enabled = false;
        }
    }

    if (exabgp_enabled) {
        // TODO: add community format validation
        if (configuration_map.count("exabgp_community")) {
            exabgp_community = configuration_map["exabgp_community"];
        }

        if (configuration_map.count("exabgp_community_subnet")) {
            exabgp_community_subnet = configuration_map["exabgp_community_subnet"];
        } else {
            exabgp_community_subnet = exabgp_community;
        }

        if (configuration_map.count("exabgp_community_host")) {
            exabgp_community_host = configuration_map["exabgp_community_host"];
        } else {
            exabgp_community_host = exabgp_community;
        }

        if (exabgp_enabled && exabgp_announce_whole_subnet && exabgp_community_subnet.empty()) {
            logger << log4cpp::Priority::ERROR << "You enabled exabgp for subnet but not specified community, we disable exabgp support";

            exabgp_enabled = false;
        }

        if (exabgp_enabled && exabgp_announce_host && exabgp_community_host.empty()) {
            logger << log4cpp::Priority::ERROR << "You enabled exabgp for host but not specified community, we disable exabgp support";

            exabgp_enabled = false;
        }
    }

    if (exabgp_enabled) {
        exabgp_command_pipe = configuration_map["exabgp_command_pipe"];

        if (exabgp_command_pipe.empty()) {
            logger << log4cpp::Priority::ERROR
                   << "You enabled exabgp but not specified "
                      "exabgp_command_pipe, so we disable exabgp "
                      "support";

            exabgp_enabled = false;
        }
    }

    if (exabgp_enabled) {
        exabgp_next_hop = configuration_map["exabgp_next_hop"];

        if (exabgp_next_hop.empty()) {
            logger << log4cpp::Priority::ERROR << "You enabled exabgp but not specified exabgp_next_hop, so we disable exabgp support";

            exabgp_enabled = false;
        }

        if (exabgp_enabled) {
            logger << log4cpp::Priority::INFO << "ExaBGP support initialized correctly";
        }
    }

    if (configuration_map.count("sflow") != 0) {
        if (configuration_map["sflow"] == "on") {
            enable_sflow_collection = true;
        } else {
            enable_sflow_collection = false;
        }
    }

    if (configuration_map.count("netflow") != 0) {
        if (configuration_map["netflow"] == "on") {
            enable_netflow_collection = true;
        } else {
            enable_netflow_collection = false;
        }
    }

    if (configuration_map.count("exabgp_announce_whole_subnet") != 0) {
        exabgp_announce_whole_subnet = configuration_map["exabgp_announce_whole_subnet"] == "on" ? true : false;
    }

    if (configuration_map.count("exabgp_announce_host") != 0) {
        exabgp_announce_host = configuration_map["exabgp_announce_host"] == "on" ? true : false;
    }

    // Graphite
    if (configuration_map.count("graphite") != 0) {
        graphite_enabled = configuration_map["graphite"] == "on" ? true : false;
    }

    if (configuration_map.count("graphite_host") != 0) {
        graphite_host = configuration_map["graphite_host"];
    }

    if (configuration_map.count("graphite_port") != 0) {
        graphite_port = convert_string_to_integer(configuration_map["graphite_port"]);
    }

    if (configuration_map.count("graphite_push_period") != 0) {
        graphite_push_period = convert_string_to_integer(configuration_map["graphite_push_period"]);
    }

    // InfluxDB
    if (configuration_map.count("influxdb") != 0) {
        influxdb_enabled = configuration_map["influxdb"] == "on" ? true : false;
    }

    if (configuration_map.count("influxdb_port") != 0) {
        influxdb_port = convert_string_to_integer(configuration_map["influxdb_port"]);
    }

    if (configuration_map.count("influxdb_push_period") != 0) {
        influxdb_push_period = convert_string_to_integer(configuration_map["influxdb_push_period"]);
    }

    if (configuration_map.count("influxdb_host") != 0) {
        influxdb_host = configuration_map["influxdb_host"];
    }

    if (configuration_map.count("influxdb_database") != 0) {
        influxdb_database = configuration_map["influxdb_database"];
    }

    if (configuration_map.count("influxdb_auth") != 0) {
        influxdb_auth = configuration_map["influxdb_auth"] == "on" ? true : false;
    }

    if (configuration_map.count("influxdb_user") != 0) {
        influxdb_user = configuration_map["influxdb_user"];
    }

    if (configuration_map.count("influxdb_password") != 0) {
        influxdb_password = configuration_map["influxdb_password"];
    }

    if (configuration_map.count("process_incoming_traffic") != 0) {
        process_incoming_traffic = configuration_map["process_incoming_traffic"] == "on" ? true : false;
    }

    if (configuration_map.count("process_outgoing_traffic") != 0) {
        process_outgoing_traffic = configuration_map["process_outgoing_traffic"] == "on" ? true : false;
    }

    if (configuration_map.count("mirror") != 0) {
        if (configuration_map["mirror"] == "on") {
            enable_data_collection_from_mirror = true;
        } else {
            enable_data_collection_from_mirror = false;
        }
    }

    if (configuration_map.count("mirror_afxdp") != 0) {
        if (configuration_map["mirror_afxdp"] == "on") {
            enable_af_xdp_collection = true;
        } else {
            enable_af_xdp_collection = false;
        }
    }

    if (configuration_map.count("mirror_netmap") != 0) {
        if (configuration_map["mirror_netmap"] == "on") {
            enable_netmap_collection = true;
        } else {
            enable_netmap_collection = false;
        }
    }

    if (configuration_map.count("mirror_afpacket") != 0) {
        enable_afpacket_collection = configuration_map["mirror_afpacket"] == "on";
    }

    if (enable_afpacket_collection && enable_af_xdp_collection) {
        logger << log4cpp::Priority::ERROR << "You cannot use AF_XDP and AF_PACKET in same time, select one";
        exit(1);
    }

    if (enable_netmap_collection && enable_data_collection_from_mirror) {
        logger << log4cpp::Priority::ERROR
               << "You have enabled pfring and netmap data collection "
                  "from mirror which strictly prohibited, please "
                  "select one";
        exit(1);
    }

    if (configuration_map.count("pcap") != 0) {
        if (configuration_map["pcap"] == "on") {
            enable_pcap_collection = true;
        } else {
            enable_pcap_collection = false;
        }
    }

    // Read global ban configuration
    global_ban_settings = read_ban_settings(configuration_map, "");

    logging_configuration = read_logging_settings(configuration_map);

    logger << log4cpp::Priority::INFO << "We read global ban settings: " << print_ban_thresholds(global_ban_settings);

    // Read host group ban settings
    for (auto hostgroup_itr = host_groups.begin(); hostgroup_itr != host_groups.end(); ++hostgroup_itr) {
        std::string host_group_name = hostgroup_itr->first;

        logger << log4cpp::Priority::DEBUG << "We will read ban settings for " << host_group_name;

        host_group_ban_settings_map[host_group_name] = read_ban_settings(configuration_map, host_group_name);

        logger << log4cpp::Priority::DEBUG << "We read " << host_group_name << " ban settings "
            << print_ban_thresholds(host_group_ban_settings_map[ host_group_name ]);
    }

    if (configuration_map.count("white_list_path") != 0) {
        fastnetmon_platform_configuration.white_list_path = configuration_map["white_list_path"];
    }

    if (configuration_map.count("networks_list_path") != 0) {
        fastnetmon_platform_configuration.networks_list_path = configuration_map["networks_list_path"];
    }

#ifdef REDIS
    if (configuration_map.count("redis_port") != 0) {
        redis_port = convert_string_to_integer(configuration_map["redis_port"]);
    }

    if (configuration_map.count("redis_host") != 0) {
        redis_host = configuration_map["redis_host"];
    }

    if (configuration_map.count("redis_prefix") != 0) {
        redis_prefix = configuration_map["redis_prefix"];
    }

    if (configuration_map.count("redis_enabled") != 0) {
        // We use yes and on because it's stupid typo :(
        if (configuration_map["redis_enabled"] == "on" or configuration_map["redis_enabled"] == "yes") {
            redis_enabled = true;
        } else {
            redis_enabled = false;
        }
    }
#endif

    if (configuration_map.count("prometheus") != 0) {
        if (configuration_map["prometheus"] == "on") {
            prometheus = true;
        }
    }

    if (configuration_map.count("prometheus_host") != 0) {
        prometheus_host = configuration_map["prometheus_host"];
    }

    if (configuration_map.count("prometheus_port") != 0) {
        prometheus_port = convert_string_to_integer(configuration_map["prometheus_port"]);
    }

#ifdef KAFKA
    if (configuration_map.count("kafka_traffic_export") != 0) {
        if (configuration_map["kafka_traffic_export"] == "on") {
            kafka_traffic_export = true;
        }
    }

    if (configuration_map.count("kafka_traffic_export_topic") != 0) {
        kafka_traffic_export_topic = configuration_map["kafka_traffic_export_topic"];
    }

    // Load brokers list
    if (configuration_map.count("kafka_traffic_export_brokers") != 0) {
        std::string brokers_list_raw = configuration_map["kafka_traffic_export_brokers"];

        boost::split(kafka_traffic_export_brokers, brokers_list_raw, boost::is_any_of(","), boost::token_compress_on);
    }

    if (configuration_map.count("kafka_traffic_export_format") != 0) {
        std::string kafka_traffic_export_format_raw = configuration_map["kafka_traffic_export_format"];

        // Switch it to lowercase
        boost::algorithm::to_lower(kafka_traffic_export_format_raw);

        if (kafka_traffic_export_format_raw == "json") {
            kafka_traffic_export_format = kafka_traffic_export_format_t::JSON;
        } else if (kafka_traffic_export_format_raw == "protobuf") {
            kafka_traffic_export_format = kafka_traffic_export_format_t::Protobuf;
        } else {
            logger << log4cpp::Priority::ERROR << "Unknown format for kafka_traffic_export_format: " << kafka_traffic_export_format_raw;

            kafka_traffic_export_format = kafka_traffic_export_format_t::Unknown;
        }
    }
#endif

#ifdef MONGO
    if (configuration_map.count("mongodb_enabled") != 0) {
        if (configuration_map["mongodb_enabled"] == "on") {
            mongodb_enabled = true;
        }
    }

    if (configuration_map.count("mongodb_host") != 0) {
        mongodb_host = configuration_map["mongodb_host"];
    }

    if (configuration_map.count("mongodb_port") != 0) {
        mongodb_port = convert_string_to_integer(configuration_map["mongodb_port"]);
    }

    if (configuration_map.count("mongodb_database_name") != 0) {
        mongodb_database_name = configuration_map["mongodb_database_name"];
    }
#endif

    if (configuration_map.count("ban_details_records_count") != 0) {
        ban_details_records_count = convert_string_to_integer(configuration_map["ban_details_records_count"]);
    }

    if (configuration_map.count("check_period") != 0) {
        check_period = convert_string_to_integer(configuration_map["check_period"]);
    }

    if (configuration_map.count("sort_parameter") != 0) {
        sort_parameter = configuration_map["sort_parameter"];
    }

    if (configuration_map.count("max_ips_in_list") != 0) {
        max_ips_in_list = convert_string_to_integer(configuration_map["max_ips_in_list"]);
    }

    if (configuration_map.count("notify_script_path") != 0) {
        fastnetmon_platform_configuration.notify_script_path = configuration_map["notify_script_path"];
    }

    if (file_exists(fastnetmon_platform_configuration.notify_script_path)) {
        notify_script_enabled = true;
    } else {
        logger << log4cpp::Priority::ERROR << "We can't find notify script " << fastnetmon_platform_configuration.notify_script_path;
        notify_script_enabled = false;
    }

    if (configuration_map.count("collect_attack_pcap_dumps") != 0) {
        collect_attack_pcap_dumps = configuration_map["collect_attack_pcap_dumps"] == "on" ? true : false;
    }

    if (configuration_map.count("dump_all_traffic") != 0) {
        DEBUG_DUMP_ALL_PACKETS = configuration_map["dump_all_traffic"] == "on" ? true : false;
    }

    if (configuration_map.count("dump_other_traffic") != 0) {
        DEBUG_DUMP_OTHER_PACKETS = configuration_map["dump_other_traffic"] == "on" ? true : false;
    }

    return true;
}

// Enable core dumps for simplify debug tasks 
#ifndef _WIN32
void enable_core_dumps() {
    struct rlimit rlim;

    int result = getrlimit(RLIMIT_CORE, &rlim);

    if (result) {
        logger << log4cpp::Priority::ERROR << "Can't get current rlimit for RLIMIT_CORE";
        return;
    } else {
        rlim.rlim_cur = rlim.rlim_max;
        setrlimit(RLIMIT_CORE, &rlim);
    }
}
#endif

void subnet_vectors_allocator(prefix_t* prefix, void* data) {
    // Network byte order
    uint32_t subnet_as_integer = prefix->add.sin.s_addr;

    u_short bitlen          = prefix->bitlen;
    double base             = 2;
    int network_size_in_ips = pow(base, 32 - bitlen);
    // logger<< log4cpp::Priority::INFO<<"Subnet: "<<prefix->add.sin.s_addr<<" network size:
    // "<<network_size_in_ips;
   
    subnet_cidr_mask_t current_subnet(subnet_as_integer, bitlen);

    logger << log4cpp::Priority::INFO << "I will allocate " << network_size_in_ips << " records for subnet "
           << convert_ipv4_subnet_to_string(current_subnet);

    subnet_counter_t zero_map_element{};

    for (int i = 0; i < network_size_in_ips; i++) {
        // We need to increment IP address by X but we have to do so in little endian / host byte order
        // incrementing big endian will not work as we expect
        uint32_t ip_as_little_endian = fast_ntoh(subnet_as_integer);

        // Increment it for specific number
        ip_as_little_endian += i;

        if (enable_connection_tracking) {
            // On creating it initializes by zeros
            conntrack_main_struct_t zero_conntrack_main_struct{};

            SubnetVectorMapFlow[ip_as_little_endian] = zero_conntrack_main_struct;
        }

        uint32_t result_ip_as_big_endian = fast_hton(ip_as_little_endian);

        // logger << log4cpp::Priority::INFO << "Allocate: " << convert_ip_as_uint_to_string(result_ip_as_big_endian);

        // We use big endian values as keys
        try {
            ipv4_host_counters.average_speed_map[result_ip_as_big_endian] = zero_map_element;
            ipv4_host_counters.counter_map[result_ip_as_big_endian] = zero_map_element;
        } catch (std::bad_alloc& ba) {
            logger << log4cpp::Priority::ERROR << "Can't allocate memory for hash counters";
            exit(1);
        }
    }

    logger << log4cpp::Priority::INFO << "Successfully allocated " << ipv4_host_counters.average_speed_map.size() << " counters";
}

bool load_our_networks_list() {
    if (file_exists(fastnetmon_platform_configuration.white_list_path)) {
        unsigned int network_entries                      = 0;
        std::vector<std::string> network_list_from_config = read_file_to_vector(fastnetmon_platform_configuration.white_list_path);

        for (std::vector<std::string>::iterator ii = network_list_from_config.begin(); ii != network_list_from_config.end(); ++ii) {
            std::string text_subnet = *ii;
            if (text_subnet.empty()) {
                continue;
            }
            if (is_v4_host(text_subnet)) {
                logger << log4cpp::Priority::INFO << "Assuming /32 netmask for " << text_subnet;
                text_subnet += "/32";
            } else if (!is_cidr_subnet(text_subnet)) {
                logger << log4cpp::Priority::ERROR << "Can't parse line from whitelist: " << text_subnet;
                continue;
            }
            network_entries++;
            make_and_lookup(whitelist_tree_ipv4, text_subnet.c_str());
        }

        logger << log4cpp::Priority::INFO << "We loaded " << network_entries << " networks from whitelist file";
    }

    std::vector<std::string> networks_list_ipv4_as_string;
    std::vector<std::string> networks_list_ipv6_as_string;

    // We can build list of our subnets automatically here
    if (monitor_openvz_vps_ip_addresses && file_exists("/proc/vz/version")) {
        logger << log4cpp::Priority::INFO << "We found OpenVZ";
        // Add /32 CIDR mask for every IP here
        std::vector<std::string> openvz_ips = read_file_to_vector("/proc/vz/veip");
        for (std::vector<std::string>::iterator ii = openvz_ips.begin(); ii != openvz_ips.end(); ++ii) {
            // skip header
            if (strstr(ii->c_str(), "Version") != NULL) {
                continue;
            }

            /*
                Example data for this lines:
                2a03:f480:1:17:0:0:0:19          0
                            185.4.72.40          0
            */

            if (strstr(ii->c_str(), ":") == NULL) {
                // IPv4

                std::vector<std::string> subnet_as_string;
                split(subnet_as_string, *ii, boost::is_any_of(" "), boost::token_compress_on);

                std::string openvz_subnet = subnet_as_string[1] + "/32";
                networks_list_ipv4_as_string.push_back(openvz_subnet);
            } else {
                // IPv6

                std::vector<std::string> subnet_as_string;
                split(subnet_as_string, *ii, boost::is_any_of(" "), boost::token_compress_on);

                std::string openvz_subnet = subnet_as_string[1] + "/128";
                networks_list_ipv6_as_string.push_back(openvz_subnet);
            }
        }

        logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv4_as_string.size() << " IPv4 networks from /proc/vz/veip";

        logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv6_as_string.size() << " IPv6 networks from /proc/vz/veip";
    }

    if (monitor_local_ip_addresses && file_exists("/sbin/ip")) {
        logger << log4cpp::Priority::INFO << "On Linux we can use ip tool to detect local IPs";

        ip_addresses_list_t ip_list = get_local_ip_v4_addresses_list();

        logger << log4cpp::Priority::INFO << "We found " << ip_list.size() << " local IP addresses";

        for (ip_addresses_list_t::iterator iter = ip_list.begin(); iter != ip_list.end(); ++iter) {
            // TODO: add IPv6 here
            networks_list_ipv4_as_string.push_back(*iter + "/32");
        }
    }

    if (file_exists(fastnetmon_platform_configuration.networks_list_path)) {
        std::vector<std::string> network_list_from_config =
            read_file_to_vector(fastnetmon_platform_configuration.networks_list_path);

        for (std::vector<std::string>::iterator line_itr = network_list_from_config.begin();
             line_itr != network_list_from_config.end(); ++line_itr) {

            if (line_itr->length() == 0) {
                // Skip blank lines in subnet list file silently
                continue;
            }

            if (strstr(line_itr->c_str(), ":") == NULL) {
                networks_list_ipv4_as_string.push_back(*line_itr);
            } else {
                networks_list_ipv6_as_string.push_back(*line_itr);
            }
        }

        logger << log4cpp::Priority::INFO << "We loaded " << network_list_from_config.size() << " networks from networks file";
    }

    logger << log4cpp::Priority::INFO << "Totally we have " << networks_list_ipv4_as_string.size() << " IPv4 subnets";
    logger << log4cpp::Priority::INFO << "Totally we have " << networks_list_ipv6_as_string.size() << " IPv6 subnets";

    for (std::vector<std::string>::iterator ii = networks_list_ipv4_as_string.begin();
         ii != networks_list_ipv4_as_string.end(); ++ii) {

        if (!is_cidr_subnet(*ii)) {
            logger << log4cpp::Priority::ERROR << "Can't parse line from subnet list: '" << *ii << "'";
            continue;
        }

        std::string network_address_in_cidr_form = *ii;

        unsigned int cidr_mask      = get_cidr_mask_from_network_as_string(network_address_in_cidr_form);
        std::string network_address = get_net_address_from_network_as_string(network_address_in_cidr_form);

        double base = 2;
        total_number_of_hosts_in_our_networks += pow(base, 32 - cidr_mask);

        // Make sure it's "subnet address" and not an host address
        uint32_t subnet_address_as_uint = 0;

        bool ip_parser_result = convert_ip_as_string_to_uint_safe(network_address, subnet_address_as_uint);

        if (!ip_parser_result) {
            logger << log4cpp::Priority::ERROR << "Cannot parse " << network_address << " as IP";
            continue;
        }

        uint32_t subnet_address_netmask_binary = convert_cidr_to_binary_netmask(cidr_mask);
        uint32_t generated_subnet_address      = subnet_address_as_uint & subnet_address_netmask_binary;

        if (subnet_address_as_uint != generated_subnet_address) {
            std::string new_network_address_as_string =
                convert_ip_as_uint_to_string(generated_subnet_address) + "/" + convert_int_to_string(cidr_mask);

            logger << log4cpp::Priority::WARN << "We will use " << new_network_address_as_string << " instead of "
                   << network_address_in_cidr_form << " because it's host address";

            network_address_in_cidr_form = new_network_address_as_string;
        }

        make_and_lookup(lookup_tree_ipv4, network_address_in_cidr_form.c_str());
    }

    for (std::vector<std::string>::iterator ii = networks_list_ipv6_as_string.begin();
         ii != networks_list_ipv6_as_string.end(); ++ii) {

        // TODO: add IPv6 subnet format validation
        make_and_lookup_ipv6(lookup_tree_ipv6, (char*)ii->c_str());
    }

    logger << log4cpp::Priority::INFO
           << "Total number of monitored hosts (total size of all networks): " << total_number_of_hosts_in_our_networks;

    // 3 - speed counter, average speed counter and data counter
    uint64_t memory_requirements = 3 * sizeof(subnet_counter_t) * total_number_of_hosts_in_our_networks / 1024 / 1024;

    logger << log4cpp::Priority::INFO << "We need " << memory_requirements << " MB of memory for storing counters for your networks";

    /* Preallocate data structures */
    patricia_process(lookup_tree_ipv4, subnet_vectors_allocator);

    logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv4_as_string.size()
           << " IPv4 subnets to our in-memory list of networks";

    return true;
}

#ifdef GEOIP
unsigned int get_asn_for_ip(uint32_t ip) {
    char* asn_raw       = GeoIP_org_by_name(geo_ip, convert_ip_as_uint_to_string(remote_ip).c_str());
    uint32_t asn_number = 0;

    if (asn_raw == NULL) {
        asn_number = 0;
    } else {
        // split string: AS1299 TeliaSonera International Carrier
        std::vector<std::string> asn_as_string;
        split(asn_as_string, asn_raw, boost::is_any_of(" "), boost::token_compress_on);

        // free up original string
        free(asn_raw);

        // extract raw number
        asn_number = convert_string_to_integer(asn_as_string[0].substr(2));
    }

    return asn_number;
}
#endif

// It's vizualization thread :)
void screen_draw_ipv4_thread() {
    // we need wait one second for calculating speed by recalculate_speed

    //#include <sys/prctl.h>
    // prctl(PR_SET_NAME , "fastnetmon calc thread", 0, 0, 0);

    // Sleep for a half second for shift against calculatiuon thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    while (true) {
        // Available only from boost 1.54: boost::this_thread::sleep_for(
        // boost::chrono::seconds(check_period) );
        boost::this_thread::sleep(boost::posix_time::seconds(check_period));
        traffic_draw_ipv4_program();
    }
}

// It's vizualization thread :)
void screen_draw_ipv6_thread() {
    // we need wait one second for calculating speed by recalculate_speed

    //#include <sys/prctl.h>
    // prctl(PR_SET_NAME , "fastnetmon calc thread", 0, 0, 0);

    // Sleep for a half second for shift against calculatiuon thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    while (true) {
        // Available only from boost 1.54: boost::this_thread::sleep_for(
        // boost::chrono::seconds(check_period) );
        boost::this_thread::sleep(boost::posix_time::seconds(check_period));
        traffic_draw_ipv6_program();
    }
}


void recalculate_speed_thread_handler() {
    while (true) {
        // recalculate data every one second
        // Available only from boost 1.54: boost::this_thread::sleep_for( boost::chrono::seconds(1)
        // );
        boost::this_thread::sleep(boost::posix_time::seconds(recalculate_speed_timeout));
        recalculate_speed();
    }
}

bool file_is_appendable(std::string path) {
    std::ofstream check_appendable_file;

    check_appendable_file.open(path.c_str(), std::ios::app);

    if (check_appendable_file.is_open()) {
        // all fine, just close file
        check_appendable_file.close();

        return true;
    } else {
        return false;
    }
}

void init_logging(bool log_to_console) {
    logger.setPriority(log4cpp::Priority::INFO);

    // In this case we log everything to console
    if (log_to_console) {
        log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
        layout->setConversionPattern("[%p] %m%n");

        // We duplicate stdout because it will be closed by log4cpp on object termination and we do not need it
        log4cpp::Appender* console_appender = new log4cpp::FileAppender("stdout", ::dup(fileno(stdout)));
        console_appender->setLayout(layout);
        logger.addAppender(console_appender);
    } else {
        log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
        layout->setConversionPattern("%d [%p] %m%n");

        // So log4cpp will never notify you if it could not write to log file due to permissions issues
        // We will check it manually

        if (!file_is_appendable(fastnetmon_platform_configuration.log_file_path)) {
            std::cerr << "Can't open log file " << fastnetmon_platform_configuration.log_file_path
                      << " for writing! Please check file and folder permissions" << std::endl;
            exit(EXIT_FAILURE);
        }

        log4cpp::Appender* appender = new log4cpp::FileAppender("default", fastnetmon_platform_configuration.log_file_path);
        appender->setLayout(layout);
        logger.addAppender(appender);
    }

    logger << log4cpp::Priority::INFO << "Logger initialized";
}

void reconfigure_logging_level(const std::string& logging_level) {
    // Configure logging level
    log4cpp::Priority::Value priority = log4cpp::Priority::INFO;

    if (logging_level == "debug") {
        priority = log4cpp::Priority::DEBUG;
        logger << log4cpp::Priority::DEBUG << "Setting logging level to debug";
    } else if (logging_level == "info" || logging_level == "") {
        // It may be set to empty value in old versions before we introduced this flag
        logger << log4cpp::Priority::DEBUG << "Setting logging level to info";
        priority = log4cpp::Priority::INFO;
    } else {
        logger << log4cpp::Priority::ERROR << "Unknown logging level: " << logging_level;
    }

    logger.setPriority(priority);
}

void reconfigure_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("[%p] %m%n");

    if (logging_configuration.local_syslog_logging) {
#ifdef _WIN32
        logger << log4cpp::Priority::ERROR << "Local syslog logging is not supported on Windows platform";
#else
        log4cpp::Appender* local_syslog_appender = new log4cpp::SyslogAppender("fastnetmon", "fastnetmon", LOG_USER);
        local_syslog_appender->setLayout(layout);
        logger.addAppender(local_syslog_appender);

        logger << log4cpp::Priority::INFO << "We start local syslog logging corectly";
#endif
    }

    if (logging_configuration.remote_syslog_logging) {
#ifdef _WIN32
        logger << log4cpp::Priority::ERROR << "Remote syslog logging is not supported on Windows platform";
#else
        log4cpp::Appender* remote_syslog_appender =
            new log4cpp::RemoteSyslogAppender("fastnetmon", "fastnetmon", logging_configuration.remote_syslog_server,
                                              LOG_USER, logging_configuration.remote_syslog_port);

        remote_syslog_appender->setLayout(layout);
        logger.addAppender(remote_syslog_appender);
#endif

        logger << log4cpp::Priority::INFO << "We start remote syslog logging correctly";
    }

    reconfigure_logging_level(logging_configuration.logging_level);
}


#ifndef _WIN32
// Call fork function
// We have no work on Windows
int do_fork() {
    int status = 0;

    switch (fork()) {
    case 0:
        // It's child
        break;
    case -1:
        /* fork failed */
        status = -1;
        break;
    default:
        // We should close master process with _exit(0)
        // We should not call exit() because it will destroy all global variables for program
        _exit(0);
    }

    return status;
}
#endif


void redirect_fds() {
    // Close stdin, stdout and stderr
    close(0);
    close(1);
    close(2);

    if (open("/dev/null", O_RDWR) != 0) {
        // We can't notify anybody now
        exit(1);
    }

    // Create copy of zero decriptor for 1 and 2 fd's
    // We do not need return codes here but we need do it for suppressing
    // complaints from compiler
    // Ignore warning because I prefer to have these unusued variables here for clarity
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
    int first_dup_result  = dup(0);
    int second_dup_result = dup(0);
#pragma GCC diagnostic pop
}

// Handles fatal failure of FastNetMon's daemon
void fatal_signal_handler(int signum) {
    ::signal(signum, SIG_DFL);
    boost::stacktrace::safe_dump_to(fastnetmon_platform_configuration.backtrace_path.c_str());
    ::raise(SIGABRT);
}

int main(int argc, char** argv) {
    bool daemonize                = false;
    bool only_configuration_check = false;

    namespace po = boost::program_options;

    // Switch logging to console
    bool log_to_console = false;

    // This was legacy logic for init V based distros to prevent multiple copies of same daemon running in same time
    bool do_pid_checks = false;

    try {
        // clang-format off
        po::options_description desc("Allowed options");
        desc.add_options()
		("help", "produce help message")
		("version", "show version")
		("daemonize", "detach from the terminal")
		("configuration_check", "check configuration and exit")
		("configuration_file", po::value<std::string>(),"set path to custom configuration file")
		("log_file", po::value<std::string>(), "set path to custom log file")
        ("log_to_console", "switches all logging to console")
        ("pid_logic", "Enables logic which stores PID to file and uses it for duplicate instance checks")
        ("disable_pid_logic", "Disables logic which stores PID to file and uses it for duplicate instance checks. No op as it's disabled by default");
        // clang-format on

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (vm.count("version")) {
            std::cout << "Version: " << fastnetmon_platform_configuration.fastnetmon_version << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (vm.count("daemonize")) {
            daemonize = true;
        }

        if (vm.count("configuration_check")) {
            only_configuration_check = true;
        }

        if (vm.count("configuration_file")) {
            fastnetmon_platform_configuration.global_config_path = vm["configuration_file"].as<std::string>();
            std::cout << "We will use custom path to configuration file: " << fastnetmon_platform_configuration.global_config_path
                      << std::endl;
        }

        if (vm.count("log_file")) {
            fastnetmon_platform_configuration.log_file_path = vm["log_file"].as<std::string>();
            std::cout << "We will use custom path to log file: " << fastnetmon_platform_configuration.log_file_path << std::endl;
        }

        if (vm.count("log_to_console")) {
            std::cout << "We will log everything on console" << std::endl;
            log_to_console = true;
        }

        // No op as it's disabled by default
        if (vm.count("disable_pid_logic")) {
            do_pid_checks = false;
        }

        if (vm.count("pid_logic")) {
            do_pid_checks = true;
        }
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        exit(EXIT_FAILURE);
    }

    // We use ideas from here https://github.com/bmc/daemonize/blob/master/daemon.c
#ifndef _WIN32
    if (daemonize) {
        int status = 0;

        std::cout << "We will run in daemonized mode" << std::endl;

        if ((status = do_fork()) < 0) {
            // fork failed
            status = -1;
        } else if (setsid() < 0) {
            // Create new session
            status = -1;
        } else if ((status = do_fork()) < 0) {
            status = -1;
        } else {
            // Clear inherited umask
            umask(0);

            // Chdir to root
            // I prefer to keep this variable for clarity
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
            int chdir_result = chdir("/");
#pragma GCC diagnostic pop

            // close all descriptors because we are daemon!
            redirect_fds();
        }
    }
#else
    if (daemonize) {
        std::cerr << "ERROR: " << "Daemon mode is not supported on Windows platforms" << std::endl;
        exit(EXIT_FAILURE);
    }
#endif


    // Enable core dumps
#ifndef _WIN32
    enable_core_dumps();
#endif

    // Setup fatal signal handlers to gracefully capture them
    ::signal(SIGSEGV, &fatal_signal_handler);
    ::signal(SIGABRT, &fatal_signal_handler);

    init_logging(log_to_console);

    if (std::filesystem::exists(fastnetmon_platform_configuration.backtrace_path)) {
        // there is a backtrace
        std::ifstream ifs(fastnetmon_platform_configuration.backtrace_path);

        boost::stacktrace::stacktrace st = boost::stacktrace::stacktrace::from_dump(ifs);
        logger << log4cpp::Priority::ERROR << "Previous run crashed, you can find stack trace below";
        logger << log4cpp::Priority::ERROR << st;

        // cleaning up
        ifs.close();
        std::filesystem::remove(fastnetmon_platform_configuration.backtrace_path);
    }

#ifdef FASTNETMON_API
    gpr_set_log_function(silent_logging_function);
#endif

    // Set default ban configuration
    init_global_ban_settings();

    // We should read configurartion file _after_ logging initialization
    bool load_config_result = load_configuration_file();

    if (!load_config_result) {
        std::cerr << "Can't open config file " << fastnetmon_platform_configuration.global_config_path
                  << " please create it!" << std::endl;
        exit(1);
    }

    if (only_configuration_check) {
        logger << log4cpp::Priority::INFO << "Configuration file is correct. Shutdown toolkit";
        exit(0);
    }

    // On Linux and FreeBSD platforms we use kill to check that process with specific PID is alive
    // Unfortunately, it's way more tricky to implement such approach on Windows and we decided just to disable this logic 
#ifdef _WIN32
    if (do_pid_checks) {
        logger << log4cpp::Priority::INFO << "PID logic is not available on Windows";
        exit(1);
    }
#else
    if (do_pid_checks && file_exists(fastnetmon_platform_configuration.pid_path)) {
        pid_t pid_from_file = 0;

        if (read_pid_from_file(pid_from_file, fastnetmon_platform_configuration.pid_path)) {
            // We could read pid
            if (pid_from_file > 0) {
                // We use signal zero for check process existence
                int kill_result = kill(pid_from_file, 0);

                if (kill_result == 0) {
                    logger << log4cpp::Priority::ERROR << "FastNetMon is already running with pid: " << pid_from_file;
                    exit(1);
                } else {
                    // Yes, we have pid with pid but it's zero
                }
            } else {
                // pid from file is broken, we assume tool is not running
            }
        } else {
            // We can't open file, let's assume it's broken and tool is not running
        }
    } else {
        // no pid file
    }

    if (do_pid_checks) {

        // If we not failed in check steps we could run toolkit
        bool print_pid_to_file_result = print_pid_to_file(getpid(), fastnetmon_platform_configuration.pid_path);

        if (!print_pid_to_file_result) {
            logger << log4cpp::Priority::ERROR
                   << "Could not create pid file, please check permissions: " << fastnetmon_platform_configuration.pid_path;
            exit(EXIT_FAILURE);
        }
    }
#endif

    lookup_tree_ipv4    = New_Patricia(32);
    whitelist_tree_ipv4 = New_Patricia(32);

    lookup_tree_ipv6    = New_Patricia(128);
    whitelist_tree_ipv6 = New_Patricia(128);

    /* Create folder for attack details */
    if (!folder_exists(fastnetmon_platform_configuration.attack_details_folder)) {
        logger << log4cpp::Priority::ERROR
               << "Folder for attack details does not exist: " << fastnetmon_platform_configuration.attack_details_folder;
    }

    if (getenv("DUMP_ALL_PACKETS") != NULL) {
        DEBUG_DUMP_ALL_PACKETS = true;
    }

    if (getenv("DUMP_OTHER_PACKETS") != NULL) {
        DEBUG_DUMP_OTHER_PACKETS = true;
    }

    if (sizeof(packed_conntrack_hash_t) != sizeof(uint64_t) or sizeof(packed_conntrack_hash_t) != 8) {
        logger << log4cpp::Priority::INFO << "Assertion about size of packed_conntrack_hash, it's "
               << sizeof(packed_conntrack_hash_t) << " instead 8";
        exit(1);
    }

    logger << log4cpp::Priority::INFO << "Read configuration file";

    // Reconfigure logging. We will enable specific logging methods here
    reconfigure_logging();

    load_our_networks_list();

    // We should specify size of circular buffers here
    packet_buckets_ipv4_storage.set_buffers_capacity(ban_details_records_count);

    // Set capacity for nested buffers
    packet_buckets_ipv6_storage.set_buffers_capacity(ban_details_records_count);

    // Setup CTRL+C handler
    if (signal(SIGINT, interruption_signal_handler) == SIG_ERR) {
        logger << log4cpp::Priority::ERROR << "Can't setup SIGINT handler";
        exit(1);
    }

    // Windows does not support SIGPIPE
#ifndef _WIN32
    /* Without this SIGPIPE error could shutdown toolkit on call of exec_with_stdin_params */
    if (signal(SIGPIPE, sigpipe_handler_for_popen) == SIG_ERR) {
        logger << log4cpp::Priority::ERROR << "Can't setup SIGPIPE handler";
        exit(1);
    }
#endif

#ifdef GEOIP
    // Init GeoIP
    if (!geoip_init()) {
        logger << log4cpp::Priority::ERROR << "Can't load geoip tables";
        exit(1);
    }
#endif
    // Init previous run date
    last_call_of_traffic_recalculation = std::chrono::steady_clock::now();

    // We call init for each action
#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        gobgp_action_init();
    }
#endif

#ifdef KAFKA
    if (kafka_traffic_export) {
        if (kafka_traffic_export_brokers.size() == 0) {
            logger << log4cpp::Priority::ERROR << "Kafka traffic export requires at least single broker, please configure kafka_traffic_export_brokers";
        } else {
            std::string all_brokers = boost::algorithm::join(kafka_traffic_export_brokers, ",");

            std::string partitioner = "random";

            // All available configuration options: https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
            cppkafka::Configuration kafka_traffic_export_config = {
                { "metadata.broker.list", all_brokers },
                { "request.required.acks", "0" }, // Disable ACKs
                { "partitioner", partitioner },
            };

            logger << log4cpp::Priority::INFO << "Initialise Kafka producer for traffic export";

            // In may crash during producer creation
            try {
                kafka_traffic_export_producer = new cppkafka::Producer(kafka_traffic_export_config);
            } catch (...) {
                logger << log4cpp::Priority::ERROR << "Cannot initialise Kafka producer";
                kafka_traffic_export = false;
            }

            logger << log4cpp::Priority::INFO << "Kafka traffic producer is ready";
        }
    }
#endif

#ifdef FASTNETMON_API
    if (enable_api) {
        service_thread_group.add_thread(new boost::thread(RunApiServer));
    }
#endif

    if (prometheus) {
        auto prometheus_thread = new boost::thread(start_prometheus_web_server);
        set_boost_process_name(prometheus_thread, "prometheus");
        service_thread_group.add_thread(prometheus_thread);
    }

    // Set inaccurate time value which will be used in process_packet() from capture backends
    time(&current_inaccurate_time);

    // start thread which pre-calculates speed for system counters
    auto system_counters_speed_thread = new boost::thread(system_counters_speed_thread_handler);
    set_boost_process_name(system_counters_speed_thread, "metrics_speed");
    service_thread_group.add_thread(system_counters_speed_thread);


    auto inaccurate_time_generator_thread = new boost::thread(inaccurate_time_generator);
    set_boost_process_name(inaccurate_time_generator_thread, "fast_time");
    service_thread_group.add_thread(inaccurate_time_generator_thread);

    // Run stats thread
    bool usage_stats = true;

    if (configuration_map.count("disable_usage_report") != 0 && configuration_map["disable_usage_report"] == "on") {
        usage_stats = false;
    }

    if (usage_stats) {
        auto stats_thread = new boost::thread(collect_stats);
        set_boost_process_name(stats_thread, "stats");
        service_thread_group.add_thread(stats_thread);
    }

    // Run screen draw thread for IPv4
    service_thread_group.add_thread(new boost::thread(screen_draw_ipv4_thread));

    // Run screen draw thread for IPv6
    service_thread_group.add_thread(new boost::thread(screen_draw_ipv6_thread));

    // Graphite export thread
    if (graphite_enabled) {
        service_thread_group.add_thread(new boost::thread(graphite_push_thread));
    }

    // InfluxDB export thread
    if (influxdb_enabled) {
        service_thread_group.add_thread(new boost::thread(influxdb_push_thread));
    }

    // start thread for recalculating speed in realtime
    service_thread_group.add_thread(new boost::thread(recalculate_speed_thread_handler));

    // Run banlist cleaner thread
    if (unban_enabled) {
        service_thread_group.add_thread(new boost::thread(cleanup_ban_list));
    }

    // This thread will check about filled buckets with packets and process they
    auto check_traffic_buckets_thread = new boost::thread(check_traffic_buckets);
    set_boost_process_name(check_traffic_buckets_thread, "check_buckets");
    service_thread_group.add_thread(check_traffic_buckets_thread);

#ifdef NETMAP_PLUGIN
    // netmap processing
    if (enable_netmap_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_netmap_collection, process_packet));
    }
#endif

#ifdef FASTNETMON_ENABLE_AFPACKET
    if (enable_afpacket_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_afpacket_collection, process_packet));
    }
#endif

#ifdef FASTNETMON_ENABLE_AF_XDP
    if (enable_af_xdp_collection) {
        auto xdp_thread = new boost::thread(start_xdp_collection, process_packet);
        set_boost_process_name(xdp_thread, "xdp");
        packet_capture_plugin_thread_group.add_thread(xdp_thread);
    }
#endif

    if (enable_sflow_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_sflow_collection, process_packet));
    }

    if (enable_netflow_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_netflow_collection, process_packet));
    }

#ifdef ENABLE_PCAP
    if (enable_pcap_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_pcap_collection, process_packet));
    }
#endif

    // Wait for all threads in capture thread group
    packet_capture_plugin_thread_group.join_all();

    // Wait for all service threads
    service_thread_group.join_all();

    free_up_all_resources();

    return 0;
}

void free_up_all_resources() {
#ifdef GEOIP
    // Free up geoip handle
    GeoIP_delete(geo_ip);
#endif

    Destroy_Patricia(lookup_tree_ipv4);
    Destroy_Patricia(whitelist_tree_ipv4);

    Destroy_Patricia(lookup_tree_ipv6);
    Destroy_Patricia(whitelist_tree_ipv6);
}

// For correct program shutdown by CTRL+C
void interruption_signal_handler(int signal_number) {

    logger << log4cpp::Priority::INFO << "SIGNAL captured, prepare toolkit shutdown";

#ifdef FASTNETMON_API
    logger << log4cpp::Priority::INFO << "Send shutdown command to API server";
    api_server->Shutdown();
#endif

    logger << log4cpp::Priority::INFO << "Interrupt service threads";
    service_thread_group.interrupt_all();

    logger << log4cpp::Priority::INFO << "Wait while they finished";
    service_thread_group.join_all();

    logger << log4cpp::Priority::INFO << "Interrupt packet capture treads";
    packet_capture_plugin_thread_group.interrupt_all();

    logger << log4cpp::Priority::INFO << "Wait while they finished";
    packet_capture_plugin_thread_group.join_all();

    logger << log4cpp::Priority::INFO << "Shutdown main process";

    // TODO: we should REMOVE this exit command and wait for correct toolkit shutdown
    exit(1);
}
