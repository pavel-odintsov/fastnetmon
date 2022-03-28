/* Author: pavel.odintsov@gmail.com */
/* License: GPLv2 */

#include <errno.h>
#include <math.h>
#include <new>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_arp.h> // struct arphdr
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "bgp_protocol.hpp"
#include "fast_library.h"
#include "fastnetmon_packet_parser.h"
#include "fastnetmon_types.h"
#include "libpatricia/patricia.h"
#include "packet_storage.h"

// Here we store variables which differs for different paltforms
#include "fast_platform.h"

#include "fastnetmon_logic.hpp"

#ifdef ENABLE_DPI
#include "fast_dpi.h"
#endif

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
#include "netflow_plugin/netflow_collector.h"
#include "pcap_plugin/pcap_collector.h"
#include "sflow_plugin/sflow_collector.h"

#ifdef NETMAP_PLUGIN
#include "netmap_plugin/netmap_collector.h"
#endif

#ifdef PF_RING
#include "pfring_plugin/pfring_collector.h"
#endif

#ifdef FASTNETMON_ENABLE_AFPACKET
#include "afpacket_plugin/afpacket_collector.h"
#endif

#ifdef ENABLE_GOBGP
#include "actions/gobgp_action.h"
#endif

// Yes, maybe it's not an good idea but with this we can guarantee working code in example plugin
#include "example_plugin/example_collector.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>

#include <sstream>
#include <utility>
#include <vector>

#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#include <boost/program_options.hpp>

#include "all_logcpp_libraries.h"

// Boost libs
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#ifdef GEOIP
#include "GeoIP.h"
#endif

#ifdef REDIS
#include <hiredis/hiredis.h>
#endif

#include "packet_bucket.h"

#include "ban_list.hpp"

#include "metrics/graphite.hpp"
#include "metrics/influxdb.hpp"

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

time_t last_call_of_traffic_recalculation;

std::string cli_stats_file_path = "/tmp/fastnetmon.dat";

std::string cli_stats_ipv6_file_path = "/tmp/fastnetmon_ipv6.dat";

unsigned int stats_thread_sleep_time = 3600;
unsigned int stats_thread_initial_call_delay = 30;

// Each this seconds we will check about available data in bucket
unsigned int check_for_availible_for_processing_packets_buckets = 1; 

// Current time with pretty low precision, we use separate thread to update it
time_t current_inaccurate_time = 0; 

// This is thread safe storage for captured from the wire packets for IPv6 traffic
packet_buckets_storage_t<subnet_ipv6_cidr_mask_t> packet_buckets_ipv6_storage;

unsigned int recalculate_speed_timeout = 1;

// We will remove all packet buckets which runs longer than this time. This value used only for one shot buckets.
// Infinite bucket's will not removed
unsigned int maximum_time_since_bucket_start_to_remove = 120; 

FastnetmonPlatformConfigurtion fastnetmon_platform_configuration;

// Send or not any details about attack for ban script call over stdin
bool notify_script_pass_details = true;

bool notify_script_enabled = true;

// We could collect attack dumps in pcap format
bool collect_attack_pcap_dumps = false;

// We could process this dumps with DPI
bool process_pcap_attack_dumps_with_dpi = false;

bool unban_only_if_attack_finished = true;

logging_configuration_t logging_configuration;

// Global map with parsed config file
configuration_map_t configuration_map;

// Every X seconds we will run ban list cleaner thread
// If customer uses ban_time smaller than this value we will use ban_time/2 as unban_iteration_sleep_time
int unban_iteration_sleep_time = 60;

bool unban_enabled = true;

#ifdef ENABLE_DPI
struct ndpi_detection_module_struct* my_ndpi_struct = NULL;

u_int32_t ndpi_size_flow_struct = 0;
u_int32_t ndpi_size_id_struct = 0;
#endif

#ifdef ENABLE_GOBGP
bool gobgp_enabled = false;
#endif

#ifdef MONGO
std::string mongodb_host = "localhost";
unsigned int mongodb_port = 27017;
bool mongodb_enabled = false;

std::string mongodb_database_name = "fastnetmon";
#endif

/* Configuration block, we must move it to configuration file  */
#ifdef REDIS
unsigned int redis_port = 6379;
std::string redis_host = "127.0.0.1";

// redis key prefix
std::string redis_prefix = "";

// because it's additional and very specific feature we should disable it by default
bool redis_enabled = false;
#endif

bool monitor_local_ip_addresses = true;

// Enable monitoring for OpenVZ VPS IP addresses by reading their list from kernel 
bool monitor_openvz_vps_ip_addresses = false;

// Trigger for enable or disable traffic counting for whole subnets
bool enable_subnet_counters = false;

// We will announce whole subnet instead single IP with BGP if this flag enabled
bool exabgp_announce_whole_subnet = false;

// We will announce only /32 host
bool exabgp_announce_host = false;

// With this flag we will announce more specfic then whole block Flow Spec announces
bool exabgp_flow_spec_announces = false;

ban_settings_t global_ban_settings;

void init_global_ban_settings() {
    // ban Configuration params
    global_ban_settings.enable_ban_for_pps = false;
    global_ban_settings.enable_ban_for_bandwidth = false;
    global_ban_settings.enable_ban_for_flows_per_second = false;

    // We must ban IP if it exceeed this limit in PPS
    global_ban_settings.ban_threshold_pps = 20000;

    // We must ban IP of it exceed this limit for number of flows in any direction
    global_ban_settings.ban_threshold_flows = 3500;

    // We must ban client if it exceed 1GBps
    global_ban_settings.ban_threshold_mbps = 1000;

    // Disable per protocol thresholds too
    global_ban_settings.enable_ban_for_tcp_pps = false;
    global_ban_settings.enable_ban_for_tcp_bandwidth = false;

    global_ban_settings.enable_ban_for_udp_pps = false;
    global_ban_settings.enable_ban_for_udp_bandwidth = false;

    global_ban_settings.enable_ban_for_icmp_pps = false;
    global_ban_settings.enable_ban_for_icmp_bandwidth = false;

    // Ban enable/disable flag
    global_ban_settings.enable_ban = true;
}

bool enable_connection_tracking = true;

bool enable_afpacket_collection = false;
bool enable_data_collection_from_mirror = true;
bool enable_netmap_collection = false;
bool enable_sflow_collection = false;
bool enable_netflow_collection = false;
bool enable_pcap_collection = false;

// Time consumed by reaclculation for all IPs
struct timeval speed_calculation_time;

// Time consumed by drawing stats for all IPs
struct timeval drawing_thread_execution_time;

// Global thread group for packet capture threads
boost::thread_group packet_capture_plugin_thread_group;

// Global thread group for service processes (speed recalculation,
// screen updater and ban list cleaner)
boost::thread_group service_thread_group;

// Total number of hosts in our networks
// We need this as global variable because it's very important value for configuring data structures
unsigned int total_number_of_hosts_in_our_networks = 0;

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

// We calc average pps/bps for subnets with this time, we use longer value for calculation average network traffic
double average_calculation_amount_for_subnets = 30;

// Show average or absolute value of speed
bool print_average_traffic_counts = true;

// Key used for sorting clients in output.  Allowed sort params: packets/bytes/flows
std::string sort_parameter = "packets";

// Number of lines in program output
unsigned int max_ips_in_list = 7;

// Number of lines for sending ben attack details to email
unsigned int ban_details_records_count = 50;

// We haven't option for configure it with configuration file
unsigned int number_of_packets_for_pcap_attack_dump = 500;

// log file
log4cpp::Category& logger = log4cpp::Category::getRoot();

// We store all active BGP Flow Spec announces here
active_flow_spec_announces_t active_flow_spec_announces;

/* Configuration block ends */

// We count total number of incoming/outgoing/internal and other traffic type packets/bytes
// And initilize by 0 all fields
total_counter_element_t total_counters[4];
total_counter_element_t total_speed_counters[4];
total_counter_element_t total_speed_average_counters[4];

// IPv6 versions of total counters
total_counter_element_t total_counters_ipv6[4];
total_counter_element_t total_speed_counters_ipv6[4];
total_counter_element_t total_speed_average_counters_ipv6[4];

// Total amount of non parsed packets
uint64_t total_unparsed_packets = 0;
uint64_t total_unparsed_packets_speed = 0;

// Total amount of IPv4 packets
uint64_t total_ipv4_packets = 0;

// Total amount of IPv6 packets
uint64_t total_ipv6_packets = 0;

// Number of non IPv4/IPv6 packets received by us
uint64_t non_ip_packets = 0;

// Total number of times when we executed process_packet()
uint64_t total_simple_packets_processed = 0;

// IPv6 traffic which belongs to our own networks
uint64_t our_ipv6_packets = 0;

uint64_t incoming_total_flows_speed = 0;
uint64_t outgoing_total_flows_speed = 0;

map_of_vector_counters_t SubnetVectorMap;

// Network counters for IPv6
abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t> ipv6_subnet_counters;

// Host counters for IPv6
abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t> ipv6_host_counters;

// Here we store taffic per subnet
map_for_subnet_counters_t PerSubnetCountersMap;

// Here we store traffic speed per subnet
map_for_subnet_counters_t PerSubnetSpeedMap;

// Here we store average speed per subnet
map_for_subnet_counters_t PerSubnetAverageSpeedMap;

// Flow tracking structures
map_of_vector_counters_for_flow_t SubnetVectorMapFlow;

/* End of our data structs */
boost::mutex ban_list_details_mutex;
boost::mutex ban_list_mutex;
std::mutex flow_counter;

// map for flows
std::map<uint64_t, int> FlowCounter;

// Struct for string speed per IP
map_of_vector_counters_t SubnetVectorMapSpeed;

// Struct for storing average speed per IP for specified interval
map_of_vector_counters_t SubnetVectorMapSpeedAverage;

#ifdef GEOIP
map_for_counters GeoIpCounter;
#endif

// IPv6 hosts
blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6_ng;

// In ddos info we store attack power and direction
std::map<uint32_t, banlist_item_t> ban_list;
std::map<uint32_t, std::vector<simple_packet_t> > ban_list_details;

host_group_map_t host_groups;

// Here we store assignment from subnet to certain host group for fast lookup
subnet_to_host_group_map_t subnet_to_host_groups;

host_group_ban_settings_map_t host_group_ban_settings_map;

std::vector<subnet_cidr_mask_t> our_networks;
std::vector<subnet_cidr_mask_t> whitelist_networks;

// ExaBGP support flag
bool exabgp_enabled = false;
std::string exabgp_community = "";

// We could use separate communities for subnet and host announces
std::string exabgp_community_subnet = "";
std::string exabgp_community_host = "";


std::string exabgp_command_pipe = "/var/run/exabgp.cmd";
std::string exabgp_next_hop = "";

// Graphite monitoring
bool graphite_enabled = false;
std::string graphite_host = "127.0.0.1";
unsigned short int graphite_port = 2003;
unsigned int graphite_push_period = 1;

// Time consumed by pushing data to Graphite
struct timeval graphite_thread_execution_time;

// Default graphite namespace
std::string graphite_prefix = "fastnetmon";


// Total number of InfluxDB writes
uint64_t influxdb_writes_total = 0; 

// Total number of failed InfluxDB writes
uint64_t influxdb_writes_failed = 0; 

// InfluxDB
bool influxdb_enabled = false;
std::string influxdb_database = "fastnetmon";
std::string influxdb_host = "127.0.0.1";
unsigned short int influxdb_port = 8086;
bool influxdb_auth = false;
std::string influxdb_user = "";
std::string influxdb_password = "";
unsigned int influxdb_push_period = 1;

bool process_incoming_traffic = true;
bool process_outgoing_traffic = true;

// Prototypes
#ifdef ENABLE_DPI
void init_current_instance_of_ndpi();
#endif

logging_configuration_t read_logging_settings(configuration_map_t configuration_map);
std::string get_amplification_attack_type(amplification_attack_type_t attack_type);
std::string generate_flow_spec_for_amplification_attack(amplification_attack_type_t amplification_attack_type,
                                                        std::string destination_ip);
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
    logger
    << log4cpp::Priority::ERROR << "Sorry but we experienced error with popen. "
    << "Please check your scripts. They should receive data on stdin! Optionally you could disable "
       "passing any details with configuration param: notify_script_pass_details = no";

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
        logger << log4cpp::Priority::WARN << "We already have this host group (" << host_group_name
               << "). Please check!";
        return;
    }

    // Split networks
    std::vector<std::string> hostgroup_subnets =
    split_strings_to_vector_by_comma(splitted_new_host_group[1]);
    for (std::vector<std::string>::iterator itr = hostgroup_subnets.begin();
         itr != hostgroup_subnets.end(); ++itr) {
        subnet_cidr_mask_t subnet = convert_subnet_from_string_to_binary_with_cidr_format(*itr);

        host_groups[host_group_name].push_back(subnet);

        logger << log4cpp::Priority::WARN << "We add subnet " << convert_subnet_to_string(subnet)
               << " to host group " << host_group_name;

        // And add to subnet to host group lookup hash
        if (subnet_to_host_groups.count(subnet) > 0) {
            // Huston, we have problem! Subnet to host group mapping should map single subnet to single group!
            logger << log4cpp::Priority::WARN << "Seems you have specified single subnet " << *itr
                   << " to multiple host groups, please fix it, it's prohibited";
        } else {
            subnet_to_host_groups[subnet] = host_group_name;
        }
    }

    logger << log4cpp::Priority::INFO << "We have created host group " << host_group_name
           << " with " << host_groups[host_group_name].size() << " subnets";
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
        average_calculation_amount =
        convert_string_to_integer(configuration_map["average_calculation_time"]);
    }

    if (configuration_map.count("average_calculation_time_for_subnets") != 0) {
        average_calculation_amount_for_subnets =
        convert_string_to_integer(configuration_map["average_calculation_time_for_subnets"]);
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
            logger
            << log4cpp::Priority::ERROR
            << "You enabled exabgp for host but not specified community, we disable exabgp support";

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
            logger
            << log4cpp::Priority::ERROR
            << "You enabled exabgp but not specified exabgp_next_hop, so we disable exabgp support";

            exabgp_enabled = false;
        }

        if (configuration_map.count("exabgp_flow_spec_announces") != 0) {
            exabgp_flow_spec_announces = configuration_map["exabgp_flow_spec_announces"] == "on";
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

    if (configuration_map.count("enable_subnet_counters") != 0) {
        enable_subnet_counters = configuration_map["enable_subnet_counters"] == "on" ? true : false;
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

    // InfluxDB
    if (configuration_map.count("influxdb") != 0) {
        influxdb_enabled = configuration_map["influxdb"] == "on" ? true : false;
    }

    if (configuration_map.count("influxdb_port") != 0) {
        influxdb_port = convert_string_to_integer(configuration_map["influxdb_port"]);
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

    // logger << log4cpp::Priority::INFO << "We read global ban settings: " << print_ban_thresholds(global_ban_settings);

    // Read host group ban settings
    for (host_group_map_t::iterator hostgroup_itr = host_groups.begin();
         hostgroup_itr != host_groups.end(); ++hostgroup_itr) {
        std::string host_group_name = hostgroup_itr->first;

        logger << log4cpp::Priority::INFO << "We will read ban settings for " << host_group_name;

        host_group_ban_settings_map[host_group_name] = read_ban_settings(configuration_map, host_group_name);

        // logger << log4cpp::Priority::INFO << "We read " << host_group_name << " ban settings "
        //    << print_ban_thresholds(host_group_ban_settings_map[ host_group_name ]);
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
        if (configuration_map["redis_enabled"] == "on" or
            configuration_map["redis_enabled"] == "yes") {
            redis_enabled = true;
        } else {
            redis_enabled = false;
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
        ban_details_records_count =
        convert_string_to_integer(configuration_map["ban_details_records_count"]);
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

    if (configuration_map.count("notify_script_pass_details") != 0) {
        notify_script_pass_details = configuration_map["notify_script_pass_details"] == "on" ? true : false;
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

    if (configuration_map.count("process_pcap_attack_dumps_with_dpi") != 0) {
        if (collect_attack_pcap_dumps) {
            process_pcap_attack_dumps_with_dpi =
            configuration_map["process_pcap_attack_dumps_with_dpi"] == "on" ? true : false;
        }
    }

    return true;
}

/* Enable core dumps for simplify debug tasks */
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

void subnet_vectors_allocator(prefix_t* prefix, void* data) {
    // Network byte order
    uint32_t subnet_as_integer = prefix->add.sin.s_addr;

    u_short bitlen = prefix->bitlen;
    double base = 2;
    int network_size_in_ips = pow(base, 32 - bitlen);
    // logger<< log4cpp::Priority::INFO<<"Subnet: "<<prefix->add.sin.s_addr<<" network size:
    // "<<network_size_in_ips;
    logger << log4cpp::Priority::INFO << "I will allocate " << network_size_in_ips
           << " records for subnet " << subnet_as_integer << " cidr mask: " << bitlen;

    subnet_cidr_mask_t current_subnet(subnet_as_integer, bitlen);

    map_element_t zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    // Initilize our counters with fill constructor
    try {
        SubnetVectorMap[current_subnet] = vector_of_counters(network_size_in_ips, zero_map_element);
        SubnetVectorMapSpeed[current_subnet] = vector_of_counters(network_size_in_ips, zero_map_element);
        SubnetVectorMapSpeedAverage[current_subnet] = vector_of_counters(network_size_in_ips, zero_map_element);
    } catch (std::bad_alloc& ba) {
        logger << log4cpp::Priority::ERROR << "Can't allocate memory for counters";
        exit(1);
    }

    // Initilize map element
    SubnetVectorMapFlow[current_subnet] = vector_of_flow_counters_t(network_size_in_ips);

    // On creating it initilizes by zeros
    conntrack_main_struct_t zero_conntrack_main_struct;
    std::fill(SubnetVectorMapFlow[current_subnet].begin(),
              SubnetVectorMapFlow[current_subnet].end(), zero_conntrack_main_struct);

    PerSubnetCountersMap[current_subnet] = zero_map_element;
    PerSubnetSpeedMap[current_subnet] = zero_map_element;
}

void zeroify_all_counters() {
    map_element_t zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    for (map_of_vector_counters_t::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); ++itr) {
        // logger<< log4cpp::Priority::INFO<<"Zeroify "<<itr->first;
        std::fill(itr->second.begin(), itr->second.end(), zero_map_element);
    }
}

bool load_our_networks_list() {
    if (file_exists(fastnetmon_platform_configuration.white_list_path)) {
        unsigned int network_entries = 0;
        std::vector<std::string> network_list_from_config = read_file_to_vector(fastnetmon_platform_configuration.white_list_path);

        for (std::vector<std::string>::iterator ii = network_list_from_config.begin();
             ii != network_list_from_config.end(); ++ii) {
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
            make_and_lookup(whitelist_tree_ipv4, const_cast<char*>(text_subnet.c_str()));
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

        logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv4_as_string.size()
               << " IPv4 networks from /proc/vz/veip";

        logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv6_as_string.size()
               << " IPv6 networks from /proc/vz/veip";
    }

    if (monitor_local_ip_addresses && file_exists("/sbin/ip")) {
        logger << log4cpp::Priority::INFO << "We are working on Linux and could use ip tool for detecting local IP's";

        ip_addresses_list_t ip_list = get_local_ip_v4_addresses_list();

        logger << log4cpp::Priority::INFO << "We found " << ip_list.size()
               << " local IP addresses and will monitor they";

        for (ip_addresses_list_t::iterator iter = ip_list.begin(); iter != ip_list.end(); ++iter) {
            // TODO: add IPv6 here
            networks_list_ipv4_as_string.push_back(*iter + "/32");
        }
    }

    if (file_exists(fastnetmon_platform_configuration.networks_list_path)) {
        std::vector<std::string> network_list_from_config = read_file_to_vector(fastnetmon_platform_configuration.networks_list_path);

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

        logger << log4cpp::Priority::INFO << "We loaded " << network_list_from_config.size()
               << " networks from networks file";
    }

    // Some consistency checks
    assert(convert_ip_as_string_to_uint("255.255.255.0") == convert_cidr_to_binary_netmask(24));
    assert(convert_ip_as_string_to_uint("255.255.255.255") == convert_cidr_to_binary_netmask(32));

    logger << log4cpp::Priority::INFO << "Totally we have " << networks_list_ipv4_as_string.size() << " IPv4 subnets";
    logger << log4cpp::Priority::INFO << "Totally we have " << networks_list_ipv6_as_string.size() << " IPv6 subnets";

    for (std::vector<std::string>::iterator ii = networks_list_ipv4_as_string.begin();
         ii != networks_list_ipv4_as_string.end(); ++ii) {

        if (!is_cidr_subnet(*ii)) {
            logger << log4cpp::Priority::ERROR << "Can't parse line from subnet list: '" << *ii << "'";
            continue;
        }

        std::string network_address_in_cidr_form = *ii;

        unsigned int cidr_mask = get_cidr_mask_from_network_as_string(network_address_in_cidr_form);
        std::string network_address = get_net_address_from_network_as_string(network_address_in_cidr_form);

        double base = 2;
        total_number_of_hosts_in_our_networks += pow(base, 32 - cidr_mask);

        // Make sure it's "subnet address" and not an host address
        uint32_t subnet_address_as_uint = convert_ip_as_string_to_uint(network_address);
        uint32_t subnet_address_netmask_binary = convert_cidr_to_binary_netmask(cidr_mask);
        uint32_t generated_subnet_address = subnet_address_as_uint & subnet_address_netmask_binary;

        if (subnet_address_as_uint != generated_subnet_address) {
            std::string new_network_address_as_string =
            convert_ip_as_uint_to_string(generated_subnet_address) + "/" + convert_int_to_string(cidr_mask);

            logger << log4cpp::Priority::WARN << "We will use " << new_network_address_as_string
                   << " instead of " << network_address_in_cidr_form << " because it's host address";

            network_address_in_cidr_form = new_network_address_as_string;
        }

        make_and_lookup(lookup_tree_ipv4, const_cast<char*>(network_address_in_cidr_form.c_str()));
    }

    for (std::vector<std::string>::iterator ii = networks_list_ipv6_as_string.begin();
         ii != networks_list_ipv6_as_string.end(); ++ii) {

        // TODO: add IPv6 subnet format validation
        make_and_lookup_ipv6(lookup_tree_ipv6, (char*)ii->c_str());
    }

    logger << log4cpp::Priority::INFO << "Total number of monitored hosts (total size of all networks): "
           << total_number_of_hosts_in_our_networks;

    // 3 - speed counter, average speed counter and data counter
    uint64_t memory_requirements = 3 * sizeof(map_element_t) * total_number_of_hosts_in_our_networks / 1024 / 1024;

    logger << log4cpp::Priority::INFO << "We need " << memory_requirements
           << " MB of memory for storing counters for your networks";

    /* Preallocate data structures */
    patricia_process(lookup_tree_ipv4, (void_fn_t)subnet_vectors_allocator);

    logger << log4cpp::Priority::INFO << "We start total zerofication of counters";
    zeroify_all_counters();
    logger << log4cpp::Priority::INFO << "We finished zerofication";

    logger << log4cpp::Priority::INFO << "We loaded " << networks_list_ipv4_as_string.size()
           << " IPv4 subnets to our in-memory list of networks";

    return true;
}

#ifdef GEOIP
unsigned int get_asn_for_ip(uint32_t ip) {
    char* asn_raw = GeoIP_org_by_name(geo_ip, convert_ip_as_uint_to_string(remote_ip).c_str());
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

void init_logging() {
    // So log4cpp will never notify you if it could not write to log file due to permissions issues
    // We will check it manually

    if (!file_is_appendable(fastnetmon_platform_configuration.log_file_path)) {
        std::cerr << "Can't open log file " << fastnetmon_platform_configuration.log_file_path
                  << " for writing! Please check file and folder permissions" << std::endl;
        exit(EXIT_FAILURE);
    }

    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* appender = new log4cpp::FileAppender("default", fastnetmon_platform_configuration.log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);

    logger << log4cpp::Priority::INFO << "Logger initialized!";
}

void reconfigure_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("[%p] %m%n");

    if (logging_configuration.local_syslog_logging) {
        log4cpp::Appender* local_syslog_appender =
        new log4cpp::SyslogAppender("fastnetmon", "fastnetmon", LOG_USER);
        local_syslog_appender->setLayout(layout);
        logger.addAppender(local_syslog_appender);

        logger << log4cpp::Priority::INFO << "We start local syslog logging corectly";
    }

    if (logging_configuration.remote_syslog_logging) {
        log4cpp::Appender* remote_syslog_appender =
        new log4cpp::RemoteSyslogAppender("fastnetmon", "fastnetmon", logging_configuration.remote_syslog_server,
                                          LOG_USER, logging_configuration.remote_syslog_port);

        remote_syslog_appender->setLayout(layout);
        logger.addAppender(remote_syslog_appender);

        logger << log4cpp::Priority::INFO << "We start remote syslog logging corectly";
    }
}

// Call fork function
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
    // We do not need return codes here but we need do it for suppressing complaints from compiler
    int first_dup_result = dup(0);
    int second_dup_result = dup(0);
}

int main(int argc, char** argv) {
    bool daemonize = false;
    bool only_configuration_check = false;

    namespace po = boost::program_options;

    try {
        // clang-format off
        po::options_description desc("Allowed options");
        desc.add_options()
		("help", "produce help message")
		("version", "show version")
		("daemonize", "detach from the terminal")
		("configuration_check", "check configuration and exit")
		("configuration_file", po::value<std::string>(),"set path to custom configuration file")
		("log_file", po::value<std::string>(), "set path to custom log file");
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
            std::cout << "We will use custom path to configuration file: " << fastnetmon_platform_configuration.global_config_path << std::endl;
        }

        if (vm.count("log_file")) {
            fastnetmon_platform_configuration.log_file_path = vm["log_file"].as<std::string>();
            std::cout << "We will use custom path to log file: " << fastnetmon_platform_configuration.log_file_path << std::endl;
        }
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        exit(EXIT_FAILURE);
    }

    // We use ideas from here https://github.com/bmc/daemonize/blob/master/daemon.c

    if (daemonize) {
        int status = 0;

        printf("We will run in daemonized mode\n");

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
            int chdir_result = chdir("/");

            // close all descriptors because we are daemon!
            redirect_fds();
        }
    }

    // enable core dumps
    enable_core_dumps();

    init_logging();

#ifdef FASTNETMON_API
    gpr_set_log_function(silent_logging_function);
#endif

    // Set default ban configuration
    init_global_ban_settings();

    // We should read configurartion file _after_ logging initialization
    bool load_config_result = load_configuration_file();

    if (!load_config_result) {
        std::cerr << "Can't open config file " << fastnetmon_platform_configuration.global_config_path << " please create it!" << std::endl;
        exit(1);
    }

    if (only_configuration_check) {
        logger << log4cpp::Priority::INFO << "Configuration file is correct. Shutdown toolkit";
        exit(0);
    }

    if (file_exists(fastnetmon_platform_configuration.pid_path)) {
        pid_t pid_from_file = 0;

        if (read_pid_from_file(pid_from_file, fastnetmon_platform_configuration.pid_path)) {
            // We could read pid
            if (pid_from_file > 0) {
                // We use signal zero for check process existence
                int kill_result = kill(pid_from_file, 0);

                if (kill_result == 0) {
                    logger << log4cpp::Priority::ERROR
                           << "FastNetMon is already running with pid: " << pid_from_file;
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

    // If we not failed in check steps we could run toolkit
    bool print_pid_to_file_result = print_pid_to_file(getpid(), fastnetmon_platform_configuration.pid_path);

    if (!print_pid_to_file_result) {
        logger << log4cpp::Priority::ERROR << "Could not create pid file, please check permissions: " << fastnetmon_platform_configuration.pid_path;
        exit(EXIT_FAILURE);
    }

#ifdef ENABLE_DPI
    init_current_instance_of_ndpi();
#endif

    lookup_tree_ipv4 = New_Patricia(32);
    whitelist_tree_ipv4 = New_Patricia(32);

    lookup_tree_ipv6 = New_Patricia(128);
    whitelist_tree_ipv6 = New_Patricia(128);

    // nullify total counters
    for (int index = 0; index < 4; index++) {
        total_counters[index].bytes = 0;
        total_counters[index].packets = 0;

        total_speed_counters[index].bytes = 0;
        total_speed_counters[index].packets = 0;

        total_speed_average_counters[index].bytes = 0;
        total_speed_average_counters[index].packets = 0;
    }

    /* Create folder for attack details */
    if (!folder_exists(fastnetmon_platform_configuration.attack_details_folder)) {
        int mkdir_result = mkdir(fastnetmon_platform_configuration.attack_details_folder.c_str(), S_IRWXU);

        if (mkdir_result != 0) {
            logger << log4cpp::Priority::ERROR << "Can't create folder for attack details: " << fastnetmon_platform_configuration.attack_details_folder;
            exit(1);
        }
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

    // Set capacity for nested buffers
    packet_buckets_ipv6_storage.set_buffers_capacity(ban_details_records_count);

    // Setup CTRL+C handler
    if (signal(SIGINT, interruption_signal_handler) == SIG_ERR) {
        logger << log4cpp::Priority::ERROR << "Can't setup SIGINT handler";
        exit(1);
    }

    /* Without this SIGPIPE error could shutdown toolkit on call of exec_with_stdin_params */
    if (signal(SIGPIPE, sigpipe_handler_for_popen) == SIG_ERR) {
        logger << log4cpp::Priority::ERROR << "Can't setup SIGPIPE handler";
        exit(1);
    }

#ifdef GEOIP
    // Init GeoIP
    if (!geoip_init()) {
        logger << log4cpp::Priority::ERROR << "Can't load geoip tables";
        exit(1);
    }
#endif
    // Init previous run date
    time(&last_call_of_traffic_recalculation);

    // We call init for each action
#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        gobgp_action_init();
    }
#endif

#ifdef FASTNETMON_API
    if (enable_api) {
        service_thread_group.add_thread(new boost::thread(RunApiServer));
    }
#endif

    // Set inaccurate time value which will be used in process_packet() from capture backends
    time(&current_inaccurate_time);

    // Start system speed recalculation thread
    service_thread_group.add_thread(new boost::thread(system_counters_speed_thread_handler));

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

#ifdef PF_RING
    if (enable_data_collection_from_mirror) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_pfring_collection, process_packet));
    }
#endif

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

    if (enable_sflow_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_sflow_collection, process_packet));
    }

    if (enable_netflow_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_netflow_collection, process_packet));
    }

    if (enable_pcap_collection) {
        packet_capture_plugin_thread_group.add_thread(new boost::thread(start_pcap_collection, process_packet));
    }

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

    Destroy_Patricia(lookup_tree_ipv4, (void_fn_t)0);
    Destroy_Patricia(whitelist_tree_ipv4, (void_fn_t)0);

    Destroy_Patricia(lookup_tree_ipv6, (void_fn_t)0);
    Destroy_Patricia(whitelist_tree_ipv6, (void_fn_t)0);
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

