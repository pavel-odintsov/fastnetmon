#include "fastnetmon_logic.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include "all_logcpp_libraries.hpp"
#include "bgp_protocol.hpp"
#include "fast_library.hpp"
#include "fast_platform.hpp"

#include "fast_endianless.hpp"

// Plugins
#include "netflow_plugin/netflow_collector.hpp"

#ifdef ENABLE_PCAP
#include "pcap_plugin/pcap_collector.hpp"
#endif

#include "sflow_plugin/sflow_collector.hpp"

#ifdef NETMAP_PLUGIN
#include "netmap_plugin/netmap_collector.hpp"
#endif

#ifdef FASTNETMON_ENABLE_AFPACKET
#include "afpacket_plugin/afpacket_collector.hpp"
#endif

#ifdef ENABLE_GOBGP
#include "actions/gobgp_action.hpp"
#endif

#include "actions/exabgp_action.hpp"

// Traffic output formats
#include "traffic_output_formats/protobuf/protobuf_traffic_format.hpp"

#include "traffic_output_formats/protobuf/traffic_data.pb.h"

// Yes, maybe it's not an good idea but with this we can guarantee working code in example plugin
#include "example_plugin/example_collector.hpp"

#ifdef MONGO
#include <bson.h>
#include <mongoc.h>
#endif

#include "fastnetmon_networks.hpp"

#include "abstract_subnet_counters.hpp"

#include "packet_bucket.hpp"

#include "ban_list.hpp"

#ifdef KAFKA
#include <cppkafka/cppkafka.h>
#endif

extern uint64_t influxdb_writes_total;
extern uint64_t influxdb_writes_failed;
extern packet_buckets_storage_t<subnet_ipv6_cidr_mask_t> packet_buckets_ipv6_storage;
extern std::string cli_stats_file_path;
extern unsigned int total_number_of_hosts_in_our_networks;
extern abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;
extern unsigned int recalculate_speed_timeout;
extern bool DEBUG_DUMP_ALL_PACKETS;
extern bool DEBUG_DUMP_OTHER_PACKETS;
extern uint64_t total_ipv4_packets;
extern uint64_t total_ipv6_packets;
extern double average_calculation_amount;
extern bool print_configuration_params_on_the_screen;
extern uint64_t our_ipv6_packets;
extern uint64_t unknown_ip_version_packets;
extern uint64_t total_simple_packets_processed;
extern unsigned int maximum_time_since_bucket_start_to_remove;
extern unsigned int max_ips_in_list;
extern struct timeval speed_calculation_time;
extern double drawing_thread_execution_time;
extern std::chrono::steady_clock::time_point last_call_of_traffic_recalculation;
extern std::string cli_stats_ipv6_file_path;
extern unsigned int check_for_availible_for_processing_packets_buckets;
extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_host_counters;
extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_subnet_counters;
extern bool process_incoming_traffic;
extern bool process_outgoing_traffic;
extern uint64_t total_unparsed_packets;
extern time_t current_inaccurate_time;
extern uint64_t total_unparsed_packets_speed;
extern bool enable_connection_tracking;
extern bool enable_afpacket_collection;
extern bool enable_data_collection_from_mirror;
extern bool enable_netmap_collection;
extern bool enable_sflow_collection;
extern bool enable_netflow_collection;
extern bool enable_pcap_collection;
extern uint64_t incoming_total_flows_speed;
extern uint64_t outgoing_total_flows_speed;
extern total_speed_counters_t total_counters_ipv4;
extern total_speed_counters_t total_counters_ipv6;
extern host_group_ban_settings_map_t host_group_ban_settings_map;
extern bool exabgp_announce_whole_subnet;
extern subnet_to_host_group_map_t subnet_to_host_groups;
extern bool collect_attack_pcap_dumps;

extern std::mutex flow_counter_mutex;

#ifdef REDIS
extern unsigned int redis_port;
extern std::string redis_host;
extern std::string redis_prefix;
extern bool redis_enabled;
#endif

extern int64_t netflow_ipfix_all_protocols_total_flows_speed;
extern int64_t sflow_raw_packet_headers_total_speed;

extern uint64_t netflow_ipfix_all_protocols_total_flows;
extern uint64_t sflow_raw_packet_headers_total;

#ifdef MONGO
extern std::string mongodb_host;
extern unsigned int mongodb_port;
extern bool mongodb_enabled;
extern std::string mongodb_database_name;
#endif

extern unsigned int number_of_packets_for_pcap_attack_dump;
extern patricia_tree_t *lookup_tree_ipv4, *whitelist_tree_ipv4;
extern patricia_tree_t *lookup_tree_ipv6, *whitelist_tree_ipv6;
extern ban_settings_t global_ban_settings;
extern bool exabgp_enabled;
extern bool gobgp_enabled;
extern int global_ban_time;
extern bool notify_script_enabled;
extern std::map<uint32_t, banlist_item_t> ban_list;
extern int unban_iteration_sleep_time;
extern bool unban_enabled;
extern bool unban_only_if_attack_finished;

extern configuration_map_t configuration_map;
extern log4cpp::Category& logger;
extern bool graphite_enabled;
extern std::string graphite_host;
extern unsigned short int graphite_port;
extern std::string sort_parameter;
extern std::string graphite_prefix;
extern unsigned int ban_details_records_count;
extern FastnetmonPlatformConfigurtion fastnetmon_platform_configuration;

#include "api.hpp"

#define my_max_on_defines(a, b) (a > b ? a : b)
unsigned int get_max_used_protocol(uint64_t tcp, uint64_t udp, uint64_t icmp) {
    unsigned int max = my_max_on_defines(my_max_on_defines(udp, tcp), icmp);

    if (max == tcp) {
        return IPPROTO_TCP;
    } else if (max == udp) {
        return IPPROTO_UDP;
    } else if (max == icmp) {
        return IPPROTO_ICMP;
    }

    return 0;
}

unsigned int detect_attack_protocol(subnet_counter_t& speed_element, direction_t attack_direction) {
    if (attack_direction == INCOMING) {
        return get_max_used_protocol(speed_element.tcp.in_packets, speed_element.udp.in_packets, speed_element.icmp.in_packets);
    } else {
        // OUTGOING
        return get_max_used_protocol(speed_element.tcp.out_packets, speed_element.udp.out_packets, speed_element.icmp.out_packets);
    }
}

std::string print_flow_tracking_for_ip(conntrack_main_struct_t& conntrack_element, std::string client_ip) {
    std::stringstream buffer;

    std::string in_tcp = print_flow_tracking_for_specified_protocol(conntrack_element.in_tcp, client_ip, INCOMING);
    std::string in_udp = print_flow_tracking_for_specified_protocol(conntrack_element.in_udp, client_ip, INCOMING);

    unsigned long long total_number_of_incoming_tcp_flows = conntrack_element.in_tcp.size();
    unsigned long long total_number_of_incoming_udp_flows = conntrack_element.in_udp.size();

    unsigned long long total_number_of_outgoing_tcp_flows = conntrack_element.out_tcp.size();
    unsigned long long total_number_of_outgoing_udp_flows = conntrack_element.out_udp.size();

    bool we_have_incoming_flows = in_tcp.length() > 0 or in_udp.length() > 0;
    if (we_have_incoming_flows) {
        buffer << "Incoming\n\n";

        if (in_tcp.length() > 0) {
            buffer << "TCP flows: " << total_number_of_incoming_tcp_flows << "\n";
            buffer << in_tcp << "\n";
        }

        if (in_udp.length() > 0) {
            buffer << "UDP flows: " << total_number_of_incoming_udp_flows << "\n";
            buffer << in_udp << "\n";
        }
    }

    std::string out_tcp = print_flow_tracking_for_specified_protocol(conntrack_element.out_tcp, client_ip, OUTGOING);
    std::string out_udp = print_flow_tracking_for_specified_protocol(conntrack_element.out_udp, client_ip, OUTGOING);

    bool we_have_outgoing_flows = out_tcp.length() > 0 or out_udp.length() > 0;

    // print delimiter if we have flows in both directions
    if (we_have_incoming_flows && we_have_outgoing_flows) {
        buffer << "\n";
    }

    if (we_have_outgoing_flows) {
        buffer << "Outgoing\n\n";

        if (out_tcp.length() > 0) {
            buffer << "TCP flows: " << total_number_of_outgoing_tcp_flows << "\n";
            buffer << out_tcp << "\n";
        }

        if (out_udp.length() > 0) {
            buffer << "UDP flows: " << total_number_of_outgoing_udp_flows << "\n";
            buffer << out_udp << "\n";
        }
    }

    return buffer.str();
}

std::string print_subnet_ipv4_load() {
    std::stringstream buffer;

    attack_detection_threshold_type_t sorter_type;

    if (sort_parameter == "packets") {
        sorter_type = attack_detection_threshold_type_t::packets_per_second;
    } else if (sort_parameter == "bytes") {
        sorter_type = attack_detection_threshold_type_t::bytes_per_second;
    } else if (sort_parameter == "flows") {
        sorter_type = attack_detection_threshold_type_t::flows_per_second;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter_type = attack_detection_threshold_type_t::packets_per_second;
    }

    std::vector<std::pair<subnet_cidr_mask_t, subnet_counter_t>> vector_for_sort;

    ipv4_network_counters.get_sorted_average_speed(vector_for_sort, sorter_type, attack_detection_direction_type_t::incoming);

    for (auto itr = vector_for_sort.begin(); itr != vector_for_sort.end(); ++itr) {
        subnet_counter_t* speed      = &itr->second;
        std::string subnet_as_string = convert_subnet_to_string(itr->first);

        buffer << std::setw(18) << std::left << subnet_as_string;

        buffer << " "
               << "pps in: " << std::setw(8) << speed->total.in_packets << " out: " << std::setw(8)
               << speed->total.out_packets << " mbps in: " << std::setw(5) << convert_speed_to_mbps(speed->total.in_bytes)
               << " out: " << std::setw(5) << convert_speed_to_mbps(speed->total.out_bytes) << "\n";
    }

    return buffer.str();
}

std::string print_ban_thresholds(ban_settings_t current_ban_settings) {
    std::stringstream output_buffer;

    output_buffer << "Configuration params:\n";
    if (current_ban_settings.enable_ban) {
        output_buffer << "We call ban script: yes\n";
    } else {
        output_buffer << "We call ban script: no\n";
    }

    if (current_ban_settings.enable_ban_ipv6) {
        output_buffer << "We call ban script for IPv6: yes\n";
    } else {
        output_buffer << "We call ban script for IPv6: no\n";
    }

    output_buffer << "Packets per second: ";
    if (current_ban_settings.enable_ban_for_pps) {
        output_buffer << current_ban_settings.ban_threshold_pps;
    } else {
        output_buffer << "disabled";
    }

    output_buffer << "\n";

    output_buffer << "Mbps per second: ";
    if (current_ban_settings.enable_ban_for_bandwidth) {
        output_buffer << current_ban_settings.ban_threshold_mbps;
    } else {
        output_buffer << "disabled";
    }

    output_buffer << "\n";

    output_buffer << "Flows per second: ";
    if (current_ban_settings.enable_ban_for_flows_per_second) {
        output_buffer << current_ban_settings.ban_threshold_flows;
    } else {
        output_buffer << "disabled";
    }

    output_buffer << "\n";
    return output_buffer.str();
}

void print_attack_details_to_file(const std::string& details, const std::string& client_ip_as_string, const attack_details_t& current_attack) {
    std::ofstream my_attack_details_file;

    // TODO: it may not work well with systems which do not allow ":" as part of file name (macOS)
    std::string ban_timestamp_as_string = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    
    std::string attack_dump_path =
        fastnetmon_platform_configuration.attack_details_folder + "/" + client_ip_as_string + "_" + ban_timestamp_as_string + ".txt";

    my_attack_details_file.open(attack_dump_path.c_str(), std::ios::app);

    if (my_attack_details_file.is_open()) {
        my_attack_details_file << details << "\n\n";
        my_attack_details_file.close();
    } else {
        logger << log4cpp::Priority::ERROR << "Can't print attack details to file" << attack_dump_path;
    }
}


logging_configuration_t read_logging_settings(configuration_map_t configuration_map) {
    logging_configuration_t logging_configuration_temp;

    if (configuration_map.count("logging_level") != 0) {
        logging_configuration_temp.logging_level = configuration_map["logging_level"];
    }

    if (configuration_map.count("logging_local_syslog_logging") != 0) {
        logging_configuration_temp.local_syslog_logging = configuration_map["logging_local_syslog_logging"] == "on";
    }

    if (configuration_map.count("logging_remote_syslog_logging") != 0) {
        logging_configuration_temp.remote_syslog_logging = configuration_map["logging_remote_syslog_logging"] == "on";
    }

    if (configuration_map.count("logging_remote_syslog_server") != 0) {
        logging_configuration_temp.remote_syslog_server = configuration_map["logging_remote_syslog_server"];
    }

    if (configuration_map.count("logging_remote_syslog_port") != 0) {
        logging_configuration_temp.remote_syslog_port =
            convert_string_to_integer(configuration_map["logging_remote_syslog_port"]);
    }

    if (logging_configuration_temp.remote_syslog_logging) {
        if (logging_configuration_temp.remote_syslog_port > 0 && !logging_configuration_temp.remote_syslog_server.empty()) {
            logger << log4cpp::Priority::INFO << "We have configured remote syslog logging corectly";
        } else {
            logger << log4cpp::Priority::ERROR << "You have enabled remote logging but haven't specified port or host";
            logging_configuration_temp.remote_syslog_logging = false;
        }
    }

    if (logging_configuration_temp.local_syslog_logging) {
        logger << log4cpp::Priority::INFO << "We have configured local syslog logging correctly";
    }

    return logging_configuration_temp;
}

ban_settings_t read_ban_settings(configuration_map_t configuration_map, std::string host_group_name) {
    ban_settings_t ban_settings;

    std::string prefix = "";
    if (host_group_name != "") {
        prefix = host_group_name + "_";
    }

    if (configuration_map.count(prefix + "enable_ban") != 0) {
        ban_settings.enable_ban = configuration_map[prefix + "enable_ban"] == "on";
    }

    if (configuration_map.count(prefix + "enable_ban_ipv6") != 0) {
        ban_settings.enable_ban_ipv6 = configuration_map[prefix + "enable_ban_ipv6"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_pps") != 0) {
        ban_settings.enable_ban_for_pps = configuration_map[prefix + "ban_for_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_bandwidth") != 0) {
        ban_settings.enable_ban_for_bandwidth = configuration_map[prefix + "ban_for_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_flows") != 0) {
        ban_settings.enable_ban_for_flows_per_second = configuration_map[prefix + "ban_for_flows"] == "on";
    }

    // Per protocol bandwidth triggers
    if (configuration_map.count(prefix + "ban_for_tcp_bandwidth") != 0) {
        ban_settings.enable_ban_for_tcp_bandwidth = configuration_map[prefix + "ban_for_tcp_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_udp_bandwidth") != 0) {
        ban_settings.enable_ban_for_udp_bandwidth = configuration_map[prefix + "ban_for_udp_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_icmp_bandwidth") != 0) {
        ban_settings.enable_ban_for_icmp_bandwidth = configuration_map[prefix + "ban_for_icmp_bandwidth"] == "on";
    }

    // Per protocol pps ban triggers
    if (configuration_map.count(prefix + "ban_for_tcp_pps") != 0) {
        ban_settings.enable_ban_for_tcp_pps = configuration_map[prefix + "ban_for_tcp_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_udp_pps") != 0) {
        ban_settings.enable_ban_for_udp_pps = configuration_map[prefix + "ban_for_udp_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_icmp_pps") != 0) {
        ban_settings.enable_ban_for_icmp_pps = configuration_map[prefix + "ban_for_icmp_pps"] == "on";
    }

    // Pps per protocol thresholds
    if (configuration_map.count(prefix + "threshold_tcp_pps") != 0) {
        ban_settings.ban_threshold_tcp_pps = convert_string_to_integer(configuration_map[prefix + "threshold_tcp_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_udp_pps") != 0) {
        ban_settings.ban_threshold_udp_pps = convert_string_to_integer(configuration_map[prefix + "threshold_udp_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_icmp_pps") != 0) {
        ban_settings.ban_threshold_icmp_pps =
            convert_string_to_integer(configuration_map[prefix + "threshold_icmp_pps"]);
    }

    // Bandwidth per protocol thresholds
    if (configuration_map.count(prefix + "threshold_tcp_mbps") != 0) {
        ban_settings.ban_threshold_tcp_mbps =
            convert_string_to_integer(configuration_map[prefix + "threshold_tcp_mbps"]);
    }

    if (configuration_map.count(prefix + "threshold_udp_mbps") != 0) {
        ban_settings.ban_threshold_udp_mbps =
            convert_string_to_integer(configuration_map[prefix + "threshold_udp_mbps"]);
    }

    if (configuration_map.count(prefix + "threshold_icmp_mbps") != 0) {
        ban_settings.ban_threshold_icmp_mbps =
            convert_string_to_integer(configuration_map[prefix + "threshold_icmp_mbps"]);
    }

    if (configuration_map.count(prefix + "threshold_pps") != 0) {
        ban_settings.ban_threshold_pps = convert_string_to_integer(configuration_map[prefix + "threshold_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_mbps") != 0) {
        ban_settings.ban_threshold_mbps = convert_string_to_integer(configuration_map[prefix + "threshold_mbps"]);
    }

    if (configuration_map.count(prefix + "threshold_flows") != 0) {
        ban_settings.ban_threshold_flows = convert_string_to_integer(configuration_map[prefix + "threshold_flows"]);
    }

    return ban_settings;
}


bool exceed_pps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold) {
    if (in_counter > threshold or out_counter > threshold) {
        return true;
    } else {
        return false;
    }
}

bool exceed_flow_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold) {
    if (in_counter > threshold or out_counter > threshold) {
        return true;
    } else {
        return false;
    }
}

bool exceed_mbps_speed(uint64_t in_counter, uint64_t out_counter, unsigned int threshold_mbps) {
    if (convert_speed_to_mbps(in_counter) > threshold_mbps or convert_speed_to_mbps(out_counter) > threshold_mbps) {
        return true;
    } else {
        return false;
    }
}

// Return true when we should ban this entity
bool we_should_ban_this_entity(const subnet_counter_t& average_speed_element,
                               const ban_settings_t& current_ban_settings,
                               attack_detection_threshold_type_t& attack_detection_source,
                               attack_detection_direction_type_t& attack_detection_direction) {

    attack_detection_source    = attack_detection_threshold_type_t::unknown;
    attack_detection_direction = attack_detection_direction_type_t::unknown;


    // we detect overspeed by packets
    if (current_ban_settings.enable_ban_for_pps &&
        exceed_pps_speed(average_speed_element.total.in_packets, average_speed_element.total.out_packets,
                         current_ban_settings.ban_threshold_pps)) {

        attack_detection_source = attack_detection_threshold_type_t::packets_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_bandwidth &&
        exceed_mbps_speed(average_speed_element.total.in_bytes, average_speed_element.total.out_bytes,
                          current_ban_settings.ban_threshold_mbps)) {

        attack_detection_source = attack_detection_threshold_type_t::bytes_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_flows_per_second &&
        exceed_flow_speed(average_speed_element.in_flows, average_speed_element.out_flows, current_ban_settings.ban_threshold_flows)) {

        attack_detection_source = attack_detection_threshold_type_t::flows_per_second;
        return true;
    }

    // We could try per protocol thresholds here

    // Per protocol pps thresholds
    if (current_ban_settings.enable_ban_for_tcp_pps &&
        exceed_pps_speed(average_speed_element.tcp.in_packets, average_speed_element.tcp.out_packets,
                         current_ban_settings.ban_threshold_tcp_pps)) {
        attack_detection_source = attack_detection_threshold_type_t::tcp_packets_per_second;

        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_pps &&
        exceed_pps_speed(average_speed_element.udp.in_packets, average_speed_element.udp.out_packets,
                         current_ban_settings.ban_threshold_udp_pps)) {

        attack_detection_source = attack_detection_threshold_type_t::udp_packets_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_icmp_pps &&
        exceed_pps_speed(average_speed_element.icmp.in_packets, average_speed_element.icmp.out_packets,
                         current_ban_settings.ban_threshold_icmp_pps)) {
        attack_detection_source = attack_detection_threshold_type_t::icmp_packets_per_second;
        return true;
    }

    // Per protocol bandwidth thresholds
    if (current_ban_settings.enable_ban_for_tcp_bandwidth &&
        exceed_mbps_speed(average_speed_element.tcp.in_bytes, average_speed_element.tcp.out_bytes,
                          current_ban_settings.ban_threshold_tcp_mbps)) {
        attack_detection_source = attack_detection_threshold_type_t::tcp_bytes_per_second;
        ;
        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_bandwidth &&
        exceed_mbps_speed(average_speed_element.udp.in_bytes, average_speed_element.udp.out_bytes,
                          current_ban_settings.ban_threshold_udp_mbps)) {
        attack_detection_source = attack_detection_threshold_type_t::udp_bytes_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_icmp_bandwidth &&
        exceed_mbps_speed(average_speed_element.icmp.in_bytes, average_speed_element.icmp.out_bytes,
                          current_ban_settings.ban_threshold_icmp_mbps)) {
        attack_detection_source = attack_detection_threshold_type_t::icmp_bytes_per_second;
        return true;
    }

    return false;
}

std::string get_amplification_attack_type(amplification_attack_type_t attack_type) {
    if (attack_type == AMPLIFICATION_ATTACK_UNKNOWN) {
        return "unknown";
    } else if (attack_type == AMPLIFICATION_ATTACK_DNS) {
        return "dns_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_NTP) {
        return "ntp_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_SSDP) {
        return "ssdp_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_SNMP) {
        return "snmp_amplification";
    } else if (attack_type == AMPLIFICATION_ATTACK_CHARGEN) {
        return "chargen_amplification";
    } else {
        return "unexpected";
    }
}

std::string print_flow_tracking_for_specified_protocol(contrack_map_type& protocol_map, std::string client_ip, direction_t flow_direction) {
    std::stringstream buffer;
    // We shoud iterate over all fields

    int printed_records = 0;
    for (contrack_map_type::iterator itr = protocol_map.begin(); itr != protocol_map.end(); ++itr) {
        // We should limit number of records in flow dump because syn flood attacks produce
        // thounsands of lines
        if (printed_records > ban_details_records_count) {
            buffer << "Flows have cropped due to very long list.\n";
            break;
        }

        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash_t unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(packed_connection_data, unpacked_key_struct);

        std::string opposite_ip_as_string = convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);
        if (flow_direction == INCOMING) {
            buffer << client_ip << ":" << unpacked_key_struct.dst_port << " < " << opposite_ip_as_string << ":"
                   << unpacked_key_struct.src_port << " ";
        } else if (flow_direction == OUTGOING) {
            buffer << client_ip << ":" << unpacked_key_struct.src_port << " > " << opposite_ip_as_string << ":"
                   << unpacked_key_struct.dst_port << " ";
        }

        buffer << itr->second.bytes << " bytes " << itr->second.packets << " packets";
        buffer << "\n";

        printed_records++;
    }

    return buffer.str();
}

void convert_integer_to_conntrack_hash_struct(const uint64_t& packed_connection_data, packed_conntrack_hash_t& unpacked_data) {
    // Normally this code will trigger
    // warning: ‘void* memcpy(void*, const void*, size_t)’ copying an object of non-trivial type ‘class
    // packed_conntrack_hash_t’ from an array of ‘const uint64_t’ {aka ‘const long unsigned int’} [-Wclass-memaccess]
    // Yes, it's very bad practice to overwrite struct memory that way but we have enough safe guards (such as
    // explicitly packed structure and static_assert with sizeof check for structure size) in place to do it We apply
    // void* for target argument to suppress this warning
    memcpy((void*)&unpacked_data, &packed_connection_data, sizeof(uint64_t));
}

// This function returns true when attack for particular IPv6 or IPv4 address is finished
template <typename T>
    requires std::is_same_v<T, subnet_ipv6_cidr_mask_t> ||
    std::is_same_v<T, uint32_t> bool
    attack_is_finished(const T& current_subnet,
                       abstract_subnet_counters_t<T, subnet_counter_t>& host_counters) {

    std::string client_ip_as_string = convert_any_ip_to_string(current_subnet);

    subnet_counter_t average_speed_element;

    // Retrieve static counters
    bool result = host_counters.get_average_speed(current_subnet, average_speed_element);

    // I think it's fine even if we run in flexible counters mode as we must have some traffic tracked by static counters in any case
    if (!result) {
        logger << log4cpp::Priority::INFO << "Could not find traffic speed for " << client_ip_as_string
               << " in traffic structure. But that's fine because it may be removed by cleanup logic. It means that "
                  "traffic is "
                  "zero for long time and we can unban host";

        return true;
    }

    // Lookup network for IP as we need it for hostgorup lookup logic
    subnet_cidr_mask_t customer_subnet;
    bool lookup_result =
        lookup_ip_in_integer_form_inpatricia_and_return_subnet_if_found(lookup_tree_ipv4, current_subnet, customer_subnet);

    if (!lookup_result) {
        // It's not critical, we can ignore it
        logger << log4cpp::Priority::WARN << "Could not get customer's network for IP " << convert_ip_as_uint_to_string(current_subnet);
    }

    std::string host_group_name;
    ban_settings_t current_ban_settings = get_ban_settings_for_this_subnet(customer_subnet, host_group_name);

    attack_detection_threshold_type_t attack_detection_source;
    attack_detection_direction_type_t attack_detection_direction;

    bool should_block_static_thresholds = we_should_ban_this_entity(average_speed_element, current_ban_settings,
                                                                    attack_detection_source, attack_detection_direction);

    if (should_block_static_thresholds) {
        logger << log4cpp::Priority::DEBUG << "Attack to IP " << client_ip_as_string
               << " is still going. We should not unblock this host";

        // Well, we still see an attack, skip to next iteration
        return false;
    }

    return true;
}


// Unbans host which are ready to it
void execute_unban_operation_ipv4() {
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;

    time_t current_time;
    time(&current_time);

    std::vector<uint32_t> ban_list_items_for_erase;

    std::map<uint32_t, attack_details_t> ban_list_copy;

    // Get whole ban list content atomically
    ban_list_ipv4.get_whole_banlist(ban_list_copy);

    for (auto itr = ban_list_copy.begin(); itr != ban_list_copy.end(); ++itr) {
        uint32_t client_ip = itr->first;

        // This IP should be banned permanently and we skip any processing
        if (!itr->second.unban_enabled) {
            continue;
        }

        // This IP banned manually and we should not unban it automatically
        if (itr->second.attack_detection_source == attack_detection_source_t::Manual) {
            continue;
        }

        double time_difference = difftime(current_time, itr->second.ban_timestamp);
        int current_ban_time   = itr->second.ban_time;

        // Yes, we reached end of ban time for this customer
        bool we_could_unban_this_ip = time_difference > current_ban_time;

        // We haven't reached time for unban yet
        if (!we_could_unban_this_ip) {
            continue;
        }

        // Check about ongoing attack
        if (unban_only_if_attack_finished) {
            std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

            if (!attack_is_finished(client_ip, ipv4_host_counters)) {
                logger << log4cpp::Priority::INFO << "Skip unban operation for " << client_ip_as_string
                       << " because attack is still active";
                continue;
            }
        }

        // Add this IP to remove list
        // We will remove keys really after this loop
        ban_list_items_for_erase.push_back(itr->first);

        // Call all hooks for unban
        subnet_ipv6_cidr_mask_t zero_ipv6_address;

        // It's empty for unban
        std::string flow_attack_details;

        // These are empty too
        boost::circular_buffer<simple_packet_t> simple_packets_buffer;
        boost::circular_buffer<fixed_size_packet_storage_t> raw_packets_buffer;

        call_blackhole_actions_per_host(attack_action_t::unban, itr->first, zero_ipv6_address, false, itr->second,
                                        attack_detection_source_t::Automatic, flow_attack_details,
                                        simple_packets_buffer, raw_packets_buffer);
    }

    // Remove all unbanned hosts from the ban list
    for (auto ban_element_for_erase : ban_list_items_for_erase) {
        ban_list_ipv4.remove_from_blackhole(ban_element_for_erase);
    }
}


// Unbans host which are ready to it
void execute_unban_operation_ipv6() {
    time_t current_time;
    time(&current_time);

    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

    std::vector<subnet_ipv6_cidr_mask_t> ban_list_items_for_erase;

    std::map<subnet_ipv6_cidr_mask_t, banlist_item_t> ban_list_copy;

    // Get whole ban list content atomically
    ban_list_ipv6.get_whole_banlist(ban_list_copy);

    for (auto itr : ban_list_copy) {
        // This IP should be banned permanentely and we skip any processing
        if (!itr.second.unban_enabled) {
            continue;
        }

        // This IP banned manually and we should not unban it automatically
        if (itr.second.attack_detection_source == attack_detection_source_t::Manual) {
            continue;
        }

        double time_difference = difftime(current_time, itr.second.ban_timestamp);
        int current_ban_time   = itr.second.ban_time;

        // Yes, we reached end of ban time for this customer
        bool we_could_unban_this_ip = time_difference > current_ban_time;

        // We haven't reached time for unban yet
        if (!we_could_unban_this_ip) {
            continue;
        }

        if (unban_only_if_attack_finished) {
            logger << log4cpp::Priority::WARN << "Sorry, we do not support unban_only_if_attack_finished for IPv6";
        }

        // Add this IP to remove list
        // We will remove keys really after this loop
        ban_list_items_for_erase.push_back(itr.first);

        // Call all hooks for unban
        uint32_t zero_ipv4_ip_address = 0;

        // It's empty for unban
        std::string flow_attack_details;

        // These are empty too
        boost::circular_buffer<simple_packet_t> simple_packets_buffer;
        boost::circular_buffer<fixed_size_packet_storage_t> raw_packets_buffer;

        call_blackhole_actions_per_host(attack_action_t::unban, zero_ipv4_ip_address, itr.first, true, itr.second,
                                        attack_detection_source_t::Automatic, flow_attack_details,
                                        simple_packets_buffer, raw_packets_buffer);
    }

    // Remove all unbanned hosts from the ban list
    for (auto ban_element_for_erase : ban_list_items_for_erase) {
        ban_list_ipv6.remove_from_blackhole(ban_element_for_erase);
    }
}

/* Thread for cleaning up ban list */
void cleanup_ban_list() {
    // If we use very small ban time we should call ban_cleanup thread more often
    if (unban_iteration_sleep_time > global_ban_time) {
        unban_iteration_sleep_time = int(global_ban_time / 2);

        logger << log4cpp::Priority::INFO << "You are using enough small ban time " << global_ban_time
               << " we need reduce unban_iteration_sleep_time twices to " << unban_iteration_sleep_time << " seconds";
    }

    logger << log4cpp::Priority::INFO << "Run banlist cleanup thread, we will awake every " << unban_iteration_sleep_time << " seconds";

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(unban_iteration_sleep_time));

        time_t current_time;
        time(&current_time);

        execute_unban_operation_ipv4(); 

        // Unban IPv6 bans
        execute_unban_operation_ipv6();
    }
}

// This code is a source of race conditions of worst kind, we had to rework it ASAP
std::string print_ddos_attack_details() {
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;

    std::stringstream output_buffer;

    std::map<uint32_t, banlist_item_t> ban_list_ipv4_copy;

    // Get whole ban list content atomically
    ban_list_ipv4.get_whole_banlist(ban_list_ipv4_copy);

    for (auto itr : ban_list_ipv4_copy) {
        uint32_t client_ip = itr.first;

        std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

        output_buffer << client_ip_as_string << " at " << print_time_t_in_fastnetmon_format(itr.second.ban_timestamp) << std::endl;
    }

    return output_buffer.str();
}

std::string get_attack_description(uint32_t client_ip, const attack_details_t& current_attack) {
    std::stringstream attack_description;

    attack_description << "IP: " << convert_ip_as_uint_to_string(client_ip) << "\n";
    attack_description << serialize_attack_description(current_attack) << "\n";

    return attack_description.str();
}

// Serialises traffic counters to JSON
bool serialize_traffic_counters_to_json(const subnet_counter_t& traffic_counters, nlohmann::json& json_details) {
    try {
        json_details["total_incoming_traffic"]      = traffic_counters.total.in_bytes;
        json_details["total_incoming_traffic_bits"] = traffic_counters.total.in_bytes * 8;

        json_details["total_outgoing_traffic"]      = traffic_counters.total.out_bytes;
        json_details["total_outgoing_traffic_bits"] = traffic_counters.total.out_bytes * 8;

        json_details["total_incoming_pps"]   = traffic_counters.total.in_packets;
        json_details["total_outgoing_pps"]   = traffic_counters.total.out_packets;
        json_details["total_incoming_flows"] = traffic_counters.in_flows;
        json_details["total_outgoing_flows"] = traffic_counters.out_flows;

        json_details["incoming_dropped_traffic"]      = traffic_counters.dropped.in_bytes;
        json_details["incoming_dropped_traffic_bits"] = traffic_counters.dropped.in_bytes * 8;

        json_details["outgoing_dropped_traffic"]      = traffic_counters.dropped.out_bytes;
        json_details["outgoing_dropped_traffic_bits"] = traffic_counters.dropped.out_bytes * 8;

        json_details["incoming_dropped_pps"] = traffic_counters.dropped.in_packets;
        json_details["outgoing_dropped_pps"] = traffic_counters.dropped.out_packets;

        json_details["incoming_ip_fragmented_traffic"] = traffic_counters.fragmented.in_bytes;

        json_details["incoming_ip_fragmented_traffic_bits"] = traffic_counters.fragmented.in_bytes * 8;

        json_details["outgoing_ip_fragmented_traffic"] = traffic_counters.fragmented.out_bytes;

        json_details["outgoing_ip_fragmented_traffic_bits"] = traffic_counters.fragmented.out_bytes * 8;

        json_details["incoming_ip_fragmented_pps"] = traffic_counters.fragmented.in_packets;
        json_details["outgoing_ip_fragmented_pps"] = traffic_counters.fragmented.out_packets;

        json_details["incoming_tcp_traffic"]      = traffic_counters.tcp.in_bytes;
        json_details["incoming_tcp_traffic_bits"] = traffic_counters.tcp.in_bytes * 8;

        json_details["outgoing_tcp_traffic"]      = traffic_counters.tcp.out_bytes;
        json_details["outgoing_tcp_traffic_bits"] = traffic_counters.tcp.out_bytes * 8;

        json_details["incoming_tcp_pps"] = traffic_counters.tcp.in_packets;
        json_details["outgoing_tcp_pps"] = traffic_counters.tcp.out_packets;

        json_details["incoming_syn_tcp_traffic"]      = traffic_counters.tcp_syn.in_bytes;
        json_details["incoming_syn_tcp_traffic_bits"] = traffic_counters.tcp_syn.in_bytes * 8;

        json_details["outgoing_syn_tcp_traffic"]      = traffic_counters.tcp_syn.out_bytes;
        json_details["outgoing_syn_tcp_traffic_bits"] = traffic_counters.tcp_syn.out_bytes * 8;

        json_details["incoming_syn_tcp_pps"] = traffic_counters.tcp_syn.in_packets;
        json_details["outgoing_syn_tcp_pps"] = traffic_counters.tcp_syn.out_packets;

        json_details["incoming_udp_traffic"]      = traffic_counters.udp.in_bytes;
        json_details["incoming_udp_traffic_bits"] = traffic_counters.udp.in_bytes * 8;

        json_details["outgoing_udp_traffic"]      = traffic_counters.udp.out_bytes;
        json_details["outgoing_udp_traffic_bits"] = traffic_counters.udp.out_bytes * 8;

        json_details["incoming_udp_pps"] = traffic_counters.udp.in_packets;
        json_details["outgoing_udp_pps"] = traffic_counters.udp.out_packets;

        json_details["incoming_icmp_traffic"]      = traffic_counters.icmp.in_bytes;
        json_details["incoming_icmp_traffic_bits"] = traffic_counters.icmp.in_bytes * 8;

        json_details["outgoing_icmp_traffic"]      = traffic_counters.icmp.out_bytes;
        json_details["outgoing_icmp_traffic_bits"] = traffic_counters.icmp.out_bytes * 8;

        json_details["incoming_icmp_pps"] = traffic_counters.icmp.in_packets;
        json_details["outgoing_icmp_pps"] = traffic_counters.icmp.out_packets;

    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Exception was triggered in attack details JSON encoder";
        return false;
    }

    return true;
}


bool serialize_attack_description_to_json(const attack_details_t& current_attack, nlohmann::json& json_details) {
    // We need to catch exceptions as code may raise them here
    try {
        json_details["attack_uuid"]      = current_attack.get_attack_uuid_as_string();
        json_details["host_group"]       = current_attack.host_group;
        json_details["protocol_version"] = current_attack.get_protocol_name();
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Exception was triggered in attack details JSON encoder";
        return false;
    }

    if (!serialize_traffic_counters_to_json(current_attack.traffic_counters, json_details)) {
        logger << log4cpp::Priority::ERROR << "Cannot add traffic counters to JSON document";
        return false;
    }

    return true;
}

std::string get_attack_description_in_json_for_web_hooks(uint32_t client_ip,
                                                         const subnet_ipv6_cidr_mask_t& client_ipv6,
                                                         bool ipv6,
                                                         const std::string& action_type,
                                                         const attack_details_t& current_attack) {
    nlohmann::json callback_info;

    callback_info["alert_scope"] = "host";

    if (ipv6) {
        callback_info["ip"] = print_ipv6_address(client_ipv6.subnet_address);
    } else {
        callback_info["ip"] = convert_ip_as_uint_to_string(client_ip);
    }

    callback_info["action"] = action_type;

    nlohmann::json attack_details;

    bool attack_details_result = serialize_attack_description_to_json(current_attack, attack_details);

    if (attack_details_result) {
        callback_info["attack_details"] = attack_details;
    } else {
        logger << log4cpp::Priority::ERROR << "Cannot generate attack details for get_attack_description_in_json_for_web_hooks";
    }


    std::string json_as_text = callback_info.dump();

    return json_as_text;
}

uint64_t convert_conntrack_hash_struct_to_integer(const packed_conntrack_hash_t& struct_value) {
    uint64_t unpacked_data = 0;
    memcpy(&unpacked_data, &struct_value, sizeof(uint64_t));
    return unpacked_data;
}


/*
    Attack types:
        - syn flood: one local port, multiple remote hosts (and maybe multiple remote ports) and
   small packet size
*/

/* Iterate over all flow tracking table */
bool process_flow_tracking_table(conntrack_main_struct_t& conntrack_element, std::string client_ip) {
    std::map<uint32_t, unsigned int> uniq_remote_hosts_which_generate_requests_to_us;
    std::map<unsigned int, unsigned int> uniq_local_ports_which_target_of_connectiuons_from_inside;

    /* Process incoming TCP connections */
    for (contrack_map_type::iterator itr = conntrack_element.in_tcp.begin(); itr != conntrack_element.in_tcp.end(); ++itr) {
        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash_t unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(packed_connection_data, unpacked_key_struct);

        uniq_remote_hosts_which_generate_requests_to_us[unpacked_key_struct.opposite_ip]++;
        uniq_local_ports_which_target_of_connectiuons_from_inside[unpacked_key_struct.dst_port]++;

        // we can calc average packet size
        // string opposite_ip_as_string =
        // convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);
        // unpacked_key_struct.src_port
        // unpacked_key_struct.dst_port
        // itr->second.packets
        // itr->second.bytes
    }

    return true;
}

// exec command and pass data to it stdin
// exec command and pass data to it stdin
bool exec_with_stdin_params(std::string cmd, std::string params) {
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        logger << log4cpp::Priority::ERROR << "Can't execute programme " << cmd << " error code: " << errno
               << " error text: " << strerror(errno);
        return false;
    }

    int fputs_ret = fputs(params.c_str(), pipe);

    if (fputs_ret) {
        int pclose_return = pclose(pipe);

        if (pclose_return < 0) {
            logger << log4cpp::Priority::ERROR << "Cannot collect return status of subprocess with error: " << errno
                   << strerror(errno);
        } else {
            logger << log4cpp::Priority::INFO << "Subprocess exit code: " << pclose_return;
        }

        return true;
    } else {
        logger << log4cpp::Priority::ERROR << "Can't pass data to stdin of programme " << cmd;
        pclose(pipe);
        return false;
    }

    return true;
}

// Get ban settings for this subnet or return global ban settings
ban_settings_t get_ban_settings_for_this_subnet(const subnet_cidr_mask_t& subnet, std::string& host_group_name) {
    // Try to find host group for this subnet
    subnet_to_host_group_map_t::iterator host_group_itr = subnet_to_host_groups.find(subnet);

    if (host_group_itr == subnet_to_host_groups.end()) {
        // We haven't host groups for all subnets, it's OK
        // logger << log4cpp::Priority::INFO << "We haven't custom host groups for this network. We will use global ban settings";
        host_group_name = "global";
        return global_ban_settings;
    }

    host_group_name = host_group_itr->second;

    // We found host group for this subnet
    auto hostgroup_settings_itr = host_group_ban_settings_map.find(host_group_itr->second);

    if (hostgroup_settings_itr == host_group_ban_settings_map.end()) {
        logger << log4cpp::Priority::ERROR << "We can't find ban settings for host group " << host_group_itr->second;
        return global_ban_settings;
    }

    // We found ban settings for this host group and use they instead global
    return hostgroup_settings_itr->second;
}

#ifdef REDIS
void store_data_in_redis(std::string key_name, std::string attack_details) {
    redisReply* reply           = NULL;
    redisContext* redis_context = redis_init_connection();

    if (!redis_context) {
        logger << log4cpp::Priority::ERROR << "Could not initiate connection to Redis";
        return;
    }

    reply = (redisReply*)redisCommand(redis_context, "SET %s %s", key_name.c_str(), attack_details.c_str());

    // If we store data correctly ...
    if (!reply) {
        logger << log4cpp::Priority::ERROR << "Can't increment traffic in redis error_code: " << redis_context->err
               << " error_string: " << redis_context->errstr;

        // Handle redis server restart corectly
        if (redis_context->err == 1 or redis_context->err == 3) {
            // Connection refused
            logger << log4cpp::Priority::ERROR << "Unfortunately we can't store data in Redis because server reject connection";
        }
    } else {
        freeReplyObject(reply);
    }

    redisFree(redis_context);
}

redisContext* redis_init_connection() {
    struct timeval timeout      = { 1, 500000 }; // 1.5 seconds
    redisContext* redis_context = redisConnectWithTimeout(redis_host.c_str(), redis_port, timeout);
    if (redis_context->err) {
        logger << log4cpp::Priority::ERROR << "Redis connection error:" << redis_context->errstr;
        return NULL;
    }

    // We should check connection with ping because redis do not check connection
    redisReply* reply = (redisReply*)redisCommand(redis_context, "PING");
    if (reply) {
        freeReplyObject(reply);
    } else {
        return NULL;
    }

    return redis_context;
}

#endif

void call_blackhole_actions_per_host(attack_action_t attack_action,
                                     uint32_t client_ip,
                                     const subnet_ipv6_cidr_mask_t& client_ipv6,
                                     bool ipv6,
                                     const attack_details_t& current_attack,
                                     attack_detection_source_t attack_detection_source,
                                     const std::string& flow_attack_details,
                                     const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
                                     const boost::circular_buffer<fixed_size_packet_storage_t>& raw_packets_buffer) { 

    bool ipv4                       = !ipv6;
    std::string client_ip_as_string = "";

    if (ipv4) {
        client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    } else {
        client_ip_as_string = print_ipv6_address(client_ipv6.subnet_address);
    }

    std::string action_name;

    if (attack_action == attack_action_t::ban) {
        action_name = "ban";
    } else if (attack_action == attack_action_t::unban) {
        action_name = "unban";
    }

    std::string simple_packets_dump;
    print_simple_packet_buffer_to_string(simple_packets_buffer, simple_packets_dump);

    std::string basic_attack_information_in_json =
        get_attack_description_in_json_for_web_hooks(client_ip, subnet_ipv6_cidr_mask_t{}, false, action_name, current_attack);

    bool store_attack_details_to_file = true;

    if (store_attack_details_to_file && attack_action == attack_action_t::ban) {
        std::string basic_attack_information = get_attack_description(client_ip, current_attack);

        std::string full_attack_description = basic_attack_information + "\n\nAttack traffic dump\n\n" + simple_packets_dump + "\n\nFlow dump\n\n" + flow_attack_details;

        if (store_attack_details_to_file) {
            print_attack_details_to_file(full_attack_description, client_ip_as_string, current_attack);
        }
    }

    if (notify_script_enabled) {
        std::string pps_as_string            = convert_int_to_string(current_attack.attack_power);
        std::string data_direction_as_string = get_direction_name(current_attack.attack_direction);

        if (attack_action == attack_action_t::ban) {
            std::string basic_attack_information = get_attack_description(client_ip, current_attack);

            std::string full_attack_description = basic_attack_information + "\n\nAttack traffic dump\n\n" + simple_packets_dump + "\n\nFlow dump\n\n" + flow_attack_details;

            std::string script_call_params = fastnetmon_platform_configuration.notify_script_path + " " + client_ip_as_string +
                                             " " + data_direction_as_string + " " + pps_as_string + " " + "ban";
            
            logger << log4cpp::Priority::INFO << "Call script for ban client: " << client_ip_as_string;

            // We should execute external script in separate thread because any lag in this code will be
            // very destructive

            // We will pass attack details over stdin
            boost::thread exec_thread(exec_with_stdin_params, script_call_params, full_attack_description);
            exec_thread.detach();

            logger << log4cpp::Priority::INFO << "Script for ban client is finished: " << client_ip_as_string;
        } else if (attack_action == attack_action_t::unban) {
            std::string script_call_params = fastnetmon_platform_configuration.notify_script_path + " " + client_ip_as_string +
                                             " " + data_direction_as_string + " " + pps_as_string + " unban";

            logger << log4cpp::Priority::INFO << "Call script for unban client: " << client_ip_as_string;

            // We should execute external script in separate thread because any lag in this
            // code will be very distructive
            boost::thread exec_thread(exec_no_error_check, script_call_params);
            exec_thread.detach();

            logger << log4cpp::Priority::INFO << "Script for unban client is finished: " << client_ip_as_string;
        }
    }

    if (exabgp_enabled && ipv4) {
        logger << log4cpp::Priority::INFO << "Call ExaBGP for " << action_name << " client started: " << client_ip_as_string;

        boost::thread exabgp_thread(exabgp_ban_manage, action_name, client_ip_as_string, current_attack.customer_network);
        exabgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to ExaBGP for " << action_name << "client is finished: " << client_ip_as_string;
    }

#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call GoBGP for " << action_name << " client started: " << client_ip_as_string;

        boost::thread gobgp_thread(gobgp_ban_manage, action_name, ipv6, client_ip_as_string, client_ipv6, current_attack.customer_network);
        gobgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to GoBGP for " << action_name << " client is finished: " << client_ip_as_string;
    }
#endif

    if (attack_action == attack_action_t::ban) { 
#ifdef REDIS
        if (redis_enabled && ipv4) {
            std::string redis_key_name = client_ip_as_string + "_information";

            if (!redis_prefix.empty()) {
                redis_key_name = redis_prefix + "_" + client_ip_as_string + "_information";
            }

            logger << log4cpp::Priority::INFO << "Start data save in Redis in key: " << redis_key_name;
            boost::thread redis_store_thread(store_data_in_redis, redis_key_name, basic_attack_information_in_json);
            redis_store_thread.detach();
            logger << log4cpp::Priority::INFO << "Finish data save in Redis in key: " << redis_key_name;

            // If we have flow dump put in redis too
            if (!flow_attack_details.empty()) {
                std::string redis_key_name = client_ip_as_string + "_flow_dump";

                if (!redis_prefix.empty()) {
                    redis_key_name = redis_prefix + "_" + client_ip_as_string + "_flow_dump";
                }

                logger << log4cpp::Priority::INFO << "Start data save in redis in key: " << redis_key_name;
                boost::thread redis_store_thread(store_data_in_redis, redis_key_name, flow_attack_details);
                redis_store_thread.detach();
                logger << log4cpp::Priority::INFO << "Finish data save in redis in key: " << redis_key_name;
            }

        }
#endif
    }

    if (attack_action == attack_action_t::ban) { 
#ifdef MONGO
        if (mongodb_enabled && ipv4) {
            std::string mongo_key_name =
                client_ip_as_string + "_information_" + print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);

            // We could not use dot in key names: http://docs.mongodb.org/manual/core/document/#dot-notation
            std::replace(mongo_key_name.begin(), mongo_key_name.end(), '.', '_');

            logger << log4cpp::Priority::INFO << "Start data save in Mongo in key: " << mongo_key_name;
            boost::thread mongo_store_thread(store_data_in_mongo, mongo_key_name, basic_attack_information_in_json);
            mongo_store_thread.detach();
            logger << log4cpp::Priority::INFO << "Finish data save in Mongo in key: " << mongo_key_name;
        }
#endif
    }
}


#ifdef MONGO
void store_data_in_mongo(std::string key_name, std::string attack_details_json) {
    mongoc_client_t* client;
    mongoc_collection_t* collection;
    bson_error_t error;
    bson_oid_t oid;
    bson_t* doc;

    mongoc_init();

    std::string collection_name   = "attacks";
    std::string connection_string = "mongodb://" + mongodb_host + ":" + convert_int_to_string(mongodb_port) + "/";

    client = mongoc_client_new(connection_string.c_str());

    if (!client) {
        logger << log4cpp::Priority::ERROR << "Can't connect to MongoDB database";
        return;
    }

    bson_error_t bson_from_json_error;
    bson_t* bson_data =
        bson_new_from_json((const uint8_t*)attack_details_json.c_str(), attack_details_json.size(), &bson_from_json_error);
    if (!bson_data) {
        logger << log4cpp::Priority::ERROR << "Could not convert JSON to BSON";
        return;
    }

    // logger << log4cpp::Priority::INFO << bson_as_json(bson_data, NULL);

    collection = mongoc_client_get_collection(client, mongodb_database_name.c_str(), collection_name.c_str());

    doc = bson_new();
    bson_oid_init(&oid, NULL);
    BSON_APPEND_OID(doc, "_id", &oid);
    bson_append_document(doc, key_name.c_str(), key_name.size(), bson_data);

    // logger << log4cpp::Priority::INFO << bson_as_json(doc, NULL);

    if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
        logger << log4cpp::Priority::ERROR << "Could not store data to MongoDB: " << error.message;
    }

    // TODO: destroy bson_data too!

    bson_destroy(doc);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
}
#endif

// pretty print channel speed in pps and MBit
std::string print_channel_speed(std::string traffic_type, direction_t packet_direction) {
    uint64_t speed_in_pps = total_counters_ipv4.total_speed_average_counters[packet_direction].packets;
    uint64_t speed_in_bps = total_counters_ipv4.total_speed_average_counters[packet_direction].bytes;

    unsigned int number_of_tabs = 1;
    // We need this for correct alignment of blocks
    if (traffic_type == "Other traffic") {
        number_of_tabs = 2;
    }

    std::stringstream stream;
    stream << traffic_type;

    for (unsigned int i = 0; i < number_of_tabs; i++) {
        stream << "\t";
    }

    uint64_t speed_in_mbps = convert_speed_to_mbps(speed_in_bps);

    stream << std::setw(6) << speed_in_pps << " pps " << std::setw(6) << speed_in_mbps << " mbps";

    if (traffic_type == "Incoming traffic" or traffic_type == "Outgoing traffic") {
        if (packet_direction == INCOMING) {
            stream << " " << std::setw(6) << incoming_total_flows_speed << " flows";
        } else if (packet_direction == OUTGOING) {
            stream << " " << std::setw(6) << outgoing_total_flows_speed << " flows";
        }
    }

    return stream.str();
}


void traffic_draw_ipv6_program() {
    std::stringstream output_buffer;

    // logger<<log4cpp::Priority::INFO<<"Draw table call";
    attack_detection_threshold_type_t sorter_type;

    if (sort_parameter == "packets") {
        sorter_type = attack_detection_threshold_type_t::packets_per_second;
    } else if (sort_parameter == "bytes") {
        sorter_type = attack_detection_threshold_type_t::bytes_per_second;
    } else if (sort_parameter == "flows") {
        sorter_type = attack_detection_threshold_type_t::flows_per_second;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter_type = attack_detection_threshold_type_t::packets_per_second;
    }

    output_buffer << "FastNetMon " << fastnetmon_platform_configuration.fastnetmon_version
                  << " Try Advanced edition: https://fastnetmon.com/product-overview/"
                  << "\n"
                  << "IPs ordered by: " << sort_parameter << "\n";

    output_buffer << print_channel_speed_ipv6("Incoming traffic", INCOMING) << std::endl;

    if (process_incoming_traffic) {
        output_buffer << draw_table_ipv6(attack_detection_direction_type_t::incoming, sorter_type);
        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed_ipv6("Outgoing traffic", OUTGOING) << std::endl;

    if (process_outgoing_traffic) {
        output_buffer << draw_table_ipv6(attack_detection_direction_type_t::outgoing, sorter_type);
        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed_ipv6("Internal traffic", INTERNAL) << std::endl;

    output_buffer << std::endl;

    output_buffer << print_channel_speed_ipv6("Other traffic", OTHER) << std::endl;

    output_buffer << std::endl;

    // Print screen contents into file
    print_screen_contents_into_file(output_buffer.str(), cli_stats_ipv6_file_path);
}

void traffic_draw_ipv4_program() {
    std::stringstream output_buffer;

    // logger<<log4cpp::Priority::INFO<<"Draw table call";
    std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

    attack_detection_threshold_type_t sorter_type;

    if (sort_parameter == "packets") {
        sorter_type = attack_detection_threshold_type_t::packets_per_second;
    } else if (sort_parameter == "bytes") {
        sorter_type = attack_detection_threshold_type_t::bytes_per_second;
    } else if (sort_parameter == "flows") {
        sorter_type = attack_detection_threshold_type_t::flows_per_second;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter_type = attack_detection_threshold_type_t::packets_per_second;
    }

    output_buffer << "FastNetMon " << fastnetmon_platform_configuration.fastnetmon_version
                  << " Try Advanced edition: https://fastnetmon.com/product-overview/"
                  << "\n"
                  << "IPs ordered by: " << sort_parameter << "\n";

    output_buffer << print_channel_speed("Incoming traffic", INCOMING) << std::endl;

    if (process_incoming_traffic) {
        output_buffer << draw_table_ipv4_hash(attack_detection_direction_type_t::incoming, sorter_type);

        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed("Outgoing traffic", OUTGOING) << std::endl;

    if (process_outgoing_traffic) {
        output_buffer << draw_table_ipv4_hash(attack_detection_direction_type_t::outgoing, sorter_type);

        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed("Internal traffic", INTERNAL) << std::endl;

    output_buffer << std::endl;

    output_buffer << print_channel_speed("Other traffic", OTHER) << std::endl;

    output_buffer << std::endl;

    // Application statistics
    output_buffer << "Screen updated in:\t\t" << std::setprecision(2) << drawing_thread_execution_time << " sec\n";

    output_buffer << "Traffic calculated in:\t\t" << speed_calculation_time.tv_sec << " sec "
                  << speed_calculation_time.tv_usec << " microseconds\n";

    output_buffer << "Not processed packets: " << total_unparsed_packets_speed << " pps\n";

    output_buffer << std::endl << "Ban list:" << std::endl;
    output_buffer << print_ddos_attack_details();

    // Print screen contents into file
    print_screen_contents_into_file(output_buffer.str(), cli_stats_file_path);

    std::chrono::duration<double> diff = std::chrono::steady_clock::now() - start_time;

    drawing_thread_execution_time = diff.count();
}

std::string get_human_readable_threshold_type(attack_detection_threshold_type_t detecttion_type) {
    if (detecttion_type == attack_detection_threshold_type_t::unknown) {
        return "unknown";
    } else if (detecttion_type == attack_detection_threshold_type_t::packets_per_second) {
        return "packets per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::bytes_per_second) {
        return "bytes per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::flows_per_second) {
        return "flows per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::tcp_packets_per_second) {
        return "tcp packets per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::tcp_syn_packets_per_second) {
        return "tcp syn packets per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::tcp_syn_bytes_per_second) {
        return "tcp syn bytes per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::udp_packets_per_second) {
        return "udp packets per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::icmp_packets_per_second) {
        return "icmp packets per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::tcp_bytes_per_second) {
        return "tcp bytes per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::udp_bytes_per_second) {
        return "udp bytes per second";
    } else if (detecttion_type == attack_detection_threshold_type_t::icmp_bytes_per_second) {
        return "icmp bytes per second";
    }

    return "unknown";
}


// This function fills attack information from different information sources
bool fill_attack_information(
                             attack_details_t& current_attack,
                             std::string& host_group_name,
                             std::string& parent_host_group_name,
                             bool unban_enabled,
                             int ban_time) {
    uint64_t pps = 0;

    uint64_t in_pps    = current_attack.traffic_counters.total.in_packets;
    uint64_t out_pps   = current_attack.traffic_counters.total.out_packets;
    uint64_t in_bps    = current_attack.traffic_counters.total.in_bytes;
    uint64_t out_bps   = current_attack.traffic_counters.total.out_bytes;

    direction_t data_direction;

    // TODO: move this logic to different function!!!

    // Detect attack direction with simple heuristic
    if (abs(int((int)in_pps - (int)out_pps)) < 1000) {
        // If difference between pps speed is so small we should do additional
        // investigation using
        // bandwidth speed
        if (in_bps > out_bps) {
            data_direction = INCOMING;
            pps            = in_pps;
        } else {
            data_direction = OUTGOING;
            pps            = out_pps;
        }
    } else {
        if (in_pps > out_pps) {
            data_direction = INCOMING;
            pps            = in_pps;
        } else {
            data_direction = OUTGOING;
            pps            = out_pps;
        }
    }

    current_attack.attack_protocol = detect_attack_protocol(current_attack.traffic_counters, data_direction);

    current_attack.host_group        = host_group_name;
    current_attack.parent_host_group = parent_host_group_name;

    std::string data_direction_as_string = get_direction_name(data_direction);

    logger << log4cpp::Priority::INFO << "We run attack block code with following params"
           << " in: " << in_pps << " pps " << convert_speed_to_mbps(in_bps) << " mbps"
           << " out: " << out_pps << " pps " << convert_speed_to_mbps(out_bps) << " mbps"
           << " and we decided it's " << data_direction_as_string << " attack";

    // Store ban time
    time(&current_attack.ban_timestamp);
    // set ban time in seconds
    current_attack.ban_time      = ban_time;
    current_attack.unban_enabled = unban_enabled;

    // Pass main information about attack
    current_attack.attack_direction = data_direction;
    current_attack.attack_power     = pps;
    current_attack.max_attack_power = pps;

    return true;
}


// Speed recalculation function for IPv6 hosts calls it for each host during speed recalculation
void speed_calculation_callback_local_ipv6(const subnet_ipv6_cidr_mask_t& current_subnet, const subnet_counter_t& current_average_speed_element) {
    // We should check thresholds only for per host counters for IPv6 and only when any ban actions for IPv6 traffic were enabled
    if (!global_ban_settings.enable_ban_ipv6) {
        return;
    }

    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

    // We support only global group
    std::string host_group_name = "global";

    attack_detection_threshold_type_t attack_detection_source;
    attack_detection_direction_type_t attack_detection_direction;

    bool should_ban = we_should_ban_this_entity(current_average_speed_element, global_ban_settings,
                                                attack_detection_source, attack_detection_direction);

    if (!should_ban) {
        return;
    }

    // This code works only for /128 subnets
    bool in_white_list = ip_belongs_to_patricia_tree_ipv6(whitelist_tree_ipv6, current_subnet.subnet_address);

    if (in_white_list) {
        // logger << log4cpp::Priority::INFO << "This IP was whitelisted";
        return;
    }

    bool we_already_have_buckets_for_this_ip = packet_buckets_ipv6_storage.we_have_bucket_for_this_ip(current_subnet);

    if (we_already_have_buckets_for_this_ip) {
        return;
    }

    bool this_ip_is_already_banned = ban_list_ipv6.is_blackholed(current_subnet);

    if (this_ip_is_already_banned) {
        return;
    }

    std::string ddos_detection_threshold_as_string = get_human_readable_threshold_type(attack_detection_source);

    logger << log4cpp::Priority::INFO << "We have detected IPv6 attack for " << print_ipv6_cidr_subnet(current_subnet)
           << " with " << ddos_detection_threshold_as_string << " threshold host group: " << host_group_name;

    std::string parent_group;

    attack_details_t attack_details;
    attack_details.traffic_counters = current_average_speed_element;
    
    fill_attack_information(attack_details, host_group_name, parent_group, unban_enabled, global_ban_time);

    attack_details.ipv6 = true;
    // TODO: Also, we should find IPv6 network for attack here

    bool enable_backet_capture =
        packet_buckets_ipv6_storage.enable_packet_capture(current_subnet, attack_details, collection_pattern_t::ONCE);

    if (!enable_backet_capture) {
        logger << log4cpp::Priority::ERROR << "Could not enable packet capture for deep analytics for IPv6 "
               << print_ipv6_cidr_subnet(current_subnet);
        return;
    }

    logger << log4cpp::Priority::INFO << "Enabled packet capture for IPv6 " << print_ipv6_address(current_subnet.subnet_address);
}


// Speed recalculation function for IPv6 networks
// It's just stub, we do not execute any actions for it
void speed_callback_subnet_ipv6(subnet_ipv6_cidr_mask_t* subnet, subnet_counter_t* speed_element) {
    return;
}

// This function works as callback from main speed calculation thread and decides when we should block host using static thresholds
void speed_calculation_callback_local_ipv4(const uint32_t& client_ip, const subnet_counter_t& speed_element) {
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;
    extern packet_buckets_storage_t<uint32_t> packet_buckets_ipv4_storage;
    extern patricia_tree_t* whitelist_tree_ipv4;
    extern patricia_tree_t* lookup_tree_ipv4;

    extern boost::circular_buffer<simple_packet_t> ipv4_packets_circular_buffer;

    // Check global ban settings
    if (!global_ban_settings.enable_ban) {
        return;
    }

    // Lookup network for IP as we need it for hostgorup lookup logic
    subnet_cidr_mask_t customer_subnet;
    bool lookup_result =
        lookup_ip_in_integer_form_inpatricia_and_return_subnet_if_found(lookup_tree_ipv4, client_ip, customer_subnet);

    if (!lookup_result) {
        // It's not critical, we can ignore it
        logger << log4cpp::Priority::WARN << "Could not get customer's network for IP " << convert_ip_as_uint_to_string(client_ip);
    }

    std::string host_group_name;
    ban_settings_t current_ban_settings = get_ban_settings_for_this_subnet(customer_subnet, host_group_name);

    // Hostgroup has blocks disabled
    if (!current_ban_settings.enable_ban) {
        return;
    }

    attack_details_t attack_details;

    // Static thresholds
    attack_detection_threshold_type_t attack_detection_source;
    attack_detection_direction_type_t attack_detection_direction;

    bool should_block = we_should_ban_this_entity(speed_element, current_ban_settings,
                                                  attack_detection_source, attack_detection_direction);

    if (!should_block) {
        return;
    }

    // We should execute check over whitelist
    // In common case, this check is pretty complicated and we should execute it only for hosts which exceed
    // threshold
    bool in_white_list = ip_belongs_to_patricia_tree(whitelist_tree_ipv4, client_ip);

    // And if we found host here disable any actions about blocks
    if (in_white_list) {
        return;
    }

    // If we decided to block this host we should check two cases:
    // 1) Already banned
    // 2) We already started packets collection for this IP address

    // They could be filled or not yet filled
    // TODO: with this check we should REMOVE items from bucket storage when attack handled
    bool we_already_have_buckets_for_this_ip = packet_buckets_ipv4_storage.we_have_bucket_for_this_ip(client_ip);

    if (we_already_have_buckets_for_this_ip) {
        return;
    }

    bool this_ip_is_already_banned = ban_list_ipv4.is_blackholed(client_ip);

    if (this_ip_is_already_banned) {
        return;
    }

    std::string ddos_detection_threshold_as_string = get_human_readable_threshold_type(attack_detection_source);
    std::string ddos_detection_direction = get_human_readable_attack_detection_direction(attack_detection_direction);

    logger << log4cpp::Priority::INFO << "We have detected attack for " << convert_ip_as_uint_to_string(client_ip)
           << " using " << ddos_detection_threshold_as_string << " threshold "
           << "in direction " << ddos_detection_direction << " "
           << "host group: " << host_group_name;

    
    attack_details.traffic_counters = speed_element;

    // Set threshold direction
    attack_details.attack_detection_direction = attack_detection_direction;

    // Set threshold type
    attack_details.attack_detection_threshold = attack_detection_source;

    // Fill attack details. This operation is pretty simple and involves only long prefix match lookup +
    // field copy
    std::string parent_group;
   
    fill_attack_information(attack_details, host_group_name,
                            parent_group, unban_enabled,
                            global_ban_time);

    attack_details.customer_network = customer_subnet;

    bool enable_backet_capture =
        packet_buckets_ipv4_storage.enable_packet_capture(client_ip, attack_details, collection_pattern_t::ONCE);

    if (!enable_backet_capture) {
        logger << log4cpp::Priority::ERROR << "Could not enable packet capture for deep analytics for IP "
               << convert_ip_as_uint_to_string(client_ip);
        return;
    }

    logger << log4cpp::Priority::INFO << "Enabled packet capture for IP " << convert_ip_as_uint_to_string(client_ip);

    return;
}

// Increments in and out flow counters
// Returns false when we cannot find flow for this IP
bool increment_flow_counters(subnet_counter_t& new_speed_element, uint32_t client_ip, double speed_calc_period) {
    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
    extern std::mutex flow_counter_mutex;

    std::lock_guard<std::mutex> lock_guard(flow_counter_mutex);

    auto current_flow_counter = SubnetVectorMapFlow.find(client_ip);

    if (current_flow_counter == SubnetVectorMapFlow.end()) {
        // We have no entries for this IP
        return false;
    }

    uint64_t total_out_flows =
        (uint64_t)current_flow_counter->second.out_tcp.size() + (uint64_t)current_flow_counter->second.out_udp.size() +
        (uint64_t)current_flow_counter->second.out_icmp.size() + (uint64_t)current_flow_counter->second.out_other.size();

    uint64_t total_in_flows =
        (uint64_t)current_flow_counter->second.in_tcp.size() + (uint64_t)current_flow_counter->second.in_udp.size() +
        (uint64_t)current_flow_counter->second.in_icmp.size() + (uint64_t)current_flow_counter->second.in_other.size();

    // logger << log4cpp::Priority::DEBUG << "total out flows: " << total_out_flows << " total in flows: " << total_in_flows << " speed calc period: " << speed_calc_period;

    new_speed_element.out_flows = uint64_t((double)total_out_flows / speed_calc_period);
    new_speed_element.in_flows  = uint64_t((double)total_in_flows / speed_calc_period);

    return true;
}


/* Calculate speed for all connnections */
void recalculate_speed() {
    // logger<< log4cpp::Priority::INFO<<"We run recalculate_speed";
    double speed_calc_period = recalculate_speed_timeout;

    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;

    std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

    // Calculate duration of our sleep duration as it may be altered by OS behaviour (i.e. process scheduler)
    // And if it differs from reference value then we need to adjust it and use new value
    std::chrono::duration<double> diff = start_time - last_call_of_traffic_recalculation;

    double time_difference = diff.count();

    // Handle case of time moving backwards
    if (time_difference < 0) {
        // It must not happen as our time source is explicitly monotonic: https://en.cppreference.com/w/cpp/chrono/steady_clock
        logger << log4cpp::Priority::ERROR << "Negative delay for traffic calculation " << time_difference;
        logger << log4cpp::Priority::ERROR << "This must not happen, please report this issue to maintainers. Skipped iteration";

        return;
    }

    // logger << log4cpp::Priority::INFO << "Delay in seconds " << time_difference;

    // Zero or positive delay
    if (time_difference < recalculate_speed_timeout) {
        // It could occur on toolkit start or in some weird cases of Linux scheduler
        // I really saw cases when sleep executed in zero seconds:
        // [WARN] Sleep time expected: 1. Sleep time experienced: 0
        // But we have handlers for such case and should not bother client about with it
        // And we are using DEBUG level here
        logger << log4cpp::Priority::DEBUG
               << "We skip one iteration of speed_calc because it runs so early! That's "
                  "really impossible! Please ask support.";
        logger << log4cpp::Priority::DEBUG << "Sleep time expected: " << recalculate_speed_timeout
               << ". Sleep time experienced: " << time_difference;
        return;
    } else if (int(time_difference) == int(speed_calc_period)) {
        // All fine, we run on time
    } else {
        // logger << log4cpp::Priority::INFO << "Time from last run of speed_recalc is soooo big, we got ugly lags: " <<
        // time_difference << " seconds";
        speed_calc_period = time_difference;
    }

    uint64_t incoming_total_flows = 0;
    uint64_t outgoing_total_flows = 0;

    ipv4_network_counters.recalculate_speed(speed_calc_period, (double)average_calculation_amount, nullptr);

    uint64_t flow_exists_for_ip         = 0;
    uint64_t flow_does_not_exist_for_ip = 0;

    ipv4_host_counters.recalculate_speed(speed_calc_period, (double)average_calculation_amount, speed_calculation_callback_local_ipv4, [&outgoing_total_flows, &incoming_total_flows, &flow_exists_for_ip,
     &flow_does_not_exist_for_ip](const uint32_t& ip, subnet_counter_t& new_speed_element, double speed_calc_period) {
        if (enable_connection_tracking) {
            bool res = increment_flow_counters(new_speed_element, fast_ntoh(ip), speed_calc_period);

            if (res) {
                // Increment global counter
                outgoing_total_flows += new_speed_element.out_flows;
                incoming_total_flows += new_speed_element.in_flows;

                flow_exists_for_ip++;

                // logger << log4cpp::Priority::DEBUG << convert_ipv4_subnet_to_string(subnet)
                //    << "in flows: " << new_speed_element.in_flows << " out flows: " <<
                //    new_speed_element.out_flows;
            } else {
                // We did not find record
                flow_does_not_exist_for_ip++;
            }
        }
    });

    // Calculate IPv6 per network traffic
    ipv6_subnet_counters.recalculate_speed(speed_calc_period, (double)average_calculation_amount, nullptr);

    // Recalculate traffic for hosts
    ipv6_host_counters.recalculate_speed(speed_calc_period, (double)average_calculation_amount, speed_calculation_callback_local_ipv6);

    if (enable_connection_tracking) {
        // Calculate global flow speed
        incoming_total_flows_speed = uint64_t((double)incoming_total_flows / (double)speed_calc_period);
        outgoing_total_flows_speed = uint64_t((double)outgoing_total_flows / (double)speed_calc_period);

        zeroify_all_flow_counters();
    }

    total_unparsed_packets_speed = uint64_t((double)total_unparsed_packets / (double)speed_calc_period);
    total_unparsed_packets       = 0;

    // Calculate IPv4 total traffic speed
    for (unsigned int index = 0; index < 4; index++) {
        total_counters_ipv4.total_speed_counters[index].bytes =
            uint64_t((double)total_counters_ipv4.total_counters[index].bytes / (double)speed_calc_period);

        total_counters_ipv4.total_speed_counters[index].packets =
            uint64_t((double)total_counters_ipv4.total_counters[index].packets / (double)speed_calc_period);

        double exp_power = -speed_calc_period / average_calculation_amount;
        double exp_value = exp(exp_power);

        total_counters_ipv4.total_speed_average_counters[index].bytes =
            uint64_t(total_counters_ipv4.total_speed_counters[index].bytes +
                     exp_value * ((double)total_counters_ipv4.total_speed_average_counters[index].bytes -
                                  (double)total_counters_ipv4.total_speed_counters[index].bytes));

        total_counters_ipv4.total_speed_average_counters[index].packets =
            uint64_t(total_counters_ipv4.total_speed_counters[index].packets +
                     exp_value * ((double)total_counters_ipv4.total_speed_average_counters[index].packets -
                                  (double)total_counters_ipv4.total_speed_counters[index].packets));

        // nullify data counters after speed calculation
        total_counters_ipv4.total_counters[index].bytes   = 0;
        total_counters_ipv4.total_counters[index].packets = 0;
    }

    // Do same for IPv6
    for (unsigned int index = 0; index < 4; index++) {
        total_counters_ipv6.total_speed_counters[index].bytes =
            uint64_t((double)total_counters_ipv6.total_counters[index].bytes / (double)speed_calc_period);
        total_counters_ipv6.total_speed_counters[index].packets =
            uint64_t((double)total_counters_ipv6.total_counters[index].packets / (double)speed_calc_period);

        double exp_power = -speed_calc_period / average_calculation_amount;
        double exp_value = exp(exp_power);

        total_counters_ipv6.total_speed_average_counters[index].bytes =
            uint64_t(total_counters_ipv6.total_speed_counters[index].bytes +
                     exp_value * ((double)total_counters_ipv6.total_speed_average_counters[index].bytes -
                                  (double)total_counters_ipv6.total_speed_counters[index].bytes));

        total_counters_ipv6.total_speed_average_counters[index].packets =
            uint64_t(total_counters_ipv6.total_speed_counters[index].packets +
                     exp_value * ((double)total_counters_ipv6.total_speed_average_counters[index].packets -
                                  (double)total_counters_ipv6.total_speed_counters[index].packets));

        // nullify data counters after speed calculation
        total_counters_ipv6.total_counters[index].zeroify();
    }

    // Set time of previous startup
    last_call_of_traffic_recalculation = std::chrono::steady_clock::now();

    // Calculate time we spent to calculate speed in this function
    std::chrono::duration<double> speed_calculation_diff = std::chrono::steady_clock::now() - start_time;

    // Populate fields of old structure for backward compatibility
    double integer = 0;

    // Split double into integer and fractional parts
    double fractional = std::modf(speed_calculation_diff.count(), &integer);

    speed_calculation_time.tv_sec  = time_t(integer);

    // timeval field tv_usec has type long on Windows
#ifdef _WIN32
    speed_calculation_time.tv_usec = long(fractional * 1000000);
#else
    speed_calculation_time.tv_usec = suseconds_t(fractional * 1000000);
#endif

    // Report cases when we calculate speed too slow
    if (speed_calculation_time.tv_sec > 0) {
        logger << log4cpp::Priority::ERROR << "ALERT. Toolkit working incorrectly. We should calculate speed counters in <1 second";
        logger << log4cpp::Priority::ERROR << "Traffic was calculated in: " << speed_calculation_time.tv_sec << " sec "
               << speed_calculation_time.tv_usec << " microseconds";

        logger << log4cpp::Priority::ERROR << "Please use CPU with higher frequency and better single core performance or reduce number of monitored hosts";
    }
}

std::string draw_table_ipv4_hash(attack_detection_direction_type_t sort_direction, attack_detection_threshold_type_t sorter_type) {
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;

    std::stringstream output_buffer;

    unsigned int shift_for_sort = max_ips_in_list;

    // Allocate vector with size which matches number of required elements
    std::vector<std::pair<uint32_t, subnet_counter_t>> vector_for_sort(shift_for_sort);

    ipv4_host_counters.get_top_k_average_speed(vector_for_sort, sorter_type, sort_direction);

    for (const auto& item: vector_for_sort) {
        // When we do not have enough hosts in output vector we will keep all entries nil, filter out them
        if (item.first == 0) {
            continue;
        }

        uint32_t client_ip              = item.first;
        std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

        uint64_t pps   = 0;
        uint64_t bps   = 0;
        uint64_t flows = 0;

        // Here we could have average or instantaneous speed
        const subnet_counter_t& current_speed_element = item.second;

        // Create polymorphic pps, byte and flow counters
        if (sort_direction == attack_detection_direction_type_t::incoming) {
            pps   = current_speed_element.total.in_packets;
            bps   = current_speed_element.total.in_bytes;
            flows = current_speed_element.in_flows;
        } else if (sort_direction == attack_detection_direction_type_t::outgoing) {
            pps   = current_speed_element.total.out_packets;
            bps   = current_speed_element.total.out_bytes;
            flows = current_speed_element.out_flows;
        }

        uint64_t mbps = convert_speed_to_mbps(bps);

        // We use setw for alignment
        output_buffer << client_ip_as_string << "\t\t";

        std::string is_banned = ban_list_ipv4.is_blackholed(client_ip) ? " *banned* " : "";

        output_buffer << std::setw(6) << pps << " pps ";
        output_buffer << std::setw(6) << mbps << " mbps ";
        output_buffer << std::setw(6) << flows << " flows ";

        output_buffer << is_banned << std::endl;
    }

    return output_buffer.str();
}


std::string draw_table_ipv6(attack_detection_direction_type_t sort_direction, attack_detection_threshold_type_t sorter_type) {
    std::vector<pair_of_map_for_ipv6_subnet_counters_elements_t> vector_for_sort;
    ssize_t size_of_ipv6_counters_map = 0;
    std::stringstream output_buffer;

    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

    // TODO: implement method for such tasks
    {
        std::lock_guard<std::mutex> lock_guard(ipv6_host_counters.counter_map_mutex);
        size_of_ipv6_counters_map = ipv6_host_counters.average_speed_map.size();
    }

    logger << log4cpp::Priority::DEBUG << "We create sort buffer with " << size_of_ipv6_counters_map << " elements";

    vector_for_sort.reserve(size_of_ipv6_counters_map);

    for (const auto& metric_pair : ipv6_host_counters.average_speed_map) {
        vector_for_sort.push_back(metric_pair);
    }

    // If we have so small number of elements reduce list length
    unsigned int vector_size = vector_for_sort.size();

    unsigned int shift_for_sort = max_ips_in_list;

    if (vector_size < shift_for_sort) {
        shift_for_sort = vector_size;
    }

    logger << log4cpp::Priority::DEBUG << "Start vector sort";

    std::partial_sort(vector_for_sort.begin(), vector_for_sort.begin() + shift_for_sort, vector_for_sort.end(),
                      TrafficComparatorClass<pair_of_map_for_ipv6_subnet_counters_elements_t>(sort_direction, sorter_type));

    logger << log4cpp::Priority::DEBUG << "Finished vector sort";

    unsigned int element_number = 0;

    // In this loop we print only top X talkers in our subnet to screen buffer
    for (std::vector<pair_of_map_for_ipv6_subnet_counters_elements_t>::iterator ii = vector_for_sort.begin();
         ii != vector_for_sort.end(); ++ii) {

        // Print first max_ips_in_list elements in list, we will show top X "huge"
        // channel loaders
        if (element_number >= shift_for_sort) {
            break;
        }

        element_number++;


        std::string client_ip_as_string;

        if (ii->first.cidr_prefix_length == 128) {
            // For host addresses we do not need prefix
            client_ip_as_string = print_ipv6_address(ii->first.subnet_address);
        } else {
            client_ip_as_string = print_ipv6_cidr_subnet(ii->first);
        }

        uint64_t pps   = 0;
        uint64_t bps   = 0;
        uint64_t flows = 0;

        // Here we could have average or instantaneous speed
        subnet_counter_t* current_speed_element = &ii->second;

        // Create polymorphic pps, byte and flow counters
        if (sort_direction == attack_detection_direction_type_t::incoming) {
            pps   = current_speed_element->total.in_packets;
            bps   = current_speed_element->total.in_bytes;
            flows = current_speed_element->in_flows;
        } else if (sort_direction == attack_detection_direction_type_t::outgoing) {
            pps   = current_speed_element->total.out_packets;
            bps   = current_speed_element->total.out_bytes;
            flows = current_speed_element->out_flows;
        }

        uint64_t mbps = convert_speed_to_mbps(bps);

        // We use setw for alignment
        output_buffer << client_ip_as_string << "\t";

        std::string is_banned = ban_list_ipv6.is_blackholed(ii->first) ? " *banned* " : "";

        output_buffer << std::setw(6) << pps << " pps ";
        output_buffer << std::setw(6) << mbps << " mbps ";
        output_buffer << std::setw(6) << flows << " flows ";

        output_buffer << is_banned << std::endl;
    }

    return output_buffer.str();
}

void print_screen_contents_into_file(std::string screen_data_stats_param, std::string file_path) {
    std::ofstream screen_data_file;
    screen_data_file.open(file_path.c_str(), std::ios::trunc);

    if (screen_data_file.is_open()) {
        // Set 660 permissions to file for security reasons
        chmod(cli_stats_file_path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

        screen_data_file << screen_data_stats_param;
        screen_data_file.close();
    } else {
        logger << log4cpp::Priority::ERROR << "Can't print program screen into file: " << file_path;
    }
}

void zeroify_all_flow_counters() {
    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
    extern std::mutex flow_counter_mutex;

    std::lock_guard<std::mutex> lock_guard(flow_counter_mutex);

    SubnetVectorMapFlow.clear();
}


#ifdef KAFKA
// Exports traffic to Kafka
void export_to_kafka(const simple_packet_t& current_packet) {
    extern std::string kafka_traffic_export_topic;
    extern cppkafka::Producer* kafka_traffic_export_producer;
    extern kafka_traffic_export_format_t kafka_traffic_export_format;

    if (kafka_traffic_export_format == kafka_traffic_export_format_t::JSON) {

        nlohmann::json json_packet;

        if (!serialize_simple_packet_to_json(current_packet, json_packet)) {
            return;
        }

        std::string simple_packet_as_json_string = json_packet.dump();

        try {
            kafka_traffic_export_producer->produce(
                cppkafka::MessageBuilder(kafka_traffic_export_topic).partition(RD_KAFKA_PARTITION_UA).payload(simple_packet_as_json_string));
        } catch (...) {
            // We do not log it as it will flood log files
            // logger << log4cpp::Priority::ERROR << "Kafka write failed";
        }
    } else if (kafka_traffic_export_format == kafka_traffic_export_format_t::Protobuf) {
        TrafficData traffic_data;

        // Encode Packet in protobuf
        write_simple_packet_to_protobuf(current_packet, traffic_data);

        std::string output_data;

        if (!traffic_data.SerializeToString(&output_data)) {
            // Encoding error happened
            return;
        }

        try {
            kafka_traffic_export_producer->produce(
                cppkafka::MessageBuilder(kafka_traffic_export_topic).partition(RD_KAFKA_PARTITION_UA).payload(output_data));
        } catch (...) {
            // We do not log it as it will flood log files
            // logger << log4cpp::Priority::ERROR << "Kafka write failed";
        }
    } else {
        // Unknown format
        return;
    }

    try {
        kafka_traffic_export_producer->flush();
    } catch (...) {
        // We do not log it as it will flood log files
        // logger << log4cpp::Priority::ERROR << "Kafka flush failed";
    }
}
#endif

// Adds traffic to buckets from hot path
template <typename T>
void collect_traffic_to_buckets_ipv6(const simple_packet_t& current_packet, packet_buckets_storage_t<T>& packet_buckets_storage) {
    // Yes, it's not very optimal to construct subnet_ipv6_cidr_mask_t again but it offers way clearer logic
    // In future we should get rid of subnet_ipv6_cidr_mask_t and use subnet_address directly
    //
    if (current_packet.packet_direction == OUTGOING) {
        subnet_ipv6_cidr_mask_t ipv6_address;
        ipv6_address.set_cidr_prefix_length(128);
        ipv6_address.set_subnet_address(&current_packet.src_ipv6);

        packet_buckets_storage.add_packet_to_storage(ipv6_address, current_packet);
    } else if (current_packet.packet_direction == INCOMING) {
        subnet_ipv6_cidr_mask_t ipv6_address;
        ipv6_address.set_cidr_prefix_length(128);
        ipv6_address.set_subnet_address(&current_packet.dst_ipv6);

        packet_buckets_storage.add_packet_to_storage(ipv6_address, current_packet);
    }
}

// Process IPv6 traffic
void process_ipv6_packet(simple_packet_t& current_packet) {
    uint64_t sampled_number_of_packets = current_packet.number_of_packets * current_packet.sample_ratio;
    uint64_t sampled_number_of_bytes   = current_packet.length * current_packet.sample_ratio;

#ifdef KAFKA
    extern bool kafka_traffic_export;
#endif

    subnet_ipv6_cidr_mask_t ipv6_cidr_subnet;

    current_packet.packet_direction =
        get_packet_direction_ipv6(lookup_tree_ipv6, current_packet.src_ipv6, current_packet.dst_ipv6, ipv6_cidr_subnet);

#ifdef KAFKA
    if (kafka_traffic_export) {
        export_to_kafka(current_packet);
    }
#endif

    // Skip processing of specific traffic direction
    if ((current_packet.packet_direction == INCOMING && !process_incoming_traffic) or
        (current_packet.packet_direction == OUTGOING && !process_outgoing_traffic)) {
        return;
    }

#ifdef USE_NEW_ATOMIC_BUILTINS
    __atomic_add_fetch(&total_counters_ipv6.total_counters[current_packet.packet_direction].packets,
                       sampled_number_of_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&total_counters_ipv6.total_counters[current_packet.packet_direction].bytes,
                       sampled_number_of_bytes, __ATOMIC_RELAXED);

    __atomic_add_fetch(&total_ipv6_packets, 1, __ATOMIC_RELAXED);
#else
    __sync_fetch_and_add(&total_counters_ipv6.total_counters[current_packet.packet_direction].packets, sampled_number_of_packets);
    __sync_fetch_and_add(&total_counters_ipv6.total_counters[current_packet.packet_direction].bytes, sampled_number_of_bytes);

    __sync_fetch_and_add(&total_ipv6_packets, 1);
#endif

    {
        std::lock_guard<std::mutex> lock_guard(ipv6_subnet_counters.counter_map_mutex);

        // We will create keys for new subnet here on demand
        subnet_counter_t* counter_ptr = &ipv6_subnet_counters.counter_map[ipv6_cidr_subnet];

        if (current_packet.packet_direction == OUTGOING) {
            counter_ptr->total.out_packets += sampled_number_of_packets;
            counter_ptr->total.out_bytes += sampled_number_of_bytes;
        } else if (current_packet.packet_direction == INCOMING) {
            counter_ptr->total.in_packets += sampled_number_of_packets;
            counter_ptr->total.in_bytes += sampled_number_of_bytes;
        }
    }

    // Here I use counters allocated per /128. In some future we could offer option to count them in diffenrent way
    // (/64, /96)
    {
        if (current_packet.packet_direction == OUTGOING) {
            subnet_ipv6_cidr_mask_t ipv6_address;
            ipv6_address.set_cidr_prefix_length(128);
            ipv6_address.set_subnet_address(&current_packet.src_ipv6);

            ipv6_host_counters.increment_outgoing_counters_for_key(ipv6_address, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
        } else if (current_packet.packet_direction == INCOMING) {
            subnet_ipv6_cidr_mask_t ipv6_address;
            ipv6_address.set_cidr_prefix_length(128);
            ipv6_address.set_subnet_address(&current_packet.dst_ipv6);

            ipv6_host_counters.increment_incoming_counters_for_key(ipv6_address, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
        }

        // Collect packets for DDoS analytics engine
        collect_traffic_to_buckets_ipv6(current_packet, packet_buckets_ipv6_storage);
    }

    return;
}

// Adds traffic to buckets from hot path
template <typename T>
void collect_traffic_to_buckets_ipv4(const simple_packet_t& current_packet, packet_buckets_storage_t<T>& packet_buckets_storage) {
    if (current_packet.packet_direction == OUTGOING) {
        // With this code we will add parsed packets and their raw versions (if we have they) to circular buffer to
        // we are interested about they
        packet_buckets_storage.add_packet_to_storage(current_packet.src_ip, current_packet);
    } else if (current_packet.packet_direction == INCOMING) {
        // With this code we will add parsed packets and their raw versions (if we have they) to circular buffer to
        // we are interested about they
        packet_buckets_storage.add_packet_to_storage(current_packet.dst_ip, current_packet);
    }
}


// Process simple unified packet
void process_packet(simple_packet_t& current_packet) {
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern packet_buckets_storage_t<uint32_t> packet_buckets_ipv4_storage;

    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;

#ifdef KAFKA
    extern bool kafka_traffic_export;
#endif

    // Packets dump is very useful for bug hunting
    if (DEBUG_DUMP_ALL_PACKETS) {
        logger << log4cpp::Priority::INFO << "Dump: " << print_simple_packet(current_packet);
    }

    // Increment counter about total number of packets processes here
#ifdef USE_NEW_ATOMIC_BUILTINS
    __atomic_add_fetch(&total_simple_packets_processed, 1, __ATOMIC_RELAXED);

    if (current_packet.ip_protocol_version == 4) {
        __atomic_add_fetch(&total_ipv4_packets, 1, __ATOMIC_RELAXED);
    } else if (current_packet.ip_protocol_version == 6) {
        __atomic_add_fetch(&total_ipv6_packets, 1, __ATOMIC_RELAXED);
    } else {
        // Non IPv4 and non IPv6 packets
        __atomic_add_fetch(&unknown_ip_version_packets, 1, __ATOMIC_RELAXED);
        return;
    }
#else
    __sync_fetch_and_add(&total_simple_packets_processed, 1);

    if (current_packet.ip_protocol_version == 4) {
        __sync_fetch_and_add(&total_ipv4_packets, 1);
    } else if (current_packet.ip_protocol_version == 6) {
        __sync_fetch_and_add(&total_ipv6_packets, 1);
    } else {
        // Non IPv4 and non IPv6 packets
        __atomic_add_fetch(&unknown_ip_version_packets, 1, __ATOMIC_RELAXED);
        return;
    }
#endif

    // Process IPv6 traffic in differnt function
    if (current_packet.ip_protocol_version == 6) {
        return process_ipv6_packet(current_packet);
    }

    uint64_t sampled_number_of_packets = current_packet.number_of_packets * current_packet.sample_ratio;
    uint64_t sampled_number_of_bytes   = current_packet.length * current_packet.sample_ratio;

    if (current_packet.ip_protocol_version != 4) {
        return;
    }

    // Subnet for found IPs
    subnet_cidr_mask_t current_subnet;

    current_packet.packet_direction =
        get_packet_direction(lookup_tree_ipv4, current_packet.src_ip, current_packet.dst_ip, current_subnet);

#ifdef KAFKA
    if (kafka_traffic_export) {
        export_to_kafka(current_packet);
    }
#endif

    // It's useful in case when we can't find what packets do not processed correctly
    if (DEBUG_DUMP_OTHER_PACKETS && current_packet.packet_direction == OTHER) {
        logger << log4cpp::Priority::INFO << "Dump other: " << print_simple_packet(current_packet);
    }

    // Skip processing of specific traffic direction
    if ((current_packet.packet_direction == INCOMING && !process_incoming_traffic) or
        (current_packet.packet_direction == OUTGOING && !process_outgoing_traffic)) {
        return;
    }

    if (current_packet.packet_direction == OUTGOING or current_packet.packet_direction == INCOMING) {
        std::lock_guard<std::mutex> lock_guard(ipv4_network_counters.counter_map_mutex);

        // We will create keys for new subnet here on demand
        subnet_counter_t& counters = ipv4_network_counters.counter_map[current_subnet];

        if (current_packet.packet_direction == OUTGOING) {
            increment_outgoing_counters(counters, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
        } else if (current_packet.packet_direction == INCOMING) {
            increment_incoming_counters(counters, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
        }
    }

    /* Because we support mirroring, sflow and netflow we should support different cases:
        - One packet passed for processing (mirror)
        - Multiple packets ("flows") passed for processing (netflow)
        - One sampled packed passed for processing (netflow)
        - Another combinations of this three options
    */

#ifdef USE_NEW_ATOMIC_BUILTINS
    __atomic_add_fetch(&total_counters_ipv4.total_counters[current_packet.packet_direction].packets,
                       sampled_number_of_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&total_counters_ipv4.total_counters[current_packet.packet_direction].bytes,
                       sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
    __sync_fetch_and_add(&total_counters_ipv4.total_counters[current_packet.packet_direction].packets, sampled_number_of_packets);
    __sync_fetch_and_add(&total_counters_ipv4.total_counters[current_packet.packet_direction].bytes, sampled_number_of_bytes);
#endif

    // Add traffic to buckets when we have them
    collect_traffic_to_buckets_ipv4(current_packet, packet_buckets_ipv4_storage);

    // Increment counters for all local hosts using new counters
    if (current_packet.packet_direction == OUTGOING) {
        ipv4_host_counters.increment_outgoing_counters_for_key(current_packet.src_ip, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
    } else if (current_packet.packet_direction == INCOMING) {
        ipv4_host_counters.increment_incoming_counters_for_key(current_packet.dst_ip, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
    } else {
        // No reasons to keep locks for other or internal
    }

    // Increment main and per protocol packet counters
    if (current_packet.packet_direction == OUTGOING) {
        if (enable_connection_tracking) {
            increment_outgoing_flow_counters(fast_ntoh(current_packet.src_ip), current_packet,
                                             sampled_number_of_packets, sampled_number_of_bytes);
        }
    } else if (current_packet.packet_direction == INCOMING) {
        if (enable_connection_tracking) {
            increment_incoming_flow_counters(fast_ntoh(current_packet.dst_ip), current_packet,
                                 sampled_number_of_packets, sampled_number_of_bytes);
        }
    } else if (current_packet.packet_direction == INTERNAL) {
    }
}

void system_counters_speed_thread_handler() {
    while (true) {
        auto netflow_ipfix_all_protocols_total_flows_previous = netflow_ipfix_all_protocols_total_flows;
        auto sflow_raw_packet_headers_total_previous          = sflow_raw_packet_headers_total;

        // We recalculate it each second to avoid confusion
        boost::this_thread::sleep(boost::posix_time::seconds(1));

        netflow_ipfix_all_protocols_total_flows_speed =
            int64_t((float)netflow_ipfix_all_protocols_total_flows - (float)netflow_ipfix_all_protocols_total_flows_previous);

        sflow_raw_packet_headers_total_speed =
            int64_t((float)sflow_raw_packet_headers_total - (float)sflow_raw_packet_headers_total_previous);
    }
}

// Generates inaccurate time for fast time operations
void inaccurate_time_generator() {
    extern time_t current_inaccurate_time;

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(1));

        // We use this thread to update time each second
        time_t current_time = 0;
        time(&current_time);

        // Update global time, yes, it may became inaccurate due to thread sync but that's OK for our purposes
        current_inaccurate_time = current_time;
    }
}

// Creates compressed flow tracking structure
void init_incoming_flow_counting_structure(packed_conntrack_hash_t& flow_tracking_structure, const simple_packet_t& current_packet) {
    flow_tracking_structure.opposite_ip = current_packet.src_ip;
    flow_tracking_structure.src_port    = current_packet.source_port;
    flow_tracking_structure.dst_port    = current_packet.destination_port;
}

// client_ip is expected in host byte order
// client_ip in host byte order!
void increment_incoming_flow_counters(uint32_t client_ip,
                                      const simple_packet_t& current_packet,
                                      uint64_t sampled_number_of_packets,
                                      uint64_t sampled_number_of_bytes) {
    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
    extern std::mutex flow_counter_mutex;

    packed_conntrack_hash_t flow_tracking_structure;
    init_incoming_flow_counting_structure(flow_tracking_structure, current_packet);

    // convert this struct to 64 bit integer
    uint64_t connection_tracking_hash = convert_conntrack_hash_struct_to_integer(flow_tracking_structure);


    // logger << log4cpp::Priority::ERROR << "incoming flow: " << convert_ip_as_uint_to_string(client_ip)
    //    << " packets " << sampled_number_of_packets << " bytes " << sampled_number_of_bytes << " hash " << connection_tracking_hash;

    {
        std::lock_guard<std::mutex> lock_guard(flow_counter_mutex);
        conntrack_main_struct_t& current_element_flow = SubnetVectorMapFlow[client_ip];

        if (current_packet.protocol == IPPROTO_TCP) {
            conntrack_key_struct_t& conntrack_key_struct = current_element_flow.in_tcp[connection_tracking_hash];

            conntrack_key_struct.packets += sampled_number_of_packets;
            conntrack_key_struct.bytes += sampled_number_of_bytes;
        } else if (current_packet.protocol == IPPROTO_UDP) {
            conntrack_key_struct_t& conntrack_key_struct = current_element_flow.in_udp[connection_tracking_hash];

            conntrack_key_struct.packets += sampled_number_of_packets;
            conntrack_key_struct.bytes += sampled_number_of_bytes;
        }
    }
}


// Creates compressed flow tracking structure
void init_outgoing_flow_counting_structure(packed_conntrack_hash_t& flow_tracking_structure, const simple_packet_t& current_packet) {
    flow_tracking_structure.opposite_ip = current_packet.dst_ip;
    flow_tracking_structure.src_port    = current_packet.source_port;
    flow_tracking_structure.dst_port    = current_packet.destination_port;
}

// Increment all flow counters using specified packet
// increment_outgoing_flow_counters
// client_ip in host byte order!
void increment_outgoing_flow_counters(uint32_t client_ip,
                                      const simple_packet_t& current_packet,
                                      uint64_t sampled_number_of_packets,
                                      uint64_t sampled_number_of_bytes) {
    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
    extern std::mutex flow_counter_mutex;

    packed_conntrack_hash_t flow_tracking_structure;
    init_outgoing_flow_counting_structure(flow_tracking_structure, current_packet);

    // convert this struct to 64 bit integer
    uint64_t connection_tracking_hash = convert_conntrack_hash_struct_to_integer(flow_tracking_structure);


    // logger << log4cpp::Priority::ERROR << "outgoing flow: " << convert_ip_as_uint_to_string(client_ip)
    //    << " packets " << sampled_number_of_packets << " bytes " << sampled_number_of_bytes << " hash " << connection_tracking_hash;

    {
        std::lock_guard<std::mutex> lock_guard(flow_counter_mutex);

        conntrack_main_struct_t& current_element_flow = SubnetVectorMapFlow[client_ip];

        if (current_packet.protocol == IPPROTO_TCP) {
            conntrack_key_struct_t& conntrack_key_struct = current_element_flow.out_tcp[connection_tracking_hash];

            conntrack_key_struct.packets += sampled_number_of_packets;
            conntrack_key_struct.bytes += sampled_number_of_bytes;
        } else if (current_packet.protocol == IPPROTO_UDP) {
            conntrack_key_struct_t& conntrack_key_struct = current_element_flow.out_udp[connection_tracking_hash];

            conntrack_key_struct.packets += sampled_number_of_packets;
            conntrack_key_struct.bytes += sampled_number_of_bytes;
        }
    }
}


// pretty print channel speed in pps and MBit
std::string print_channel_speed_ipv6(std::string traffic_type, direction_t packet_direction) {
    uint64_t speed_in_pps = total_counters_ipv6.total_speed_average_counters[packet_direction].packets;
    uint64_t speed_in_bps = total_counters_ipv6.total_speed_average_counters[packet_direction].bytes;

    unsigned int number_of_tabs = 3;

    // We need this for correct alignment of blocks
    if (traffic_type == "Other traffic") {
        number_of_tabs = 4;
    }

    std::stringstream stream;
    stream << traffic_type;

    for (unsigned int i = 0; i < number_of_tabs; i++) {
        stream << "\t";
    }

    uint64_t speed_in_mbps = convert_speed_to_mbps(speed_in_bps);

    stream << std::setw(6) << speed_in_pps << " pps " << std::setw(6) << speed_in_mbps << " mbps";

    // Flows are not supported yet

    return stream.str();
}

template <typename TemplateKeyType>
void remove_orphaned_buckets(packet_buckets_storage_t<TemplateKeyType>& packet_storage, std::string protocol) {
    std::lock_guard<std::mutex> lock_guard(packet_storage.packet_buckets_map_mutex);

    // List of buckets to remove
    std::vector<TemplateKeyType> buckets_to_remove;

    // logger << log4cpp::Priority::DEBUG << "We've got " << packet_storage->packet_buckets_map.size() << " packets buckets for processing";

    // Find buckets for removal
    // We should not remove them here because it's tricky to do properly in C++
    for (auto it = packet_storage.packet_buckets_map.begin(); it != packet_storage.packet_buckets_map.end(); ++it) {
        if (should_remove_orphaned_bucket<TemplateKeyType>(*it)) {
            logger << log4cpp::Priority::DEBUG << "We decided to remove " << protocol << " bucket "
                   << convert_any_ip_to_string(it->first);
            buckets_to_remove.push_back(it->first);
        }
    }

    // logger << log4cpp::Priority::DEBUG << "We have " << buckets_to_remove.size() << " " << protocol << " orphaned buckets for cleanup";


    for (auto client_ip : buckets_to_remove) {
        // Let's dump some data from it
        packet_bucket_t& bucket = packet_storage.packet_buckets_map[client_ip];

        logger << log4cpp::Priority::WARN << "We've found orphaned bucket for IP: " << convert_any_ip_to_string(client_ip)
               << " it has " << bucket.parsed_packets_circular_buffer.size() << " parsed packets"
               << " and " << bucket.raw_packets_circular_buffer.size() << " raw packets"
               << " we will remove it";

        // Stop packet collection ASAP
        bucket.we_could_receive_new_data = false;

        // Remove it completely from map
        packet_storage.packet_buckets_map.erase(client_ip);
    }

    return;
}

std::string get_attack_description_ipv6(subnet_ipv6_cidr_mask_t ipv6_address, const attack_details_t& current_attack) {
    std::stringstream attack_description;

    attack_description << "IP: " << print_ipv6_address(ipv6_address.subnet_address) << "\n";
    attack_description << serialize_attack_description(current_attack) << "\n";

    return attack_description.str();
}

void execute_ipv6_ban(subnet_ipv6_cidr_mask_t ipv6_client,
                      const attack_details_t& current_attack,
                      const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
                      const boost::circular_buffer<fixed_size_packet_storage_t>& raw_packets_buffer) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;

    // Execute ban actions
    ban_list_ipv6.add_to_blackhole(ipv6_client, current_attack);

    logger << log4cpp::Priority::INFO << "IPv6 address " << print_ipv6_cidr_subnet(ipv6_client) << " was banned";

    uint32_t zero_ipv4_address = 0;
    call_blackhole_actions_per_host(attack_action_t::ban, zero_ipv4_address, ipv6_client, true, current_attack, attack_detection_source_t::Automatic, "", simple_packets_buffer, raw_packets_buffer);
}

void execute_ipv4_ban(uint32_t client_ip,
                    const attack_details_t& current_attack,
                    const std::string& flow_attack_details,
                    const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
                    const boost::circular_buffer<fixed_size_packet_storage_t>& raw_packets_buffer) {
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;

    // Execute ban actions
    ban_list_ipv4.add_to_blackhole(client_ip, current_attack);

    subnet_ipv6_cidr_mask_t zero_ipv6_address;

    call_blackhole_actions_per_host(attack_action_t::ban, client_ip, zero_ipv6_address, false, current_attack,
                                    attack_detection_source_t::Automatic, flow_attack_details, simple_packets_buffer,
                                    raw_packets_buffer);
}


// With this function we could get any element from our flow counter structure
bool get_element_from_map_of_flow_counters(map_of_vector_counters_for_flow_t& map_of_counters,
                                           uint32_t client_ip,
                                           conntrack_main_struct_t& current_conntrack_structure) {
    extern std::mutex flow_counter_mutex;

    std::lock_guard<std::mutex> lock_guard(flow_counter_mutex);
    current_conntrack_structure = map_of_counters[client_ip];

    return true;
}

void process_filled_buckets_ipv4() {
    extern packet_buckets_storage_t<uint32_t> packet_buckets_ipv4_storage;
    extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;

    std::vector<uint32_t> filled_buckets;

    // TODO: amount of processing we do under lock is absolutely insane
    // We need to rework it
    std::lock_guard<std::mutex> lock_guard(packet_buckets_ipv4_storage.packet_buckets_map_mutex);

    for (auto itr = packet_buckets_ipv4_storage.packet_buckets_map.begin();
         itr != packet_buckets_ipv4_storage.packet_buckets_map.end(); ++itr) {
        // Find one time capture requests which filled completely
        if (itr->second.collection_pattern == collection_pattern_t::ONCE &&
            itr->second.we_collected_full_buffer_least_once && !itr->second.is_already_processed) {

            logger << log4cpp::Priority::DEBUG << "Found filled bucket for IPv4 " << convert_any_ip_to_string(itr->first);

            filled_buckets.push_back(itr->first);
        }
    }

    // logger << log4cpp::Priority::DEBUG << "We have " << filled_buckets.size() << " filled buckets to process";

    for (auto client_ip_as_integer : filled_buckets) {
        std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip_as_integer);

        packet_bucket_t& bucket = packet_buckets_ipv4_storage.packet_buckets_map[client_ip_as_integer];

        // We found something, let's do processing
        logger << log4cpp::Priority::INFO << "We've got new completely filled bucket with packets for IP " << client_ip_as_string;

        std::string flow_attack_details = "";
        
        if (enable_connection_tracking) {
            conntrack_main_struct_t current_conntrack_main_struct;

            bool get_flow_result = get_element_from_map_of_flow_counters(SubnetVectorMapFlow, fast_ntoh(client_ip_as_integer),
                                                                         current_conntrack_main_struct);

            if (get_flow_result) {
                flow_attack_details = print_flow_tracking_for_ip(current_conntrack_main_struct, client_ip_as_string);
            } else {
                logger << log4cpp::Priority::WARN << "Could not get flow structure address";
            }
        }

       // Here I extract attack details saved at time when we crossed threshold
        attack_details_t current_attack = bucket.attack_details;
        
        // If we have no flow spec just do blackhole
        execute_ipv4_ban(client_ip_as_integer, current_attack, flow_attack_details,
                           bucket.parsed_packets_circular_buffer, bucket.raw_packets_circular_buffer);


        // Mark it as processed. This will hide it from second call of same function
        bucket.is_already_processed = true;

        // Stop packet collection ASAP
        bucket.we_could_receive_new_data = false;

        // Remove it completely from map
        packet_buckets_ipv4_storage.packet_buckets_map.erase(client_ip_as_integer);
    }
}


void process_filled_buckets_ipv6() {
    std::lock_guard<std::mutex> lock_guard(packet_buckets_ipv6_storage.packet_buckets_map_mutex);

    std::vector<subnet_ipv6_cidr_mask_t> filled_buckets;

    for (auto itr = packet_buckets_ipv6_storage.packet_buckets_map.begin();
         itr != packet_buckets_ipv6_storage.packet_buckets_map.end(); ++itr) {

        // Find one time capture requests which filled completely
        if (itr->second.collection_pattern == collection_pattern_t::ONCE &&
            itr->second.we_collected_full_buffer_least_once && !itr->second.is_already_processed) {

            logger << log4cpp::Priority::DEBUG << "We have filled buckets for " << convert_any_ip_to_string(itr->first);
            filled_buckets.push_back(itr->first);
        }
    }

    // logger << log4cpp::Priority::DEBUG << "We have " << filled_buckets.size() << " filled buckets";

    for (auto ipv6_address : filled_buckets) {
        logger << log4cpp::Priority::INFO << "We've got new completely filled bucket with packets for IPv6 "
               << print_ipv6_cidr_subnet(ipv6_address);

        packet_bucket_t* bucket = &packet_buckets_ipv6_storage.packet_buckets_map[ipv6_address];

        // Here I extract attack details saved at time when we crossed threshold
        attack_details_t current_attack = bucket->attack_details;

        std::string basic_attack_information = get_attack_description_ipv6(ipv6_address, current_attack);

        // For IPv6 we support only blackhole at this moment. BGP Flow spec for IPv6 isn't so popular and we will skip implementation for some future
        execute_ipv6_ban(ipv6_address, current_attack, bucket->parsed_packets_circular_buffer, bucket->raw_packets_circular_buffer);

        // Mark it as processed. This will hide it from second call of same function
        bucket->is_already_processed = true;

        // Stop packet collection ASAP
        bucket->we_could_receive_new_data = false;

        // Remove it completely from map
        packet_buckets_ipv6_storage.packet_buckets_map.erase(ipv6_address);
    }
}


// This functions will check for packet buckets availible for processing
void check_traffic_buckets() {
    extern packet_buckets_storage_t<uint32_t> packet_buckets_ipv4_storage;

    while (true) {
        remove_orphaned_buckets(packet_buckets_ipv4_storage, "ipv4");

        // Process buckets which haven't filled by packets
        remove_orphaned_buckets(packet_buckets_ipv6_storage, "ipv6");

        process_filled_buckets_ipv4();

        process_filled_buckets_ipv6();

        boost::this_thread::sleep(boost::posix_time::seconds(check_for_availible_for_processing_packets_buckets));
    }
}

// We use this function as callback for find_if to clean up orphaned buckets
template <typename TemplatedKeyType>
bool should_remove_orphaned_bucket(const std::pair<TemplatedKeyType, packet_bucket_t>& pair) {
    logger << log4cpp::Priority::DEBUG << "Process bucket for " << convert_any_ip_to_string(pair.first);

    // We process only "once" buckets
    if (pair.second.collection_pattern != collection_pattern_t::ONCE) {
        logger << log4cpp::Priority::DEBUG << "We do not cleanup buckets with non-once collection pattern "
               << convert_any_ip_to_string(pair.first);
        return false;
    }

    std::chrono::duration<double> elapsed_from_start_seconds = std::chrono::system_clock::now() - pair.second.collection_start_time;

    // We do cleanup for them in another function
    if (pair.second.we_collected_full_buffer_least_once) {
        logger << log4cpp::Priority::DEBUG << "We do not cleanup finished bucket for "
               << convert_any_ip_to_string(pair.first) << " it's " << elapsed_from_start_seconds.count() << " seconds old";
        return false;
    }

    logger << log4cpp::Priority::DEBUG << "Bucket is " << elapsed_from_start_seconds.count() << " seconds old for "
           << convert_any_ip_to_string(pair.first) << " and has " << pair.second.parsed_packets_circular_buffer.size()
           << " parsed packets and " << pair.second.raw_packets_circular_buffer.size() << " raw packets";

    if (elapsed_from_start_seconds.count() > maximum_time_since_bucket_start_to_remove) {
        logger << log4cpp::Priority::DEBUG << "We're going to remove bucket for "
               << convert_any_ip_to_string(pair.first) << " because it's too old";
        return true;
    }

    return false;
}

bool get_statistics(std::vector<system_counter_t>& system_counters) {
    extern std::string total_simple_packets_processed_desc;
    extern std::string total_ipv6_packets_desc;
    extern std::string total_ipv4_packets_desc;
    extern std::string unknown_ip_version_packets_desc;
    extern std::string total_unparsed_packets_desc;
    extern std::string total_unparsed_packets_speed_desc;
    extern std::string speed_calculation_time_desc;
    extern std::string total_number_of_hosts_in_our_networks_desc;
    extern std::string influxdb_writes_total_desc;
    extern std::string influxdb_writes_failed_desc;

    system_counters.push_back(system_counter_t("total_simple_packets_processed", total_simple_packets_processed,
                                               metric_type_t::counter, total_simple_packets_processed_desc));

    system_counters.push_back(system_counter_t("total_ipv4_packets", total_ipv4_packets, metric_type_t::counter, total_ipv4_packets_desc));
    system_counters.push_back(system_counter_t("total_ipv6_packets", total_ipv6_packets, metric_type_t::counter, total_ipv6_packets_desc));
    system_counters.push_back(system_counter_t("unknown_ip_version_packets", unknown_ip_version_packets,
                                               metric_type_t::counter, unknown_ip_version_packets_desc));

    system_counters.push_back(system_counter_t("total_unparsed_packets", total_unparsed_packets, metric_type_t::counter,
                                               total_unparsed_packets_desc));
    system_counters.push_back(system_counter_t("total_unparsed_packets_speed", total_unparsed_packets_speed,
                                               metric_type_t::gauge, total_unparsed_packets_speed_desc));


    system_counters.push_back(system_counter_t("speed_recalculation_time_seconds", speed_calculation_time.tv_sec,
                                               metric_type_t::gauge, speed_calculation_time_desc));
    system_counters.push_back(system_counter_t("speed_recalculation_time_microseconds", speed_calculation_time.tv_usec,
                                               metric_type_t::gauge, speed_calculation_time_desc));


    system_counters.push_back(system_counter_t("total_number_of_hosts", total_number_of_hosts_in_our_networks,
                                               metric_type_t::gauge, total_number_of_hosts_in_our_networks_desc));

    system_counters.push_back(system_counter_t("influxdb_writes_total", influxdb_writes_total, metric_type_t::counter,
                                               influxdb_writes_total_desc));
    system_counters.push_back(system_counter_t("influxdb_writes_failed", influxdb_writes_failed, metric_type_t::counter,
                                               influxdb_writes_failed_desc));

    if (enable_sflow_collection) {
        auto sflow_stats = get_sflow_stats();
        system_counters.insert(system_counters.end(), sflow_stats.begin(), sflow_stats.end());
    }

    if (enable_netflow_collection) {
        auto netflow_stats = get_netflow_stats();

        system_counters.insert(system_counters.end(), netflow_stats.begin(), netflow_stats.end());
    }

#ifdef FASTNETMON_ENABLE_AFPACKET
    if (enable_afpacket_collection) {
        auto af_packet_counters = get_af_packet_stats();

        system_counters.insert(system_counters.end(), af_packet_counters.begin(), af_packet_counters.end());
    }
#endif

    return true;
}

// Generates human readable comma separated list of enabled traffic capture plugins
std::vector<std::string> generate_list_of_enabled_capture_engines() {
    std::vector<std::string> list;

    if (configuration_map.count("sflow") != 0 && configuration_map["sflow"] == "on") {
        list.push_back("sflow");
    }

    if (configuration_map.count("netflow") != 0 && configuration_map["netflow"] == "on") {
        list.push_back("netflow");
    }

    if (configuration_map.count("mirror_afpacket") != 0 && configuration_map["mirror_afpacket"] == "on") {
        list.push_back("af_packet");
    }

    if (configuration_map.count("mirror_afxdp") != 0 && configuration_map["mirror_afxdp"] == "on") {
        list.push_back("af_xdp");
    }

    return list;
}

// Reads instance_id from filesystem
bool get_instance_id(std::string& instance_id) {
    std::string instance_id_path = "/var/lib/instance_id.fst";

    // Not found and that's OK
    if (!file_exists(instance_id_path)) {
        return false;
    }

    // It has no newline inside
    if (!read_file_to_string(instance_id_path, instance_id)) {
        return false;
    }

    return true;
}

void send_usage_data_to_reporting_server() {
    extern std::string reporting_server;
    extern total_speed_counters_t total_counters_ipv4;
    extern total_speed_counters_t total_counters_ipv6;

    // Build query
    std::stringstream request_stream;

    request_stream << "https://" << reporting_server << "/stats_v1";


    std::string stats_json_string;

    try {
        nlohmann::json stats;

        uint64_t incoming_ipv4 = total_counters_ipv4.total_speed_average_counters[INCOMING].bytes;
        uint64_t outgoing_ipv4 = total_counters_ipv4.total_speed_average_counters[OUTGOING].bytes;

        uint64_t incoming_ipv6 = total_counters_ipv6.total_speed_average_counters[INCOMING].bytes;
        uint64_t outgoing_ipv6 = total_counters_ipv6.total_speed_average_counters[OUTGOING].bytes;

        stats["incoming_traffic_speed"] = incoming_ipv4 + incoming_ipv6;
        stats["outgoing_traffic_speed"] = outgoing_ipv4 + outgoing_ipv6;

        stats["incoming_traffic_speed_ipv4"] = incoming_ipv4;
        stats["outgoing_traffic_speed_ipv4"] = outgoing_ipv4;

        stats["incoming_traffic_speed_ipv6"] = incoming_ipv6;
        stats["outgoing_traffic_speed_ipv6"] = outgoing_ipv6;

        stats["flows_speed"]            = netflow_ipfix_all_protocols_total_flows_speed;
        stats["headers_speed"]          = sflow_raw_packet_headers_total_speed;
        stats["total_hosts"]            = total_number_of_hosts_in_our_networks;
        stats["cap_plugins"]            = generate_list_of_enabled_capture_engines();
        stats["speed_calc_time"]        = speed_calculation_time.tv_sec;
        stats["version"]                = fastnetmon_platform_configuration.fastnetmon_version;
        stats["virt_method"]            = get_virtualisation_method();

        // We use statically allocated counters in that case
        stats["hosts_hash_ipv4"] = total_number_of_hosts_in_our_networks;

        ssize_t hosts_hash_size_ipv6 = 0;

        {
            std::lock_guard<std::mutex> lock_guard(ipv6_host_counters.counter_map_mutex);
            hosts_hash_size_ipv6 = ipv6_host_counters.average_speed_map.size();
        }

        stats["hosts_hash_ipv6"] = hosts_hash_size_ipv6;

        bool gobgp = false;

        if (configuration_map.count("gobgp") != 0 && configuration_map["gobgp"] == "on") {
            gobgp = true;
        }

        stats["bgp"] = gobgp;

        stats["bgp_flow_spec"] = false;

        bool influxdb = false;

        if (configuration_map.count("influxdb") != 0 && configuration_map["influxdb"] == "on") {
            influxdb = true;
        }

        stats["influxdb"] = influxdb;

        stats["clickhouse_metrics"] = false;
        stats["traffic_db"]         = false;
        stats["prometheus"]         = false;

        stats["cpu_model"]         = get_cpu_model();
        stats["cpu_logical_cores"] = get_logical_cpus_number();

        // Mbytes
        stats["memory_size"] = get_total_memory();

        std::string kernel_version = "unknown";

        if (!get_kernel_version(kernel_version)) {
            logger << log4cpp::Priority::ERROR << "Cannot get Linux kernel version";
        }

        stats["kernel_version"] = kernel_version;

        std::vector<std::string> cpu_flags;

        if (!get_cpu_flags(cpu_flags)) {
            logger << log4cpp::Priority::ERROR << "Cannot get CPU flags";
        }

        stats["cpu_flags"] = cpu_flags;

        std::string linux_distro_name = "unknown";

        if (!get_linux_distro_name(linux_distro_name)) {
            logger << log4cpp::Priority::ERROR << "Cannot get Linux distro name";
        }

        stats["linux_distro_name"] = linux_distro_name;

        std::string linux_distro_version = "unknown";

        if (!get_linux_distro_version(linux_distro_version)) {
            logger << log4cpp::Priority::ERROR << "Cannot get Linux distro version";
        }

        stats["linux_distro_version"] = linux_distro_version;

        std::string instance_id;

        if (get_instance_id(instance_id)) {
            stats["instance_id"] = instance_id;
        } else {
            // OK, it's optional
        }

        stats_json_string = stats.dump();
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Failed to serialise stats";
        return;
    }

    // It's fair to show but we will expose our delay. We need to make delay random first
    // logger << log4cpp::Priority::DEBUG << "Preparing to send following information to telemetry server " << request_stream.str();

    uint32_t response_code = 0;
    std::string response_body;
    std::string error_text;

    std::map<std::string, std::string> headers;

    // I think we need to do it to make clear about format for remote app
    headers["Content-Type"] = "application/json";

    // Just do it to know about DNS issues, execute_web_request can do DNS resolution on it's own
    std::string reporting_server_ip_address = dns_lookup(reporting_server);

    if (reporting_server_ip_address.empty()) {
        logger << log4cpp::Priority::DEBUG << "Stats server resolver failed, please check your DNS";
        return;
    }

    bool result = execute_web_request_secure(request_stream.str(), "post", stats_json_string, response_code,
                                             response_body, headers, error_text);

    if (!result) {
        logger << log4cpp::Priority::DEBUG << "Can't collect stats data";
        return;
    }

    if (response_code != 200) {
        logger << log4cpp::Priority::DEBUG << "Got code " << response_code << " from stats server instead of 200";
        return;
    }
}

void collect_stats() {
    extern unsigned int stats_thread_initial_call_delay;
    extern unsigned int stats_thread_sleep_time;

    boost::this_thread::sleep(boost::posix_time::seconds(stats_thread_initial_call_delay));

    while (true) {
        send_usage_data_to_reporting_server();
        boost::this_thread::sleep(boost::posix_time::seconds(stats_thread_sleep_time));
    }
}

// Adds total traffic metrics to Prometheus endpoint
void add_total_traffic_to_prometheus(const total_speed_counters_t& total_counters, std::stringstream& output, const std::string& protocol_version) {
    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        std::string direction_as_string = get_direction_name(packet_direction);

        // Packets
        std::string packet_metric_name = "fastnetmon_total_traffic_packets";

        output << "# HELP Total traffic in packets\n";
        output << "# TYPE " << packet_metric_name << " gauge\n";
        output << packet_metric_name << "{traffic_direction=\"" << direction_as_string << "\",protocol_version=\""
               << protocol_version << "\"} " << total_counters.total_speed_average_counters[packet_direction].packets << "\n";

        // Bytes
        std::string bits_metric_name = "fastnetmon_total_traffic_bits";

        output << "# HELP Total traffic in bits\n";
        output << "# TYPE " << bits_metric_name << " gauge\n";
        output << bits_metric_name << "{traffic_direction=\"" << direction_as_string << "\",protocol_version=\"" << protocol_version
               << "\"} " << total_counters.total_speed_average_counters[packet_direction].bytes * 8 << "\n";

        // Flows
        if (protocol_version == "ipv4" && enable_connection_tracking &&
            (packet_direction == INCOMING || packet_direction == OUTGOING)) {
            uint64_t flow_rate = 0;

            std::string flows_metric_name = "fastnetmon_total_traffic_flows";

            if (packet_direction == INCOMING) {
                flow_rate = incoming_total_flows_speed;
            } else if (packet_direction == OUTGOING) {
                flow_rate = outgoing_total_flows_speed;
            }

            output << "# HELP Total traffic in flows\n";
            output << "# TYPE " << flows_metric_name << " gauge\n";
            output << flows_metric_name << "{traffic_direction=\"" << direction_as_string << "\",protocol_version=\""
                   << protocol_version << "\"}" << flow_rate << "\n";
        }
    }
}


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
void handle_prometheus_http_request(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req,
                                    Send&& send) {
    // Returns a bad request response
    auto const bad_request = [&req](boost::beast::string_view why) {
        boost::beast::http::response<boost::beast::http::string_body> res{ boost::beast::http::status::bad_request, req.version() };

        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "text/html");

        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();

        return res;
    };

    // Returns a not found response
    auto const not_found = [&req](boost::beast::string_view target) {
        boost::beast::http::response<boost::beast::http::string_body> res{ boost::beast::http::status::not_found, req.version() };

        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "The resource '" + std::string(target) + "' was not found.";
        res.prepare_payload();

        return res;
    };

    // Returns a server error response
    auto const server_error = [&req](boost::beast::string_view what) {
        boost::beast::http::response<boost::beast::http::string_body> res{ boost::beast::http::status::internal_server_error,
                                                                           req.version() };
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    };

    // Make sure we can handle the method
    if (req.method() != boost::beast::http::verb::get) {
        return send(bad_request("Unknown HTTP-method"));
    }

    // We support only /metrics URL
    if (req.target() != "/metrics") {
        return send(not_found(req.target()));
    }

    // Respond to GET request
    boost::beast::http::response<boost::beast::http::string_body> res{ boost::beast::http::status::ok, req.version() };

    res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(boost::beast::http::field::content_type, "text/html");

    std::vector<system_counter_t> system_counters;

    // Application statistics
    bool result = get_statistics(system_counters);

    if (!result) {
        return send(server_error("Could not get application statistics"));
    }

    std::stringstream output;

    for (auto counter : system_counters) {
        std::string metric_type = "counter";

        if (counter.counter_type == metric_type_t::gauge) {
            metric_type = "gauge";
        }

        // It's good idea to add proper descriptions in future
        output << "# HELP " << counter.counter_description << "\n";
        output << "# TYPE "
               << "fastnetmon_" << counter.counter_name << " " << metric_type << "\n";
        output << "fastnetmon_" << counter.counter_name << " " << counter.counter_value << "\n";
    }

    extern total_speed_counters_t total_counters_ipv4;

    // Add total traffic metrics
    add_total_traffic_to_prometheus(total_counters_ipv4, output, "ipv4");

    extern total_speed_counters_t total_counters_ipv6;

    add_total_traffic_to_prometheus(total_counters_ipv6, output, "ipv6");

    res.body() = output.str();

    res.keep_alive(req.keep_alive());

    res.prepare_payload();

    return send(std::move(res));
}


// This is the C++11 equivalent of a generic lambda.
// The function object is used to send an HTTP message.
template <class Stream> struct send_lambda {
    Stream& stream_;
    bool& close_;
    boost::beast::error_code& ec_;

    explicit send_lambda(Stream& stream, bool& close, boost::beast::error_code& ec)
    : stream_(stream), close_(close), ec_(ec) {
    }

    template <bool isRequest, class Body, class Fields>
    void operator()(boost::beast::http::message<isRequest, Body, Fields>&& msg) const {
        // Determine if we should close the connection after
        close_ = msg.need_eof();

        // We need the serialiser here because the serialiser requires
        // a non-const file_body, and the message oriented version of
        // http::write only works with const messages.
        boost::beast::http::serializer<isRequest, Body, Fields> sr{ msg };
        boost::beast::http::write(stream_, sr, ec_);
    }
};

// handled http query to Prometheus endpoint
void do_prometheus_http_session(boost::asio::ip::tcp::socket& socket) {
    bool close = false;
    boost::beast::error_code ec;

    // This buffer is required to persist across reads
    boost::beast::flat_buffer buffer;

    // This lambda is used to send messages
    send_lambda<boost::asio::ip::tcp::socket> lambda{ socket, close, ec };

    while (true) {
        // Read a request
        boost::beast::http::request<boost::beast::http::string_body> req;
        boost::beast::http::read(socket, buffer, req, ec);

        if (ec == boost::beast::http::error::end_of_stream) {
            break;
        }

        if (ec) {
            logger << log4cpp::Priority::ERROR << "HTTP query read failed: " << ec.message();
            return;
        }

        // Send the response
        handle_prometheus_http_request(std::move(req), lambda);

        if (ec) {
            logger << log4cpp::Priority::ERROR << "HTTP query read failed: " << ec.message();
            return;
        }

        if (close) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            break;
        }
    }

    // Send a TCP shutdown
    socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    // At this point the connection is closed gracefully
}


void start_prometheus_web_server() {
    extern unsigned short prometheus_port;
    extern std::string prometheus_host;

    try {
        logger << log4cpp::Priority::INFO << "Starting Prometheus endpoint on " << prometheus_host << ":" << prometheus_port;

        auto const address = boost::asio::ip::make_address(prometheus_host);
        auto const port    = static_cast<unsigned short>(prometheus_port);

        // The io_context is required for all I/O
        boost::asio::io_context ioc{ 1 };

        // The acceptor receives incoming connections
        boost::asio::ip::tcp::acceptor acceptor{ ioc, { address, port } };

        while (true) {
            // This will receive the new connection
            boost::asio::ip::tcp::socket socket{ ioc };

            // Block until we get a connection
            acceptor.accept(socket);

            // Launch the session, transferring ownership of the socket
            std::thread{ std::bind(&do_prometheus_http_session, std::move(socket)) }.detach();
        }

    } catch (const std::exception& e) {
        logger << log4cpp::Priority::ERROR << "Prometheus server exception: " << e.what();
    }
}

std::string get_human_readable_attack_detection_direction(attack_detection_direction_type_t attack_detection_direction) {
    if (attack_detection_direction == attack_detection_direction_type_t::unknown) {
        return "unknown";
    } else if (attack_detection_direction == attack_detection_direction_type_t::incoming) {
        return "incoming";
    } else if (attack_detection_direction == attack_detection_direction_type_t::outgoing) {
        return "outgoing";
    } else {
        return "unknown";
    }
}

