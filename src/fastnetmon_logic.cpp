#include "fastnetmon_logic.hpp"
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <vector>

#include "all_logcpp_libraries.h"
#include "bgp_protocol.hpp"
#include "fast_library.h"
#include "fast_platform.h"
#include "fastnetmon_packet_parser.h"

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

#include "actions/exabgp_action.hpp"

// Yes, maybe it's not an good idea but with this we can guarantee working code in example plugin
#include "example_plugin/example_collector.h"

#ifdef MONGO
#include <bson.h>
#include <mongoc.h>
#endif

#include "fastnetmon_networks.hpp"

#include "abstract_subnet_counters.hpp"

#include "packet_bucket.h"

#include "ban_list.hpp"

extern packet_buckets_storage_t<subnet_ipv6_cidr_mask_t> packet_buckets_ipv6_storage;
extern bool print_average_traffic_counts;
extern std::string cli_stats_file_path;
extern unsigned int total_number_of_hosts_in_our_networks;
extern  map_for_subnet_counters_t PerSubnetCountersMap;
extern unsigned int recalculate_speed_timeout;
extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
extern bool DEBUG_DUMP_ALL_PACKETS;
extern bool DEBUG_DUMP_OTHER_PACKETS;
extern uint64_t total_ipv4_packets;
extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6_ng;
extern uint64_t total_ipv6_packets;
extern map_of_vector_counters_t SubnetVectorMapSpeed;
extern double average_calculation_amount;
extern double average_calculation_amount_for_subnets;
extern bool print_configuration_params_on_the_screen;
extern uint64_t our_ipv6_packets;
extern map_of_vector_counters_t SubnetVectorMap;
extern uint64_t non_ip_packets; 
extern uint64_t total_simple_packets_processed;
extern unsigned int maximum_time_since_bucket_start_to_remove;
extern unsigned int max_ips_in_list;
extern struct timeval speed_calculation_time;
extern struct timeval drawing_thread_execution_time;
extern time_t last_call_of_traffic_recalculation;
extern std::string cli_stats_ipv6_file_path;
extern unsigned int check_for_availible_for_processing_packets_buckets;
extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t> ipv6_host_counters;
extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t> ipv6_subnet_counters;
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
extern total_counter_element_t total_counters[4];
extern total_counter_element_t total_speed_counters[4];
extern total_counter_element_t total_speed_average_counters[4];
extern total_counter_element_t total_counters_ipv6[4];
extern total_counter_element_t total_speed_counters_ipv6[4];
extern total_counter_element_t total_speed_average_counters_ipv6[4];
extern host_group_ban_settings_map_t host_group_ban_settings_map;
extern bool exabgp_announce_whole_subnet;
extern subnet_to_host_group_map_t subnet_to_host_groups;
extern active_flow_spec_announces_t active_flow_spec_announces;
extern bool collect_attack_pcap_dumps;

#ifdef ENABLE_DPI
#include "fast_dpi.h"
#endif

#ifdef ENABLE_DPI
extern struct ndpi_detection_module_struct* my_ndpi_struct;
extern u_int32_t ndpi_size_flow_struct; 
extern u_int32_t ndpi_size_id_struct; 
#endif

extern boost::mutex ban_list_details_mutex;
extern boost::mutex ban_list_mutex;
extern std::mutex flow_counter;

#ifdef REDIS
extern unsigned int redis_port;
extern std::string redis_host;
extern std::string redis_prefix;
extern bool redis_enabled;
#endif


#ifdef MONGO
extern std::string mongodb_host;
extern unsigned int mongodb_port;
extern bool mongodb_enabled;
extern std::string mongodb_database_name;
#endif

extern bool notify_script_pass_details;
extern unsigned int number_of_packets_for_pcap_attack_dump;
extern patricia_tree_t *lookup_tree_ipv4, *whitelist_tree_ipv4;
extern patricia_tree_t *lookup_tree_ipv6, *whitelist_tree_ipv6;
extern bool process_pcap_attack_dumps_with_dpi;
extern std::map<uint32_t, std::vector<simple_packet_t> > ban_list_details;
extern map_for_subnet_counters_t PerSubnetAverageSpeedMap;
extern bool enable_subnet_counters;
extern ban_settings_t global_ban_settings;
extern bool exabgp_enabled;
extern bool exabgp_flow_spec_announces;
extern bool gobgp_enabled;
extern map_of_vector_counters_t SubnetVectorMapSpeedAverage;
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
extern map_for_subnet_counters_t PerSubnetSpeedMap;
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

unsigned int detect_attack_protocol(map_element_t& speed_element, direction_t attack_direction) {
    if (attack_direction == INCOMING) {
        return get_max_used_protocol(speed_element.tcp_in_packets, speed_element.udp_in_packets,
                                     speed_element.icmp_in_packets);
    } else {
        // OUTGOING
        return get_max_used_protocol(speed_element.tcp_out_packets, speed_element.udp_out_packets,
                                     speed_element.icmp_out_packets);
    }    
}

// We calculate speed from packet counters here
void build_speed_counters_from_packet_counters(map_element_t& new_speed_element,
                                                      map_element_t* vector_itr,
                                                      double speed_calc_period) {
    // calculate_speed(new_speed_element speed_element, vector_itr* );
    new_speed_element.in_packets = uint64_t((double)vector_itr->in_packets / speed_calc_period);
    new_speed_element.out_packets = uint64_t((double)vector_itr->out_packets / speed_calc_period);

    new_speed_element.in_bytes = uint64_t((double)vector_itr->in_bytes / speed_calc_period);
    new_speed_element.out_bytes = uint64_t((double)vector_itr->out_bytes / speed_calc_period);

    // Fragmented
    new_speed_element.fragmented_in_packets =
    uint64_t((double)vector_itr->fragmented_in_packets / speed_calc_period);
    new_speed_element.fragmented_out_packets =
    uint64_t((double)vector_itr->fragmented_out_packets / speed_calc_period);

    new_speed_element.fragmented_in_bytes =
    uint64_t((double)vector_itr->fragmented_in_bytes / speed_calc_period);
    new_speed_element.fragmented_out_bytes =
    uint64_t((double)vector_itr->fragmented_out_bytes / speed_calc_period);

    // By protocol counters

    // TCP
    new_speed_element.tcp_in_packets = uint64_t((double)vector_itr->tcp_in_packets / speed_calc_period);
    new_speed_element.tcp_out_packets = uint64_t((double)vector_itr->tcp_out_packets / speed_calc_period);

    new_speed_element.tcp_in_bytes = uint64_t((double)vector_itr->tcp_in_bytes / speed_calc_period);
    new_speed_element.tcp_out_bytes = uint64_t((double)vector_itr->tcp_out_bytes / speed_calc_period);

    // TCP syn
    new_speed_element.tcp_syn_in_packets = uint64_t((double)vector_itr->tcp_syn_in_packets / speed_calc_period);
    new_speed_element.tcp_syn_out_packets =
    uint64_t((double)vector_itr->tcp_syn_out_packets / speed_calc_period);

    new_speed_element.tcp_syn_in_bytes = uint64_t((double)vector_itr->tcp_syn_in_bytes / speed_calc_period);
    new_speed_element.tcp_syn_out_bytes = uint64_t((double)vector_itr->tcp_syn_out_bytes / speed_calc_period);

    // UDP
    new_speed_element.udp_in_packets = uint64_t((double)vector_itr->udp_in_packets / speed_calc_period);
    new_speed_element.udp_out_packets = uint64_t((double)vector_itr->udp_out_packets / speed_calc_period);

    new_speed_element.udp_in_bytes = uint64_t((double)vector_itr->udp_in_bytes / speed_calc_period);
    new_speed_element.udp_out_bytes = uint64_t((double)vector_itr->udp_out_bytes / speed_calc_period);

    // ICMP
    new_speed_element.icmp_in_packets = uint64_t((double)vector_itr->icmp_in_packets / speed_calc_period);
    new_speed_element.icmp_out_packets = uint64_t((double)vector_itr->icmp_out_packets / speed_calc_period);

    new_speed_element.icmp_in_bytes = uint64_t((double)vector_itr->icmp_in_bytes / speed_calc_period);
    new_speed_element.icmp_out_bytes = uint64_t((double)vector_itr->icmp_out_bytes / speed_calc_period);
}

void build_average_speed_counters_from_speed_counters(map_element_t* current_average_speed_element,
                                                             map_element_t& new_speed_element,
                                                             double exp_value,
                                                             double exp_power) {

    // Global bytes counters
    current_average_speed_element->in_bytes =
    uint64_t(new_speed_element.in_bytes + exp_value * ((double)current_average_speed_element->in_bytes -
                                                       (double)new_speed_element.in_bytes));

    current_average_speed_element->out_bytes =
    uint64_t(new_speed_element.out_bytes + exp_value * ((double)current_average_speed_element->out_bytes -
                                                        (double)new_speed_element.out_bytes));

    // Global packet counters
    current_average_speed_element->in_packets =
    uint64_t(new_speed_element.in_packets + exp_value * ((double)current_average_speed_element->in_packets -
                                                         (double)new_speed_element.in_packets));

    current_average_speed_element->out_packets =
    uint64_t(new_speed_element.out_packets + exp_value * ((double)current_average_speed_element->out_packets -
                                                          (double)new_speed_element.out_packets));

    // Per packet type packet counters for in traffic
    current_average_speed_element->fragmented_in_packets =
    uint64_t(new_speed_element.fragmented_in_packets +
             exp_value * ((double)current_average_speed_element->fragmented_in_packets -
                          (double)new_speed_element.fragmented_in_packets));

    current_average_speed_element->tcp_in_packets =
    uint64_t(new_speed_element.tcp_in_packets + exp_value * ((double)current_average_speed_element->tcp_in_packets -
                                                             (double)new_speed_element.tcp_in_packets));

    current_average_speed_element->tcp_syn_in_packets =
    uint64_t(new_speed_element.tcp_syn_in_packets +
             exp_value * ((double)current_average_speed_element->tcp_syn_in_packets -
                          (double)new_speed_element.tcp_syn_in_packets));

    current_average_speed_element->udp_in_packets =
    uint64_t(new_speed_element.udp_in_packets + exp_value * ((double)current_average_speed_element->udp_in_packets -
                                                             (double)new_speed_element.udp_in_packets));

    current_average_speed_element->icmp_in_packets =
    uint64_t(new_speed_element.icmp_in_packets + exp_value * ((double)current_average_speed_element->icmp_in_packets -
                                                              (double)new_speed_element.icmp_in_packets));

    // Per packet type packets counters for out
    current_average_speed_element->fragmented_out_packets =
    uint64_t(new_speed_element.fragmented_out_packets +
             exp_value * ((double)current_average_speed_element->fragmented_out_packets -
                          (double)new_speed_element.fragmented_out_packets));

    current_average_speed_element->tcp_out_packets =
    uint64_t(new_speed_element.tcp_out_packets + exp_value * ((double)current_average_speed_element->tcp_out_packets -
                                                              (double)new_speed_element.tcp_out_packets));

    current_average_speed_element->tcp_syn_out_packets =
    uint64_t(new_speed_element.tcp_syn_out_packets +
             exp_value * ((double)current_average_speed_element->tcp_syn_out_packets -
                          (double)new_speed_element.tcp_syn_out_packets));

    current_average_speed_element->udp_out_packets =
    uint64_t(new_speed_element.udp_out_packets + exp_value * ((double)current_average_speed_element->udp_out_packets -
                                                              (double)new_speed_element.udp_out_packets));

    current_average_speed_element->icmp_out_packets = uint64_t(
    new_speed_element.icmp_out_packets + exp_value * ((double)current_average_speed_element->icmp_out_packets -
                                                      (double)new_speed_element.icmp_out_packets));

    // Per packet type bytes counter for out
    current_average_speed_element->fragmented_out_bytes =
    uint64_t(new_speed_element.fragmented_out_bytes +
             exp_value * ((double)current_average_speed_element->fragmented_out_bytes -
                          (double)new_speed_element.fragmented_out_bytes));

    current_average_speed_element->tcp_out_bytes =
    uint64_t(new_speed_element.tcp_out_bytes + exp_value * ((double)current_average_speed_element->tcp_out_bytes -
                                                            (double)new_speed_element.tcp_out_bytes));

    current_average_speed_element->tcp_syn_out_bytes = uint64_t(
    new_speed_element.tcp_syn_out_bytes + exp_value * ((double)current_average_speed_element->tcp_syn_out_bytes -
                                                       (double)new_speed_element.tcp_syn_out_bytes));

    current_average_speed_element->udp_out_bytes =
    uint64_t(new_speed_element.udp_out_bytes + exp_value * ((double)current_average_speed_element->udp_out_bytes -
                                                            (double)new_speed_element.udp_out_bytes));

    current_average_speed_element->icmp_out_bytes =
    uint64_t(new_speed_element.icmp_out_bytes + exp_value * ((double)current_average_speed_element->icmp_out_bytes -
                                                             (double)new_speed_element.icmp_out_bytes));

    // Per packet type bytes counter for in
    current_average_speed_element->fragmented_in_bytes =
    uint64_t(new_speed_element.fragmented_in_bytes +
             exp_value * ((double)current_average_speed_element->fragmented_in_bytes -
                          (double)new_speed_element.fragmented_in_bytes));

    current_average_speed_element->tcp_in_bytes =
    uint64_t(new_speed_element.tcp_in_bytes + exp_value * ((double)current_average_speed_element->tcp_in_bytes -
                                                           (double)new_speed_element.tcp_in_bytes));

    current_average_speed_element->tcp_syn_in_bytes = uint64_t(
    new_speed_element.tcp_syn_in_bytes + exp_value * ((double)current_average_speed_element->tcp_syn_in_bytes -
                                                      (double)new_speed_element.tcp_syn_in_bytes));

    current_average_speed_element->udp_in_bytes =
    uint64_t(new_speed_element.udp_in_bytes + exp_value * ((double)current_average_speed_element->udp_in_bytes -
                                                           (double)new_speed_element.udp_in_bytes));

    current_average_speed_element->icmp_in_bytes =
    uint64_t(new_speed_element.icmp_in_bytes + exp_value * ((double)current_average_speed_element->icmp_in_bytes -
                                                            (double)new_speed_element.icmp_in_bytes));
}


std::string print_flow_tracking_for_ip(conntrack_main_struct_t& conntrack_element, std::string client_ip) {
    std::stringstream buffer;

    std::string in_tcp =
    print_flow_tracking_for_specified_protocol(conntrack_element.in_tcp, client_ip, INCOMING);
    std::string in_udp =
    print_flow_tracking_for_specified_protocol(conntrack_element.in_udp, client_ip, INCOMING);

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

    std::string out_tcp =
    print_flow_tracking_for_specified_protocol(conntrack_element.out_tcp, client_ip, OUTGOING);
    std::string out_udp =
    print_flow_tracking_for_specified_protocol(conntrack_element.out_udp, client_ip, OUTGOING);

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

    sort_type_t sorter;
    if (sort_parameter == "packets") {
        sorter = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter = BYTES;
    } else if (sort_parameter == "flows") {
        sorter = FLOWS;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter = PACKETS;
    }

    std::vector<pair_of_map_for_subnet_counters_elements_t> vector_for_sort;
    vector_for_sort.reserve(PerSubnetSpeedMap.size());

    for (map_for_subnet_counters_t::iterator itr = PerSubnetSpeedMap.begin();
         itr != PerSubnetSpeedMap.end(); ++itr) {
        vector_for_sort.push_back(std::make_pair(itr->first, itr->second));
    }

    std::sort(vector_for_sort.begin(), vector_for_sort.end(),
              TrafficComparatorClass<pair_of_map_for_subnet_counters_elements_t>(INCOMING, sorter));

    for (std::vector<pair_of_map_for_subnet_counters_elements_t>::iterator itr = vector_for_sort.begin();
         itr != vector_for_sort.end(); ++itr) {
        map_element_t* speed = &itr->second;
        std::string subnet_as_string = convert_subnet_to_string(itr->first);

        buffer << std::setw(18) << std::left << subnet_as_string;

        buffer << " "
               << "pps in: " << std::setw(8) << speed->in_packets << " out: " << std::setw(8)
               << speed->out_packets << " mbps in: " << std::setw(5) << convert_speed_to_mbps(speed->in_bytes)
               << " out: " << std::setw(5) << convert_speed_to_mbps(speed->out_bytes) << "\n";
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

void print_attack_details_to_file(std::string details, std::string client_ip_as_string, attack_details_t current_attack) {
    std::ofstream my_attack_details_file;

    std::string ban_timestamp_as_string = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    std::string attack_dump_path =
        fastnetmon_platform_configuration.attack_details_folder + "/" + client_ip_as_string + "_" + ban_timestamp_as_string + ".txt";

    my_attack_details_file.open(attack_dump_path.c_str(), std::ios::app);

    if (my_attack_details_file.is_open()) {
        my_attack_details_file << details << "\n\n";
        my_attack_details_file.close();
    } else {
        logger << log4cpp::Priority::ERROR << "Can't print attack details to file";
    }
}

logging_configuration_t read_logging_settings(configuration_map_t configuration_map) {
    logging_configuration_t logging_configuration_temp;

    if (configuration_map.count("logging:local_syslog_logging") != 0) {
        logging_configuration_temp.local_syslog_logging =
        configuration_map["logging:local_syslog_logging"] == "on";
    }

    if (configuration_map.count("logging:remote_syslog_logging") != 0) {
        logging_configuration_temp.remote_syslog_logging =
        configuration_map["logging:remote_syslog_logging"] == "on";
    }

    if (configuration_map.count("logging:remote_syslog_server") != 0) {
        logging_configuration_temp.remote_syslog_server =
        configuration_map["logging:remote_syslog_server"];
    }

    if (configuration_map.count("logging:remote_syslog_port") != 0) {
        logging_configuration_temp.remote_syslog_port =
        convert_string_to_integer(configuration_map["logging:remote_syslog_port"]);
    }

    if (logging_configuration_temp.remote_syslog_logging) {
        if (logging_configuration_temp.remote_syslog_port > 0 &&
            !logging_configuration_temp.remote_syslog_server.empty()) {
            logger << log4cpp::Priority::INFO << "We have configured remote syslog logging corectly";
        } else {
            logger << log4cpp::Priority::ERROR << "You have enabled remote logging but haven't specified port or host";
            logging_configuration_temp.remote_syslog_logging = false;
        }
    }

    if (logging_configuration_temp.local_syslog_logging) {
        logger << log4cpp::Priority::INFO << "We have configured local syslog logging corectly";
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
        ban_settings.enable_ban_for_flows_per_second =
        configuration_map[prefix + "ban_for_flows"] == "on";
    }

    // Per protocol bandwidth triggers
    if (configuration_map.count(prefix + "ban_for_tcp_bandwidth") != 0) {
        ban_settings.enable_ban_for_tcp_bandwidth =
        configuration_map[prefix + "ban_for_tcp_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_udp_bandwidth") != 0) {
        ban_settings.enable_ban_for_udp_bandwidth =
        configuration_map[prefix + "ban_for_udp_bandwidth"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_icmp_bandwidth") != 0) {
        ban_settings.enable_ban_for_icmp_bandwidth =
        configuration_map[prefix + "ban_for_icmp_bandwidth"] == "on";
    }

    // Per protocol pps ban triggers
    if (configuration_map.count(prefix + "ban_for_tcp_pps") != 0) {
        ban_settings.enable_ban_for_tcp_pps = configuration_map[prefix + "ban_for_tcp_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_udp_pps") != 0) {
        ban_settings.enable_ban_for_udp_pps = configuration_map[prefix + "ban_for_udp_pps"] == "on";
    }

    if (configuration_map.count(prefix + "ban_for_icmp_pps") != 0) {
        ban_settings.enable_ban_for_icmp_pps =
        configuration_map[prefix + "ban_for_icmp_pps"] == "on";
    }

    // Pps per protocol thresholds
    if (configuration_map.count(prefix + "threshold_tcp_pps") != 0) {
        ban_settings.ban_threshold_tcp_pps =
        convert_string_to_integer(configuration_map[prefix + "threshold_tcp_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_udp_pps") != 0) {
        ban_settings.ban_threshold_udp_pps =
        convert_string_to_integer(configuration_map[prefix + "threshold_udp_pps"]);
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
        ban_settings.ban_threshold_pps =
        convert_string_to_integer(configuration_map[prefix + "threshold_pps"]);
    }

    if (configuration_map.count(prefix + "threshold_mbps") != 0) {
        ban_settings.ban_threshold_mbps =
        convert_string_to_integer(configuration_map[prefix + "threshold_mbps"]);
    }

    if (configuration_map.count(prefix + "threshold_flows") != 0) {
        ban_settings.ban_threshold_flows =
        convert_string_to_integer(configuration_map[prefix + "threshold_flows"]);
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
bool we_should_ban_this_entity(map_element_t* average_speed_element,
                               ban_settings_t& current_ban_settings,
                               attack_detection_threshold_type_t& attack_detection_source,
                               attack_detection_direction_type_t& attack_detection_direction) {

    attack_detection_source    = attack_detection_threshold_type_t::unknown;
    attack_detection_direction = attack_detection_direction_type_t::unknown;


    // we detect overspeed by packets
    if (current_ban_settings.enable_ban_for_pps &&
        exceed_pps_speed(average_speed_element->in_packets, average_speed_element->out_packets,
                         current_ban_settings.ban_threshold_pps)) {

        attack_detection_source = attack_detection_threshold_type_t::packets_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_bandwidth &&
        exceed_mbps_speed(average_speed_element->in_bytes, average_speed_element->out_bytes,
                          current_ban_settings.ban_threshold_mbps)) {

        attack_detection_source = attack_detection_threshold_type_t::bytes_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_flows_per_second &&
        exceed_flow_speed(average_speed_element->in_flows, average_speed_element->out_flows,
                          current_ban_settings.ban_threshold_flows)) {

        attack_detection_source = attack_detection_threshold_type_t::flows_per_second;
        return true;
    }

    // We could try per protocol thresholds here

    // Per protocol pps thresholds
    if (current_ban_settings.enable_ban_for_tcp_pps &&
        exceed_pps_speed(average_speed_element->tcp_in_packets, average_speed_element->tcp_out_packets,
                         current_ban_settings.ban_threshold_tcp_pps)) {
        attack_detection_source = attack_detection_threshold_type_t::tcp_packets_per_second;

        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_pps &&
        exceed_pps_speed(average_speed_element->udp_in_packets, average_speed_element->udp_out_packets,
                         current_ban_settings.ban_threshold_udp_pps)) {
        
        attack_detection_source = attack_detection_threshold_type_t::udp_packets_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_icmp_pps &&
        exceed_pps_speed(average_speed_element->icmp_in_packets, average_speed_element->icmp_out_packets,
                         current_ban_settings.ban_threshold_icmp_pps)) {
        attack_detection_source = attack_detection_threshold_type_t::icmp_packets_per_second;
        return true;
    }

    // Per protocol bandwidth thresholds
    if (current_ban_settings.enable_ban_for_tcp_bandwidth &&
        exceed_mbps_speed(average_speed_element->tcp_in_bytes, average_speed_element->tcp_out_bytes,
                          current_ban_settings.ban_threshold_tcp_mbps)) {
        attack_detection_source = attack_detection_threshold_type_t::tcp_bytes_per_second;;
        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_bandwidth &&
        exceed_mbps_speed(average_speed_element->udp_in_bytes, average_speed_element->udp_out_bytes,
                          current_ban_settings.ban_threshold_udp_mbps)) {
        attack_detection_source = attack_detection_threshold_type_t::udp_bytes_per_second;
        return true;
    }

    if (current_ban_settings.enable_ban_for_icmp_bandwidth &&
        exceed_mbps_speed(average_speed_element->icmp_in_bytes, average_speed_element->icmp_out_bytes,
                          current_ban_settings.ban_threshold_icmp_mbps)) {
        attack_detection_source = attack_detection_threshold_type_t::icmp_bytes_per_second;
        return true;
    }

    return false;
}

std::string generate_flow_spec_for_amplification_attack(amplification_attack_type_t amplification_attack_type,
                                                        std::string destination_ip) {
    exabgp_flow_spec_rule_t exabgp_rule;

    bgp_flow_spec_action_t my_action;

    // We drop all traffic by default
    my_action.set_type(FLOW_SPEC_ACTION_DISCARD);

    // Assign action to the rule
    exabgp_rule.set_action(my_action);

    // TODO: rewrite!
    exabgp_rule.set_destination_subnet(
    convert_subnet_from_string_to_binary_with_cidr_format(destination_ip + "/32"));

    // We use only UDP here
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);

    if (amplification_attack_type == AMPLIFICATION_ATTACK_DNS) {
        exabgp_rule.add_source_port(53);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_NTP) {
        exabgp_rule.add_source_port(123);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_SSDP) {
        exabgp_rule.add_source_port(1900);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_SNMP) {
        exabgp_rule.add_source_port(161);
    } else if (amplification_attack_type == AMPLIFICATION_ATTACK_CHARGEN) {
        exabgp_rule.add_source_port(19);
    }

    return exabgp_rule.serialize_single_line_exabgp_v4_configuration();
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

std::string print_flow_tracking_for_specified_protocol(contrack_map_type& protocol_map,
                                                       std::string client_ip,
                                                       direction_t flow_direction) {
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
        convert_integer_to_conntrack_hash_struct(&packed_connection_data, &unpacked_key_struct);

        std::string opposite_ip_as_string = convert_ip_as_uint_to_string(unpacked_key_struct.opposite_ip);
        if (flow_direction == INCOMING) {
            buffer << client_ip << ":" << unpacked_key_struct.dst_port << " < "
                   << opposite_ip_as_string << ":" << unpacked_key_struct.src_port << " "; 
        } else if (flow_direction == OUTGOING) {
            buffer << client_ip << ":" << unpacked_key_struct.src_port << " > "
                   << opposite_ip_as_string << ":" << unpacked_key_struct.dst_port << " "; 
        }

        buffer << itr->second.bytes << " bytes " << itr->second.packets << " packets";
        buffer << "\n";

        printed_records++;
    }    

    return buffer.str();
}

void convert_integer_to_conntrack_hash_struct(packed_session* packed_connection_data,
                                              packed_conntrack_hash_t* unpacked_data) {
    memcpy(unpacked_data, packed_connection_data, sizeof(uint64_t));
}

// Unbans host which are ready to it
void execute_unban_operation_ipv6() {
    time_t current_time;
    time(&current_time);

    std::vector<subnet_ipv6_cidr_mask_t> ban_list_items_for_erase;

    std::map<subnet_ipv6_cidr_mask_t, banlist_item_t> ban_list_copy;

    // Get whole ban list content atomically
    ban_list_ipv6_ng.get_whole_banlist(ban_list_copy);

    for (auto itr : ban_list_copy) {
        auto client_ip = itr.first;

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
        // We will remove keyas really after this loop
        ban_list_items_for_erase.push_back(itr.first);

        // Call all hooks for unban
        uint32_t zero_ipv4_ip_address = 0; 
        call_unban_handlers(zero_ipv4_ip_address, itr.first, true, itr.second, attack_detection_source_t::Automatic);
    }    

    // Remove all unbanned hosts from the ban list
    for (auto ban_element_for_erase : ban_list_items_for_erase) {
        ban_list_ipv6_ng.remove_from_blackhole(ban_element_for_erase);
    }    
}

/* Thread for cleaning up ban list */
void cleanup_ban_list() {
    // If we use very small ban time we should call ban_cleanup thread more often
    if (unban_iteration_sleep_time > global_ban_time) {
        unban_iteration_sleep_time = int(global_ban_time / 2);

        logger << log4cpp::Priority::INFO << "You are using enough small ban time "
               << global_ban_time << " we need reduce unban_iteration_sleep_time twices to "
               << unban_iteration_sleep_time << " seconds";
    }

    logger << log4cpp::Priority::INFO << "Run banlist cleanup thread, we will awake every "
           << unban_iteration_sleep_time << " seconds";

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(unban_iteration_sleep_time));

        time_t current_time;
        time(&current_time);

        std::vector<uint32_t> ban_list_items_for_erase;

        for (std::map<uint32_t, banlist_item_t>::iterator itr = ban_list.begin(); itr != ban_list.end(); ++itr) {
            uint32_t client_ip = itr->first;

            // This IP should be banned permanentely and we skip any processing
            if (!itr->second.unban_enabled) {
                continue;
            }

            double time_difference = difftime(current_time, itr->second.ban_timestamp);
            int ban_time = itr->second.ban_time;

            // Yes, we reached end of ban time for this customer
            bool we_could_unban_this_ip = time_difference > ban_time;

            // We haven't reached time for unban yet
            if (!we_could_unban_this_ip) {
                continue;
            }

            // Check about ongoing attack
            if (unban_only_if_attack_finished) {
                std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
                
                uint32_t subnet_in_host_byte_order = ntohl(itr->second.customer_network.subnet_address);
                int64_t shift_in_vector = (int64_t)ntohl(client_ip) - (int64_t)subnet_in_host_byte_order;

                // Try to find average speed element
                map_of_vector_counters_t::iterator itr_average_speed =
                SubnetVectorMapSpeedAverage.find(itr->second.customer_network);

                if (itr_average_speed == SubnetVectorMapSpeedAverage.end()) {
                    logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet map for unban function";
                    continue;
                }

                if (shift_in_vector < 0 or shift_in_vector >= itr_average_speed->second.size()) {
                    logger << log4cpp::Priority::ERROR << "We tried to access to element with index "
                           << shift_in_vector << " which located outside allocated vector with size "
                           << itr_average_speed->second.size();

                    continue;
                }

                map_element_t* average_speed_element = &itr_average_speed->second[shift_in_vector];

                // We get ban settings from host subnet
                std::string host_group_name;
                ban_settings_t current_ban_settings =
                get_ban_settings_for_this_subnet(itr->second.customer_network, host_group_name);

                attack_detection_threshold_type_t attack_detection_source;
                attack_detection_direction_type_t attack_detection_direction;

                if (we_should_ban_this_entity(average_speed_element, current_ban_settings, attack_detection_source, attack_detection_direction)) {
                    logger << log4cpp::Priority::ERROR << "Attack to IP " << client_ip_as_string
                           << " still going! We should not unblock this host";

                    // Well, we still saw attack, skip to next iteration
                    continue;
                }
            }

            // Add this IP to remove list
            // We will remove keyas really after this loop
            ban_list_items_for_erase.push_back(itr->first);

            // Call all hooks for unban
            subnet_ipv6_cidr_mask_t zero_ipv6_address;
            call_unban_handlers(itr->first, zero_ipv6_address, false,  itr->second, attack_detection_source_t::Automatic);
        }

        // Remove all unbanned hosts from the ban list
        for (std::vector<uint32_t>::iterator itr = ban_list_items_for_erase.begin();
             itr != ban_list_items_for_erase.end(); ++itr) {
            ban_list_mutex.lock();
            ban_list.erase(*itr);
            ban_list_mutex.unlock();
        }

        // Unban IPv6 bans
        execute_unban_operation_ipv6();
    }
}

void call_unban_handlers(uint32_t client_ip,
                         subnet_ipv6_cidr_mask_t client_ipv6,
                         bool ipv6,
                         attack_details_t& current_attack,
                         attack_detection_source_t attack_detection_source) {
    bool ipv4 = !ipv6;

    std::string client_ip_as_string;

    if (ipv4) {
        client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    } else {
        client_ip_as_string = print_ipv6_address(client_ipv6.subnet_address);
    }    

    logger << log4cpp::Priority::INFO << "We will unban banned IP: " << client_ip_as_string
           << " because it ban time " << current_attack.ban_time << " seconds is ended";

    if (notify_script_enabled) {
        std::string data_direction_as_string = get_direction_name(current_attack.attack_direction);
        std::string pps_as_string = convert_int_to_string(current_attack.attack_power);

        std::string script_call_params = fastnetmon_platform_configuration.notify_script_path + " " + client_ip_as_string + " " +
                                         data_direction_as_string + " " + pps_as_string + " unban";

        logger << log4cpp::Priority::INFO << "Call script for unban client: " << client_ip_as_string;

        // We should execute external script in separate thread because any lag in this
        // code will be very distructive
        boost::thread exec_thread(exec, script_call_params);
        exec_thread.detach();

        logger << log4cpp::Priority::INFO << "Script for unban client is finished: " << client_ip_as_string;
    }

    if (exabgp_enabled && ipv4) {
        logger << log4cpp::Priority::INFO << "Call ExaBGP for unban client started: " << client_ip_as_string;

        boost::thread exabgp_thread(exabgp_ban_manage, "unban", client_ip_as_string, current_attack);
        exabgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to ExaBGP for unban client is finished: " << client_ip_as_string;
    }

#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call GoBGP for unban client started: " << client_ip_as_string;

        boost::thread gobgp_thread(gobgp_ban_manage, "unban", ipv6, client_ip_as_string, client_ipv6,  current_attack);
        gobgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to GoBGP for unban client is finished: " << client_ip_as_string;
    }
#endif
}

std::string print_ddos_attack_details() {
    std::stringstream output_buffer;

    for (std::map<uint32_t, banlist_item_t>::iterator ii = ban_list.begin(); ii != ban_list.end(); ++ii) {
        uint32_t client_ip = (*ii).first;

        std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
        std::string max_pps_as_string = convert_int_to_string(((*ii).second).max_attack_power);
        std::string attack_direction = get_direction_name(((*ii).second).attack_direction);

        output_buffer << client_ip_as_string << "/" << max_pps_as_string << " pps " << attack_direction
                      << " at " << print_time_t_in_fastnetmon_format(ii->second.ban_timestamp) << std::endl;

        send_attack_details(client_ip, (*ii).second);
    }


    return output_buffer.str();
}

std::string get_attack_description(uint32_t client_ip, attack_details_t& current_attack) {
    std::stringstream attack_description;

    attack_description << "IP: " << convert_ip_as_uint_to_string(client_ip) << "\n";
    attack_description << serialize_attack_description(current_attack) << "\n";

    if (enable_subnet_counters) {
        // Got subnet tracking structure
        // TODO: we suppose case "no key exists" is not possible
        map_element_t network_speed_meter = PerSubnetSpeedMap[current_attack.customer_network];
        map_element_t average_network_speed_meter = PerSubnetAverageSpeedMap[current_attack.customer_network];

        attack_description << "Network: " << convert_subnet_to_string(current_attack.customer_network) << "\n";

        attack_description << serialize_network_load_to_text(network_speed_meter, false);
        attack_description << serialize_network_load_to_text(average_network_speed_meter, true);
    }

    attack_description << serialize_statistic_counters_about_attack(current_attack);

    return attack_description.str();
}

std::string get_attack_description_in_json(uint32_t client_ip, attack_details_t& current_attack) {
    json_object* jobj = json_object_new_object();

    json_object_object_add(jobj, "ip",
                           json_object_new_string(convert_ip_as_uint_to_string(client_ip).c_str()));
    json_object_object_add(jobj, "attack_details", serialize_attack_description_to_json(current_attack));

    if (enable_subnet_counters) {
        map_element_t network_speed_meter = PerSubnetSpeedMap[current_attack.customer_network];
        map_element_t average_network_speed_meter = PerSubnetAverageSpeedMap[current_attack.customer_network];

        json_object_object_add(jobj, "network_load", serialize_network_load_to_json(network_speed_meter));
        json_object_object_add(jobj, "network_average_load",
                               serialize_network_load_to_json(average_network_speed_meter));
    }

    // So we haven't statistic_counters here but from my point of view they are useless

    std::string json_as_text = json_object_to_json_string(jobj);

    // Free memory
    json_object_put(jobj);

    return json_as_text;
}

std::string generate_simple_packets_dump(std::vector<simple_packet_t>& ban_list_details) {
    std::stringstream attack_details;

    std::map<unsigned int, unsigned int> protocol_counter;
    for (std::vector<simple_packet_t>::iterator iii = ban_list_details.begin();
         iii != ban_list_details.end(); ++iii) {
        attack_details << print_simple_packet(*iii);

        protocol_counter[iii->protocol]++;
    }

    std::map<unsigned int, unsigned int>::iterator max_proto =
    std::max_element(protocol_counter.begin(), protocol_counter.end(), protocol_counter.value_comp());

    return attack_details.str();
}

void send_attack_details(uint32_t client_ip, attack_details_t current_attack_details) {
    std::string pps_as_string = convert_int_to_string(current_attack_details.attack_power);
    std::string attack_direction = get_direction_name(current_attack_details.attack_direction);
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

    // In this case we do not collect any traffic samples
    if (ban_details_records_count == 0) {
        return;
    }

    // Very strange code but it work in 95% cases
    if (ban_list_details.count(client_ip) > 0 && ban_list_details[client_ip].size() >= ban_details_records_count) {
        std::stringstream attack_details;

        attack_details << get_attack_description(client_ip, current_attack_details) << "\n\n";
        attack_details << generate_simple_packets_dump(ban_list_details[client_ip]);

        logger << log4cpp::Priority::INFO << "Attack with direction: " << attack_direction
               << " IP: " << client_ip_as_string << " Power: " << pps_as_string
               << " traffic samples collected";

        call_attack_details_handlers(client_ip, current_attack_details, attack_details.str());

        // TODO: here we have definitely RACE CONDITION!!! FIX IT

        // Remove key and prevent collection new data about this attack
        ban_list_details_mutex.lock();
        ban_list_details.erase(client_ip);
        ban_list_details_mutex.unlock();
    }
}

#ifdef ENABLE_DPI
// Parse raw binary stand-alone packet with nDPI
ndpi_protocol dpi_parse_packet(char* buffer,
                               uint32_t len,
                               uint32_t snap_len,
                               struct ndpi_id_struct* src,
                               struct ndpi_id_struct* dst,
                               struct ndpi_flow_struct* flow,
                               std::string& parsed_packet_as_string) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = snap_len;

    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0);

    uint32_t current_tickt = 0;
    uint8_t* iph = (uint8_t*)(&buffer[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);
    unsigned int ipsize = packet_header.len;

    ndpi_protocol detected_protocol =
    ndpi_detection_process_packet(my_ndpi_struct, flow, iph, ipsize, current_tickt, src, dst);

    // So bad approach :(
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);

    parsed_packet_as_string = std::string(print_buffer);

    return detected_protocol;
}
#endif

#ifdef ENABLE_DPI
void init_current_instance_of_ndpi() {
    my_ndpi_struct = init_ndpi();

    if (my_ndpi_struct == NULL) {
        logger << log4cpp::Priority::ERROR << "Can't load nDPI, disable it!";
        process_pcap_attack_dumps_with_dpi = false;

        return;
    }

    // Load sizes of main parsing structures
    ndpi_size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
}

// Zeroify nDPI structure without memory leaks
void zeroify_ndpi_flow(struct ndpi_flow_struct* flow) {
    if (flow->http.url) {
        ndpi_free(flow->http.url);
    }

    if (flow->http.content_type) {
        ndpi_free(flow->http.content_type);
    }

    memset(flow, 0, ndpi_size_flow_struct);
}

// Run flow spec mitigation rule
void launch_bgp_flow_spec_rule(amplification_attack_type_t attack_type, std::string client_ip_as_string) {
    logger << log4cpp::Priority::INFO
           << "We detected this attack as: " << get_amplification_attack_type(attack_type);

    std::string flow_spec_rule_text =
    generate_flow_spec_for_amplification_attack(attack_type, client_ip_as_string);

    logger << log4cpp::Priority::INFO
           << "We have generated BGP Flow Spec rule for this attack: " << flow_spec_rule_text;

    if (exabgp_flow_spec_announces) {
        active_flow_spec_announces_t::iterator itr = active_flow_spec_announces.find(flow_spec_rule_text);

        if (itr == active_flow_spec_announces.end()) {
            // We havent this flow spec rule active yet

            logger << log4cpp::Priority::INFO << "We will publish flow spec announce about this attack";
            bool exabgp_publish_result = exabgp_flow_spec_ban_manage("ban", flow_spec_rule_text);

            if (exabgp_publish_result) {
                active_flow_spec_announces[flow_spec_rule_text] = 1;
            }
        } else {
            // We have already blocked this attack
            logger << log4cpp::Priority::INFO << "The same rule was already sent to ExaBGP previously";
        }
    } else {
        logger << log4cpp::Priority::INFO << "exabgp_flow_spec_announces disabled. We will not talk to ExaBGP";
    }
}

// Not so pretty copy and paste from pcap_reader()
// TODO: rewrite to memory parser
void produce_dpi_dump_for_pcap_dump(std::string pcap_file_path, std::stringstream& ss, std::string client_ip_as_string) {
    int filedesc = open(pcap_file_path.c_str(), O_RDONLY);

    if (filedesc <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open file for DPI";
        return;
    }

    struct fastnetmon_pcap_file_header pcap_header;
    ssize_t file_header_readed_bytes =
    read(filedesc, &pcap_header, sizeof(struct fastnetmon_pcap_file_header));

    if (file_header_readed_bytes != sizeof(struct fastnetmon_pcap_file_header)) {
        logger << log4cpp::Priority::ERROR << "Can't read pcap file header";
        return;
    }

    // http://www.tcpdump.org/manpages/pcap-savefile.5.html
    if (pcap_header.magic == 0xa1b2c3d4 or pcap_header.magic == 0xd4c3b2a1) {
        // printf("Magic readed correctly\n");
    } else {
        logger << log4cpp::Priority::ERROR << "Magic in file header broken";
        return;
    }

    // Buffer for packets
    char packet_buffer[pcap_header.snaplen];

    unsigned int total_packets_number = 0;

    uint64_t dns_amplification_packets = 0;
    uint64_t ntp_amplification_packets = 0;
    uint64_t ssdp_amplification_packets = 0;
    uint64_t snmp_amplification_packets = 0;


    struct ndpi_id_struct* src = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    memset(src, 0, ndpi_size_id_struct);

    struct ndpi_id_struct* dst = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    memset(dst, 0, ndpi_size_id_struct);

    struct ndpi_flow_struct* flow = (struct ndpi_flow_struct*)malloc(ndpi_size_flow_struct);
    memset(flow, 0, ndpi_size_flow_struct);

    while (1) {
        struct fastnetmon_pcap_pkthdr pcap_packet_header;
        ssize_t packet_header_readed_bytes =
        read(filedesc, &pcap_packet_header, sizeof(struct fastnetmon_pcap_pkthdr));

        if (packet_header_readed_bytes != sizeof(struct fastnetmon_pcap_pkthdr)) {
            if (packet_header_readed_bytes != 0) {
                logger << log4cpp::Priority::INFO << "All packet read ? ("
                       << packet_header_readed_bytes << ", " << errno << ")";
            }
            // We haven't any packets
            break;
        }

        if (pcap_packet_header.incl_len > pcap_header.snaplen) {
            logger << log4cpp::Priority::ERROR << "Please enlarge packet buffer for DPI";
            return;
        }

        ssize_t packet_payload_readed_bytes = read(filedesc, packet_buffer, pcap_packet_header.incl_len);

        if (pcap_packet_header.incl_len != packet_payload_readed_bytes) {
            logger << log4cpp::Priority::ERROR << "I read packet header but can't read packet payload";
            return;
        }

        // The flow must be reset to zero state - in other case the DPI will not detect all packets properly.
        // To use flow properly there must be much more complicated code (with flow buffer for each flow probably)
        // following code is copied from ndpi_free_flow() just to be sure there will be no memory leaks due to memset()
        zeroify_ndpi_flow(flow);

        std::string parsed_packet_as_string;

        ndpi_protocol detected_protocol =
        dpi_parse_packet(packet_buffer, pcap_packet_header.orig_len, pcap_packet_header.incl_len,
                         src, dst, flow, parsed_packet_as_string);

#if NDPI_MAJOR >= 2
        u_int16_t app_protocol = detected_protocol.app_protocol;
#else
        u_int16_t app_protocol = detected_protocol.protocol;
#endif
        char* protocol_name = ndpi_get_proto_name(my_ndpi_struct, app_protocol);
        char* master_protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol);

        if (app_protocol == NDPI_PROTOCOL_DNS) {
            // It's answer for ANY request with so much
            if (flow->protos.dns.query_type == 255 &&
                flow->protos.dns.num_queries < flow->protos.dns.num_answers) {
                dns_amplification_packets++;
            }

        } else if (app_protocol == NDPI_PROTOCOL_NTP) {
            // Detect packets with type MON_GETLIST_1
            if (flow->protos.ntp.version == 2 && flow->protos.ntp.request_code == 42) {
                ntp_amplification_packets++;
            }
        } else if (app_protocol == NDPI_PROTOCOL_SSDP) {
            // So, this protocol completely unexpected in WAN networks
            ssdp_amplification_packets++;
        } else if (app_protocol == NDPI_PROTOCOL_SNMP) {
            // TODO: we need detailed tests for SNMP!
            snmp_amplification_packets++;
        }

        ss << parsed_packet_as_string << " protocol: " << protocol_name
           << " master_protocol: " << master_protocol_name << "\n";

        total_packets_number++;
    }

    // Free up all memory
    ndpi_free_flow(flow);
    free(dst);
    free(src);

    close(filedesc);

    logger << log4cpp::Priority::INFO << "DPI pkt stats: total:" << total_packets_number
           << " DNS:" << dns_amplification_packets << " NTP:" << ntp_amplification_packets
           << " SSDP:" << ssdp_amplification_packets << " SNMP:" << snmp_amplification_packets;

    amplification_attack_type_t attack_type;

    // Attack type in unknown by default
    attack_type = AMPLIFICATION_ATTACK_UNKNOWN;

    // Detect amplification attack type
    if ((double)dns_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_DNS, client_ip_as_string);
    } else if ((double)ntp_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_NTP, client_ip_as_string);
    } else if ((double)ssdp_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_SSDP, client_ip_as_string);
    } else if ((double)snmp_amplification_packets / (double)total_packets_number > 0.2) {
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_SNMP, client_ip_as_string);
    } else {
        /*TODO
            - full IP ban should be announced here !
            - and maybe some protocol/port based statistics could be used to filter new/unknown attacks...
        */

        logger
        << log4cpp::Priority::ERROR
        << "We can't detect attack type with DPI. It's not so critical, only for your information";
    }
}

#endif

void call_attack_details_handlers(uint32_t client_ip, attack_details_t& current_attack, std::string attack_fingerprint) {
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    std::string attack_direction = get_direction_name(current_attack.attack_direction);
    std::string pps_as_string = convert_int_to_string(current_attack.attack_power);

    // We place this variables here because we need this paths from DPI parser code
    std::string ban_timestamp_as_string = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    std::string attack_pcap_dump_path =
        fastnetmon_platform_configuration.attack_details_folder + "/" + client_ip_as_string + "_" + ban_timestamp_as_string + ".pcap";

    if (collect_attack_pcap_dumps) {
        int pcap_fump_filedesc = open(attack_pcap_dump_path.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (pcap_fump_filedesc <= 0) {
            logger << log4cpp::Priority::ERROR << "Can't open file for storing pcap dump: " << attack_pcap_dump_path;
        } else {
            ssize_t wrote_bytes =
            write(pcap_fump_filedesc, (void*)current_attack.pcap_attack_dump.get_buffer_pointer(),
                  current_attack.pcap_attack_dump.get_used_memory());

            if (wrote_bytes != current_attack.pcap_attack_dump.get_used_memory()) {
                logger << log4cpp::Priority::ERROR << "Can't wrote all attack details to the disk correctly";
            }

            close(pcap_fump_filedesc);

            // Freeup memory
            current_attack.pcap_attack_dump.deallocate_buffer();
        }
    }

#ifdef ENABLE_DPI
    // Yes, will be fine to read packets from the memory but we haven't this code yet
    // Thus we could read from file with not good performance because it's simpler
    if (collect_attack_pcap_dumps && process_pcap_attack_dumps_with_dpi) {
        std::stringstream string_buffer_for_dpi_data;

        string_buffer_for_dpi_data << "\n\nDPI\n\n";

        produce_dpi_dump_for_pcap_dump(attack_pcap_dump_path, string_buffer_for_dpi_data, client_ip_as_string);

        attack_fingerprint = attack_fingerprint + string_buffer_for_dpi_data.str();
    }
#endif

    print_attack_details_to_file(attack_fingerprint, client_ip_as_string, current_attack);

    // Pass attack details to script
    if (notify_script_enabled) {
        logger << log4cpp::Priority::INFO
               << "Call script for notify about attack details for: " << client_ip_as_string;

        std::string script_params = fastnetmon_platform_configuration.notify_script_path + " " + client_ip_as_string + " " +
                                    attack_direction + " " + pps_as_string + " attack_details";

        // We should execute external script in separate thread because any lag in this code
        // will be very distructive
        boost::thread exec_with_params_thread(exec_with_stdin_params, script_params, attack_fingerprint);
        exec_with_params_thread.detach();

        logger << log4cpp::Priority::INFO
               << "Script for notify about attack details is finished: " << client_ip_as_string;
    }

#ifdef REDIS
    if (redis_enabled) {
        std::string redis_key_name = client_ip_as_string + "_packets_dump";

        if (!redis_prefix.empty()) {
            redis_key_name = redis_prefix + "_" + client_ip_as_string + "_packets_dump";
        }

        logger << log4cpp::Priority::INFO << "Start data save in redis for key: " << redis_key_name;
        boost::thread redis_store_thread(store_data_in_redis, redis_key_name, attack_fingerprint);
        redis_store_thread.detach();
        logger << log4cpp::Priority::INFO << "Finish data save in redis for key: " << redis_key_name;
    }
#endif
}

uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash_t* struct_value) {
    uint64_t unpacked_data = 0;
    memcpy(&unpacked_data, struct_value, sizeof(uint64_t));
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
    for (contrack_map_type::iterator itr = conntrack_element.in_tcp.begin();
         itr != conntrack_element.in_tcp.end(); ++itr) {
        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash_t unpacked_key_struct;
        convert_integer_to_conntrack_hash_struct(&packed_connection_data, &unpacked_key_struct);

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
        logger << log4cpp::Priority::ERROR << "Can't execute programm " << cmd << " error code: " << errno
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
        logger << log4cpp::Priority::ERROR << "Can't pass data to stdin of programm " << cmd; 
        pclose(pipe);
        return false;
    }    

    return true;
}

// Get ban settings for this subnet or return global ban settings
ban_settings_t get_ban_settings_for_this_subnet(subnet_cidr_mask_t subnet, std::string& host_group_name) {
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
    host_group_ban_settings_map_t::iterator hostgroup_settings_itr =
    host_group_ban_settings_map.find(host_group_itr->second);

    if (hostgroup_settings_itr == host_group_ban_settings_map.end()) {
        logger << log4cpp::Priority::ERROR << "We can't find ban settings for host group "
               << host_group_itr->second;
        return global_ban_settings;
    }    

    // We found ban settings for this host group and use they instead global
    return hostgroup_settings_itr->second;
}

#ifdef REDIS
void store_data_in_redis(std::string key_name, std::string attack_details) {
    redisReply* reply = NULL;
    redisContext* redis_context = redis_init_connection();

    if (!redis_context) {
        logger << log4cpp::Priority::ERROR << "Could not initiate connection to Redis";
        return;
    }

    reply = (redisReply*)redisCommand(redis_context, "SET %s %s", key_name.c_str(), attack_details.c_str());

    // If we store data correctly ...
    if (!reply) {
        logger << log4cpp::Priority::ERROR
               << "Can't increment traffic in redis error_code: " << redis_context->err
               << " error_string: " << redis_context->errstr;

        // Handle redis server restart corectly
        if (redis_context->err == 1 or redis_context->err == 3) {
            // Connection refused
            logger << log4cpp::Priority::ERROR
                   << "Unfortunately we can't store data in Redis because server reject connection";
        }
    } else {
        freeReplyObject(reply);
    }

    redisFree(redis_context);
}

redisContext* redis_init_connection() {
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
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


void execute_ip_ban(uint32_t client_ip, map_element_t average_speed_element, std::string flow_attack_details, subnet_cidr_mask_t customer_subnet) {
    attack_details_t current_attack;
    uint64_t pps = 0;

    uint64_t in_pps = average_speed_element.in_packets;
    uint64_t out_pps = average_speed_element.out_packets;
    uint64_t in_bps = average_speed_element.in_bytes;
    uint64_t out_bps = average_speed_element.out_bytes;
    uint64_t in_flows = average_speed_element.in_flows;
    uint64_t out_flows = average_speed_element.out_flows;

    direction_t data_direction;

    if (!global_ban_settings.enable_ban) {
        logger << log4cpp::Priority::INFO << "We do not ban: " << convert_ip_as_uint_to_string(client_ip)
               << " because ban disabled completely";
        return;
    }

    // Detect attack direction with simple heuristic
    if (abs(int((int)in_pps - (int)out_pps)) < 1000) {
        // If difference between pps speed is so small we should do additional investigation using
        // bandwidth speed
        if (in_bps > out_bps) {
            data_direction = INCOMING;
            pps = in_pps;
        } else {
            data_direction = OUTGOING;
            pps = out_pps;
        }
    } else {
        if (in_pps > out_pps) {
            data_direction = INCOMING;
            pps = in_pps;
        } else {
            data_direction = OUTGOING;
            pps = out_pps;
        }
    }

    current_attack.attack_protocol = detect_attack_protocol(average_speed_element, data_direction);

    if (ban_list.count(client_ip) > 0) {
        if (ban_list[client_ip].attack_direction != data_direction) {
            logger << log4cpp::Priority::INFO << "We expected very strange situation: attack direction for "
                   << convert_ip_as_uint_to_string(client_ip) << " was changed";

            return;
        }

        // update attack power
        if (pps > ban_list[client_ip].max_attack_power) {
            ban_list[client_ip].max_attack_power = pps;
        }

        return;
    }

    prefix_t prefix_for_check_adreess;
    prefix_for_check_adreess.add.sin.s_addr = client_ip;
    prefix_for_check_adreess.family = AF_INET;
    prefix_for_check_adreess.bitlen = 32;

    bool in_white_list = (patricia_search_best2(whitelist_tree_ipv4, &prefix_for_check_adreess, 1) != NULL);

    if (in_white_list) {
        return;
    }

    std::string data_direction_as_string = get_direction_name(data_direction);

    logger << log4cpp::Priority::INFO << "We run execute_ip_ban code with following params "
           << " in_pps: " << in_pps << " out_pps: " << out_pps << " in_bps: " << in_bps
           << " out_bps: " << out_bps << " and we decide it's " << data_direction_as_string << " attack";

    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    std::string pps_as_string = convert_int_to_string(pps);

    // Store information about subnet
    current_attack.customer_network = customer_subnet;

    // Store ban time
    time(&current_attack.ban_timestamp);
    // set ban time in seconds
    current_attack.ban_time = global_ban_time;
    current_attack.unban_enabled = unban_enabled;

    // Pass main information about attack
    current_attack.attack_direction = data_direction;
    current_attack.attack_power = pps;
    current_attack.max_attack_power = pps;

    current_attack.in_packets = in_pps;
    current_attack.out_packets = out_pps;

    current_attack.in_bytes = in_bps;
    current_attack.out_bytes = out_bps;

    // pass flow information
    current_attack.in_flows = in_flows;
    current_attack.out_flows = out_flows;

    current_attack.fragmented_in_packets = average_speed_element.fragmented_in_packets;
    current_attack.tcp_in_packets = average_speed_element.tcp_in_packets;
    current_attack.tcp_syn_in_packets = average_speed_element.tcp_syn_in_packets;
    current_attack.udp_in_packets = average_speed_element.udp_in_packets;
    current_attack.icmp_in_packets = average_speed_element.icmp_in_packets;

    current_attack.fragmented_out_packets = average_speed_element.fragmented_out_packets;
    current_attack.tcp_out_packets = average_speed_element.tcp_out_packets;
    current_attack.tcp_syn_out_packets = average_speed_element.tcp_syn_out_packets;
    current_attack.udp_out_packets = average_speed_element.udp_out_packets;
    current_attack.icmp_out_packets = average_speed_element.icmp_out_packets;

    current_attack.fragmented_out_bytes = average_speed_element.fragmented_out_bytes;
    current_attack.tcp_out_bytes = average_speed_element.tcp_out_bytes;
    current_attack.tcp_syn_out_bytes = average_speed_element.tcp_syn_out_bytes;
    current_attack.udp_out_bytes = average_speed_element.udp_out_bytes;
    current_attack.icmp_out_bytes = average_speed_element.icmp_out_bytes;

    current_attack.fragmented_in_bytes = average_speed_element.fragmented_in_bytes;
    current_attack.tcp_in_bytes = average_speed_element.tcp_in_bytes;
    current_attack.tcp_syn_in_bytes = average_speed_element.tcp_syn_in_bytes;
    current_attack.udp_in_bytes = average_speed_element.udp_in_bytes;
    current_attack.icmp_in_bytes = average_speed_element.icmp_in_bytes;

    current_attack.average_in_packets = average_speed_element.in_packets;
    current_attack.average_in_bytes = average_speed_element.in_bytes;
    current_attack.average_in_flows = average_speed_element.in_flows;

    current_attack.average_out_packets = average_speed_element.out_packets;
    current_attack.average_out_bytes = average_speed_element.out_bytes;
    current_attack.average_out_flows = average_speed_element.out_flows;

    if (collect_attack_pcap_dumps) {
        bool buffer_allocation_result =
        current_attack.pcap_attack_dump.allocate_buffer(number_of_packets_for_pcap_attack_dump);

        if (!buffer_allocation_result) {
            logger << log4cpp::Priority::ERROR
                   << "Can't allocate buffer for attack, switch off this option completely ";
            collect_attack_pcap_dumps = false;
        }
    }

    ban_list_mutex.lock();
    ban_list[client_ip] = current_attack;
    ban_list_mutex.unlock();

    ban_list_details_mutex.lock();
    ban_list_details[client_ip] = std::vector<simple_packet_t>();
    ban_list_details_mutex.unlock();

    logger << log4cpp::Priority::INFO << "Attack with direction: " << data_direction_as_string
           << " IP: " << client_ip_as_string << " Power: " << pps_as_string;

    subnet_ipv6_cidr_mask_t zero_ipv6_address;

    boost::circular_buffer<simple_packet_t> empty_simple_packets_buffer;

    call_ban_handlers(client_ip, zero_ipv6_address, false, ban_list[client_ip], flow_attack_details, attack_detection_source_t::Automatic, "", empty_simple_packets_buffer);
}

void call_ban_handlers(uint32_t client_ip,
                       subnet_ipv6_cidr_mask_t client_ipv6,
                       bool ipv6,
                       attack_details_t& current_attack,
                       std::string flow_attack_details,
                       attack_detection_source_t attack_detection_source,
                       std::string simple_packets_dump,
                       boost::circular_buffer<simple_packet_t>& simple_packets_buffer) {
    
    bool ipv4 = !ipv6;
    std::string client_ip_as_string = "";

    if (ipv4) {
        client_ip_as_string = convert_ip_as_uint_to_string(client_ip);
    } else {
        client_ip_as_string = print_ipv6_address(client_ipv6.subnet_address);
    }


    std::string pps_as_string = convert_int_to_string(current_attack.attack_power);
    std::string data_direction_as_string = get_direction_name(current_attack.attack_direction);

    bool store_attack_details_to_file = true;

    std::string basic_attack_information = get_attack_description(client_ip, current_attack);

    std::string basic_attack_information_in_json = get_attack_description_in_json(client_ip, current_attack);

    std::string full_attack_description = basic_attack_information + flow_attack_details;

    if (store_attack_details_to_file && ipv4) {
        print_attack_details_to_file(full_attack_description, client_ip_as_string, current_attack);
    }

    if (notify_script_enabled) {
        std::string script_call_params = fastnetmon_platform_configuration.notify_script_path + " " + client_ip_as_string + " " +
                                         data_direction_as_string + " " + pps_as_string + " " + "ban";
        logger << log4cpp::Priority::INFO << "Call script for ban client: " << client_ip_as_string;

        // We should execute external script in separate thread because any lag in this code will be
        // very distructive

        if (notify_script_pass_details) {
            // We will pass attack details over stdin
            boost::thread exec_thread(exec_with_stdin_params, script_call_params, full_attack_description);
            exec_thread.detach();
        } else {
            // Do not pass anything to script
            boost::thread exec_thread(exec, script_call_params);
            exec_thread.detach();
        }

        logger << log4cpp::Priority::INFO << "Script for ban client is finished: " << client_ip_as_string;
    }

    if (exabgp_enabled && ipv4) {
        logger << log4cpp::Priority::INFO << "Call ExaBGP for ban client started: " << client_ip_as_string;

        boost::thread exabgp_thread(exabgp_ban_manage, "ban", client_ip_as_string, current_attack);
        exabgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to ExaBGP for ban client is finished: " << client_ip_as_string;
    }

#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call GoBGP for ban client started: " << client_ip_as_string;

        boost::thread gobgp_thread(gobgp_ban_manage, "ban", ipv6, client_ip_as_string, client_ipv6,  current_attack);
        gobgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to GoBGP for ban client is finished: " << client_ip_as_string;
    }
#endif

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

#ifdef MONGO
    if (mongodb_enabled && ipv4) {
        std::string mongo_key_name = client_ip_as_string + "_information_" +
                                     print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);

        // We could not use dot in key names: http://docs.mongodb.org/manual/core/document/#dot-notation
        std::replace(mongo_key_name.begin(), mongo_key_name.end(), '.', '_');

        logger << log4cpp::Priority::INFO << "Start data save in Mongo in key: " << mongo_key_name;
        boost::thread mongo_store_thread(store_data_in_mongo, mongo_key_name, basic_attack_information_in_json);
        mongo_store_thread.detach();
        logger << log4cpp::Priority::INFO << "Finish data save in Mongo in key: " << mongo_key_name;
    }
#endif
}


#ifdef MONGO
void store_data_in_mongo(std::string key_name, std::string attack_details_json) {
    mongoc_client_t* client;
    mongoc_collection_t* collection;
    mongoc_cursor_t* cursor;
    bson_error_t error;
    bson_oid_t oid;
    bson_t* doc;

    mongoc_init();

    std::string collection_name = "attacks";
    std::string connection_string =
    "mongodb://" + mongodb_host + ":" + convert_int_to_string(mongodb_port) + "/";

    client = mongoc_client_new(connection_string.c_str());

    if (!client) {
        logger << log4cpp::Priority::ERROR << "Can't connect to MongoDB database";
        return;
    }

    bson_error_t bson_from_json_error;
    bson_t* bson_data = bson_new_from_json((const uint8_t*)attack_details_json.c_str(),
                                           attack_details_json.size(), &bson_from_json_error);
    if (!bson_data) {
        logger << log4cpp::Priority::ERROR << "Could not convert JSON to BSON";
        return;
    }

    // logger << log4cpp::Priority::INFO << bson_as_json(bson_data, NULL);

    collection =
    mongoc_client_get_collection(client, mongodb_database_name.c_str(), collection_name.c_str());

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
    uint64_t speed_in_pps = total_speed_average_counters[packet_direction].packets;
    uint64_t speed_in_bps = total_speed_average_counters[packet_direction].bytes;

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

    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    sort_type_t sorter;
    if (sort_parameter == "packets") {
        sorter = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter = BYTES;
    } else if (sort_parameter == "flows") {
        sorter = FLOWS;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter = PACKETS;
    }    

    output_buffer << "FastNetMon " << fastnetmon_platform_configuration.fastnetmon_version << " Try Advanced edition: https://fastnetmon.com"
                  << "\n" 
                  << "IPs ordered by: " << sort_parameter << "\n";

    output_buffer << print_channel_speed_ipv6("Incoming traffic", INCOMING) << std::endl;

    if (process_incoming_traffic) {
        output_buffer << draw_table_ipv6(INCOMING, true, sorter);
        output_buffer << std::endl;
    }    

    output_buffer << print_channel_speed_ipv6("Outgoing traffic", OUTGOING) << std::endl;

    if (process_outgoing_traffic) {
        output_buffer << draw_table_ipv6(OUTGOING, false, sorter);
        output_buffer << std::endl;
    }    

    output_buffer << print_channel_speed_ipv6("Internal traffic", INTERNAL) << std::endl;

    output_buffer << std::endl;

    output_buffer << print_channel_speed_ipv6("Other traffic", OTHER) << std::endl;

    output_buffer << std::endl;

   if (enable_subnet_counters) {
        output_buffer << std::endl << "Subnet load:" << std::endl;
        output_buffer << print_subnet_ipv6_load() << "\n";
    }

    // Print screen contents into file
    print_screen_contents_into_file(output_buffer.str(), cli_stats_ipv6_file_path);
}

std::string print_subnet_ipv6_load() {
    std::stringstream buffer;

    sort_type_t sorter_type;
    if (sort_parameter == "packets") {
        sorter_type = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter_type = BYTES;
    } else if (sort_parameter == "flows") {
        sorter_type = FLOWS;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter_type = PACKETS;
    }    

    direction_t sort_direction = OUTGOING;

    std::vector<pair_of_map_for_ipv6_subnet_counters_elements_t> vector_for_sort;
    ipv6_subnet_counters.get_sorted_average_speed(vector_for_sort, sorter_type, sort_direction);


    for (std::vector<pair_of_map_for_ipv6_subnet_counters_elements_t>::iterator itr = vector_for_sort.begin();
         itr != vector_for_sort.end(); ++itr) {
        map_element_t* speed = &itr->second;
        std::string subnet_as_string = print_ipv6_cidr_subnet(itr->first);

        buffer << std::setw(42) << std::left << subnet_as_string;
        
        buffer << " "
               << "pps in: " << std::setw(8) << speed->in_packets << " out: " << std::setw(8)
               << speed->out_packets << " mbps in: " << std::setw(5) << convert_speed_to_mbps(speed->in_bytes)
               << " out: " << std::setw(5) << convert_speed_to_mbps(speed->out_bytes) << "\n";
    }

    return buffer.str();
}

void traffic_draw_ipv4_program() {
    std::stringstream output_buffer;

    // logger<<log4cpp::Priority::INFO<<"Draw table call";

    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    sort_type_t sorter;
    if (sort_parameter == "packets") {
        sorter = PACKETS;
    } else if (sort_parameter == "bytes") {
        sorter = BYTES;
    } else if (sort_parameter == "flows") {
        sorter = FLOWS;
    } else {
        logger << log4cpp::Priority::INFO << "Unexpected sorter type: " << sort_parameter;
        sorter = PACKETS;
    }

    output_buffer << "FastNetMon " << fastnetmon_platform_configuration.fastnetmon_version << " Try Advanced edition: https://fastnetmon.com"
                  << "\n"
                  << "IPs ordered by: " << sort_parameter << "\n";

    output_buffer << print_channel_speed("Incoming traffic", INCOMING) << std::endl;

    if (process_incoming_traffic) {
        output_buffer << draw_table_ipv4(INCOMING, true, sorter);
        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed("Outgoing traffic", OUTGOING) << std::endl;

    if (process_outgoing_traffic) {
        output_buffer << draw_table_ipv4(OUTGOING, false, sorter);
        output_buffer << std::endl;
    }

    output_buffer << print_channel_speed("Internal traffic", INTERNAL) << std::endl;

    output_buffer << std::endl;

    output_buffer << print_channel_speed("Other traffic", OTHER) << std::endl;

    output_buffer << std::endl;

    // Application statistics
    output_buffer << "Screen updated in:\t\t" << drawing_thread_execution_time.tv_sec << " sec "
                  << drawing_thread_execution_time.tv_usec << " microseconds\n";

    output_buffer << "Traffic calculated in:\t\t" << speed_calculation_time.tv_sec << " sec "
                  << speed_calculation_time.tv_usec << " microseconds\n";

    if (speed_calculation_time.tv_sec > 0) {
        output_buffer
        << "ALERT! Toolkit working incorrectly! We should calculate speed in ~1 second\n";
    }

    output_buffer << "Not processed packets: " << total_unparsed_packets_speed << " pps\n";

    // Print backend stats
    if (enable_pcap_collection) {
        output_buffer << get_pcap_stats() << "\n";
    }

#ifdef PF_RING
    if (enable_data_collection_from_mirror) {
        output_buffer << get_pf_ring_stats();
    }
#endif

    if (!ban_list.empty()) {
        output_buffer << std::endl << "Ban list:" << std::endl;
        output_buffer << print_ddos_attack_details();
    }

    if (enable_subnet_counters) {
        output_buffer << std::endl << "Subnet load:" << std::endl;
        output_buffer << print_subnet_ipv4_load() << "\n";
    }

    // Print screen contents into file
    print_screen_contents_into_file(output_buffer.str(), cli_stats_file_path);

    struct timeval end_calc_time;
    gettimeofday(&end_calc_time, NULL);

    timeval_subtract(&drawing_thread_execution_time, &end_calc_time, &start_calc_time);
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
bool fill_attack_information(map_element_t average_speed_element,
                             attack_details_t& current_attack,
                             std::string& host_group_name,
                             std::string& parent_host_group_name,
                             bool unban_enabled,
                             int ban_time) {
    uint64_t pps = 0;

    uint64_t in_pps    = average_speed_element.in_packets;
    uint64_t out_pps   = average_speed_element.out_packets;
    uint64_t in_bps    = average_speed_element.in_bytes;
    uint64_t out_bps   = average_speed_element.out_bytes;
    uint64_t in_flows  = average_speed_element.in_flows;
    uint64_t out_flows = average_speed_element.out_flows;

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

    current_attack.attack_protocol = detect_attack_protocol(average_speed_element, data_direction);

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

    current_attack.in_packets  = in_pps;
    current_attack.out_packets = out_pps;

    current_attack.in_bytes  = in_bps;
    current_attack.out_bytes = out_bps;

    // pass flow information
    current_attack.in_flows  = in_flows;
    current_attack.out_flows = out_flows;

    current_attack.fragmented_in_packets = average_speed_element.fragmented_in_packets;
    current_attack.tcp_in_packets        = average_speed_element.tcp_in_packets;
    current_attack.tcp_syn_in_packets    = average_speed_element.tcp_syn_in_packets;
    current_attack.udp_in_packets        = average_speed_element.udp_in_packets;
    current_attack.icmp_in_packets       = average_speed_element.icmp_in_packets;

    current_attack.fragmented_out_packets = average_speed_element.fragmented_out_packets;
    current_attack.tcp_out_packets        = average_speed_element.tcp_out_packets;
    current_attack.tcp_syn_out_packets    = average_speed_element.tcp_syn_out_packets;
    current_attack.udp_out_packets        = average_speed_element.udp_out_packets;
    current_attack.icmp_out_packets       = average_speed_element.icmp_out_packets;

    current_attack.fragmented_out_bytes = average_speed_element.fragmented_out_bytes;
    current_attack.tcp_out_bytes        = average_speed_element.tcp_out_bytes;
    current_attack.tcp_syn_out_bytes    = average_speed_element.tcp_syn_out_bytes;
    current_attack.udp_out_bytes        = average_speed_element.udp_out_bytes;
    current_attack.icmp_out_bytes       = average_speed_element.icmp_out_bytes;

    current_attack.fragmented_in_bytes = average_speed_element.fragmented_in_bytes;
    current_attack.tcp_in_bytes        = average_speed_element.tcp_in_bytes;
    current_attack.tcp_syn_in_bytes    = average_speed_element.tcp_syn_in_bytes;
    current_attack.udp_in_bytes        = average_speed_element.udp_in_bytes;
    current_attack.icmp_in_bytes       = average_speed_element.icmp_in_bytes;

    current_attack.average_in_packets = average_speed_element.in_packets;
    current_attack.average_in_bytes   = average_speed_element.in_bytes;
    current_attack.average_in_flows   = average_speed_element.in_flows;

    current_attack.average_out_packets = average_speed_element.out_packets;
    current_attack.average_out_bytes   = average_speed_element.out_bytes;
    current_attack.average_out_flows   = average_speed_element.out_flows;

    return true;
}


// Speed recalculation function for IPv6 hosts calls it for each host during speed recalculation
void speed_callback_ipv6(subnet_ipv6_cidr_mask_t* current_subnet, map_element_t* current_average_speed_element) {
    // We should check thresholds only for per host counters for IPv6 and only when any ban actions for IPv6 traffic were enabled
    if (!global_ban_settings.enable_ban_ipv6) {
        return;
    }    

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
    bool in_white_list = ip_belongs_to_patricia_tree_ipv6(whitelist_tree_ipv6, current_subnet->subnet_address);

    if (in_white_list) {
        // logger << log4cpp::Priority::INFO << "This IP was whitelisted";
        return;
    }    

    bool we_already_have_buckets_for_this_ip = packet_buckets_ipv6_storage.we_have_bucket_for_this_ip(*current_subnet);

    if (we_already_have_buckets_for_this_ip) {
        return;
    }    

    bool this_ip_is_already_banned = ban_list_ipv6_ng.is_blackholed(*current_subnet);

    if (this_ip_is_already_banned) {
        return;
    }    

    std::string ddos_detection_threshold_as_string = get_human_readable_threshold_type(attack_detection_source);

    logger << log4cpp::Priority::INFO << "We have detected IPv6 attack for " << print_ipv6_cidr_subnet(*current_subnet)
           << " with " << ddos_detection_threshold_as_string << " threshold host group: " << host_group_name;

    std::string parent_group;

    attack_details_t attack_details;
    fill_attack_information(*current_average_speed_element, attack_details, host_group_name, parent_group,
            unban_enabled, global_ban_time);

	attack_details.ipv6 = true;
    // TODO: Also, we should find IPv6 network for attack here

    bool enable_backet_capture =
        packet_buckets_ipv6_storage.enable_packet_capture(*current_subnet, attack_details, collection_pattern_t::ONCE);

    if (!enable_backet_capture) {
        logger << log4cpp::Priority::ERROR << "Could not enable packet capture for deep analytics for IPv6 "
               << print_ipv6_cidr_subnet(*current_subnet);
        return;
    }

    logger << log4cpp::Priority::INFO << "Enabled packet capture for IPv6 " << print_ipv6_address(current_subnet->subnet_address);
}


// Speed recalculation function for IPv6 networks
// It's just stub, we do not execute any actions for it
void speed_callback_subnet_ipv6(subnet_ipv6_cidr_mask_t* subnet, map_element_t* speed_element) {
    return;
}


/* Calculate speed for all connnections */
void recalculate_speed() {
    // logger<< log4cpp::Priority::INFO<<"We run recalculate_speed";

    struct timeval start_calc_time;
    gettimeofday(&start_calc_time, NULL);

    double speed_calc_period = recalculate_speed_timeout;
    time_t start_time;
    time(&start_time);

    // If we got 1+ seconds lag we should use new "delta" or skip this step
    double time_difference = difftime(start_time, last_call_of_traffic_recalculation);

    if (time_difference < 0) {
        // It may happen when you adjust time
        logger << log4cpp::Priority::ERROR << "Negative delay for traffic calculation " << time_difference << " Skipped iteration";
        return;
    } else if (time_difference < recalculate_speed_timeout) {
        // It could occur on toolkit start or in some weird cases of Linux scheduler
        // I really saw cases when sleep executed in zero zeconds:
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

    map_element_t zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    uint64_t incoming_total_flows = 0;
    uint64_t outgoing_total_flows = 0;

    if (enable_subnet_counters) {
        for (map_for_subnet_counters_t::iterator itr = PerSubnetSpeedMap.begin();
             itr != PerSubnetSpeedMap.end(); ++itr) {
            subnet_cidr_mask_t current_subnet = itr->first;

            map_for_subnet_counters_t::iterator iter_subnet = PerSubnetCountersMap.find(current_subnet);

            if (iter_subnet == PerSubnetCountersMap.end()) {
                logger << log4cpp::Priority::INFO << "Can't find traffic counters for subnet";
                break;
            }

            subnet_counter_t* subnet_traffic = &iter_subnet->second;

            subnet_counter_t new_speed_element;

            new_speed_element.in_packets = uint64_t((double)subnet_traffic->in_packets / speed_calc_period);
            new_speed_element.in_bytes = uint64_t((double)subnet_traffic->in_bytes / speed_calc_period);

            new_speed_element.out_packets = uint64_t((double)subnet_traffic->out_packets / speed_calc_period);
            new_speed_element.out_bytes = uint64_t((double)subnet_traffic->out_bytes / speed_calc_period);

            /* Moving average recalculation for subnets */
            /* http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance */
            double exp_power_subnet = -speed_calc_period / average_calculation_amount_for_subnets;
            double exp_value_subnet = exp(exp_power_subnet);

            map_element_t* current_average_speed_element = &PerSubnetAverageSpeedMap[current_subnet];

            current_average_speed_element->in_bytes = uint64_t(
            new_speed_element.in_bytes + exp_value_subnet * ((double)current_average_speed_element->in_bytes -
                                                             (double)new_speed_element.in_bytes));

            current_average_speed_element->out_bytes = uint64_t(
            new_speed_element.out_bytes + exp_value_subnet * ((double)current_average_speed_element->out_bytes -
                                                              (double)new_speed_element.out_bytes));

            current_average_speed_element->in_packets = uint64_t(
            new_speed_element.in_packets + exp_value_subnet * ((double)current_average_speed_element->in_packets -
                                                               (double)new_speed_element.in_packets));

            current_average_speed_element->out_packets =
            uint64_t(new_speed_element.out_packets +
                     exp_value_subnet * ((double)current_average_speed_element->out_packets -
                                         (double)new_speed_element.out_packets));

            // Update speed calculation structure
            PerSubnetSpeedMap[current_subnet] = new_speed_element;
            *subnet_traffic = zero_map_element;

            // logger << log4cpp::Priority::INFO<<convert_subnet_to_string(current_subnet)
            //    << "in pps: " << new_speed_element.in_packets << " out pps: " << new_speed_element.out_packets;
        }
    }

    for (map_of_vector_counters_t::iterator itr = SubnetVectorMap.begin(); itr != SubnetVectorMap.end(); ++itr) {
        for (vector_of_counters::iterator vector_itr = itr->second.begin();
             vector_itr != itr->second.end(); ++vector_itr) {
            int current_index = vector_itr - itr->second.begin();

            // New element
            map_element_t new_speed_element;

            // convert to host order for math operations
            uint32_t subnet_ip = ntohl(itr->first.subnet_address);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);

            // Calculate speed for IP or whole subnet
            build_speed_counters_from_packet_counters(new_speed_element, &*vector_itr, speed_calc_period);

            conntrack_main_struct_t* flow_counter_ptr = &SubnetVectorMapFlow[itr->first][current_index];

            if (enable_connection_tracking) {
                // todo: optimize this operations!
                // it's really bad and SLOW CODE
                uint64_t total_out_flows = (uint64_t)flow_counter_ptr->out_tcp.size() +
                                           (uint64_t)flow_counter_ptr->out_udp.size() +
                                           (uint64_t)flow_counter_ptr->out_icmp.size() +
                                           (uint64_t)flow_counter_ptr->out_other.size();

                uint64_t total_in_flows =
                (uint64_t)flow_counter_ptr->in_tcp.size() + (uint64_t)flow_counter_ptr->in_udp.size() +
                (uint64_t)flow_counter_ptr->in_icmp.size() + (uint64_t)flow_counter_ptr->in_other.size();

                new_speed_element.out_flows = uint64_t((double)total_out_flows / speed_calc_period);
                new_speed_element.in_flows = uint64_t((double)total_in_flows / speed_calc_period);

                // Increment global counter
                outgoing_total_flows += new_speed_element.out_flows;
                incoming_total_flows += new_speed_element.in_flows;
            } else {
                new_speed_element.out_flows = 0;
                new_speed_element.in_flows = 0;
            }

            /* Moving average recalculation */
            // http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance
            // double speed_calc_period = 1;
            double exp_power = -speed_calc_period / average_calculation_amount;
            double exp_value = exp(exp_power);

            map_element_t* current_average_speed_element = &SubnetVectorMapSpeedAverage[itr->first][current_index];

            // Calculate average speed from per-second speed
            build_average_speed_counters_from_speed_counters(current_average_speed_element,
                                                             new_speed_element, exp_value, exp_power);

            if (enable_connection_tracking) {
                current_average_speed_element->out_flows = uint64_t(
                new_speed_element.out_flows + exp_value * ((double)current_average_speed_element->out_flows -
                                                           (double)new_speed_element.out_flows));

                current_average_speed_element->in_flows = uint64_t(
                new_speed_element.in_flows + exp_value * ((double)current_average_speed_element->in_flows -
                                                          (double)new_speed_element.in_flows));
            }

            /* Moving average recalculation end */
            std::string host_group_name;
            ban_settings_t current_ban_settings = get_ban_settings_for_this_subnet(itr->first, host_group_name);

            attack_detection_threshold_type_t attack_detection_source;
            attack_detection_direction_type_t attack_detection_direction;


            if (we_should_ban_this_entity(current_average_speed_element, current_ban_settings, attack_detection_source, attack_detection_direction)) {
                logger << log4cpp::Priority::DEBUG
                       << "We have found host group for this host as: " << host_group_name;

                std::string flow_attack_details = "";

                if (enable_connection_tracking) {
                    flow_attack_details =
                    print_flow_tracking_for_ip(*flow_counter_ptr, convert_ip_as_uint_to_string(client_ip));
                }

                // TODO: we should pass type of ddos ban source (pps, flowd, bandwidth)!
                execute_ip_ban(client_ip, *current_average_speed_element, flow_attack_details, itr->first);
            }

            SubnetVectorMapSpeed[itr->first][current_index] = new_speed_element;

            *vector_itr = zero_map_element;
        }
    }

    // Calculate IPv6 trafffic
    if (enable_subnet_counters) {
        ipv6_subnet_counters.recalculate_speed(speed_calc_period, (double)average_calculation_amount_for_subnets,
            speed_callback_subnet_ipv6);
    }

    // Recalculate traffic for hosts
    ipv6_host_counters.recalculate_speed(speed_calc_period, (double)average_calculation_amount,
        speed_callback_ipv6);


    // Calculate global flow speed
    incoming_total_flows_speed = uint64_t((double)incoming_total_flows / (double)speed_calc_period);
    outgoing_total_flows_speed = uint64_t((double)outgoing_total_flows / (double)speed_calc_period);

    if (enable_connection_tracking) {
        // Clean Flow Counter
        flow_counter.lock();
        zeroify_all_flow_counters();
        flow_counter.unlock();
    }

    total_unparsed_packets_speed = uint64_t((double)total_unparsed_packets / (double)speed_calc_period);
    total_unparsed_packets = 0;

    for (unsigned int index = 0; index < 4; index++) {
        total_speed_counters[index].bytes =
        uint64_t((double)total_counters[index].bytes / (double)speed_calc_period);

        total_speed_counters[index].packets =
        uint64_t((double)total_counters[index].packets / (double)speed_calc_period);

        double exp_power = -speed_calc_period / average_calculation_amount;
        double exp_value = exp(exp_power);

        total_speed_average_counters[index].bytes = uint64_t(
        total_speed_counters[index].bytes + exp_value * ((double)total_speed_average_counters[index].bytes -
                                                         (double)total_speed_counters[index].bytes));

        total_speed_average_counters[index].packets =
        uint64_t(total_speed_counters[index].packets +
                 exp_value * ((double)total_speed_average_counters[index].packets -
                              (double)total_speed_counters[index].packets));

        // nullify data counters after speed calculation
        total_counters[index].bytes = 0;
        total_counters[index].packets = 0;
    }

    // Do same for IPv6
	for (unsigned int index = 0; index < 4; index++) {
		total_speed_counters_ipv6[index].bytes = uint64_t((double)total_counters_ipv6[index].bytes / (double)speed_calc_period);
		total_speed_counters_ipv6[index].packets =
			uint64_t((double)total_counters_ipv6[index].packets / (double)speed_calc_period);

		double exp_power = -speed_calc_period / average_calculation_amount;
		double exp_value = exp(exp_power);

		total_speed_average_counters_ipv6[index].bytes = uint64_t(
			total_speed_counters_ipv6[index].bytes + exp_value * ((double)total_speed_average_counters_ipv6[index].bytes -
																  (double)total_speed_counters_ipv6[index].bytes));

		total_speed_average_counters_ipv6[index].packets = uint64_t(
			total_speed_counters_ipv6[index].packets + exp_value * ((double)total_speed_average_counters_ipv6[index].packets -
																	(double)total_speed_counters_ipv6[index].packets));

		// nullify data counters after speed calculation
		total_counters_ipv6[index].zeroify();
	}

    // Set time of previous startup
    time(&last_call_of_traffic_recalculation);

    struct timeval finish_calc_time;
    gettimeofday(&finish_calc_time, NULL);

    timeval_subtract(&speed_calculation_time, &finish_calc_time, &start_calc_time);
}

std::string draw_table_ipv6(direction_t sort_direction, bool do_redis_update, sort_type_t sorter_type) {
 	std::vector<pair_of_map_for_ipv6_subnet_counters_elements_t> vector_for_sort;
    ssize_t size_of_ipv6_counters_map = 0; 
    std::stringstream output_buffer;

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

        uint64_t pps = 0; 
        uint64_t bps = 0; 
        uint64_t flows = 0; 

        uint64_t pps_average = 0; 
        uint64_t bps_average = 0; 
        uint64_t flows_average = 0; 

        // Here we could have average or instantaneous speed
        map_element_t* current_speed_element = &ii->second;

        // Create polymorphic pps, byte and flow counters
        if (sort_direction == INCOMING) {
            pps = current_speed_element->in_packets;
            bps = current_speed_element->in_bytes;
            flows = current_speed_element->in_flows;
        } else if (sort_direction == OUTGOING) {
            pps = current_speed_element->out_packets;
            bps = current_speed_element->out_bytes;
            flows = current_speed_element->out_flows;
        }

        uint64_t mbps = convert_speed_to_mbps(bps);
        uint64_t mbps_average = convert_speed_to_mbps(bps_average);


        // We use setw for alignment
        output_buffer << client_ip_as_string << "\t";

        std::string is_banned = ban_list_ipv6_ng.is_blackholed(ii->first) ? " *banned* " : "";

        output_buffer << std::setw(6) << pps << " pps ";
        output_buffer << std::setw(6) << mbps << " mbps ";
        output_buffer << std::setw(6) << flows << " flows ";

        output_buffer << is_banned <<  std::endl;
    }

    return output_buffer.str();
}

std::string draw_table_ipv4(direction_t data_direction, bool do_redis_update, sort_type_t sort_item) {
    std::vector<pair_of_map_elements> vector_for_sort;

    std::stringstream output_buffer;

    // Preallocate memory for sort vector
    // We use total networks size for this vector
    vector_for_sort.reserve(total_number_of_hosts_in_our_networks);

    // Switch to Average speed there!!!
    map_of_vector_counters_t* current_speed_map = NULL;

    if (print_average_traffic_counts) {
        current_speed_map = &SubnetVectorMapSpeedAverage;
    } else {
        current_speed_map = &SubnetVectorMapSpeed;
    }

    map_element_t zero_map_element;
    memset(&zero_map_element, 0, sizeof(zero_map_element));

    unsigned int count_of_zero_speed_packets = 0;
    for (map_of_vector_counters_t::iterator itr = current_speed_map->begin();
         itr != current_speed_map->end(); ++itr) {
        for (vector_of_counters::iterator vector_itr = itr->second.begin();
             vector_itr != itr->second.end(); ++vector_itr) {
            int current_index = vector_itr - itr->second.begin();

            // convert to host order for math operations
            uint32_t subnet_ip = ntohl(itr->first.subnet_address);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);

            // Do not add zero speed packets to sort list
            if (memcmp((void*)&zero_map_element, &*vector_itr, sizeof(map_element_t)) != 0) {
                vector_for_sort.push_back(std::make_pair(client_ip, *vector_itr));
            } else {
                count_of_zero_speed_packets++;
            }
        }
    }

    // Sort only first X elements in this vector
    unsigned int shift_for_sort = max_ips_in_list;

    if (data_direction == INCOMING or data_direction == OUTGOING) {
        // Because in another case we will got segmentation fault
        unsigned int vector_size = vector_for_sort.size();

        if (vector_size < shift_for_sort) {
            shift_for_sort = vector_size;
        }

        std::partial_sort(vector_for_sort.begin(), vector_for_sort.begin() + shift_for_sort,
                          vector_for_sort.end(),
                          TrafficComparatorClass<pair_of_map_elements>(data_direction, sort_item));
    } else {
        logger << log4cpp::Priority::ERROR << "Unexpected bahaviour on sort function";
        return "Internal error";
    }

    unsigned int element_number = 0;

    // In this loop we print only top X talkers in our subnet to screen buffer
    for (std::vector<pair_of_map_elements>::iterator ii = vector_for_sort.begin();
         ii != vector_for_sort.end(); ++ii) {
        // Print first max_ips_in_list elements in list, we will show top X "huge" channel loaders
        if (element_number >= max_ips_in_list) {
            break;
        }

        uint32_t client_ip = (*ii).first;
        std::string client_ip_as_string = convert_ip_as_uint_to_string((*ii).first);

        uint64_t pps = 0;
        uint64_t bps = 0;
        uint64_t flows = 0;

        uint64_t pps_average = 0;
        uint64_t bps_average = 0;
        uint64_t flows_average = 0;

        // Here we could have average or instantaneous speed
        map_element_t* current_speed_element = &ii->second;

        // Create polymorphic pps, byte and flow counters
        if (data_direction == INCOMING) {
            pps = current_speed_element->in_packets;
            bps = current_speed_element->in_bytes;
            flows = current_speed_element->in_flows;
        } else if (data_direction == OUTGOING) {
            pps = current_speed_element->out_packets;
            bps = current_speed_element->out_bytes;
            flows = current_speed_element->out_flows;
        }

        uint64_t mbps = convert_speed_to_mbps(bps);
        uint64_t mbps_average = convert_speed_to_mbps(bps_average);

        std::string is_banned = ban_list.count(client_ip) > 0 ? " *banned* " : "";

        // We use setw for alignment
        output_buffer << client_ip_as_string << "\t\t";

        output_buffer << std::setw(6) << pps << " pps ";
        output_buffer << std::setw(6) << mbps << " mbps ";
        output_buffer << std::setw(6) << flows << " flows ";

        output_buffer << is_banned << std::endl;

        element_number++;
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
    // On creating it initilizes by zeros
    conntrack_main_struct_t zero_conntrack_main_struct;

    // Iterate over map
    for (map_of_vector_counters_for_flow_t::iterator itr = SubnetVectorMapFlow.begin();
         itr != SubnetVectorMapFlow.end(); ++itr) {
        // Iterate over vector
        for (vector_of_flow_counters_t::iterator vector_iterator = itr->second.begin();
             vector_iterator != itr->second.end(); ++vector_iterator) {
            // TODO: rewrite this monkey code
            vector_iterator->in_tcp.clear();
            vector_iterator->in_udp.clear();
            vector_iterator->in_icmp.clear();
            vector_iterator->in_other.clear();

            vector_iterator->out_tcp.clear();
            vector_iterator->out_udp.clear();
            vector_iterator->out_icmp.clear();
            vector_iterator->out_other.clear();
        }
    }
}

/* Process simple unified packet */
void process_packet(simple_packet_t& current_packet) {
    // Packets dump is very useful for bug hunting
    if (DEBUG_DUMP_ALL_PACKETS) {
        logger << log4cpp::Priority::INFO << "Dump: " << print_simple_packet(current_packet);
    }

    // Increment counter about total number of packets processes here
    __sync_fetch_and_add(&total_simple_packets_processed, 1);

    if (current_packet.ip_protocol_version == 4) { 
        __sync_fetch_and_add(&total_ipv4_packets, 1);
    } else if (current_packet.ip_protocol_version == 6) { 
        __sync_fetch_and_add(&total_ipv6_packets, 1);
    } else {
        // Non IP packets
        __sync_fetch_and_add(&non_ip_packets, 1);
        return;
    }    

    uint64_t sampled_number_of_packets = current_packet.number_of_packets * current_packet.sample_ratio;
    uint64_t sampled_number_of_bytes   = current_packet.length * current_packet.sample_ratio;

    if (current_packet.ip_protocol_version == 6) {
        subnet_ipv6_cidr_mask_t ipv6_cidr_subnet;

        current_packet.packet_direction =
            get_packet_direction_ipv6(lookup_tree_ipv6, current_packet.src_ipv6, current_packet.dst_ipv6, ipv6_cidr_subnet);

        __sync_fetch_and_add(&total_counters_ipv6[current_packet.packet_direction].packets, sampled_number_of_packets);
        __sync_fetch_and_add(&total_counters_ipv6[current_packet.packet_direction].bytes, sampled_number_of_bytes);


#ifdef USE_NEW_ATOMIC_BUILTINS
        __atomic_add_fetch(&total_ipv6_packets, 1, __ATOMIC_RELAXED);
#else
        __sync_fetch_and_add(&total_ipv6_packets, 1);
#endif

        if (enable_subnet_counters) {
            std::lock_guard<std::mutex> lock_guard(ipv6_subnet_counters.counter_map_mutex);

            // We will create keys for new subnet here on demand
            subnet_counter_t* counter_ptr = &ipv6_subnet_counters.counter_map[ipv6_cidr_subnet];

            if (current_packet.packet_direction == OUTGOING) {
                counter_ptr->out_packets += sampled_number_of_packets;
                counter_ptr->out_bytes += sampled_number_of_bytes;
            } else if (current_packet.packet_direction == INCOMING) {
                counter_ptr->in_packets += sampled_number_of_packets;
                counter_ptr->in_bytes += sampled_number_of_bytes;
            }
        }

        // Here I use counters allocated per /128. In some future we could offer option to count them in diffenrent way
        // (/64, /96)
        {
            std::lock_guard<std::mutex> lock_guard(ipv6_host_counters.counter_map_mutex);

            if (current_packet.packet_direction == OUTGOING) {
                subnet_ipv6_cidr_mask_t ipv6_address;
                ipv6_address.set_cidr_prefix_length(128);
                ipv6_address.set_subnet_address(&current_packet.src_ipv6);

                subnet_counter_t* counter_ptr = &ipv6_host_counters.counter_map[ipv6_address];
                increment_outgoing_counters(counter_ptr, current_packet, sampled_number_of_packets, sampled_number_of_bytes);

                // Collect packets for DDoS analytics engine
                packet_buckets_ipv6_storage.add_packet_to_storage(ipv6_address, current_packet);
            } else if (current_packet.packet_direction == INCOMING) {
                subnet_ipv6_cidr_mask_t ipv6_address;
                ipv6_address.set_cidr_prefix_length(128);
                ipv6_address.set_subnet_address(&current_packet.dst_ipv6);

                subnet_counter_t* counter_ptr = &ipv6_host_counters.counter_map[ipv6_address];
                increment_incoming_counters(counter_ptr, current_packet, sampled_number_of_packets, sampled_number_of_bytes);

                // Collect packets for DDoS analytics engine
                packet_buckets_ipv6_storage.add_packet_to_storage(ipv6_address, current_packet);
            }

        }

        return;
    }

    // We do not process IPv6 at all on this mement
    if (current_packet.ip_protocol_version != 4) {
        return;
    }

    // Subnet for found IPs
    subnet_cidr_mask_t current_subnet;

    current_packet.packet_direction = get_packet_direction(lookup_tree_ipv4, current_packet.src_ip,
                                                      current_packet.dst_ip, current_subnet);

    // It's useful in case when we can't find what packets do not processed correctly
    if (DEBUG_DUMP_OTHER_PACKETS && current_packet.packet_direction == OTHER) {
        logger << log4cpp::Priority::INFO << "Dump other: " << print_simple_packet(current_packet);
    }

    // Skip processing of specific traffic direction
    if ((current_packet.packet_direction == INCOMING && !process_incoming_traffic) or
        (current_packet.packet_direction == OUTGOING && !process_outgoing_traffic)) {
        return;
    }

    uint32_t subnet_in_host_byte_order = 0; 
    // We operate in host bytes order and need to convert subnet
    if (!current_subnet.is_zero_subnet()) {
        subnet_in_host_byte_order = ntohl(current_subnet.subnet_address);
    }    

    if (enable_subnet_counters && (current_packet.packet_direction == OUTGOING or current_packet.packet_direction == INCOMING)) {
        map_for_subnet_counters_t::iterator subnet_iterator;

        // Find element in map of subnet counters
        subnet_iterator = PerSubnetCountersMap.find(current_subnet);

        if (subnet_iterator == PerSubnetCountersMap.end()) {
            logger << log4cpp::Priority::ERROR << "Can't find counter structure for subnet";
            return;
        }

        subnet_counter_t* subnet_counter = &subnet_iterator->second;

        // Increment countres for each subnet
        if (current_packet.packet_direction == OUTGOING) {
            increment_outgoing_counters(subnet_counter, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
        } else if (current_packet.packet_direction == INCOMING) {
            increment_incoming_counters(subnet_counter, current_packet, sampled_number_of_packets, sampled_number_of_bytes);
        }
    }

    map_of_vector_counters_for_flow_t::iterator itr_flow;

    if (enable_connection_tracking) {
        if (current_packet.packet_direction == OUTGOING or current_packet.packet_direction == INCOMING) {
            itr_flow = SubnetVectorMapFlow.find(current_subnet);

            if (itr_flow == SubnetVectorMapFlow.end()) {
                logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet flow map";
                return;
            }
        }
    }

    /* Because we support mirroring, sflow and netflow we should support different cases:
        - One packet passed for processing (mirror)
        - Multiple packets ("flows") passed for processing (netflow)
        - One sampled packed passed for processing (netflow)
        - Another combinations of this three options
    */

#ifdef USE_NEW_ATOMIC_BUILTINS
    __atomic_add_fetch(&total_counters[current_packet.packet_direction].packets, sampled_number_of_packets, __ATOMIC_RELAXED);
    __atomic_add_fetch(&total_counters[current_packet.packet_direction].bytes, sampled_number_of_bytes, __ATOMIC_RELAXED);
#else
    __sync_fetch_and_add(&total_counters[current_packet.packet_direction].packets, sampled_number_of_packets);
    __sync_fetch_and_add(&total_counters[current_packet.packet_direction].bytes, sampled_number_of_bytes);
#endif

        // Try to find map key for this subnet
        map_of_vector_counters_t::iterator itr;

        if (current_packet.packet_direction == OUTGOING or current_packet.packet_direction == INCOMING) {
            // Find element in map of vectors
            itr = SubnetVectorMap.find(current_subnet);

            if (itr == SubnetVectorMap.end()) {
                logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet map";
                return;
            }
        }


        // Incerement main and per protocol packet counters
        if (current_packet.packet_direction == OUTGOING) {
            int64_t shift_in_vector = (int64_t)ntohl(current_packet.src_ip) - (int64_t)subnet_in_host_byte_order;

            if (shift_in_vector < 0 or shift_in_vector >= itr->second.size()) {
                logger << log4cpp::Priority::ERROR << "We tried to access to element with index " << shift_in_vector
                       << " which located outside allocated vector with size " << itr->second.size();

                logger << log4cpp::Priority::ERROR
                       << "We expect issues with this packet in OUTGOING direction: " << print_simple_packet(current_packet);

                return;
            }

            map_element_t* current_element = &itr->second[shift_in_vector];

            increment_outgoing_counters(current_element, current_packet, sampled_number_of_packets, sampled_number_of_bytes);

            if (enable_connection_tracking) {
                increment_outgoing_flow_counters(SubnetVectorMapFlow, shift_in_vector, current_packet,
                                                 sampled_number_of_packets, sampled_number_of_bytes, current_subnet);
            }
        } else if (current_packet.packet_direction == INCOMING) {
            int64_t shift_in_vector = (int64_t)ntohl(current_packet.dst_ip) - (int64_t)subnet_in_host_byte_order;

            if (shift_in_vector < 0 or shift_in_vector >= itr->second.size()) {
                logger << log4cpp::Priority::ERROR << "We tried to access to element with index " << shift_in_vector
                       << " which located outside allocated vector with size " << itr->second.size();

                logger << log4cpp::Priority::ERROR
                       << "We expect issues with this packet in INCOMING direction: " << print_simple_packet(current_packet);

                return;
            }

            map_element_t* current_element = &itr->second[shift_in_vector];

            increment_incoming_counters(current_element, current_packet, sampled_number_of_packets, sampled_number_of_bytes);

            if (enable_connection_tracking) {
                increment_incoming_flow_counters(SubnetVectorMapFlow, shift_in_vector, current_packet,
                                                 sampled_number_of_packets, sampled_number_of_bytes, current_subnet);
            }
        } else if (current_packet.packet_direction == INTERNAL) {
        }

	// Exceute ban related processing
	if (current_packet.packet_direction == OUTGOING) {
        // Collect data when ban client
        if (ban_details_records_count != 0 &&
            !ban_list_details.empty() && ban_list_details.count(current_packet.src_ip) > 0 && 
            ban_list_details[current_packet.src_ip].size() < ban_details_records_count) {

            ban_list_details_mutex.lock();

            if (collect_attack_pcap_dumps) {
                // this code SHOULD NOT be called without mutex!
                if (current_packet.packet_payload_length > 0 && current_packet.packet_payload_pointer != NULL) {
                    ban_list[current_packet.src_ip].pcap_attack_dump.write_packet(current_packet.packet_payload_pointer,
                                                                                  current_packet.packet_payload_length, current_packet.packet_payload_length);
                }
            }

            ban_list_details[current_packet.src_ip].push_back(current_packet);
            ban_list_details_mutex.unlock();
        }
	}


	if (current_packet.packet_direction == INCOMING) {
        // Collect attack details
        if (ban_details_records_count != 0 &&
            !ban_list_details.empty() && ban_list_details.count(current_packet.dst_ip) > 0 &&
            ban_list_details[current_packet.dst_ip].size() < ban_details_records_count) {

            ban_list_details_mutex.lock();

            if (collect_attack_pcap_dumps) {
                // this code SHOULD NOT be called without mutex!
                if (current_packet.packet_payload_length > 0 && current_packet.packet_payload_pointer != NULL) {
                    ban_list[current_packet.dst_ip].pcap_attack_dump.write_packet(current_packet.packet_payload_pointer,
                                                                                  current_packet.packet_payload_length, current_packet.packet_payload_length);
                }
            }

            ban_list_details[current_packet.dst_ip].push_back(current_packet);
            ban_list_details_mutex.unlock();
        }

	}
}

// Increment fields using data from specified packet
void increment_outgoing_counters(map_element_t* current_element,
                                 simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Update last update time
    current_element->last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    __sync_fetch_and_add(&current_element->out_packets, sampled_number_of_packets);
    __sync_fetch_and_add(&current_element->out_bytes, sampled_number_of_bytes);

    // Fragmented IP packets
    if (current_packet.ip_fragmented) {
        __sync_fetch_and_add(&current_element->fragmented_out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->fragmented_out_bytes, sampled_number_of_bytes);
    }

    if (current_packet.protocol == IPPROTO_TCP) {
        __sync_fetch_and_add(&current_element->tcp_out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->tcp_out_bytes, sampled_number_of_bytes);

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            __sync_fetch_and_add(&current_element->tcp_syn_out_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->tcp_syn_out_bytes, sampled_number_of_bytes);
        }
    } else if (current_packet.protocol == IPPROTO_UDP) {
        __sync_fetch_and_add(&current_element->udp_out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->udp_out_bytes, sampled_number_of_bytes);
    } else if (current_packet.protocol == IPPROTO_ICMP) {
        __sync_fetch_and_add(&current_element->icmp_out_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->icmp_out_bytes, sampled_number_of_bytes);
        // no flow tracking for icmp
    } else {
    }
}

// This function increments all our accumulators according to data from packet
void increment_incoming_counters(map_element_t* current_element,
                                 simple_packet_t& current_packet,
                                 uint64_t sampled_number_of_packets,
                                 uint64_t sampled_number_of_bytes) {

    // Uodate last update time
    current_element->last_update_time = current_inaccurate_time;

    // Main packet/bytes counter
    __sync_fetch_and_add(&current_element->in_packets, sampled_number_of_packets);
    __sync_fetch_and_add(&current_element->in_bytes, sampled_number_of_bytes);

    // Count fragmented IP packets
    if (current_packet.ip_fragmented) {
        __sync_fetch_and_add(&current_element->fragmented_in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->fragmented_in_bytes, sampled_number_of_bytes);
    }

    // Count per protocol packets
    if (current_packet.protocol == IPPROTO_TCP) {
        __sync_fetch_and_add(&current_element->tcp_in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->tcp_in_bytes, sampled_number_of_bytes);

        if (extract_bit_value(current_packet.flags, TCP_SYN_FLAG_SHIFT)) {
            __sync_fetch_and_add(&current_element->tcp_syn_in_packets, sampled_number_of_packets);
            __sync_fetch_and_add(&current_element->tcp_syn_in_bytes, sampled_number_of_bytes);
        }
    } else if (current_packet.protocol == IPPROTO_UDP) {
        __sync_fetch_and_add(&current_element->udp_in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->udp_in_bytes, sampled_number_of_bytes);
    } else if (current_packet.protocol == IPPROTO_ICMP) {
        __sync_fetch_and_add(&current_element->icmp_in_packets, sampled_number_of_packets);
        __sync_fetch_and_add(&current_element->icmp_in_bytes, sampled_number_of_bytes);
    } else {
        // TBD
    }
}

void system_counters_speed_thread_handler() {
    while (true) {
        // We recalculate it each second to avoid confusion
        boost::this_thread::sleep(boost::posix_time::seconds(1));

        // We use this thread to update time each second
        time_t current_time = 0;
        time(&current_time);

        // Update global time, yes, it may became inaccurate due to thread syncronization but that's OK for our purposes
        current_inaccurate_time = current_time;
    }
}


void increment_incoming_flow_counters(map_of_vector_counters_for_flow_t& SubnetVectorMapFlow,
                                      int64_t shift_in_vector,
                                      simple_packet_t& current_packet,
                                      uint64_t sampled_number_of_packets,
                                      uint64_t sampled_number_of_bytes,
                                      const subnet_cidr_mask_t& current_subnet) {

    map_of_vector_counters_for_flow_t::iterator itr_flow = SubnetVectorMapFlow.find(current_subnet);

    if (itr_flow == SubnetVectorMapFlow.end()) {
        logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet flow map";
        return;
    }    

    conntrack_main_struct_t* current_element_flow = &itr_flow->second[shift_in_vector];

    packed_conntrack_hash_t flow_tracking_structure;
    flow_tracking_structure.opposite_ip = current_packet.src_ip;
    flow_tracking_structure.src_port    = current_packet.source_port;
    flow_tracking_structure.dst_port    = current_packet.destination_port;

    // convert this struct to 64 bit integer
    uint64_t connection_tracking_hash = convert_conntrack_hash_struct_to_integer(&flow_tracking_structure);

    if (current_packet.protocol == IPPROTO_TCP) {
        std::lock_guard<std::mutex> lock_guard(flow_counter);
        conntrack_key_struct_t* conntrack_key_struct_ptr = &current_element_flow->in_tcp[connection_tracking_hash];

        conntrack_key_struct_ptr->packets += sampled_number_of_packets;
        conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;
    } else if (current_packet.protocol == IPPROTO_UDP) {
        std::lock_guard<std::mutex> lock_guard(flow_counter);
        conntrack_key_struct_t* conntrack_key_struct_ptr = &current_element_flow->in_udp[connection_tracking_hash];

        conntrack_key_struct_ptr->packets += sampled_number_of_packets;
        conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;
    }    
}

// Increment all flow counters using specified packet
void increment_outgoing_flow_counters(map_of_vector_counters_for_flow_t& SubnetVectorMapFlow,
                                      int64_t shift_in_vector,
                                      simple_packet_t& current_packet,
                                      uint64_t sampled_number_of_packets,
                                      uint64_t sampled_number_of_bytes,
                                      const subnet_cidr_mask_t& current_subnet) {
    map_of_vector_counters_for_flow_t::iterator itr_flow = SubnetVectorMapFlow.find(current_subnet);

    if (itr_flow == SubnetVectorMapFlow.end()) {
        logger << log4cpp::Priority::ERROR << "Can't find vector address in subnet flow map";
        return;
    }

    conntrack_main_struct_t* current_element_flow = &itr_flow->second[shift_in_vector];

    packed_conntrack_hash_t flow_tracking_structure;
    flow_tracking_structure.opposite_ip = current_packet.dst_ip;
    flow_tracking_structure.src_port    = current_packet.source_port;
    flow_tracking_structure.dst_port    = current_packet.destination_port;

    // convert this struct to 64 bit integer
    uint64_t connection_tracking_hash = convert_conntrack_hash_struct_to_integer(&flow_tracking_structure);

    if (current_packet.protocol == IPPROTO_TCP) {
        std::lock_guard<std::mutex> lock_guard(flow_counter);
        conntrack_key_struct_t* conntrack_key_struct_ptr = &current_element_flow->out_tcp[connection_tracking_hash];

        conntrack_key_struct_ptr->packets += sampled_number_of_packets;
        conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;
    } else if (current_packet.protocol == IPPROTO_UDP) {
        std::lock_guard<std::mutex> lock_guard(flow_counter);
        conntrack_key_struct_t* conntrack_key_struct_ptr = &current_element_flow->out_udp[connection_tracking_hash];

        conntrack_key_struct_ptr->packets += sampled_number_of_packets;
        conntrack_key_struct_ptr->bytes += sampled_number_of_bytes;
    }
}

// pretty print channel speed in pps and MBit
std::string print_channel_speed_ipv6(std::string traffic_type, direction_t packet_direction) {
    uint64_t speed_in_pps = total_speed_average_counters_ipv6[packet_direction].packets;
    uint64_t speed_in_bps = total_speed_average_counters_ipv6[packet_direction].bytes;

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
void remove_orphaned_buckets(packet_buckets_storage_t<TemplateKeyType>* packet_storage, std::string protocol) {
    std::lock_guard<std::mutex> lock_guard(packet_storage->packet_buckets_map_mutex);

    // List of buckets to remove
    std::vector<TemplateKeyType> buckets_to_remove;

    // logger << log4cpp::Priority::DEBUG << "We've got " << packet_storage->packet_buckets_map.size() << " packets buckets for processing";

    // Find buckets for removal
    // We should not remove them here because it's tricky to do properly in C++
    for (auto it = packet_storage->packet_buckets_map.begin(); it != packet_storage->packet_buckets_map.end(); ++it) {
        if (should_remove_orphaned_bucket<TemplateKeyType>(*it)) {
            logger << log4cpp::Priority::DEBUG << "We decided to remove " << protocol << " bucket "
                   << convert_any_ip_to_string(it->first);
            buckets_to_remove.push_back(it->first);
        }
    }

    // logger << log4cpp::Priority::DEBUG << "We have " << buckets_to_remove.size() << " " << protocol << " orphaned buckets for cleanup";


    for (auto client_ip : buckets_to_remove) {
        // Let's dump some data from it
        packet_bucket_t* bucket = &packet_storage->packet_buckets_map[client_ip];

        logger << log4cpp::Priority::WARN << "We've found orphaned bucket for IP: " << convert_any_ip_to_string(client_ip)
               << " it has " << bucket->parsed_packets_circular_buffer.size() << " parsed packets"
               << " and " << bucket->raw_packets_circular_buffer.size() << " raw packets"
               << " we will remove it";

        // Stop packet collection ASAP
        bucket->we_could_receive_new_data = false;

        // Remove it completely from map
        packet_storage->packet_buckets_map.erase(client_ip);
    }

    return;
}

std::string get_attack_description_ipv6(subnet_ipv6_cidr_mask_t ipv6_address, attack_details_t& current_attack) {
    std::stringstream attack_description;

    attack_description << "IP: " << print_ipv6_address(ipv6_address.subnet_address) << "\n";
    attack_description << serialize_attack_description(current_attack) << "\n";

    attack_description << serialize_statistic_counters_about_attack(current_attack);

    return attack_description.str();
}

void execute_ipv6_ban(subnet_ipv6_cidr_mask_t ipv6_client,
                      attack_details_t current_attack,
                      std::string simple_packets_dump,
                      boost::circular_buffer<simple_packet_t>& simple_packets_buffer) {
    // Execute ban actions
    ban_list_ipv6_ng.add_to_blackhole(ipv6_client, current_attack);

    logger << log4cpp::Priority::INFO << "IPv6 address " << print_ipv6_cidr_subnet(ipv6_client) << " was banned";

    uint32_t zero_ipv4_address = 0;
    call_ban_handlers(zero_ipv4_address, ipv6_client, true, current_attack, "", attack_detection_source_t::Automatic,
                      simple_packets_dump, simple_packets_buffer);
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

        // For all attack types at this moment we could prepare simple packet dump
        std::string simple_packet_dump;

        if (bucket->parsed_packets_circular_buffer.size() != 0) { 
            std::stringstream ss;

            for (simple_packet_t& packet : bucket->parsed_packets_circular_buffer) {
                ss << print_simple_packet(packet);
            }

            simple_packet_dump = ss.str();
        }

        // For IPv6 we support only blackhole at this moment. BGP Flow spec for IPv6 isn't so populare and we will skip implementation for some future
        execute_ipv6_ban(ipv6_address, current_attack, simple_packet_dump, bucket->parsed_packets_circular_buffer);

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
    while (true) {
        // Process buckets which haven't filled by packets
        remove_orphaned_buckets(&packet_buckets_ipv6_storage, "ipv6");

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

