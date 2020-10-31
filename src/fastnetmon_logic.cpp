#include "fastnetmon_logic.hpp"
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <vector>

#include "all_logcpp_libraries.h"
#include "bgp_flow_spec.h"
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

#ifdef PF_RING
#include "actions/pfring_hardware_filter_action.h"
#endif

#ifdef ENABLE_GOBGP
#include "actions/gobgp_action.h"
#endif

// Yes, maybe it's not an good idea but with this we can guarantee working code in example plugin
#include "example_plugin/example_collector.h"

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
extern boost::mutex flow_counter;

#ifdef REDIS
extern unsigned int redis_port;
extern std::string redis_host;
extern std::string redis_prefix;
extern bool redis_enabled;
#endif

extern bool process_pcap_attack_dumps_with_dpi;
extern std::map<uint32_t, std::vector<simple_packet_t> > ban_list_details;
extern map_for_subnet_counters PerSubnetAverageSpeedMap;
extern bool enable_subnet_counters;
extern ban_settings_t global_ban_settings;
extern bool exabgp_enabled;
extern std::string exabgp_community;
extern std::string exabgp_community_subnet;
extern std::string exabgp_community_host;
extern std::string exabgp_command_pipe;
extern std::string exabgp_next_hop;
extern bool exabgp_announce_host;
extern bool exabgp_flow_spec_announces;
extern bool gobgp_enabled;
extern map_of_vector_counters SubnetVectorMapSpeedAverage;
extern int global_ban_time;
extern bool notify_script_enabled;
extern std::map<uint32_t, banlist_item> ban_list;
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
extern map_for_subnet_counters PerSubnetSpeedMap;
extern unsigned int ban_details_records_count;
extern FastnetmonPlatformConfigurtion fastnetmon_platform_configuration;

// We calculate speed from packet counters here
void build_speed_counters_from_packet_counters(map_element& new_speed_element,
                                                      map_element* vector_itr,
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

void build_average_speed_counters_from_speed_counters(map_element* current_average_speed_element,
                                                             map_element& new_speed_element,
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


std::string print_flow_tracking_for_ip(conntrack_main_struct& conntrack_element, std::string client_ip) {
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

std::string print_subnet_load() {
    std::stringstream buffer;

    sort_type sorter;
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

    for (map_for_subnet_counters::iterator itr = PerSubnetSpeedMap.begin();
         itr != PerSubnetSpeedMap.end(); ++itr) {
        vector_for_sort.push_back(std::make_pair(itr->first, itr->second));
    }

    std::sort(vector_for_sort.begin(), vector_for_sort.end(),
              TrafficComparatorClass<pair_of_map_for_subnet_counters_elements_t>(INCOMING, sorter));

    graphite_data_t graphite_data;

    for (std::vector<pair_of_map_for_subnet_counters_elements_t>::iterator itr = vector_for_sort.begin();
         itr != vector_for_sort.end(); ++itr) {
        map_element* speed = &itr->second;
        std::string subnet_as_string = convert_subnet_to_string(itr->first);

        buffer << std::setw(18) << std::left << subnet_as_string;

        if (graphite_enabled) {
            std::string subnet_as_string_as_dash_delimiters = subnet_as_string;

            // Replace dots by dashes
            std::replace(subnet_as_string_as_dash_delimiters.begin(),
                         subnet_as_string_as_dash_delimiters.end(), '.', '_');

            // Replace / by dashes too
            std::replace(subnet_as_string_as_dash_delimiters.begin(),
                         subnet_as_string_as_dash_delimiters.end(), '/', '_');

            graphite_data[graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".incoming.pps"] =
            speed->in_packets;
            graphite_data[graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".outgoing.pps"] =
            speed->out_packets;

            graphite_data[graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".incoming.bps"] =
            speed->in_bytes * 8;
            graphite_data[graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".outgoing.bps"] =
            speed->out_bytes * 8;
        }

        buffer << " "
               << "pps in: " << std::setw(8) << speed->in_packets << " out: " << std::setw(8)
               << speed->out_packets << " mbps in: " << std::setw(5) << convert_speed_to_mbps(speed->in_bytes)
               << " out: " << std::setw(5) << convert_speed_to_mbps(speed->out_bytes) << "\n";
    }

    if (graphite_enabled) {
        bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

        if (!graphite_put_result) {
            logger << log4cpp::Priority::ERROR << "Can't store network load data to Graphite";
        }
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

void print_attack_details_to_file(std::string details, std::string client_ip_as_string, attack_details current_attack) {
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

// Return true when we should ban this IP
bool we_should_ban_this_ip(map_element* average_speed_element, ban_settings_t current_ban_settings) {
    // we detect overspeed by packets

    if (current_ban_settings.enable_ban_for_pps &&
        exceed_pps_speed(average_speed_element->in_packets, average_speed_element->out_packets,
                         current_ban_settings.ban_threshold_pps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by pps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_bandwidth &&
        exceed_mbps_speed(average_speed_element->in_bytes, average_speed_element->out_bytes,
                          current_ban_settings.ban_threshold_mbps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by mbps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_flows_per_second &&
        exceed_flow_speed(average_speed_element->in_flows, average_speed_element->out_flows,
                          current_ban_settings.ban_threshold_flows)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by flow limit";
        return true;
    }

    // We could try per protocol thresholds here

    // Per protocol pps thresholds
    if (current_ban_settings.enable_ban_for_tcp_pps &&
        exceed_pps_speed(average_speed_element->tcp_in_packets, average_speed_element->tcp_out_packets,
                         current_ban_settings.ban_threshold_tcp_pps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by tcp pps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_pps &&
        exceed_pps_speed(average_speed_element->udp_in_packets, average_speed_element->udp_out_packets,
                         current_ban_settings.ban_threshold_udp_pps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by udp pps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_icmp_pps &&
        exceed_pps_speed(average_speed_element->icmp_in_packets, average_speed_element->icmp_out_packets,
                         current_ban_settings.ban_threshold_icmp_pps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by icmp pps limit";
        return true;
    }

    // Per protocol bandwidth thresholds
    if (current_ban_settings.enable_ban_for_tcp_bandwidth &&
        exceed_mbps_speed(average_speed_element->tcp_in_bytes, average_speed_element->tcp_out_bytes,
                          current_ban_settings.ban_threshold_tcp_mbps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by tcp mbps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_udp_bandwidth &&
        exceed_mbps_speed(average_speed_element->udp_in_bytes, average_speed_element->udp_out_bytes,
                          current_ban_settings.ban_threshold_udp_mbps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by udp mbps limit";
        return true;
    }

    if (current_ban_settings.enable_ban_for_icmp_bandwidth &&
        exceed_mbps_speed(average_speed_element->icmp_in_bytes, average_speed_element->icmp_out_bytes,
                          current_ban_settings.ban_threshold_icmp_mbps)) {
        logger << log4cpp::Priority::DEBUG << "We detected this attack by icmp mbps limit";
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
        packed_conntrack_hash unpacked_key_struct;
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
                                              packed_conntrack_hash* unpacked_data) {
    memcpy(unpacked_data, packed_connection_data, sizeof(uint64_t));
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

        for (std::map<uint32_t, banlist_item>::iterator itr = ban_list.begin(); itr != ban_list.end(); ++itr) {
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
                uint32_t subnet_in_host_byte_order = ntohl(itr->second.customer_network.first);
                int64_t shift_in_vector = (int64_t)ntohl(client_ip) - (int64_t)subnet_in_host_byte_order;

                // Try to find average speed element
                map_of_vector_counters::iterator itr_average_speed =
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

                map_element* average_speed_element = &itr_average_speed->second[shift_in_vector];

                // We get ban settings from host subnet
                std::string host_group_name;
                ban_settings_t current_ban_settings =
                get_ban_settings_for_this_subnet(itr->second.customer_network, host_group_name);

                if (we_should_ban_this_ip(average_speed_element, current_ban_settings)) {
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
            call_unban_handlers(itr->first, itr->second);
        }

        // Remove all unbanned hosts from the ban list
        for (std::vector<uint32_t>::iterator itr = ban_list_items_for_erase.begin();
             itr != ban_list_items_for_erase.end(); ++itr) {
            ban_list_mutex.lock();
            ban_list.erase(*itr);
            ban_list_mutex.unlock();
        }
    }
}

void call_unban_handlers(uint32_t client_ip, attack_details& current_attack) {
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

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

    if (exabgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call ExaBGP for unban client started: " << client_ip_as_string;

        boost::thread exabgp_thread(exabgp_ban_manage, "unban", client_ip_as_string, current_attack);
        exabgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to ExaBGP for unban client is finished: " << client_ip_as_string;
    }

#ifdef ENABLE_GOBGP
    if (gobgp_enabled) {
        logger << log4cpp::Priority::INFO << "Call GoBGP for unban client started: " << client_ip_as_string;

        boost::thread gobgp_thread(gobgp_ban_manage, "unban", client_ip_as_string, current_attack);
        gobgp_thread.detach();

        logger << log4cpp::Priority::INFO << "Call to GoBGP for unban client is finished: " << client_ip_as_string;
    }
#endif
}

std::string print_ddos_attack_details() {
    std::stringstream output_buffer;

    for (std::map<uint32_t, banlist_item>::iterator ii = ban_list.begin(); ii != ban_list.end(); ++ii) {
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

std::string get_attack_description(uint32_t client_ip, attack_details& current_attack) {
    std::stringstream attack_description;

    attack_description << "IP: " << convert_ip_as_uint_to_string(client_ip) << "\n";
    attack_description << serialize_attack_description(current_attack) << "\n";

    if (enable_subnet_counters) {
        // Got subnet tracking structure
        // TODO: we suppose case "no key exists" is not possible
        map_element network_speed_meter = PerSubnetSpeedMap[current_attack.customer_network];
        map_element average_network_speed_meter = PerSubnetAverageSpeedMap[current_attack.customer_network];

        attack_description << "Network: " << convert_subnet_to_string(current_attack.customer_network) << "\n";

        attack_description << serialize_network_load_to_text(network_speed_meter, false);
        attack_description << serialize_network_load_to_text(average_network_speed_meter, true);
    }

    attack_description << serialize_statistic_counters_about_attack(current_attack);

    return attack_description.str();
}

std::string get_attack_description_in_json(uint32_t client_ip, attack_details& current_attack) {
    json_object* jobj = json_object_new_object();

    json_object_object_add(jobj, "ip",
                           json_object_new_string(convert_ip_as_uint_to_string(client_ip).c_str()));
    json_object_object_add(jobj, "attack_details", serialize_attack_description_to_json(current_attack));

    if (enable_subnet_counters) {
        map_element network_speed_meter = PerSubnetSpeedMap[current_attack.customer_network];
        map_element average_network_speed_meter = PerSubnetAverageSpeedMap[current_attack.customer_network];

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
    /*
    attack_details
        << "\n"
        << "We got more packets (" << max_proto->second << " from " << ban_details_records_count
        << ") for protocol: " << get_protocol_name_by_number(max_proto->first) << "\n";
    */

    return attack_details.str();
}

void send_attack_details(uint32_t client_ip, attack_details current_attack_details) {
    std::string pps_as_string = convert_int_to_string(current_attack_details.attack_power);
    std::string attack_direction = get_direction_name(current_attack_details.attack_direction);
    std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

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
            logger << log4cpp::Priority::INFO << "The same rule was already sent to ExaBGP formerly";
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

void call_attack_details_handlers(uint32_t client_ip, attack_details& current_attack, std::string attack_fingerprint) {
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

uint64_t convert_conntrack_hash_struct_to_integer(packed_conntrack_hash* struct_value) {
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
bool process_flow_tracking_table(conntrack_main_struct& conntrack_element, std::string client_ip) {
    std::map<uint32_t, unsigned int> uniq_remote_hosts_which_generate_requests_to_us;
    std::map<unsigned int, unsigned int> uniq_local_ports_which_target_of_connectiuons_from_inside;

    /* Process incoming TCP connections */
    for (contrack_map_type::iterator itr = conntrack_element.in_tcp.begin();
         itr != conntrack_element.in_tcp.end(); ++itr) {
        uint64_t packed_connection_data = itr->first;
        packed_conntrack_hash unpacked_key_struct;
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
bool exec_with_stdin_params(std::string cmd, std::string params) {
    FILE* pipe = popen(cmd.c_str(), "w");
    if (!pipe) {
        logger << log4cpp::Priority::ERROR << "Can't execute program " << cmd
               << " error code: " << errno << " error text: " << strerror(errno);
        return false;
    }

    int fputs_ret = fputs(params.c_str(), pipe);

    if (fputs_ret) {
        pclose(pipe);
        return true;
    } else {
        logger << log4cpp::Priority::ERROR << "Can't pass data to stdin of program " << cmd;
        pclose(pipe);
        return false;
    }
}

// Get ban settings for this subnet or return global ban settings
ban_settings_t get_ban_settings_for_this_subnet(subnet_t subnet, std::string& host_group_name) {
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


void exabgp_ban_manage(std::string action, std::string ip_as_string, attack_details current_attack) {
    // We will announce whole subent here
    if (exabgp_announce_whole_subnet) {
        std::string subnet_as_string_with_mask = convert_subnet_to_string(current_attack.customer_network);

        exabgp_prefix_ban_manage(action, subnet_as_string_with_mask, exabgp_next_hop, exabgp_community_subnet);
    }

    // And we could announce single host here (/32)
    if (exabgp_announce_host) {
        std::string ip_as_string_with_mask = ip_as_string + "/32";

        exabgp_prefix_ban_manage(action, ip_as_string_with_mask, exabgp_next_hop, exabgp_community_host);
    }
}


// Low level ExaBGP ban management
void exabgp_prefix_ban_manage(std::string action,
                              std::string prefix_as_string_with_mask,
                              std::string exabgp_next_hop,
                              std::string exabgp_community) {

    /* Buffer for BGP message */
    char bgp_message[256];

    if (action == "ban") {
        sprintf(bgp_message, "announce route %s next-hop %s community %s\n",
                prefix_as_string_with_mask.c_str(), exabgp_next_hop.c_str(), exabgp_community.c_str());
    } else {
        sprintf(bgp_message, "withdraw route %s next-hop %s\n", prefix_as_string_with_mask.c_str(),
                exabgp_next_hop.c_str());
    }

    logger << log4cpp::Priority::INFO << "ExaBGP announce message: " << bgp_message;

    int exabgp_pipe = open(exabgp_command_pipe.c_str(), O_WRONLY);

    if (exabgp_pipe <= 0) {
        logger << log4cpp::Priority::ERROR << "Can't open ExaBGP pipe " << exabgp_command_pipe
               << " Ban is not executed";
        return;
    }

    int wrote_bytes = write(exabgp_pipe, bgp_message, strlen(bgp_message));

    if (wrote_bytes != strlen(bgp_message)) {
        logger << log4cpp::Priority::ERROR << "Can't write message to ExaBGP pipe";
    }

    close(exabgp_pipe);
}

bool exabgp_flow_spec_ban_manage(std::string action, std::string flow_spec_rule_as_text) {
    std::string announce_action;

    if (action == "ban") {
        announce_action = "announce";
    } else {
        announce_action = "withdraw";
    }    

    // Trailing \n is very important!
    std::string bgp_message = announce_action + " " + flow_spec_rule_as_text + "\n";

    int exabgp_pipe = open(exabgp_command_pipe.c_str(), O_WRONLY);

    if (exabgp_pipe <= 0) { 
        logger << log4cpp::Priority::ERROR << "Can't open ExaBGP pipe for flow spec announce " << exabgp_command_pipe;
        return false;
    }    

    int wrote_bytes = write(exabgp_pipe, bgp_message.c_str(), bgp_message.size());

    if (wrote_bytes != bgp_message.size()) {
        logger << log4cpp::Priority::ERROR << "Can't write message to ExaBGP pipe";
        return false;
    }    

    close(exabgp_pipe);
    return true;
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

