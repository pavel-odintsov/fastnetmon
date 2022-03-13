#include "fastnetmon_logic.hpp"
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <fstream>

#include "all_logcpp_libraries.h"
#include "bgp_flow_spec.h"
#include "fast_library.h"
#include "fast_platform.h"

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

