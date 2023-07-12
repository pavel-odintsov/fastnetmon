#include "graphite.hpp"


#include "../fast_library.hpp"
#include "../fastnetmon_types.hpp"

#include <vector>

#include "../all_logcpp_libraries.hpp"

#include "../abstract_subnet_counters.hpp"

extern log4cpp::Category& logger;
extern uint64_t incoming_total_flows_speed;
extern uint64_t outgoing_total_flows_speed;
extern abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;
extern total_speed_counters_t total_counters_ipv4;
extern total_speed_counters_t total_counters_ipv6;

extern bool graphite_enabled;
extern std::string graphite_host;
extern unsigned short int graphite_port;
extern std::string graphite_prefix;
extern unsigned int graphite_push_period;

// Push host traffic to Graphite
bool push_hosts_traffic_counters_to_graphite() {
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;

    std::vector<direction_t> processed_directions = { INCOMING, OUTGOING };

    graphite_data_t graphite_data;

    std::vector<std::pair<uint32_t, subnet_counter_t>> speed_elements;
    ipv4_host_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    for (const auto& speed_element : speed_elements) {
        std::string client_ip_as_string = convert_ip_as_uint_to_string(speed_element.first);

        const subnet_counter_t* current_speed_element = &speed_element.second;

        // Skip elements with zero speed
        if (current_speed_element->is_zero()) {
            continue;
        }

        std::string ip_as_string_with_dash_delimiters = client_ip_as_string;
        // Replace dots by dashes
        std::replace(ip_as_string_with_dash_delimiters.begin(), ip_as_string_with_dash_delimiters.end(), '.', '_');

        for (auto data_direction : processed_directions) {
            std::string direction_as_string;

            if (data_direction == INCOMING) {
                direction_as_string = "incoming";
            } else if (data_direction == OUTGOING) {
                direction_as_string = "outgoing";
            }

            std::string graphite_current_prefix = graphite_prefix + ".hosts." +
                                                  ip_as_string_with_dash_delimiters + "." + direction_as_string;


            if (data_direction == INCOMING) {
                // Prepare incoming traffic data

                // We do not store zero data to Graphite
                if (current_speed_element->total.in_packets != 0) {
                    graphite_data[graphite_current_prefix + ".pps"] = current_speed_element->total.in_packets;
                }

                if (current_speed_element->total.in_bytes != 0) {
                    graphite_data[graphite_current_prefix + ".bps"] = current_speed_element->total.in_bytes * 8;
                }

                if (current_speed_element->in_flows != 0) {
                    graphite_data[graphite_current_prefix + ".flows"] = current_speed_element->in_flows;
                }

            } else if (data_direction == OUTGOING) {
                // Prepare outgoing traffic data

                // We do not store zero data to Graphite
                if (current_speed_element->total.out_packets != 0) {
                    graphite_data[graphite_current_prefix + ".pps"] = current_speed_element->total.out_packets;
                }

                if (current_speed_element->total.out_bytes != 0) {
                    graphite_data[graphite_current_prefix + ".bps"] = current_speed_element->total.out_bytes * 8;
                }

                if (current_speed_element->out_flows != 0) {
                    graphite_data[graphite_current_prefix + ".flows"] = current_speed_element->out_flows;
                }
            }
        }
    }

    bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

    if (!graphite_put_result) {
        logger << log4cpp::Priority::ERROR << "Can't store host load data to Graphite server "
               << graphite_host << " port: " << graphite_port;
        return false;
    }

    return true;
}


// Push total counters to graphite
bool push_total_traffic_counters_to_graphite() {
    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        uint64_t speed_in_pps = total_counters_ipv4.total_speed_average_counters[packet_direction].packets;
        uint64_t speed_in_bps = total_counters_ipv4.total_speed_average_counters[packet_direction].bytes;

        graphite_data_t graphite_data;

        std::string direction_as_string = get_direction_name(packet_direction);

        // We have flow information only for incoming and outgoing directions
        if (packet_direction == INCOMING or packet_direction == OUTGOING) {
            uint64_t flow_counter_for_this_direction = 0;

            if (packet_direction == INCOMING) {
                flow_counter_for_this_direction = incoming_total_flows_speed;
            } else {
                flow_counter_for_this_direction = outgoing_total_flows_speed;
            }

            graphite_data[graphite_prefix + ".total." + direction_as_string + ".flows"] = flow_counter_for_this_direction;
        }

        graphite_data[graphite_prefix + ".total." + direction_as_string + ".pps"] = speed_in_pps;
        graphite_data[graphite_prefix + ".total." + direction_as_string + ".bps"] = speed_in_bps * 8;

        bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

        if (!graphite_put_result) {
            logger << log4cpp::Priority::ERROR << "Can't store total load data to Graphite server " << graphite_host
                   << " port: " << graphite_port;
            ;
            return false;
        }
    }

    return true;
}

// Push per subnet traffic counters to graphite
bool push_network_traffic_counters_to_graphite() {
    graphite_data_t graphite_data;

    std::vector<std::pair<subnet_cidr_mask_t, subnet_counter_t>> speed_elements;
    ipv4_network_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    for (const auto& itr : speed_elements) {
        const subnet_counter_t* speed                   = &itr.second;
        std::string subnet_as_string_as_dash_delimiters = convert_subnet_to_string(itr.first);

        // Replace dots by dashes
        std::replace(subnet_as_string_as_dash_delimiters.begin(), subnet_as_string_as_dash_delimiters.end(), '.', '_');

        // Replace / by dashes too
        std::replace(subnet_as_string_as_dash_delimiters.begin(), subnet_as_string_as_dash_delimiters.end(), '/', '_');

        std::string current_prefix = graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + ".";

        graphite_data[current_prefix + "incoming.pps"] = speed->total.in_packets;
        graphite_data[current_prefix + "outgoing.pps"] = speed->total.out_packets;
        graphite_data[current_prefix + "incoming.bps"] = speed->total.in_bytes * 8;
        graphite_data[current_prefix + "outgoing.bps"] = speed->total.out_bytes * 8;
    }


    bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

    if (!graphite_put_result) {
        logger << log4cpp::Priority::ERROR << "Can't store network load data to Graphite server " << graphite_host
               << " port: " << graphite_port;
        return false;
    }

    return true;
}


// This thread pushes speed counters to graphite
void graphite_push_thread() {
    
    // Sleep for a half second for shift against calculatiuon thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(graphite_push_period));

        std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();

        // First of all push total counters to Graphite
        push_total_traffic_counters_to_graphite();

        // Push per subnet counters to graphite
        push_network_traffic_counters_to_graphite();

        // Push per host counters to graphite
        push_hosts_traffic_counters_to_graphite();

        std::chrono::duration<double> diff = std::chrono::steady_clock::now() - start_time;

        logger << log4cpp::Priority::DEBUG << "Graphite data pushed in: " << diff.count() << " seconds";
    }
}
