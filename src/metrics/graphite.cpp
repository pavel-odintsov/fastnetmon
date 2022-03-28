#include "graphite.hpp"


#include "../fastnetmon_types.h"
#include "../fast_library.h"

#include <vector>

#include "../all_logcpp_libraries.h"

extern log4cpp::Category& logger;
extern bool print_average_traffic_counts;
extern struct timeval graphite_thread_execution_time;
extern total_counter_element_t total_speed_average_counters[4];
extern map_of_vector_counters_t SubnetVectorMapSpeed;
extern map_of_vector_counters_t SubnetVectorMapSpeedAverage;
extern uint64_t incoming_total_flows_speed;
extern uint64_t outgoing_total_flows_speed;
extern map_for_subnet_counters_t PerSubnetAverageSpeedMap;

extern bool graphite_enabled;
extern std::string graphite_host;
extern unsigned short int graphite_port;
extern std::string graphite_prefix;
extern unsigned int graphite_push_period;

// Push host traffic to Graphite
bool push_hosts_traffic_counters_to_graphite() {
    std::vector<direction_t> processed_directions = { INCOMING, OUTGOING };

    graphite_data_t graphite_data;

    map_of_vector_counters_t* current_speed_map = nullptr;

    if (print_average_traffic_counts) {
        current_speed_map = &SubnetVectorMapSpeedAverage;
    } else {
        current_speed_map = &SubnetVectorMapSpeed;
    }

    // Iterate over all networks
    for (map_of_vector_counters_t::iterator itr = current_speed_map->begin(); itr != current_speed_map->end(); ++itr) {

        // Iterate over all hosts in network
        for (vector_of_counters_t::iterator vector_itr = itr->second.begin(); vector_itr != itr->second.end(); ++vector_itr) {
            int current_index = vector_itr - itr->second.begin();

            // convert to host order for math operations
            uint32_t subnet_ip                     = ntohl(itr->first.subnet_address);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // covnert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);

            std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

            std::string ip_as_string_with_dash_delimiters = client_ip_as_string;
            // Replace dots by dashes
            std::replace(ip_as_string_with_dash_delimiters.begin(), ip_as_string_with_dash_delimiters.end(), '.', '_');

            // Here we could have average or instantaneous speed
            map_element_t* current_speed_element = &*vector_itr;

            for (auto data_direction : processed_directions) {
                std::string direction_as_string;

                if (data_direction == INCOMING) {
                    direction_as_string = "incoming";
                } else if (data_direction == OUTGOING) {
                    direction_as_string = "outgoing";
                }

                std::string graphite_current_prefix = graphite_prefix + ".hosts." +
                                                      ip_as_string_with_dash_delimiters + "." + direction_as_string;

                if (print_average_traffic_counts) {
                    graphite_current_prefix = graphite_current_prefix + ".average";
                }

                if (data_direction == INCOMING) {
                    // Prepare incoming traffic data

                    // We do not store zero data to Graphite
                    if (current_speed_element->in_packets != 0) {
                        graphite_data[graphite_current_prefix + ".pps"] = current_speed_element->in_packets;
                    }

                    if (current_speed_element->in_bytes != 0) {
                        graphite_data[graphite_current_prefix + ".bps"] = current_speed_element->in_bytes * 8;
                    }

                    if (current_speed_element->in_flows != 0) {
                        graphite_data[graphite_current_prefix + ".flows"] = current_speed_element->in_flows;
                    }

                } else if (data_direction == OUTGOING) {
                    // Prepare outgoing traffic data

                    // We do not store zero data to Graphite
                    if (current_speed_element->out_packets != 0) {
                        graphite_data[graphite_current_prefix + ".pps"] = current_speed_element->out_packets;
                    }

                    if (current_speed_element->out_bytes != 0) {
                        graphite_data[graphite_current_prefix + ".bps"] = current_speed_element->out_bytes * 8;
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
    }

    return true;
}

// Push total counters to graphite
bool push_total_traffic_counters_to_graphite() {
    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        uint64_t speed_in_pps = total_speed_average_counters[packet_direction].packets;
        uint64_t speed_in_bps = total_speed_average_counters[packet_direction].bytes;

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

            graphite_data[graphite_prefix + ".total." + direction_as_string + ".flows"] =
                flow_counter_for_this_direction;
        }

        graphite_data[graphite_prefix + ".total." + direction_as_string + ".pps"] = speed_in_pps;
        graphite_data[graphite_prefix + ".total." + direction_as_string + ".bps"] =
            speed_in_bps * 8;

        bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

        if (!graphite_put_result) {
            logger << log4cpp::Priority::ERROR << "Can't store total load data to Graphite server "
                   << graphite_host << " port: " << graphite_port;
            ;
            return false;
        }
    }

    return true;
}

// Push per subnet traffic counters to graphite
bool push_network_traffic_counters_to_graphite() {
    graphite_data_t graphite_data;

    for (map_for_subnet_counters_t::iterator itr = PerSubnetAverageSpeedMap.begin(); itr != PerSubnetAverageSpeedMap.end(); ++itr) {
        map_element_t* speed                            = &itr->second;
        std::string subnet_as_string_as_dash_delimiters = convert_subnet_to_string(itr->first);
        ;

        // Replace dots by dashes
        std::replace(subnet_as_string_as_dash_delimiters.begin(), subnet_as_string_as_dash_delimiters.end(), '.', '_');

        // Replace / by dashes too
        std::replace(subnet_as_string_as_dash_delimiters.begin(), subnet_as_string_as_dash_delimiters.end(), '/', '_');

        std::string current_prefix = graphite_prefix + ".networks." + subnet_as_string_as_dash_delimiters + "."; 

        graphite_data[current_prefix + "incoming.pps"] = speed->in_packets;
        graphite_data[current_prefix + "outgoing.pps"] = speed->out_packets;
        graphite_data[current_prefix + "incoming.bps"] = speed->in_bytes * 8; 
        graphite_data[current_prefix + "outgoing.bps"] = speed->out_bytes * 8; 
    }    


    bool graphite_put_result = store_data_to_graphite(graphite_port, graphite_host, graphite_data);

    if (!graphite_put_result) {
        logger << log4cpp::Priority::ERROR << "Can't store network load data to Graphite server "
               << graphite_host << " port: " << graphite_port;
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

        struct timeval start_calc_time;
        gettimeofday(&start_calc_time, NULL);

        // First of all push total counters to Graphite
        push_total_traffic_counters_to_graphite();

        // Push per subnet counters to graphite
        push_network_traffic_counters_to_graphite();

        // Push per host counters to graphite
        push_hosts_traffic_counters_to_graphite();

        struct timeval end_calc_time;
        gettimeofday(&end_calc_time, NULL);

        timeval_subtract(&graphite_thread_execution_time, &end_calc_time, &start_calc_time);

        logger << log4cpp::Priority::DEBUG << "Graphite data pushed in: " << graphite_thread_execution_time.tv_sec
               << " sec " << graphite_thread_execution_time.tv_usec << " microseconds\n";
    }
}

