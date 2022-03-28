#include "influxdb.hpp"

#include "../fastnetmon_types.h"
#include "../fast_library.h"
#include "../abstract_subnet_counters.hpp"

#include "../all_logcpp_libraries.h"

#include <vector>

extern bool print_average_traffic_counts;
extern struct timeval graphite_thread_execution_time;
extern total_counter_element_t total_speed_average_counters[4];
extern map_of_vector_counters_t SubnetVectorMapSpeed;
extern map_of_vector_counters_t SubnetVectorMapSpeedAverage;
extern uint64_t incoming_total_flows_speed;
extern uint64_t outgoing_total_flows_speed;
extern map_for_subnet_counters_t PerSubnetAverageSpeedMap;
extern uint64_t influxdb_writes_total;
extern uint64_t influxdb_writes_failed;
extern total_counter_element_t total_speed_average_counters_ipv6[4];
extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t> ipv6_host_counters;
extern abstract_subnet_counters_t<subnet_cidr_mask_t> ipv4_host_counters;
extern abstract_subnet_counters_t<subnet_cidr_mask_t> ipv4_remote_host_counters;
extern std::vector<ban_settings_t> hostgroup_list_total_calculation;
extern std::mutex hostgroup_list_total_calculation_mutex;
extern abstract_subnet_counters_t<int64_t> per_hostgroup_total_counters;
extern log4cpp::Category& logger;

extern std::string influxdb_database;
extern std::string influxdb_host;
extern unsigned short int influxdb_port;
extern bool influxdb_auth;
extern std::string influxdb_user;
extern std::string influxdb_password;
extern unsigned int influxdb_push_period;

// I do this delcaration here to avoid circuclar dependencies between fastnetmon_logic and this file
bool get_statistics(std::vector<system_counter_t>& system_counters);

// Push system counters to InfluxDB
bool push_system_counters_to_influxdb(std::string influx_database,
                                      std::string influx_host,
                                      std::string influx_port,
                                      bool enable_auth,
                                      std::string influx_user,
                                      std::string influx_password) {
    std::vector<system_counter_t> system_counters;

    bool result = get_statistics(system_counters);

    if (!result) {
        logger << log4cpp::Priority::ERROR << "Can't collect system counters";
        return false;
    }

    std::map<std::string, uint64_t> plain_total_counters_map;

    for (auto counter : system_counters) {
        plain_total_counters_map[counter.counter_name] = counter.counter_value;
    }

    influxdb_writes_total++;

    std::map<std::string, std::string> tags = { { "metric", "metric_value" } };

    bool influx_result = write_line_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                        influx_password, "system_counters", tags, plain_total_counters_map);

    if (!influx_result) {
        influxdb_writes_failed++;
        logger << log4cpp::Priority::DEBUG << "InfluxDB write operation failed for system counters";
        return false;
    }

    return true;
}



// Push total traffic counters to InfluxDB
bool push_total_traffic_counters_to_influxdb(std::string influx_database,
                                             std::string influx_host,
                                             std::string influx_port,
                                             bool enable_auth,
                                             std::string influx_user,
                                             std::string influx_password,
                                             std::string measurement_name,
                                             total_counter_element_t total_speed_average_counters_param[4],
                                             bool ipv6) {
    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        std::map<std::string, uint64_t> plain_total_counters_map;

        uint64_t speed_in_pps             = total_speed_average_counters_param[packet_direction].packets;
        uint64_t speed_in_bits_per_second = total_speed_average_counters_param[packet_direction].bytes * 8;

        // We do not have this counter for IPv6
        if (!ipv6) {
            // We have flow information only for incoming and outgoing directions
            if (packet_direction == INCOMING or packet_direction == OUTGOING) {
                uint64_t flow_counter_for_this_direction = 0;

                if (packet_direction == INCOMING) {
                    flow_counter_for_this_direction = incoming_total_flows_speed;
                } else {
                    flow_counter_for_this_direction = outgoing_total_flows_speed;
                }

                plain_total_counters_map["flows"] = flow_counter_for_this_direction;
            }
        }

        plain_total_counters_map["packets"] = speed_in_pps;
        plain_total_counters_map["bits"]    = speed_in_bits_per_second;

        std::string direction_as_string = get_direction_name(packet_direction);

        influxdb_writes_total++;

        std::map<std::string, std::string> tags = { { "direction", direction_as_string } };

        bool result = write_line_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                     influx_password, measurement_name, tags, plain_total_counters_map);

        if (!result) {
            influxdb_writes_failed++;
            logger << log4cpp::Priority::DEBUG << "InfluxDB write operation failed for total_traffic";
            return false;
        }
    }


    return true;
}

// This thread pushes data to InfluxDB
void influxdb_push_thread() {
    // Sleep for a half second for shift against calculation thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    bool do_dns_resolution = false;

    // If address does not look like IPv4 or IPv6 then we will use DNS resolution for it
    if (!validate_ipv6_or_ipv4_host(influxdb_host)) {
        logger << log4cpp::Priority::INFO << "You set InfluxDB server address as hostname and we will use DNS to resolve it";
        do_dns_resolution = true;
    }

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(influxdb_push_period));

        std::string current_influxdb_ip_address = "";

        if (do_dns_resolution) {
            std::string ip_address = dns_lookup(influxdb_host);

            if (ip_address.empty()) {
                logger << log4cpp::Priority::ERROR << "Cannot resolve " << influxdb_host << " to address";
                continue;
            }

            logger << log4cpp::Priority::DEBUG << "Resolved " << influxdb_host << " to " << ip_address;

            current_influxdb_ip_address = ip_address;
        } else {
            // We do not need DNS resolution here, use address as is
            current_influxdb_ip_address = influxdb_host;
        }

        // First of all push total counters to InfluxDB
        push_total_traffic_counters_to_influxdb(influxdb_database, current_influxdb_ip_address, std::to_string(influxdb_port), influxdb_auth, influxdb_user,
                                                influxdb_password, "total_traffic", total_speed_average_counters, false);

        // Push per subnet counters to InfluxDB
        push_network_traffic_counters_to_influxdb(influxdb_database, current_influxdb_ip_address, std::to_string(influxdb_port),
                                                  influxdb_auth, influxdb_user, influxdb_password);

        // Push per host counters to InfluxDB
        push_hosts_traffic_counters_to_influxdb(influxdb_database, current_influxdb_ip_address, std::to_string(influxdb_port), influxdb_auth,
                                                influxdb_user, influxdb_password);

        push_system_counters_to_influxdb(influxdb_database, current_influxdb_ip_address, std::to_string(influxdb_port), influxdb_auth,
                                         influxdb_user, influxdb_password);

        // Push per host IPv6 counters to InfluxDB
        push_hosts_ipv6_traffic_counters_to_influxdb(influxdb_database, current_influxdb_ip_address, std::to_string(influxdb_port),
                                                     influxdb_auth, influxdb_user, influxdb_password);

        // Push total IPv6 counters
        push_total_traffic_counters_to_influxdb(influxdb_database, current_influxdb_ip_address, std::to_string(influxdb_port),
                                            influxdb_auth, influxdb_user, influxdb_password, "total_traffic_ipv6",
                                                total_speed_average_counters_ipv6, true);
    }
}


// Push host traffic to InfluxDB
bool push_hosts_ipv6_traffic_counters_to_influxdb(std::string influx_database,
                                                  std::string influx_host,
                                                  std::string influx_port,
                                                  bool enable_auth,
                                                  std::string influx_user,
                                                  std::string influx_password) {
    std::vector<std::pair<subnet_ipv6_cidr_mask_t, subnet_counter_t>> speed_elements;

    // TODO: preallocate memory here for this array to avoid memory allocations under the lock
    ipv6_host_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    // Structure for InfluxDB
    std::vector<std::pair<std::string, std::map<std::string, uint64_t>>> hosts_vector;

    for (const auto& speed_element : speed_elements) {
        std::map<std::string, uint64_t> plain_total_counters_map;

        std::string client_ip_as_string = print_ipv6_address(speed_element.first.subnet_address);

        fill_main_counters_for_influxdb(&speed_element.second, plain_total_counters_map, true);

        hosts_vector.push_back(std::make_pair(client_ip_as_string, plain_total_counters_map));
    }

    // TODO: For big networks it will cause HUGE batches, it will make sense to split them in 5-10k batches
    if (hosts_vector.size() > 0) {
        influxdb_writes_total++;

        bool result = write_batch_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                      influx_password, "hosts_ipv6_traffic", "host", hosts_vector);

        if (!result) {
            influxdb_writes_failed++;
            logger << log4cpp::Priority::DEBUG << "InfluxDB batch operation failed for hosts_traffic";
            return false;
        }
    }

    return true;
}


// Push host traffic to InfluxDB
bool push_hosts_traffic_counters_to_influxdb(std::string influx_database,
                                             std::string influx_host,
                                             std::string influx_port,
                                             bool enable_auth,
                                             std::string influx_user,
                                             std::string influx_password) {
    /* https://docs.influxdata.com/influxdb/v1.7/concepts/glossary/:
     A collection of points in line protocol format, separated by newlines (0x0A). A batch of points may be submitted to
     the database using a single HTTP request to the write endpoint. This makes writes via the HTTP API much more
     performant by drastically reducing the HTTP overhead. InfluxData recommends batch sizes of 5,000-10,000 points,
     although different use cases may be better served by significantly smaller or larger batches.
     */

    map_of_vector_counters_t* current_speed_map = nullptr;

    if (print_average_traffic_counts) {
        current_speed_map = &SubnetVectorMapSpeedAverage;
    } else {
        current_speed_map = &SubnetVectorMapSpeed;
    }

    // Iterate over all networks
    for (map_of_vector_counters_t::iterator itr = current_speed_map->begin(); itr != current_speed_map->end(); ++itr) {
        std::vector<std::pair<std::string, std::map<std::string, uint64_t>>> hosts_vector;

        // Iterate over all hosts in network
        for (vector_of_counters_t::iterator vector_itr = itr->second.begin(); vector_itr != itr->second.end(); ++vector_itr) {
            std::map<std::string, uint64_t> plain_total_counters_map;

            int current_index = vector_itr - itr->second.begin();

            // Convert to host order for math operations
            uint32_t subnet_ip                     = ntohl(itr->first.subnet_address);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // Convert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);

            std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

            // Here we could have average or instantaneous speed
            map_element_t* current_speed_element = &*vector_itr;

            // Skip elements with zero speed
            if (current_speed_element->is_zero()) {
                continue;
            }

            fill_main_counters_for_influxdb(current_speed_element, plain_total_counters_map, true);

            // Key: client_ip_as_string
            hosts_vector.push_back(std::make_pair(client_ip_as_string, plain_total_counters_map));
        }

        if (hosts_vector.size() > 0) {
            bool result = write_batch_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                          influx_password, "hosts_traffic", "host", hosts_vector);

            if (!result) {
                influxdb_writes_failed++;
                logger << log4cpp::Priority::DEBUG << "InfluxDB batch operation failed for hosts_traffic";
                return false;
            }
        }
    }

    return true;
}

// Write batch of data for particular InfluxDB database
bool write_batch_of_data_to_influxdb(std::string influx_database,
                                     std::string influx_host,
                                     std::string influx_port,
                                     bool enable_auth,
                                     std::string influx_user,
                                     std::string influx_password,
                                     std::string measurement,
                                     std::string tag_name,
                                     std::vector<std::pair<std::string, std::map<std::string, uint64_t>>>& hosts_vector) {
    // Nothing to write
    if (hosts_vector.size() == 0) {
        return true;
    }

    std::stringstream buffer;
    uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

    // Prepare batch for insert
    for (auto& host_traffic : hosts_vector) {
        std::map<std::string, std::string> tags = { { tag_name, host_traffic.first } };

        std::string line_protocol_format =
            craft_line_for_influxdb_line_protocol(unix_timestamp_nanoseconds, measurement, tags, host_traffic.second);

        buffer << line_protocol_format << "\n";
    }

    // logger << log4cpp::Priority::INFO << "Raw data to InfluxDB: " << buffer.str();
    return write_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user, influx_password,
                                  buffer.str());
}

// Push per subnet traffic counters to influxDB
bool push_network_traffic_counters_to_influxdb(std::string influx_database,
                                               std::string influx_host,
                                               std::string influx_port,
                                               bool enable_auth,
                                               std::string influx_user,
                                               std::string influx_password) {
    for (map_for_subnet_counters_t::iterator itr = PerSubnetAverageSpeedMap.begin(); itr != PerSubnetAverageSpeedMap.end(); ++itr) {
        std::map<std::string, uint64_t> plain_total_counters_map;

        map_element_t* speed         = &itr->second;
        std::string subnet_as_string = convert_subnet_to_string(itr->first);

        fill_main_counters_for_influxdb(speed, plain_total_counters_map, false);

        influxdb_writes_total++;

        std::map<std::string, std::string> tags = { { "network", subnet_as_string } };

        bool result = write_line_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                     influx_password, "networks_traffic", tags, plain_total_counters_map);

        if (!result) {
            influxdb_writes_failed++;
            logger << log4cpp::Priority::DEBUG << "InfluxDB write operation failed for networks_traffic";
            return false;
        }
    }


    return true;
}


// Set block of data into InfluxDB
bool write_line_of_data_to_influxdb(std::string influx_database,
                                    std::string influx_host,
                                    std::string influx_port,
                                    bool enable_auth,
                                    std::string influx_user,
                                    std::string influx_password,
                                    std::string measurement,
                                    std::map<std::string, std::string>& tags,
                                    std::map<std::string, uint64_t>& plain_total_counters_map) {
    uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

    auto influxdb_line =
        craft_line_for_influxdb_line_protocol(unix_timestamp_nanoseconds, measurement, tags, plain_total_counters_map);

    // logger << log4cpp::Priority::INFO << "Raw data to InfluxDB: " << buffer.str();

    return write_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user, influx_password, influxdb_line);
}

// Fills special structure which we use to export metrics into InfluxDB
void fill_per_protocol_countres_for_influxdb(const map_element_t* current_speed_element,
                                             std::map<std::string, uint64_t>& plain_total_counters_map) {
    plain_total_counters_map["fragmented_packets_incoming"] = current_speed_element->fragmented_in_packets;
    plain_total_counters_map["tcp_packets_incoming"]        = current_speed_element->tcp_in_packets;
    plain_total_counters_map["tcp_syn_packets_incoming"]    = current_speed_element->tcp_syn_in_packets;
    plain_total_counters_map["udp_packets_incoming"]        = current_speed_element->udp_in_packets;
    plain_total_counters_map["icmp_packets_incoming"]       = current_speed_element->icmp_in_packets;

    plain_total_counters_map["fragmented_bits_incoming"] = current_speed_element->fragmented_in_bytes * 8; 
    plain_total_counters_map["tcp_bits_incoming"]        = current_speed_element->tcp_in_bytes * 8; 
    plain_total_counters_map["tcp_syn_bits_incoming"]    = current_speed_element->tcp_syn_in_bytes * 8; 
    plain_total_counters_map["udp_bits_incoming"]        = current_speed_element->udp_in_bytes * 8; 
    plain_total_counters_map["icmp_bits_incoming"]       = current_speed_element->icmp_in_bytes * 8; 


    // Outgoing
    plain_total_counters_map["fragmented_packets_outgoing"] = current_speed_element->fragmented_out_packets;
    plain_total_counters_map["tcp_packets_outgoing"]        = current_speed_element->tcp_out_packets;
    plain_total_counters_map["tcp_syn_packets_outgoing"]    = current_speed_element->tcp_syn_out_packets;
    plain_total_counters_map["udp_packets_outgoing"]        = current_speed_element->udp_out_packets;
    plain_total_counters_map["icmp_packets_outgoing"]       = current_speed_element->icmp_out_packets;

    plain_total_counters_map["fragmented_bits_outgoing"] = current_speed_element->fragmented_out_bytes * 8; 
    plain_total_counters_map["tcp_bits_outgoing"]        = current_speed_element->tcp_out_bytes * 8; 
    plain_total_counters_map["tcp_syn_bits_outgoing"]    = current_speed_element->tcp_syn_out_bytes * 8; 
    plain_total_counters_map["udp_bits_outgoing"]        = current_speed_element->udp_out_bytes * 8; 
    plain_total_counters_map["icmp_bits_outgoing"]       = current_speed_element->icmp_out_bytes * 8; 
}

// Fills special structure which we use to export metrics into InfluxDB
void fill_main_counters_for_influxdb(const map_element_t* current_speed_element,
                                     std::map<std::string, uint64_t>& plain_total_counters_map,
                                     bool populate_flow) {
    // Prepare incoming traffic data
    plain_total_counters_map["packets_incoming"] = current_speed_element->in_packets;
    plain_total_counters_map["bits_incoming"]    = current_speed_element->in_bytes * 8; 

    // Outdoing traffic
    plain_total_counters_map["packets_outgoing"] = current_speed_element->out_packets;
    plain_total_counters_map["bits_outgoing"]    = current_speed_element->out_bytes * 8; 

    if (populate_flow) {
        plain_total_counters_map["flows_incoming"] = current_speed_element->in_flows;
        plain_total_counters_map["flows_outgoing"] = current_speed_element->out_flows;
    }    
}


// Prepare string to insert data into InfluxDB
std::string craft_line_for_influxdb_line_protocol(uint64_t unix_timestamp_nanoseconds,
                                                  std::string measurement,
                                                  std::map<std::string, std::string>& tags,
                                                  std::map<std::string, uint64_t>& plain_total_counters_map) {
    std::stringstream buffer;
    buffer << measurement << ","; 

    // tag set section
    buffer << join_by_comma_and_equal(tags);

    buffer << " "; 

    // field set section
    for (auto itr = plain_total_counters_map.begin(); itr != plain_total_counters_map.end(); ++itr) {
        buffer << itr->first << "=" << std::to_string(itr->second);

        // it's last element
        if (std::distance(itr, plain_total_counters_map.end()) == 1) { 
            // Do not print comma
        } else {
            buffer << ","; 
        }
    }    

    buffer << " " << std::to_string(unix_timestamp_nanoseconds);

    return buffer.str();
}


