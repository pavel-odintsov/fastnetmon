#include "influxdb.hpp"

#include "../abstract_subnet_counters.hpp"
#include "../fast_library.hpp"
#include "../fastnetmon_types.hpp"

#include "../all_logcpp_libraries.hpp"

#include "../abstract_subnet_counters.hpp"

#include "../fastnetmon_configuration_scheme.hpp"

#include <vector>

extern struct timeval graphite_thread_execution_time;
extern uint64_t influxdb_writes_total;
extern uint64_t influxdb_writes_failed;
extern log4cpp::Category& logger;

extern fastnetmon_configuration_t fastnetmon_global_configuration;

// I do this declaration here to avoid circular dependencies between fastnetmon_logic and this file
bool get_statistics(std::vector<system_counter_t>& system_counters);

bool write_batch_of_data_to_influxdb(const std::string& influx_database,
                                     const std::string& influx_host,
                                     const std::string& influx_port,
                                     bool enable_auth,
                                     const std::string& influx_user,
                                     const std::string& influx_password,
                                     const std::string& measurement,
                                     const std::string& tag_name,
                                     const std::vector<std::pair<std::string, std::map<std::string, uint64_t>>>& hosts_vector,
                                     std::string& error_text);

// Set block of data into InfluxDB
bool write_line_of_data_to_influxdb(const std::string& influx_database,
                                    const std::string& influx_host,
                                    const std::string& influx_port,
                                    bool enable_auth,
                                    const std::string& influx_user,
                                    const std::string& influx_password,
                                    const std::string& measurement,
                                    const std::map<std::string, std::string>& tags,
                                    const std::map<std::string, uint64_t>& plain_total_counters_map,
                                    std::string& error_text);

// Prepare string to insert data into InfluxDB
std::string craft_line_for_influxdb_line_protocol(uint64_t unix_timestamp_nanoseconds,
                                                  const std::string& measurement,
                                                  const std::map<std::string, std::string>& tags,
                                                  const std::map<std::string, uint64_t>& plain_total_counters_map);

void fill_fixed_counters_for_influxdb(const subnet_counter_t& counter,
                                      std::map<std::string, uint64_t>& plain_total_counters_map,
                                      bool populate_flow);

bool push_system_counters_to_influxdb(const std::string& influx_database,
                                      const std::string& influx_host,
                                      const std::string& influx_port,
                                      bool enable_auth,
                                      const std::string& influx_user,
                                      const std::string& influx_password);

bool push_total_traffic_counters_to_influxdb(const std::string& influx_database,
                                             const std::string& influx_host,
                                             const std::string& influx_port,
                                             bool enable_auth,
                                             const std::string& influx_user,
                                             const std::string& influx_password,
                                             const std::string& measurement_name,
                                             total_counter_element_t total_speed_average_counters_param[4],
                                             bool ipv6);


// Push system counters to InfluxDB
bool push_system_counters_to_influxdb(const std::string& influx_database,
                                      const std::string& influx_host,
                                      const std::string& influx_port,
                                      bool enable_auth,
                                      const std::string& influx_user,
                                      const std::string& influx_password) {
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

    std::string error_text;

    bool influx_result =
        write_line_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                       influx_password, "system_counters", tags, plain_total_counters_map, error_text);

    if (!influx_result) {
        influxdb_writes_failed++;
        logger << log4cpp::Priority::DEBUG << "InfluxDB write operation failed for system counters with error " << error_text;
        return false;
    }

    return true;
}

// Push network traffic to InfluxDB
template <typename T, typename C>
requires std::is_same_v<C, subnet_counter_t> bool
push_network_traffic_counters_to_influxdb(abstract_subnet_counters_t<T, C>& network_counters,
                                          const std::string& influx_database,
                                          const std::string& influx_host,
                                          const std::string& influx_port,
                                          bool enable_auth,
                                          const std::string& influx_user,
                                          const std::string& influx_password,
                                          const std::string& measurement,
                                          const std::string& tag_name) {

    std::vector<std::pair<T, C>> speed_elements;

    // Retrieve copy of all counters
    network_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    // Structure for InfluxDB
    std::vector<std::pair<std::string, std::map<std::string, uint64_t>>> networks_vector;

    for (const auto& speed_element : speed_elements) {
        std::map<std::string, uint64_t> plain_total_counters_map;

        // This function can convert both IPv4 and IPv6 subnets to text format
        std::string network_as_cidr_string = convert_any_subnet_to_string(speed_element.first);

        fill_fixed_counters_for_influxdb(speed_element.second, plain_total_counters_map, true);

        networks_vector.push_back(std::make_pair(network_as_cidr_string, plain_total_counters_map));
    }

    if (networks_vector.size() > 0) {
        influxdb_writes_total++;

        std::string error_text;

        bool result = write_batch_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                      influx_password, measurement, tag_name, networks_vector, error_text);

        if (!result) {
            influxdb_writes_failed++;
            logger << log4cpp::Priority::DEBUG << "InfluxDB batch operation failed for " << measurement << " with error " << error_text;
            return false;
        }
    }

    return true;
}

// Push total traffic counters to InfluxDB
bool push_total_traffic_counters_to_influxdb(const std::string& influx_database,
                                             const std::string& influx_host,
                                             const std::string& influx_port,
                                             bool enable_auth,
                                             const std::string& influx_user,
                                             const std::string& influx_password,
                                             const std::string& measurement_name,
                                             total_counter_element_t total_speed_average_counters_param[4],
                                             bool ipv6) {
    extern uint64_t incoming_total_flows_speed;
    extern uint64_t outgoing_total_flows_speed;

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        std::map<std::string, uint64_t> plain_total_counters_map;

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

        plain_total_counters_map["packets"] = total_speed_average_counters_param[packet_direction].total.packets;
        plain_total_counters_map["bits"] = total_speed_average_counters_param[packet_direction].total.bytes * 8;

        plain_total_counters_map["udp_packets"] = total_speed_average_counters_param[packet_direction].udp.packets;
        plain_total_counters_map["udp_bits"] = total_speed_average_counters_param[packet_direction].udp.bytes * 8;

        plain_total_counters_map["tcp_packets"] = total_speed_average_counters_param[packet_direction].tcp.packets;
        plain_total_counters_map["tcp_bits"] = total_speed_average_counters_param[packet_direction].tcp.bytes * 8;

        plain_total_counters_map["icmp_packets"] = total_speed_average_counters_param[packet_direction].icmp.packets;
        plain_total_counters_map["icmp_bits"] = total_speed_average_counters_param[packet_direction].icmp.bytes * 8;

        plain_total_counters_map["fragmented_packets"] = total_speed_average_counters_param[packet_direction].fragmented.packets;
        plain_total_counters_map["fragmented_bits"] = total_speed_average_counters_param[packet_direction].fragmented.bytes * 8;

        plain_total_counters_map["tcp_syn_packets"] = total_speed_average_counters_param[packet_direction].tcp_syn.packets;
        plain_total_counters_map["tcp_syn_bits"] = total_speed_average_counters_param[packet_direction].tcp_syn.bytes * 8;

        plain_total_counters_map["dropped_packets"] = total_speed_average_counters_param[packet_direction].dropped.packets;
        plain_total_counters_map["dropped_bits"] = total_speed_average_counters_param[packet_direction].dropped.bytes * 8;

        std::string direction_as_string = get_direction_name(packet_direction);

        influxdb_writes_total++;

        std::map<std::string, std::string> tags = { { "direction", direction_as_string } };

        std::string error_text;

        bool result = write_line_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                     influx_password, measurement_name, tags, plain_total_counters_map, error_text);

        if (!result) {
            influxdb_writes_failed++;
            logger << log4cpp::Priority::DEBUG << "InfluxDB write operation failed for total_traffic with error: " << error_text;
            return false;
        }
    }


    return true;
}

// Push host traffic to InfluxDB
template <typename T, typename C>
    // Apply limitation on type of keys because we use special string conversion function inside and we must not instantiate it for other unknown types
    requires(std::is_same_v<T, subnet_ipv6_cidr_mask_t> || std::is_same_v<T, uint32_t>) &&
    (std::is_same_v<C, subnet_counter_t>)bool push_hosts_traffic_counters_to_influxdb(abstract_subnet_counters_t<T, C>& host_counters,
                                                                                      const std::string& influx_database,
                                                                                      const std::string& influx_host,
                                                                                      const std::string& influx_port,
                                                                                      bool enable_auth,
                                                                                      const std::string& influx_user,
                                                                                      const std::string& influx_password,
                                                                                      const std::string& measurement,
                                                                                      const std::string& tag_name) {

    std::vector<std::pair<T, C>> speed_elements;

    // TODO: preallocate memory here for this array to avoid memory allocations under the lock
    host_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    // Structure for InfluxDB
    std::vector<std::pair<std::string, std::map<std::string, uint64_t>>> hosts_vector;

    for (const auto& speed_element : speed_elements) {
        std::map<std::string, uint64_t> plain_total_counters_map;

        std::string client_ip_as_string;

        if constexpr (std::is_same_v<T, subnet_ipv6_cidr_mask_t>) {
            // We use pretty strange encoding here which encodes IPv6 address as subnet but
            // then we just discard CIDR mask because it does not matter
            client_ip_as_string = print_ipv6_address(speed_element.first.subnet_address);
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            // We use this encoding when we use
            client_ip_as_string = convert_ip_as_uint_to_string(speed_element.first);
        } else {
            logger << log4cpp::Priority::ERROR << "No match for push_hosts_traffic_counters_to_influxdb";
            return false;
        }

        fill_fixed_counters_for_influxdb(speed_element.second, plain_total_counters_map, true);

        hosts_vector.push_back(std::make_pair(client_ip_as_string, plain_total_counters_map));
    }

    // TODO: For big networks it will cause HUGE batches, it will make sense to split them in 5-10k batches
    if (hosts_vector.size() > 0) {
        influxdb_writes_total++;

        std::string error_text;

        bool result = write_batch_of_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user,
                                                      influx_password, measurement, tag_name, hosts_vector, error_text);

        if (!result) {
            influxdb_writes_failed++;
            logger << log4cpp::Priority::DEBUG << "InfluxDB batch operation failed for hosts_traffic with error " << error_text;
            return false;
        }
    }

    return true;
}

// This thread pushes data to InfluxDB
void influxdb_push_thread() {
 extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_host_counters;
    extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_network_counters;
    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern total_speed_counters_t total_counters_ipv4;
    extern total_speed_counters_t total_counters_ipv6;
    extern abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;
    extern abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_24_counters;
                                    
    std::string influx_database = fastnetmon_global_configuration.influxdb_database;
    std::string influx_host     = fastnetmon_global_configuration.influxdb_host;
    std::string influx_port     = std::to_string(fastnetmon_global_configuration.influxdb_port);
        
    bool enable_auth            = fastnetmon_global_configuration.influxdb_auth;
    std::string influx_user     = fastnetmon_global_configuration.influxdb_user;
    std::string influx_password = fastnetmon_global_configuration.influxdb_password;

    bool do_dns_resolution = false;
 
    // If address does not look like IPv4 or IPv6 then we will use DNS resolution for it
    if (!validate_ipv6_or_ipv4_host(influx_host)) {
        logger << log4cpp::Priority::INFO << "You set InfluxDB server address as hostname " << influx_host
               << " and we will use DNS to resolve it";
        do_dns_resolution = true;
    }

    // Sleep less then 1 second to capture speed calculated for very first time by speed calculation logic
    boost::this_thread::sleep(boost::posix_time::milliseconds(700));

    while (true) {
        std::string current_influxdb_ip_address = "";

        if (do_dns_resolution) {
            std::string ip_address = dns_lookup(influx_host);

            if (ip_address.empty()) {
                logger << log4cpp::Priority::ERROR << "Cannot resolve " << influx_host << " to address";

                // Each loop interruption must have similar sleep section
                boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.influxdb_push_period));
                continue;
            }

            logger << log4cpp::Priority::DEBUG << "Resolved " << influx_host << " to " << ip_address;

            current_influxdb_ip_address = ip_address;
        } else {
            // We do not need DNS resolution here, use address as is
            current_influxdb_ip_address = fastnetmon_global_configuration.influxdb_host;
        }

        // First of all push total counters to InfluxDB
        push_total_traffic_counters_to_influxdb(influx_database, current_influxdb_ip_address, influx_port, enable_auth,
			                        influx_user, influx_password, "total_traffic",
                                                total_counters_ipv4.total_speed_average_counters, false);

        // Push per subnet counters to InfluxDB
        push_network_traffic_counters_to_influxdb(ipv4_network_counters, influx_database, current_influxdb_ip_address, influx_port,
                                                  enable_auth, influx_user, influx_password, "networks_traffic", "network");

        // Push per host counters to InfluxDB
        push_hosts_traffic_counters_to_influxdb(ipv4_host_counters, influx_database,
                                                current_influxdb_ip_address, influx_port, enable_auth,
                                                influx_user, influx_password, "hosts_traffic", "host");

        push_system_counters_to_influxdb(influx_database, current_influxdb_ip_address, influx_port,
                                         enable_auth, influx_user, influx_password);

        // Push per host IPv6 counters to InfluxDB
        push_hosts_traffic_counters_to_influxdb(ipv6_host_counters, influx_database,
                                                current_influxdb_ip_address, influx_port, enable_auth,
                                                influx_user, influx_password, "hosts_ipv6_traffic", "host");

        // Push per network IPv6 counters to InfluxDB
        push_network_traffic_counters_to_influxdb(ipv6_network_counters, influx_database,
                                                current_influxdb_ip_address, influx_port, enable_auth,
                                                influx_user, influx_password, "networks_ipv6_traffic", "network");

        // Push total IPv6 counters
        push_total_traffic_counters_to_influxdb(influx_database, current_influxdb_ip_address, influx_port,
                                                enable_auth, influx_user, influx_password, "total_traffic_ipv6",
                                                total_counters_ipv6.total_speed_average_counters, true);

	boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.influxdb_push_period));
    }
}

// Write batch of data for particular InfluxDB database
bool write_batch_of_data_to_influxdb(const std::string& influx_database,
                                     const std::string& influx_host,
                                     const std::string& influx_port,
                                     bool enable_auth,
                                     const std::string& influx_user,
                                     const std::string& influx_password,
                                     const std::string& measurement,
                                     const std::string& tag_name,
                                     const std::vector<std::pair<std::string, std::map<std::string, uint64_t>>>& hosts_vector,
                                     std::string& error_text) {
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
                                  buffer.str(), error_text);
}

// Set block of data into InfluxDB
bool write_line_of_data_to_influxdb(const std::string& influx_database,
                                    const std::string& influx_host,
                                    const std::string& influx_port,
                                    bool enable_auth,
                                    const std::string& influx_user,
                                    const std::string& influx_password,
                                    const std::string& measurement,
                                    const std::map<std::string, std::string>& tags,
                                    const std::map<std::string, uint64_t>& plain_total_counters_map,
				    std::string& error_text) {
    uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

    auto influxdb_line =
        craft_line_for_influxdb_line_protocol(unix_timestamp_nanoseconds, measurement, tags, plain_total_counters_map);

    // logger << log4cpp::Priority::INFO << "Raw data to InfluxDB: " << buffer.str();

    return write_data_to_influxdb(influx_database, influx_host, influx_port, enable_auth, influx_user, influx_password, influxdb_line, error_text);
}

// Simple helper function to add additional metrics easily
void add_counter_to_influxdb(std::map<std::string, uint64_t>& plain_total_counters_map,
                             const traffic_counter_element_t& counter,
                             const std::string& counter_name) {
    plain_total_counters_map[counter_name + "_packets_incoming"] = counter.in_packets;
    plain_total_counters_map[counter_name + "_bits_incoming"]    = counter.in_bytes * 8;
    plain_total_counters_map[counter_name + "_packets_outgoing"] = counter.out_packets;
    plain_total_counters_map[counter_name + "_bits_outgoing"]    = counter.out_bytes * 8;
}

// Fills special structure which we use to export metrics into InfluxDB
void fill_per_protocol_countres_for_influxdb(const subnet_counter_t& current_speed_element,
                                             std::map<std::string, uint64_t>& plain_total_counters_map) {

    add_counter_to_influxdb(plain_total_counters_map, current_speed_element.dropped, "dropped");
    add_counter_to_influxdb(plain_total_counters_map, current_speed_element.fragmented, "fragmented");
    add_counter_to_influxdb(plain_total_counters_map, current_speed_element.tcp, "tcp");
    add_counter_to_influxdb(plain_total_counters_map, current_speed_element.tcp_syn, "tcp_syn");
    add_counter_to_influxdb(plain_total_counters_map, current_speed_element.udp, "udp");
    add_counter_to_influxdb(plain_total_counters_map, current_speed_element.icmp, "icmp");
}


// Fills special structure which we use to export metrics into InfluxDB
void fill_main_counters_for_influxdb(const subnet_counter_t& current_speed_element,
                                     std::map<std::string, uint64_t>& plain_total_counters_map,
                                     bool populate_flow) {
    // Prepare incoming traffic data
    plain_total_counters_map["packets_incoming"] = current_speed_element.total.in_packets;
    plain_total_counters_map["bits_incoming"]    = current_speed_element.total.in_bytes * 8;

    // Outdoing traffic
    plain_total_counters_map["packets_outgoing"] = current_speed_element.total.out_packets;
    plain_total_counters_map["bits_outgoing"]    = current_speed_element.total.out_bytes * 8;

    if (populate_flow) {
        plain_total_counters_map["flows_incoming"] = current_speed_element.in_flows;
        plain_total_counters_map["flows_outgoing"] = current_speed_element.out_flows;
    }
}

// Fills counters for standard fixed counters
void fill_fixed_counters_for_influxdb(const subnet_counter_t& counter,
                                      std::map<std::string, uint64_t>& plain_total_counters_map,
                                      bool populate_flow) {
    fill_main_counters_for_influxdb(counter, plain_total_counters_map, populate_flow);

    fill_per_protocol_countres_for_influxdb(counter, plain_total_counters_map);

    return;
}


// Prepare string to insert data into InfluxDB
std::string craft_line_for_influxdb_line_protocol(uint64_t unix_timestamp_nanoseconds,
                                                  const std::string& measurement,
                                                  const std::map<std::string, std::string>& tags,
                                                  const std::map<std::string, uint64_t>& plain_total_counters_map) {
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
