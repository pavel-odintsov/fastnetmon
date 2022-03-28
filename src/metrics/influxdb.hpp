#pragma once

#include <string>
#include <vector>

#include "../fastnetmon_types.h"

bool push_system_counters_to_influxdb(std::string influx_database,
                                      std::string influx_host,
                                      std::string influx_port,
                                      bool enable_auth,
                                      std::string influx_user,
                                      std::string influx_password);
                                      
                                      bool push_total_traffic_counters_to_influxdb(std::string influx_database,
                                             std::string influx_host,
                                             std::string influx_port,
                                             bool enable_auth,
                                             std::string influx_user,
                                             std::string influx_password,
                                             std::string measurement_name,
                                             total_counter_element_t total_speed_average_counters_param[4],
                                             bool ipv6);
                                             
                  void send_grafana_alert(std::string title, std::string text, std::vector<std::string>& tags) ;
                  
                  void influxdb_push_thread();
                  
                  bool push_hosts_ipv6_traffic_counters_to_influxdb(std::string influx_database,
                                                  std::string influx_host,
                                                  std::string influx_port,
                                                  bool enable_auth,
                                                  std::string influx_user,
                                                  std::string influx_password);
                                                  
                                                 bool push_hosts_traffic_counters_to_influxdb(std::string influx_database,
                                             std::string influx_host,
                                             std::string influx_port,
                                             bool enable_auth,
                                             std::string influx_user,
                                             std::string influx_password) ;
                                             
                                             bool push_hostgroup_traffic_counters_to_influxdb(std::string influx_database,
                                                 std::string influx_host,
                                                 std::string influx_port,
                                                 bool enable_auth,
                                                 std::string influx_user,
                                                 std::string influx_password);
                                                 
                                                 bool write_batch_of_data_to_influxdb(std::string influx_database,
                                     std::string influx_host,
                                     std::string influx_port,
                                     bool enable_auth,
                                     std::string influx_user,
                                     std::string influx_password,
                                     std::string measurement,
                                     std::string tag_name,
                                     std::vector<std::pair<std::string, std::map<std::string, uint64_t>>>& hosts_vector);
                                     
                                     
                            bool push_network_traffic_counters_to_influxdb(std::string influx_database,
                                               std::string influx_host,
                                               std::string influx_port,
                                               bool enable_auth,
                                               std::string influx_user,
                                               std::string influx_password);
                                               
                                   
// Set block of data into InfluxDB
bool write_line_of_data_to_influxdb(std::string influx_database,
                                    std::string influx_host,
                                    std::string influx_port,
                                    bool enable_auth,
                                    std::string influx_user,
                                    std::string influx_password,
                                    std::string measurement,
                                    std::map<std::string, std::string>& tags,
                                    std::map<std::string, uint64_t>& plain_total_counters_map);

void fill_per_protocol_countres_for_influxdb(const map_element_t* current_speed_element,                                              std::map<std::string, uint64_t>& plain_total_counters_map);

void fill_main_counters_for_influxdb(const map_element_t* current_speed_element,
                                             std::map<std::string, uint64_t>& plain_total_counters_map,
                                                                                  bool populate_flow);

// Prepare string to insert data into InfluxDB
std::string craft_line_for_influxdb_line_protocol(uint64_t unix_timestamp_nanoseconds,
                                                  std::string measurement,
                                                  std::map<std::string, std::string>& tags,
                                                  std::map<std::string, uint64_t>& plain_total_counters_map);


