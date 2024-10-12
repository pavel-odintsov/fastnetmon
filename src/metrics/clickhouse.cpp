#include "clickhouse.hpp"

#include <clickhouse/client.h>

#include "../abstract_subnet_counters.hpp"
#include "../fast_library.hpp"
#include "../fastnetmon_types.hpp"

#include "../all_logcpp_libraries.hpp"

extern fastnetmon_configuration_t fastnetmon_global_configuration;

extern uint64_t clickhouse_metrics_writes_total;
extern uint64_t clickhouse_metrics_writes_failed;

extern log4cpp::Category& logger;

// I do this declaration here to avoid circular dependencies between fastnetmon_logic and this file
bool get_statistics(std::vector<system_counter_t>& system_counters);

class PerProtocolMetrics {
    public:
    PerProtocolMetrics() {
        // Per protocol packet counters
        tcp_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        tcp_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        udp_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        udp_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        icmp_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        icmp_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        fragmented_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        fragmented_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        tcp_syn_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        tcp_syn_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        // Per protocol bytes countres
        tcp_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        tcp_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        udp_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        udp_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        icmp_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        icmp_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        fragmented_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        fragmented_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        tcp_syn_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        tcp_syn_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    }

    // Per protocol packet counters
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_packets_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> udp_packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> udp_packets_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> icmp_packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> icmp_packets_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> fragmented_packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> fragmented_packets_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> tcp_syn_packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_syn_packets_outgoing{ nullptr };

    // Per protocol bytes counters
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_bits_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> udp_bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> udp_bits_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> icmp_bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> icmp_bits_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> fragmented_bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> fragmented_bits_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> tcp_syn_bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_syn_bits_outgoing{ nullptr };
};

// Keeps pointers to Clickhouse metrics
class ClickhouseHostMetrics {
    public:
    ClickhouseHostMetrics() {
        date_time = std::make_shared<clickhouse::ColumnDateTime>();

        host             = std::make_shared<clickhouse::ColumnString>();
        packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

        flows_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        flows_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    }

    std::shared_ptr<clickhouse::ColumnDateTime> date_time{ nullptr };

    std::shared_ptr<clickhouse::ColumnString> host{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> packets_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> bits_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> flows_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> flows_outgoing{ nullptr };

    // Per protocol metrics
    PerProtocolMetrics pp{};
};


// Keeps pointers to Clickhouse metrics
// Slightly different from hosts: uses field network instead of host and does not have flows
class ClickhouseNetworkMetrics {
    public:
    ClickhouseNetworkMetrics() {
        date_time = std::make_shared<clickhouse::ColumnDateTime>();

        network          = std::make_shared<clickhouse::ColumnString>();
        packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
        packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
        bits_incoming    = std::make_shared<clickhouse::ColumnUInt64>();
        bits_outgoing    = std::make_shared<clickhouse::ColumnUInt64>();
    }

    std::shared_ptr<clickhouse::ColumnDateTime> date_time{ nullptr };

    std::shared_ptr<clickhouse::ColumnString> network{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> packets_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> packets_outgoing{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> bits_incoming{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> bits_outgoing{ nullptr };

    // Per protocol metrics
    PerProtocolMetrics pp{};
};

// We use template to use it for both per host and network counters which use slightly different structures
void register_clickhouse_per_protocol_metrics_block(clickhouse::Block& block, PerProtocolMetrics& metrics) {
    // Per packet counters
    block.AppendColumn("tcp_packets_incoming", metrics.tcp_packets_incoming);
    block.AppendColumn("tcp_packets_outgoing", metrics.tcp_packets_outgoing);

    block.AppendColumn("udp_packets_incoming", metrics.udp_packets_incoming);
    block.AppendColumn("udp_packets_outgoing", metrics.udp_packets_outgoing);

    block.AppendColumn("icmp_packets_incoming", metrics.icmp_packets_incoming);
    block.AppendColumn("icmp_packets_outgoing", metrics.icmp_packets_outgoing);

    block.AppendColumn("fragmented_packets_incoming", metrics.fragmented_packets_incoming);
    block.AppendColumn("fragmented_packets_outgoing", metrics.fragmented_packets_outgoing);

    block.AppendColumn("tcp_syn_packets_incoming", metrics.tcp_syn_packets_incoming);
    block.AppendColumn("tcp_syn_packets_outgoing", metrics.tcp_syn_packets_outgoing);

    // Per bit counters
    block.AppendColumn("tcp_bits_incoming", metrics.tcp_bits_incoming);
    block.AppendColumn("tcp_bits_outgoing", metrics.tcp_bits_outgoing);

    block.AppendColumn("udp_bits_incoming", metrics.udp_bits_incoming);
    block.AppendColumn("udp_bits_outgoing", metrics.udp_bits_outgoing);

    block.AppendColumn("icmp_bits_incoming", metrics.icmp_bits_incoming);
    block.AppendColumn("icmp_bits_outgoing", metrics.icmp_bits_outgoing);

    block.AppendColumn("fragmented_bits_incoming", metrics.fragmented_bits_incoming);
    block.AppendColumn("fragmented_bits_outgoing", metrics.fragmented_bits_outgoing);

    block.AppendColumn("tcp_syn_bits_incoming", metrics.tcp_syn_bits_incoming);
    block.AppendColumn("tcp_syn_bits_outgoing", metrics.tcp_syn_bits_outgoing);
}

void increment_clickhouse_per_protocol_counters(PerProtocolMetrics& metrics, const subnet_counter_t& current_speed_element) {
    metrics.tcp_packets_incoming->Append(current_speed_element.tcp.in_packets);
    metrics.udp_packets_incoming->Append(current_speed_element.udp.in_packets);
    metrics.icmp_packets_incoming->Append(current_speed_element.icmp.in_packets);
    metrics.fragmented_packets_incoming->Append(current_speed_element.fragmented.in_packets);
    metrics.tcp_syn_packets_incoming->Append(current_speed_element.tcp_syn.in_packets);

    metrics.tcp_bits_incoming->Append(current_speed_element.tcp.in_bytes * 8);
    metrics.udp_bits_incoming->Append(current_speed_element.udp.in_bytes * 8);
    metrics.icmp_bits_incoming->Append(current_speed_element.icmp.in_bytes * 8);
    metrics.fragmented_bits_incoming->Append(current_speed_element.fragmented.in_bytes * 8);
    metrics.tcp_syn_bits_incoming->Append(current_speed_element.tcp_syn.in_bytes * 8);

    metrics.tcp_packets_outgoing->Append(current_speed_element.tcp.out_packets);
    metrics.udp_packets_outgoing->Append(current_speed_element.udp.out_packets);
    metrics.icmp_packets_outgoing->Append(current_speed_element.icmp.out_packets);
    metrics.fragmented_packets_outgoing->Append(current_speed_element.fragmented.out_packets);
    metrics.tcp_syn_packets_outgoing->Append(current_speed_element.tcp_syn.out_packets);

    metrics.tcp_bits_outgoing->Append(current_speed_element.tcp.out_bytes * 8);
    metrics.udp_bits_outgoing->Append(current_speed_element.udp.out_bytes * 8);
    metrics.icmp_bits_outgoing->Append(current_speed_element.icmp.out_bytes * 8);
    metrics.fragmented_bits_outgoing->Append(current_speed_element.fragmented.out_bytes * 8);
    metrics.tcp_syn_bits_outgoing->Append(current_speed_element.tcp_syn.out_bytes * 8);
}


// Populates Clickhouse host counters using speed_element
void increment_clickhouse_host_counters(ClickhouseHostMetrics& metrics, const subnet_counter_t& current_speed_element) {
    metrics.packets_incoming->Append(current_speed_element.total.in_packets);
    metrics.bits_incoming->Append(current_speed_element.total.in_bytes * 8);
    metrics.flows_incoming->Append(current_speed_element.in_flows);

    metrics.packets_outgoing->Append(current_speed_element.total.out_packets);
    metrics.bits_outgoing->Append(current_speed_element.total.out_bytes * 8);
    metrics.flows_outgoing->Append(current_speed_element.out_flows);

    increment_clickhouse_per_protocol_counters(metrics.pp, current_speed_element);
}

std::string generate_total_metrics_schema(const std::string& table_name) {
    std::string total_metrics_schema = "CREATE TABLE IF NOT EXISTS " +
                                       fastnetmon_global_configuration.clickhouse_metrics_database + "." + table_name +
                                       "(metricDate Date DEFAULT toDate(metricDateTime),"
                                       "metricDateTime      DateTime,"
                                       "direction           String,"
                                       "flows               UInt64,"
                                       "packets             UInt64,"
                                       "bits                UInt64,"
                                       "tcp_packets         UInt64,"
                                       "udp_packets         UInt64,"
                                       "icmp_packets        UInt64,"
                                       "fragmented_packets  UInt64,"
                                       "tcp_syn_packets     UInt64,"
                                       "dropped_packets     UInt64,"
                                       "tcp_bits            UInt64,"
                                       "udp_bits            UInt64,"
                                       "icmp_bits           UInt64,"
                                       "fragmented_bits     UInt64,"
                                       "tcp_syn_bits        UInt64,"
                                       "dropped_bits        UInt64,"
                                       "schema_version UInt8 Default 0 COMMENT '1'"
                                       ") ENGINE = MergeTree ORDER BY (direction, metricDate) PARTITION BY metricDate "
                                       "TTL metricDate + toIntervalDay(7) SETTINGS index_granularity=8192;";

    return total_metrics_schema;
}


std::string generate_host_metrics_schema(std::string database_name, std::string table_name) {
    std::string host_metrics_schema =
        "CREATE TABLE IF NOT EXISTS " + database_name + "." + table_name +
        "(metricDate Date DEFAULT toDate(metricDateTime), "
        "metricDateTime DateTime, "
        "host String, "
        "packets_incoming UInt64, "
        "packets_outgoing UInt64, "
        "bits_incoming UInt64,    "
        "bits_outgoing UInt64,    "
        "flows_incoming UInt64,   "
        "flows_outgoing UInt64,   "

        "tcp_packets_incoming         UInt64, tcp_packets_outgoing        UInt64,"
        "udp_packets_incoming         UInt64, udp_packets_outgoing        UInt64,"
        "icmp_packets_incoming        UInt64, icmp_packets_outgoing       UInt64,"
        "fragmented_packets_incoming  UInt64, fragmented_packets_outgoing UInt64,"
        "tcp_syn_packets_incoming     UInt64, tcp_syn_packets_outgoing    UInt64,"

        "tcp_bits_incoming            UInt64, tcp_bits_outgoing           UInt64,"
        "udp_bits_incoming            UInt64, udp_bits_outgoing           UInt64,"
        "icmp_bits_incoming           UInt64, icmp_bits_outgoing          UInt64,"
        "fragmented_bits_incoming     UInt64, fragmented_bits_outgoing    UInt64,"
        "tcp_syn_bits_incoming        UInt64, tcp_syn_bits_outgoing       UInt64,"

        "schema_version UInt8 Default 0 COMMENT '2') ENGINE = MergeTree ORDER BY (host, metricDate) PARTITION BY "
        "metricDate TTL metricDate + toIntervalDay(7) SETTINGS index_granularity=8192;";
    return host_metrics_schema;
}

// Create database in Clickhouse
bool create_clickhouse_database_for_metrics(fastnetmon_configuration_t& fastnetmon_global_configuration,
                                            clickhouse::Client* clickhouse_metrics_client) {
    // Create database for FastNetMon metrics
    bool we_already_have_fastnetmon_database = false;

    // List all databases in Clickhouse
    clickhouse_metrics_client->Select("SHOW DATABASES", [&](const clickhouse::Block& block) {
        for (size_t i = 0; i < block.GetRowCount(); ++i) {
            if (block[0]->As<clickhouse::ColumnString>()->At(i) == fastnetmon_global_configuration.clickhouse_metrics_database) { //-V767
                we_already_have_fastnetmon_database = true;
            }
        }
    });

    if (we_already_have_fastnetmon_database) {
        logger << log4cpp::Priority::DEBUG << "We found database for metrics in Clickhouse";
        return true;
    }

    logger << log4cpp::Priority::INFO << "We do not have database for metrics in Clickhouse. Need to create it";

    try {
        logger << log4cpp::Priority::INFO << "Create database " + fastnetmon_global_configuration.clickhouse_metrics_database;

        clickhouse_metrics_client->Execute("CREATE DATABASE IF NOT EXISTS " + fastnetmon_global_configuration.clickhouse_metrics_database);
    } catch (const std::exception& e) {
        logger << log4cpp::Priority::ERROR << "Could not create database: " << e.what();
        return false;
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Could not create database";
        return false;
    }

    return true;
}

// Creates Clickhouse table using provided table name and schema
bool create_clickhouse_table_using_schema(const std::string& schema, const std::string& table_name, clickhouse::Client* clickhouse_metrics_client) {

    try {
        logger << log4cpp::Priority::DEBUG << "Attempt to create table " << table_name << " if it does not exist";
        clickhouse_metrics_client->Execute(schema);
    } catch (const std::exception& e) {
        logger << log4cpp::Priority::ERROR << "Could not create table " << table_name << ": " << e.what();
        return false;
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Could not create table " << table_name;
        return false;
    }

    return true;
}

// Creates tables in Clickhouse
bool create_clickhouse_tables_for_metrics(fastnetmon_configuration_t& fastnetmon_global_configuration,
                                          clickhouse::Client* clickhouse_metrics_client) {

    auto create_databases_result =
        create_clickhouse_database_for_metrics(fastnetmon_global_configuration, clickhouse_metrics_client);

    if (!create_databases_result) {
        return false;
    }

    // clang-format off
    // Create tables for Clickhouse metrics
    
    std::string network_metrics_schema =
        "CREATE TABLE IF NOT EXISTS " + fastnetmon_global_configuration.clickhouse_metrics_database +
        ".network_metrics("
        "metricDate Date DEFAULT toDate(metricDateTime),"
        "metricDateTime DateTime,"
        "network String,"
        "packets_incoming UInt64, packets_outgoing UInt64,"
        "bits_incoming UInt64,    bits_outgoing UInt64,"
        "tcp_packets_incoming         UInt64, tcp_packets_outgoing        UInt64,"
        "udp_packets_incoming         UInt64, udp_packets_outgoing        UInt64,"
        "icmp_packets_incoming        UInt64, icmp_packets_outgoing       UInt64,"
        "fragmented_packets_incoming  UInt64, fragmented_packets_outgoing UInt64,"
        "tcp_syn_packets_incoming     UInt64, tcp_syn_packets_outgoing    UInt64,"

        "tcp_bits_incoming            UInt64, tcp_bits_outgoing           UInt64,"
        "udp_bits_incoming            UInt64, udp_bits_outgoing           UInt64,"
        "icmp_bits_incoming           UInt64, icmp_bits_outgoing          UInt64,"
        "fragmented_bits_incoming     UInt64, fragmented_bits_outgoing    UInt64,"
        "tcp_syn_bits_incoming        UInt64, tcp_syn_bits_outgoing       UInt64,"
        "schema_version UInt8 Default 0 COMMENT '1'"
        ") ENGINE = MergeTree ORDER BY (network, metricDate) PARTITION BY metricDate TTL metricDate + toIntervalDay(7) SETTINGS index_granularity=8192;";

    std::string network_metrics_ipv6_schema =
        "CREATE TABLE IF NOT EXISTS " + fastnetmon_global_configuration.clickhouse_metrics_database +
        ".network_metrics_ipv6("
        "metricDate Date DEFAULT toDate(metricDateTime),"
        "metricDateTime DateTime,"
        "network String,"
        "packets_incoming UInt64,     packets_outgoing UInt64,"
        "bits_incoming UInt64,        bits_outgoing UInt64,"
        "tcp_packets_incoming         UInt64, tcp_packets_outgoing        UInt64,"
        "udp_packets_incoming         UInt64, udp_packets_outgoing        UInt64,"
        "icmp_packets_incoming        UInt64, icmp_packets_outgoing       UInt64,"
        "fragmented_packets_incoming  UInt64, fragmented_packets_outgoing UInt64,"
        "tcp_syn_packets_incoming     UInt64, tcp_syn_packets_outgoing    UInt64,"

        "tcp_bits_incoming            UInt64, tcp_bits_outgoing           UInt64,"
        "udp_bits_incoming            UInt64, udp_bits_outgoing           UInt64,"
        "icmp_bits_incoming           UInt64, icmp_bits_outgoing          UInt64,"
        "fragmented_bits_incoming     UInt64, fragmented_bits_outgoing    UInt64,"
        "tcp_syn_bits_incoming        UInt64, tcp_syn_bits_outgoing       UInt64,"
        "schema_version UInt8 Default 0 COMMENT '1'"
        ") ENGINE = MergeTree ORDER BY (network, metricDate) PARTITION BY metricDate TTL metricDate + toIntervalDay(7) SETTINGS index_granularity=8192;";

    std::string total_metrics_schema = generate_total_metrics_schema("total_metrics");

    std::string total_metrics_ipv4_schema = generate_total_metrics_schema("total_metrics_ipv4");

    std::string total_metrics_ipv6_schema = generate_total_metrics_schema("total_metrics_ipv6");
    
    // clang-format on

    if (!create_clickhouse_table_using_schema(network_metrics_schema, "network_metrics", clickhouse_metrics_client)) {
        return false;
    }

    if (!create_clickhouse_table_using_schema(network_metrics_ipv6_schema, "network_metrics_ipv6", clickhouse_metrics_client)) {
        return false;
    }

    std::string host_metrics_schema =
        generate_host_metrics_schema(fastnetmon_global_configuration.clickhouse_metrics_database, "host_metrics");

    if (!create_clickhouse_table_using_schema(host_metrics_schema, "host_metrics", clickhouse_metrics_client)) {
        return false;
    }

    std::string host_metrics_ipv6_schema =
        generate_host_metrics_schema(fastnetmon_global_configuration.clickhouse_metrics_database, "host_metrics_ipv6");

    if (!create_clickhouse_table_using_schema(host_metrics_ipv6_schema, "host_metrics_ipv6", clickhouse_metrics_client)) {
        return false;
    }

    if (!create_clickhouse_table_using_schema(total_metrics_schema, "total_metrics", clickhouse_metrics_client)) {
        return false;
    }

    if (!create_clickhouse_table_using_schema(total_metrics_ipv4_schema, "total_metrics_ipv4", clickhouse_metrics_client)) {
        return false;
    }


    if (!create_clickhouse_table_using_schema(total_metrics_ipv6_schema, "total_metrics_ipv6", clickhouse_metrics_client)) {
        return false;
    }

    // Create table for system counters
    std::string system_metrics_schema =
        "CREATE TABLE IF NOT EXISTS " + fastnetmon_global_configuration.clickhouse_metrics_database + ".system_metrics" +
        "(metricDate Date DEFAULT toDate(metricDateTime), "
        "metricDateTime DateTime, "
        "name String, "
        "type String, "
        "value UInt64, "
        "schema_version UInt8 Default 0 COMMENT '1') ENGINE = MergeTree ORDER BY (name, metricDate) PARTITION BY "
        "metricDate TTL metricDate + toIntervalDay(7) SETTINGS index_granularity=8192;";

    if (!create_clickhouse_table_using_schema(system_metrics_schema, "system_metrics", clickhouse_metrics_client)) {
        return false;
    }

    return true;
}

// Registers metrics to block to push them into database
void register_clickhouse_host_metrics_block(clickhouse::Block& block, ClickhouseHostMetrics& metrics) {
    block.AppendColumn("metricDateTime", metrics.date_time);
    block.AppendColumn("host", metrics.host);

    block.AppendColumn("packets_incoming", metrics.packets_incoming);
    block.AppendColumn("packets_outgoing", metrics.packets_outgoing);

    block.AppendColumn("bits_incoming", metrics.bits_incoming);
    block.AppendColumn("bits_outgoing", metrics.bits_outgoing);

    block.AppendColumn("flows_incoming", metrics.flows_incoming);
    block.AppendColumn("flows_outgoing", metrics.flows_outgoing);

    register_clickhouse_per_protocol_metrics_block(block, metrics.pp);
}


// Registers metrics to block to push them into database
void register_clickhouse_network_metrics_block(clickhouse::Block& block, ClickhouseNetworkMetrics& metrics) {
    block.AppendColumn("metricDateTime", metrics.date_time);
    block.AppendColumn("network", metrics.network);

    block.AppendColumn("packets_incoming", metrics.packets_incoming);
    block.AppendColumn("packets_outgoing", metrics.packets_outgoing);

    block.AppendColumn("bits_incoming", metrics.bits_incoming);
    block.AppendColumn("bits_outgoing", metrics.bits_outgoing);
}


// Push per host traffic counters to Clickhouse
template <typename T, typename C>
    // Apply limitation on type of keys because we use special string conversion function inside and we must not instantiate it for other unknown types
    requires(std::is_same_v<T, subnet_ipv6_cidr_mask_t> || std::is_same_v<T, uint32_t>) &&
    (std::is_same_v<C, subnet_counter_t>)bool push_hosts_traffic_counters_to_clickhouse(clickhouse::Client* clickhouse_metrics_client,
                                                                                        abstract_subnet_counters_t<T, C>& host_counters,
                                                                                        const std::string& table_name) {
    clickhouse::Block block;

    ClickhouseHostMetrics metrics;

    time_t seconds_since_epoch = time(NULL);

    uint64_t elements_in_dataset = 0;

    std::vector<std::pair<T, C>> speed_elements;

    // TODO: preallocate memory here for this array to avoid memory allocations under the lock
    host_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    for (const auto& speed_element : speed_elements) {
        std::string client_ip_as_string;

        if constexpr (std::is_same_v<T, subnet_ipv6_cidr_mask_t>) {
            // We use pretty strange encoding here which encodes IPv6 address as subnet but
            // then we just discard CIDR mask because it does not matter
            client_ip_as_string = print_ipv6_address(speed_element.first.subnet_address);
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            // We use this encoding when we use
            client_ip_as_string = convert_ip_as_uint_to_string(speed_element.first);
        } else {
            logger << log4cpp::Priority::ERROR << "No match for push_hosts_traffic_counters_to_clickhouse";
            return false;
        }

        const subnet_counter_t& current_speed_element = speed_element.second;

        // Skip elements with zero speed
        if (current_speed_element.is_zero()) {
            continue;
        }

        elements_in_dataset++;

        metrics.host->Append(client_ip_as_string);

        metrics.date_time->Append(seconds_since_epoch);

        // Populate Clickhouse metrics data using speed element data
        increment_clickhouse_host_counters(metrics, current_speed_element);
    }

    register_clickhouse_host_metrics_block(block, metrics);

    clickhouse_metrics_writes_total++;

    try {
        clickhouse_metrics_client->Insert(fastnetmon_global_configuration.clickhouse_metrics_database + "." + table_name, block);
    } catch (const std::exception& e) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push " << elements_in_dataset
               << " host metrics to clickhouse: " << e.what();
        return false;
    } catch (...) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push " << elements_in_dataset << " host metrics to clickhouse";
        return false;
    }

    return true;
}

class TotalMetricsElement {
    public:
    std::shared_ptr<clickhouse::ColumnDateTime> date_time{ nullptr };
    std::shared_ptr<clickhouse::ColumnString> direction{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> flows{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> packets{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> bits{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> tcp_packets{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> udp_packets{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> icmp_packets{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> fragmented_packets{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_syn_packets{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> dropped_packets{ nullptr };

    std::shared_ptr<clickhouse::ColumnUInt64> tcp_bits{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> udp_bits{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> icmp_bits{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> fragmented_bits{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> tcp_syn_bits{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> dropped_bits{ nullptr };
};


// Push total counters to Clickhouse
bool push_total_traffic_counters_to_clickhouse(clickhouse::Client* clickhouse_metrics_client,
                                               const total_speed_counters_t& total_counters,
                                               const std::string& table_name,
                                               bool ipv6) {
    extern uint64_t incoming_total_flows_speed;
    extern uint64_t outgoing_total_flows_speed;

    clickhouse::Block block;

    time_t seconds_since_epoch = time(NULL);

    TotalMetricsElement metrics{};

    metrics.direction = std::make_shared<clickhouse::ColumnString>();
    metrics.date_time = std::make_shared<clickhouse::ColumnDateTime>();

    metrics.flows   = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.packets = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.bits    = std::make_shared<clickhouse::ColumnUInt64>();

    metrics.tcp_packets        = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.udp_packets        = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.icmp_packets       = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.fragmented_packets = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.tcp_syn_packets    = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.dropped_packets    = std::make_shared<clickhouse::ColumnUInt64>();

    metrics.tcp_bits        = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.udp_bits        = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.icmp_bits       = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.fragmented_bits = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.tcp_syn_bits    = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.dropped_bits    = std::make_shared<clickhouse::ColumnUInt64>();

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    for (auto packet_direction : directions) {
        metrics.date_time->Append(seconds_since_epoch);

        // We have flow information only for incoming and outgoing directions
        if (packet_direction == INCOMING or packet_direction == OUTGOING) {
            uint64_t flow_counter_for_this_direction = 0;

            if (ipv6) {
                // TODO: we do not calculate flow counters for IPv6 yet
            } else {
                if (packet_direction == INCOMING) {
                    flow_counter_for_this_direction = incoming_total_flows_speed;
                } else {
                    flow_counter_for_this_direction = outgoing_total_flows_speed;
                }
            }

            metrics.flows->Append(flow_counter_for_this_direction);
        } else {
            metrics.flows->Append(0);
        }

        metrics.packets->Append(total_counters.total_speed_average_counters[packet_direction].total.packets);
        metrics.bits->Append(total_counters.total_speed_average_counters[packet_direction].total.bytes * 8);

	// Per protocol counters
    	metrics.tcp_packets->Append(total_counters.total_speed_average_counters[packet_direction].tcp.packets);
    	metrics.udp_packets->Append(total_counters.total_speed_average_counters[packet_direction].udp.packets);
    	metrics.icmp_packets->Append(total_counters.total_speed_average_counters[packet_direction].icmp.packets);
    	metrics.fragmented_packets->Append(total_counters.total_speed_average_counters[packet_direction].fragmented.packets);
    	metrics.tcp_syn_packets->Append(total_counters.total_speed_average_counters[packet_direction].tcp_syn.packets);
    	metrics.dropped_packets->Append(total_counters.total_speed_average_counters[packet_direction].dropped.packets);

    	metrics.tcp_bits->Append(total_counters.total_speed_average_counters[packet_direction].tcp.bytes * 8);
    	metrics.udp_bits->Append(total_counters.total_speed_average_counters[packet_direction].udp.bytes * 8);
    	metrics.icmp_bits->Append(total_counters.total_speed_average_counters[packet_direction].icmp.bytes * 8);
    	metrics.fragmented_bits->Append(total_counters.total_speed_average_counters[packet_direction].fragmented.bytes * 8);
    	metrics.tcp_syn_bits->Append(total_counters.total_speed_average_counters[packet_direction].tcp_syn.bytes * 8);
    	metrics.dropped_bits->Append(total_counters.total_speed_average_counters[packet_direction].dropped.bytes * 8);

        std::string direction_as_string = get_direction_name(packet_direction);
        metrics.direction->Append(direction_as_string.c_str());
    }

    block.AppendColumn("metricDateTime", metrics.date_time);
    block.AppendColumn("direction", metrics.direction);
    block.AppendColumn("flows", metrics.flows);
    block.AppendColumn("packets", metrics.packets);
    block.AppendColumn("bits", metrics.bits);

    // Per protocol
    block.AppendColumn("tcp_packets", metrics.tcp_packets);
    block.AppendColumn("udp_packets", metrics.udp_packets);
    block.AppendColumn("icmp_packets", metrics.icmp_packets);
    block.AppendColumn("fragmented_packets", metrics.fragmented_packets);
    block.AppendColumn("tcp_syn_packets", metrics.tcp_syn_packets);
    block.AppendColumn("dropped_packets", metrics.dropped_packets);

    block.AppendColumn("tcp_bits", metrics.tcp_bits);
    block.AppendColumn("udp_bits", metrics.udp_bits);
    block.AppendColumn("icmp_bits", metrics.icmp_bits);
    block.AppendColumn("fragmented_bits", metrics.fragmented_bits);
    block.AppendColumn("tcp_syn_bits", metrics.tcp_syn_bits);
    block.AppendColumn("dropped_bits", metrics.dropped_bits);

    clickhouse_metrics_writes_total++;

    try {
        clickhouse_metrics_client->Insert(fastnetmon_global_configuration.clickhouse_metrics_database + "." + table_name, block);
    } catch (const std::exception& e) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push total metrics to clickhouse: " << e.what();
        return false;
    } catch (...) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push total metrics to clickhouse";
        return false;
    }

    return true;
}

class SystemMetricsElement {
    public:
    std::shared_ptr<clickhouse::ColumnDateTime> date_time{ nullptr };
    std::shared_ptr<clickhouse::ColumnString> name{ nullptr };
    std::shared_ptr<clickhouse::ColumnUInt64> value{ nullptr };
    std::shared_ptr<clickhouse::ColumnString> type{ nullptr };
};


// Push system counters to Clickhouse
bool push_system_counters_to_clickhouse(clickhouse::Client* clickhouse_metrics_client) {
    clickhouse::Block block;

    time_t seconds_since_epoch = time(NULL);

    SystemMetricsElement metrics{};

    metrics.name      = std::make_shared<clickhouse::ColumnString>();
    metrics.date_time = std::make_shared<clickhouse::ColumnDateTime>();
    metrics.value     = std::make_shared<clickhouse::ColumnUInt64>();
    metrics.type      = std::make_shared<clickhouse::ColumnString>();

    std::vector<system_counter_t> system_counters;

    bool result = get_statistics(system_counters);

    if (!result) {
        logger << log4cpp::Priority::ERROR << "Can't collect system counters";
        return false;
    }

    for (auto counter : system_counters) {
        metrics.date_time->Append(seconds_since_epoch);
        metrics.name->Append(counter.counter_name);
        metrics.value->Append(counter.counter_value);

        if (counter.counter_type == metric_type_t::counter) {
            metrics.type->Append("counter");
        } else if (counter.counter_type == metric_type_t::gauge) {
            metrics.type->Append("gauge");
        } else {
            metrics.type->Append("unknown");
        }
    }

    block.AppendColumn("metricDateTime", metrics.date_time);
    block.AppendColumn("name", metrics.name);
    block.AppendColumn("value", metrics.value);
    block.AppendColumn("type", metrics.type);

    clickhouse_metrics_writes_total++;

    try {
        clickhouse_metrics_client->Insert(fastnetmon_global_configuration.clickhouse_metrics_database + "." + "system_metrics", block);
    } catch (const std::exception& e) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push total metrics to clickhouse: " << e.what();
        return false;
    } catch (...) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push system metrics to clickhouse";
        return false;
    }

    return true;
}

// Push per subnet traffic counters to Clickhouse
template <typename T, typename C>
requires std::is_same_v<C, subnet_counter_t> bool
push_network_traffic_counters_to_clickhouse(clickhouse::Client* clickhouse_metrics_client,
                                            abstract_subnet_counters_t<T, C>& network_counters,
                                            const std::string& table_name) {
    clickhouse::Block block;

    ClickhouseNetworkMetrics metrics;

    time_t seconds_since_epoch = time(NULL);

    uint64_t elements_in_dataset = 0;

    std::vector<std::pair<T, C>> speed_elements;
    network_counters.get_all_non_zero_average_speed_elements_as_pairs(speed_elements);

    for (const auto& itr : speed_elements) {
        const subnet_counter_t& speed = itr.second;

        // This function can convert both IPv4 and IPv6 subnets to text format
        std::string subnet_as_string = convert_any_subnet_to_string(itr.first);

        metrics.date_time->Append(seconds_since_epoch);

        metrics.network->Append(subnet_as_string.c_str());

        metrics.packets_incoming->Append(speed.total.in_packets);
        metrics.packets_outgoing->Append(speed.total.out_packets);

        metrics.bits_incoming->Append(speed.total.in_bytes * 8);
        metrics.bits_outgoing->Append(speed.total.out_bytes * 8);

        increment_clickhouse_per_protocol_counters(metrics.pp, speed);

        elements_in_dataset++;
    }

    register_clickhouse_network_metrics_block(block, metrics);

    // Per protocol metrics
    register_clickhouse_per_protocol_metrics_block(block, metrics.pp);

    clickhouse_metrics_writes_total++;

    try {
        clickhouse_metrics_client->Insert(fastnetmon_global_configuration.clickhouse_metrics_database + "." + table_name, block);
    } catch (const std::exception& e) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push " << elements_in_dataset
               << " network metrics to clickhouse: " << e.what();
        return false;
    } catch (...) {
        clickhouse_metrics_writes_failed++;

        logger << log4cpp::Priority::DEBUG << "Failed to push " << elements_in_dataset << " network metrics to clickhouse";
        return false;
    }

    return true;
}

// We need this flag to avoid attempts to create Clickhouse tables on each iteration, we need do it only once
bool clickhouse_tables_successfully_created = false;

// This thread pushes data to Clickhouse
void clickhouse_push_thread() {
    extern total_speed_counters_t total_counters;
    extern total_speed_counters_t total_counters_ipv4;
    extern total_speed_counters_t total_counters_ipv6;

    extern abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;
    extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_network_counters;

    extern abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;
    extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_host_counters;

    // Sleep less then 1 second to capture speed calculated for very first time by speed calculation logic
    boost::this_thread::sleep(boost::posix_time::milliseconds(700));

    while (true) {
        // Client object for Clickhouse to push metrics
        clickhouse::Client* clickhouse_metrics_client = nullptr;

        // Connect to Clickhouse socket to push metrics
        logger << log4cpp::Priority::DEBUG << "Establish connection to Clickhouse to store metrics";

        // Create ClickHouse connection
        auto client_options = clickhouse::ClientOptions()
                                  .SetHost(fastnetmon_global_configuration.clickhouse_metrics_host)
                                  .SetPort(fastnetmon_global_configuration.clickhouse_metrics_port)
                                  .SetUser(fastnetmon_global_configuration.clickhouse_metrics_username)
                                  .SetPassword(fastnetmon_global_configuration.clickhouse_metrics_password)
                                  .SetSendRetries(1) // We do not need retry logic here as we try to connect again and again on each new iteration
                                  .SetRetryTimeout(std::chrono::seconds(3))
                                  .SetPingBeforeQuery(true)
                                  .SetRethrowException(true);

        try {
            clickhouse_metrics_client = new clickhouse::Client(client_options);
        } catch (const std::exception& ex) {
            logger << log4cpp::Priority::ERROR << "Could not connect to ClickHouse: " << ex.what();

            // Each loop interruption must have similar sleep section
            boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.clickhouse_metrics_push_period));
            continue;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not connect to ClickHouse for some reasons";

            // Each loop interruption must have similar sleep section
            boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.clickhouse_metrics_push_period));
            continue;
        }

        logger << log4cpp::Priority::DEBUG << "Established connection with Clickhouse";

        // We need to create tables only on first iteration
        if (!clickhouse_tables_successfully_created) {
            // Create database and tables
            auto clickhouse_init_res =
                create_clickhouse_tables_for_metrics(fastnetmon_global_configuration, clickhouse_metrics_client);

            if (!clickhouse_init_res) {
                logger << log4cpp::Priority::ERROR << "Could not create Clickhouse tables for metrics";

                // Each loop interruption must have similar sleep section
                boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.clickhouse_metrics_push_period));
                continue;
            }

            clickhouse_tables_successfully_created = true;
        }

        // Total traffic
        push_total_traffic_counters_to_clickhouse(clickhouse_metrics_client, total_counters, "total_metrics", false);

        // Total IPv4 traffic
        push_total_traffic_counters_to_clickhouse(clickhouse_metrics_client, total_counters_ipv4, "total_metrics_ipv4",
                                                  false);

        // Total IPv6 traffic
    	push_total_traffic_counters_to_clickhouse(clickhouse_metrics_client, total_counters_ipv6,
					      "total_metrics_ipv6", true);

        // System counters
        push_system_counters_to_clickhouse(clickhouse_metrics_client);

        // Push per subnet counters to ClickHouse
        push_network_traffic_counters_to_clickhouse(clickhouse_metrics_client, ipv4_network_counters, "network_metrics");

    	push_network_traffic_counters_to_clickhouse(clickhouse_metrics_client, ipv6_network_counters,
						"network_metrics_ipv6");

        // Push per host counters to ClickHouse
        push_hosts_traffic_counters_to_clickhouse(clickhouse_metrics_client, ipv4_host_counters, "host_metrics");

        push_hosts_traffic_counters_to_clickhouse(clickhouse_metrics_client, ipv6_host_counters, "host_metrics_ipv6");

        boost::this_thread::sleep(boost::posix_time::seconds(fastnetmon_global_configuration.clickhouse_metrics_push_period));

        // It's not very clear that destructor for clickhouse::Client actually exists but we need to clear memory for
        // object at least I did tests and confirmed that we do not have fd leaks with this logic
        delete clickhouse_metrics_client;
    }
}

