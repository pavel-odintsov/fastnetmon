#pragma once

#include <boost/serialization/nvp.hpp>
#include <map>
#include <sstream>
#include <vector>

#include "fastnetmon_networks.hpp"

class fastnetmon_configuration_t {
    public:
    // sFlow
    bool sflow{ false };
    std::vector<unsigned int> sflow_ports{};
    std::string sflow_host{ "0.0.0.0" };
    bool sflow_read_packet_length_from_ip_header{ false };
    bool sflow_extract_tunnel_traffic{ false };

    // Netflow / IPFIX
    bool netflow{ false };
    std::vector<unsigned int> netflow_ports{};
    std::string netflow_host{ "0.0.0.0" };
    unsigned int netflow_sampling_ratio{ 1 };

    // Mirror AF_PACKET
    bool mirror_afpacket{ false };
    std::vector<std::string> interfaces{};
    bool afpacket_strict_cpu_affinity{ false };
    std::string mirror_af_packet_fanout_mode{ "cpu" };
    bool af_packet_read_packet_length_from_ip_header{ false };

    // Clickhouse metrics
    bool clickhouse_metrics{ false };
    std::string clickhouse_metrics_database{ "fastnetmon" };
    std::string clickhouse_metrics_username{ "default" };
    std::string clickhouse_metrics_password{ "" };
    std::string clickhouse_metrics_host{ "127.0.0.1" };
    unsigned int clickhouse_metrics_port{ 9000 };
    unsigned int clickhouse_metrics_push_period{ 1 };

    // InfluxDB metrics
    bool influxdb{ false };
    std::string influxdb_database{ "fastnetmon" };
    std::string influxdb_host{ "127.0.0.1" };
    unsigned int influxdb_port{ 8086 };
    std::string influxdb_user{ "fastnetmon" };
    std::string influxdb_password{ "fastnetmon" };
    bool influxdb_auth{ false };
    unsigned int influxdb_push_period{ 1 };

    // Graphtie metrics
    bool graphite{ false };
    std::string graphite_host{ "127.0.0.1" };
    unsigned int graphite_port{ 2003 };
    std::string graphite_prefix{ "fastnetmon" };
    unsigned int graphite_push_period{ 1 };

    // GoBGP
    bool gobgp{ false };

    // IPv4
    bool gobgp_announce_host{ false };
    bool gobgp_announce_whole_subnet{ false };
	
    std::string gobgp_community_host{ "65001:668" };
    std::string gobgp_community_subnet{ "65001:667" };
    std::string gobgp_next_hop{ "0.0.0.0" }; 
    std::string gobgp_next_hop_host_ipv4{ "0.0.0.0" }; 
    std::string gobgp_next_hop_subnet_ipv4{ "0.0.0.0" };

    // IPv6
    bool gobgp_announce_host_ipv6{ false };
    bool gobgp_announce_whole_subnet_ipv6{ false };

    std::string gobgp_next_hop_ipv6{ "100::1" };
    std::string gobgp_next_hop_host_ipv6{ "::0" };
    std::string gobgp_next_hop_subnet_ipv6{ "::0" };

    std::string gobgp_community_host_ipv6{ "65001:668" };
    std::string gobgp_community_subnet_ipv6{ "65001:667" };
};

