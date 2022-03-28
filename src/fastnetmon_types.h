#ifndef FASTNETMON_TYPES_H
#define FASTNETMON_TYPES_H

#include <netinet/in.h> // struct in6_addr
#include <stdint.h> // uint32_t
#include <sys/time.h> // struct timeval
#include <utility> // std::pair

#include <unordered_map>
#include <map>
#include <string>
#include <vector>

#include "packet_storage.h"

#include "fastnetmon_simple_packet.h"

#include "map_element.hpp"

#include "fastnetmon_networks.hpp"

typedef std::vector<map_element_t> vector_of_counters_t;

typedef std::map<std::string, std::string> configuration_map_t;
typedef std::map<std::string, uint64_t> graphite_data_t;

// Enum with available sort by field
enum sort_type_t { PACKETS, BYTES, FLOWS };

// Source of attack detection
enum class attack_detection_source_t : uint32_t { Automatic = 1, Manual = 2, Other = 255 };

// Which direction of traffic triggered attack
enum class attack_detection_direction_type_t {
    unknown,
    incoming,
    outgoing,
};


// How we have detected this attack?
enum class attack_detection_threshold_type_t {
    unknown,

    packets_per_second,
    bytes_per_second,
    flows_per_second,

    tcp_packets_per_second,
    udp_packets_per_second,
    icmp_packets_per_second,

    tcp_bytes_per_second,
    udp_bytes_per_second,
    icmp_bytes_per_second,

    tcp_syn_packets_per_second,
    tcp_syn_bytes_per_second,
};


/* Class for custom comparison fields by different fields */
template <typename T> class TrafficComparatorClass {
    private:
    sort_type_t sort_field;
    direction_t sort_direction;

    public:
    TrafficComparatorClass(direction_t sort_direction, sort_type_t sort_field) {
        this->sort_field = sort_field;
        this->sort_direction = sort_direction;
    }    

    bool operator()(T a, T b) { 
        if (sort_field == FLOWS) {
            if (sort_direction == INCOMING) {
                return a.second.in_flows > b.second.in_flows;
            } else if (sort_direction == OUTGOING) {
                return a.second.out_flows > b.second.out_flows;
            } else {
                return false;
            }
        } else if (sort_field == PACKETS) {
            if (sort_direction == INCOMING) {
                return a.second.in_packets > b.second.in_packets;
            } else if (sort_direction == OUTGOING) {
                return a.second.out_packets > b.second.out_packets;
            } else {
                return false;
            }
        } else if (sort_field == BYTES) {
            if (sort_direction == INCOMING) {
                return a.second.in_bytes > b.second.in_bytes;
            } else if (sort_direction == OUTGOING) {
                return a.second.out_bytes > b.second.out_bytes;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }    
};



class logging_configuration_t {
    public:
    logging_configuration_t()
    : filesystem_logging(true), local_syslog_logging(false), remote_syslog_logging(false),
      remote_syslog_port(0) {
    }
    bool filesystem_logging;
    std::string filesystem_logging_path;

    bool local_syslog_logging;

    bool remote_syslog_logging;
    std::string remote_syslog_server;
    unsigned int remote_syslog_port;
};

typedef std::vector<subnet_cidr_mask_t> subnet_vector_t;

typedef std::map<subnet_cidr_mask_t, std::string> subnet_to_host_group_map_t;
typedef std::map<std::string, subnet_vector_t> host_group_map_t;

typedef void (*process_packet_pointer)(simple_packet_t&);

// Attack types
enum attack_type_t {
    ATTACK_UNKNOWN = 1,
    ATTACK_SYN_FLOOD = 2,
    ATTACK_ICMP_FLOOD = 3,
    ATTACK_UDP_FLOOD = 4,
    ATTACK_IP_FRAGMENTATION_FLOOD = 5,
};

// Amplification types
enum amplification_attack_type_t {
    AMPLIFICATION_ATTACK_UNKNOWN = 1,
    AMPLIFICATION_ATTACK_DNS = 2,
    AMPLIFICATION_ATTACK_NTP = 3,
    AMPLIFICATION_ATTACK_SSDP = 4,
    AMPLIFICATION_ATTACK_SNMP = 5,
    AMPLIFICATION_ATTACK_CHARGEN = 6,
};

class total_counter_element_t {
    public:
    uint64_t bytes;
    uint64_t packets;
    uint64_t flows;

    void zeroify() {
        bytes   = 0;
        packets = 0;
        flows   = 0;
    } 
};

// structure with attack details
class attack_details_t : public map_element_t {
    public:
    attack_details_t()
    : attack_protocol(0), attack_power(0), max_attack_power(0), average_in_bytes(0),
      average_out_bytes(0), average_in_packets(0), average_out_packets(0), average_in_flows(0),
      average_out_flows(0), ban_time(0), attack_direction(OTHER), unban_enabled(true) {

        customer_network.subnet_address     = 0;
        customer_network.cidr_prefix_length = 0;
    }
    
    // Host group for this attack
    std::string host_group;

    // Parent hostgroup for host's host group
    std::string parent_host_group;

    direction_t attack_direction;
    // first attackpower detected
    uint64_t attack_power;
    // max attack power
    uint64_t max_attack_power;
    unsigned int attack_protocol;

    // Average counters
    uint64_t average_in_bytes;
    uint64_t average_out_bytes;
    uint64_t average_in_packets;
    uint64_t average_out_packets;
    uint64_t average_in_flows;
    uint64_t average_out_flows;

    // time when we but this user
    time_t ban_timestamp;
    bool unban_enabled;
    int ban_time; // seconds of the ban

    // If this attack was detected for IPv6 protocol
    bool ipv6 = false;
   
    attack_detection_source_t attack_detection_source = attack_detection_source_t::Automatic;

    subnet_cidr_mask_t customer_network;

    packet_storage_t pcap_attack_dump;
};


typedef attack_details_t banlist_item_t;

// struct for save per direction and per protocol details for flow
class conntrack_key_struct_t {
    public:
    uint64_t bytes   = 0;
    uint64_t packets = 0;
    // will be used for Garbage Collection
    time_t last_update_time = 0;
};


typedef uint64_t packed_session;
// Main mega structure for storing conntracks
// We should use class instead struct for correct std::map allocation
typedef std::map<packed_session, conntrack_key_struct_t> contrack_map_type;

class conntrack_main_struct_t {
    public:
    contrack_map_type in_tcp;
    contrack_map_type in_udp;
    contrack_map_type in_icmp;
    contrack_map_type in_other;

    contrack_map_type out_tcp;
    contrack_map_type out_udp;
    contrack_map_type out_icmp;
    contrack_map_type out_other;
};

typedef std::map<uint32_t, map_element_t> map_for_counters;
typedef std::vector<map_element_t> vector_of_counters;

typedef std::map<subnet_cidr_mask_t, vector_of_counters> map_of_vector_counters_t;

// Flow tracking structures
typedef std::vector<conntrack_main_struct_t> vector_of_flow_counters_t;
typedef std::map<subnet_cidr_mask_t, vector_of_flow_counters_t> map_of_vector_counters_for_flow_t;


typedef map_element_t subnet_counter_t;
typedef std::pair<subnet_cidr_mask_t, subnet_counter_t> pair_of_map_for_subnet_counters_elements_t;
typedef std::map<subnet_cidr_mask_t, subnet_counter_t> map_for_subnet_counters_t;

// IPv6 per subnet counters
typedef std::pair<subnet_ipv6_cidr_mask_t, subnet_counter_t> pair_of_map_for_ipv6_subnet_counters_elements_t;
typedef std::unordered_map<subnet_ipv6_cidr_mask_t, subnet_counter_t> map_for_ipv6_subnet_counters_t;


class packed_conntrack_hash_t {
    public:
    packed_conntrack_hash_t() : opposite_ip(0), src_port(0), dst_port(0) {
    }
    // src or dst IP
    uint32_t opposite_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

// This class consists of all configuration of global or per subnet ban thresholds
class ban_settings_t {
    public:
    ban_settings_t()
    : enable_ban(false), enable_ban_ipv6(false), enable_ban_for_pps(false), enable_ban_for_bandwidth(false),
      enable_ban_for_flows_per_second(false), enable_ban_for_tcp_pps(false),
      enable_ban_for_tcp_bandwidth(false), enable_ban_for_udp_pps(false),
      enable_ban_for_udp_bandwidth(false), enable_ban_for_icmp_pps(false),
      enable_ban_for_icmp_bandwidth(false), ban_threshold_tcp_mbps(0), ban_threshold_tcp_pps(0),
      ban_threshold_udp_mbps(0), ban_threshold_udp_pps(0), ban_threshold_icmp_mbps(0),
      ban_threshold_icmp_pps(0), ban_threshold_mbps(0), ban_threshold_flows(0), ban_threshold_pps(0) {
    }
    bool enable_ban;
    bool enable_ban_ipv6;

    bool enable_ban_for_pps;
    bool enable_ban_for_bandwidth;
    bool enable_ban_for_flows_per_second;

    bool enable_ban_for_tcp_pps;
    bool enable_ban_for_tcp_bandwidth;

    bool enable_ban_for_udp_pps;
    bool enable_ban_for_udp_bandwidth;

    bool enable_ban_for_icmp_pps;
    bool enable_ban_for_icmp_bandwidth;

    unsigned int ban_threshold_tcp_mbps;
    unsigned int ban_threshold_tcp_pps;

    unsigned int ban_threshold_udp_mbps;
    unsigned int ban_threshold_udp_pps;

    unsigned int ban_threshold_icmp_mbps;
    unsigned int ban_threshold_icmp_pps;

    unsigned int ban_threshold_mbps;
    unsigned int ban_threshold_flows;
    unsigned int ban_threshold_pps;
};


typedef std::map<std::string, ban_settings_t> host_group_ban_settings_map_t;

// data structure for storing data in Vector
typedef std::pair<uint32_t, map_element_t> pair_of_map_elements;


#endif
