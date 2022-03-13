#ifndef FASTNETMON_TYPES_H
#define FASTNETMON_TYPES_H

#include <netinet/in.h> // struct in6_addr
#include <stdint.h> // uint32_t
#include <sys/time.h> // struct timeval
#include <utility> // std::pair

#include <map>
#include <string>
#include <vector>

#include "packet_storage.h"

#include "fastnetmon_simple_packet.h"

typedef std::map<std::string, std::string> configuration_map_t;
typedef std::map<std::string, uint64_t> graphite_data_t;

// Enum with available sort by field
enum sort_type { PACKETS, BYTES, FLOWS };

/* Class for custom comparison fields by different fields */
template <typename T> class TrafficComparatorClass {
    private:
    sort_type sort_field;
    direction_t sort_direction;

    public:
    TrafficComparatorClass(direction_t sort_direction, sort_type sort_field) {
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

typedef std::pair<uint32_t, uint32_t> subnet_t;
typedef std::vector<subnet_t> subnet_vector_t;

typedef std::map<subnet_t, std::string> subnet_to_host_group_map_t;
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

typedef struct {
    uint64_t bytes;
    uint64_t packets;
    uint64_t flows;
} total_counter_element;


// main data structure for storing traffic and speed data for all our IPs
class map_element {
    public:
    map_element()
    : in_bytes(0), out_bytes(0), in_packets(0), out_packets(0), tcp_in_packets(0), tcp_out_packets(0),
      tcp_in_bytes(0), tcp_out_bytes(0), tcp_syn_in_packets(0), tcp_syn_out_packets(0),
      tcp_syn_in_bytes(0), tcp_syn_out_bytes(0), udp_in_packets(0), udp_out_packets(0),
      udp_in_bytes(0), udp_out_bytes(0), in_flows(0), out_flows(0), fragmented_in_packets(0),
      fragmented_out_packets(0), fragmented_in_bytes(0), fragmented_out_bytes(0),
      icmp_in_packets(0), icmp_out_packets(0), icmp_in_bytes(0), icmp_out_bytes(0) {
    }
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint64_t in_packets;
    uint64_t out_packets;

    // Fragmented traffic is so recently used for attacks
    uint64_t fragmented_in_packets;
    uint64_t fragmented_out_packets;
    uint64_t fragmented_in_bytes;
    uint64_t fragmented_out_bytes;

    // Additional data for correct attack protocol detection
    uint64_t tcp_in_packets;
    uint64_t tcp_out_packets;
    uint64_t tcp_in_bytes;
    uint64_t tcp_out_bytes;

    // Additional details about one of most popular atatck type
    uint64_t tcp_syn_in_packets;
    uint64_t tcp_syn_out_packets;
    uint64_t tcp_syn_in_bytes;
    uint64_t tcp_syn_out_bytes;

    uint64_t udp_in_packets;
    uint64_t udp_out_packets;
    uint64_t udp_in_bytes;
    uint64_t udp_out_bytes;

    uint64_t icmp_in_packets;
    uint64_t icmp_out_packets;
    uint64_t icmp_in_bytes;
    uint64_t icmp_out_bytes;

    uint64_t in_flows;
    uint64_t out_flows;
};

// structure with attack details
class attack_details : public map_element {
    public:
    attack_details()
    : attack_protocol(0), attack_power(0), max_attack_power(0), average_in_bytes(0),
      average_out_bytes(0), average_in_packets(0), average_out_packets(0), average_in_flows(0),
      average_out_flows(0), ban_time(0), attack_direction(OTHER), unban_enabled(true) {

        customer_network.first = 0;
        customer_network.second = 0;
    }
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

    subnet_t customer_network;

    packet_storage_t pcap_attack_dump;
};


typedef attack_details banlist_item;

// struct for save per direction and per protocol details for flow
typedef struct {
    uint64_t bytes;
    uint64_t packets;
    // will be used for Garbage Collection
    time_t last_update_time;
} conntrack_key_struct;

typedef uint64_t packed_session;
// Main mega structure for storing conntracks
// We should use class instead struct for correct std::map allocation
typedef std::map<packed_session, conntrack_key_struct> contrack_map_type;

class conntrack_main_struct {
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

typedef std::map<uint32_t, map_element> map_for_counters;
typedef std::vector<map_element> vector_of_counters;

typedef std::map<subnet_t, vector_of_counters> map_of_vector_counters;

// Flow tracking structures
typedef std::vector<conntrack_main_struct> vector_of_flow_counters;
typedef std::map<subnet_t, vector_of_flow_counters> map_of_vector_counters_for_flow;

typedef map_element subnet_counter_t;
typedef std::pair<subnet_t, subnet_counter_t> pair_of_map_for_subnet_counters_elements_t;
typedef std::map<subnet_t, subnet_counter_t> map_for_subnet_counters;

class packed_conntrack_hash {
    public:
    packed_conntrack_hash() : opposite_ip(0), src_port(0), dst_port(0) {
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
    : enable_ban(false), enable_ban_for_pps(false), enable_ban_for_bandwidth(false),
      enable_ban_for_flows_per_second(false), enable_ban_for_tcp_pps(false),
      enable_ban_for_tcp_bandwidth(false), enable_ban_for_udp_pps(false),
      enable_ban_for_udp_bandwidth(false), enable_ban_for_icmp_pps(false),
      enable_ban_for_icmp_bandwidth(false), ban_threshold_tcp_mbps(0), ban_threshold_tcp_pps(0),
      ban_threshold_udp_mbps(0), ban_threshold_udp_pps(0), ban_threshold_icmp_mbps(0),
      ban_threshold_icmp_pps(0), ban_threshold_mbps(0), ban_threshold_flows(0), ban_threshold_pps(0) {
    }
    bool enable_ban;

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
typedef std::pair<uint32_t, map_element> pair_of_map_elements;

#endif
