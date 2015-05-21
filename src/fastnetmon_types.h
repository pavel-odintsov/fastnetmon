#ifndef FASTNETMON_TYPES_H
#define FASTNETMON_TYPES_H

#include <utility> // std::pair
#include <stdint.h> // uint32_t
#include <sys/time.h> // struct timeval

#include <map>
#include <vector>

// simplified packet struct for lightweight save into memory
class simple_packet {
    public:
    simple_packet()
    : sample_ratio(1), src_ip(0), dst_ip(0), source_port(0), destination_port(0), protocol(0),
      length(0), flags(0), number_of_packets(1), ip_fragmented(false) {

        ts.tv_usec = 0;
        ts.tv_sec = 0;
    }
    uint32_t sample_ratio;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t source_port;
    uint16_t destination_port;
    unsigned int protocol;
    uint64_t length;
    uint64_t number_of_packets; /* for netflow */
    uint8_t flags; /* tcp flags */
    bool ip_fragmented; /* If IP packet fragmented */
    struct timeval ts;
};

typedef std::pair<uint32_t, uint32_t> subnet;
typedef void (*process_packet_pointer)(simple_packet&);

// Enum with available sort by field
enum sort_type { PACKETS, BYTES, FLOWS };

enum direction { INCOMING = 0, OUTGOING, INTERNAL, OTHER };

// Attack types
enum attack_type_t {
    ATTACK_UNKNOWN = 1,
    ATTACK_SYN_FLOOD = 2,
    ATTACK_ICMP_FLOOD = 3,
    ATTACK_UDP_FLOOD = 4,
    ATTACK_IP_FRAGMENTATION_FLOOD = 5,
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
      average_out_flows(0), ban_time(0), attack_direction(OTHER) {
    }
    direction attack_direction;
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
    int ban_time; // seconds of the ban
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

typedef std::map<unsigned long int, vector_of_counters> map_of_vector_counters;

// Flow tracking structures
typedef std::vector<conntrack_main_struct> vector_of_flow_counters;
typedef std::map<unsigned long int, vector_of_flow_counters> map_of_vector_counters_for_flow;

typedef map_element subnet_counter_t;
typedef std::map<subnet, subnet_counter_t> map_for_subnet_counters;

class packed_conntrack_hash {
    public:
    packed_conntrack_hash() : opposite_ip(0), src_port(0), dst_port(0) {
    }
    // src or dst IP
    uint32_t opposite_ip;
    uint16_t src_port;
    uint16_t dst_port;
};


// data structure for storing data in Vector
typedef std::pair<uint32_t, map_element> pair_of_map_elements;

#endif
