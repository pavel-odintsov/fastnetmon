#ifndef PFRING_PACKET_PARSER_H
#define PFRING_PACKET_PARSER_H

#include <sys/types.h>
#include <netinet/in.h> // in6_addr

#if defined(__APPLE__)
// For Mac OS X here we can find definition of "struct timeval"
#include <sys/time.h>
#endif

#define ETH_ALEN 6

/*
  Note that as offsets *can* be negative,
  please do not change them to unsigned
*/
struct pkt_offset {
    int16_t eth_offset; /*
                           This offset *must* be added to all offsets below
                           ONLY if you are inside the kernel (e.g. when you
                           code a pf_ring plugin). Ignore it in user-space.
                         */
    int16_t vlan_offset;
    int16_t l3_offset;
    int16_t l4_offset;
    int16_t payload_offset;
};


typedef union {
    struct in6_addr v6; /* IPv6 src/dst IP addresses (Network byte order) */
    u_int32_t v4; /* IPv4 src/dst IP addresses */
} ip_addr;

/* GPRS Tunneling Protocol */
typedef struct {
    u_int32_t tunnel_id; /* GTP/GRE tunnelId or NO_TUNNEL_ID for no filtering */
    u_int8_t tunneled_proto;
    ip_addr tunneled_ip_src, tunneled_ip_dst;
    u_int16_t tunneled_l4_src_port, tunneled_l4_dst_port;
} tunnel_info;

struct pkt_parsing_info {
    /* Core fields (also used by NetFlow) */
    u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN]; /* MAC src/dst addresses */
    u_int16_t eth_type; /* Ethernet type */
    u_int16_t vlan_id; /* VLAN Id or NO_VLAN */
    u_int8_t ip_version;
    u_int8_t l3_proto, ip_tos; /* Layer 3 protocol/TOS */
    u_int8_t ip_fragmented; /* Layer 3 fragmentation flag */
    u_int16_t ip_total_size; /* Total size of IP packet */ 
    u_int8_t ip_ttl; /* TTL flag */
    ip_addr ip_src, ip_dst; /* IPv4 src/dst IP addresses */
    u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
    struct {
        u_int8_t flags; /* TCP flags (0 if not available) */
        u_int32_t seq_num, ack_num; /* TCP sequence number */
    } tcp;

    tunnel_info tunnel;
    u_int16_t last_matched_plugin_id; /* If > 0 identifies a plugin to that matched the packet */
    u_int16_t last_matched_rule_id; /* If > 0 identifies a rule that matched the packet */
    struct pkt_offset offset; /* Offsets of L3/L4/payload elements */
};

struct pfring_extended_pkthdr {
    u_int64_t timestamp_ns; /* Packet timestamp at ns precision. Note that if your NIC supports
                               hardware timestamp, this is the place to read timestamp from */
#define PKT_FLAGS_CHECKSUM_OFFLOAD 1 << 0 /* IP/TCP checksum offload enabled */
#define PKT_FLAGS_CHECKSUM_OK 1 << 1 /* Valid checksum (with IP/TCP checksum offload enabled) */
#define PKT_FLAGS_IP_MORE_FRAG 1 << 2 /* IP More fragments flag set */
#define PKT_FLAGS_IP_FRAG_OFFSET 1 << 3 /* IP fragment offset set (not 0) */
#define PKT_FLAGS_VLAN_HWACCEL 1 << 4 /* VLAN stripped by hw */
    u_int32_t flags;
    /* --- short header ends here --- */
    u_int8_t rx_direction; /* 1=RX: packet received by the NIC, 0=TX: packet transmitted by the NIC
                              */
    int32_t if_index; /* index of the interface on which the packet has been received.
                         It can be also used to report other information */
    u_int32_t pkt_hash; /* Hash based on the packet header */
    struct {
        int bounce_interface; /* Interface Id where this packet will bounce after processing
                                 if its values is other than UNKNOWN_INTERFACE */
        struct sk_buff* reserved; /* Kernel only pointer */
    } tx;
    u_int16_t parsed_header_len; /* Extra parsing data before packet */

    /* NOTE: leave it as last field of the memset on parse_pkt() will fail */
    struct pkt_parsing_info parsed_pkt; /* packet parsing info */
};


/* NOTE: Keep 'struct pfring_pkthdr' in sync with 'struct pcap_pkthdr' */
struct pfring_pkthdr {
    /* pcap header */
    struct timeval ts; /* time stamp */
    u_int32_t caplen; /* length of portion present */
    u_int32_t len; /* length of whole packet (off wire) */
    struct pfring_extended_pkthdr extended_hdr; /* PF_RING extended header */
};

#ifdef __cplusplus
extern "C" {
#endif

// Prototypes
int fastnetmon_print_parsed_pkt(char* buff, u_int buff_len, const u_char* p, const struct pfring_pkthdr* h);
int fastnetmon_parse_pkt(unsigned char* pkt,
                         struct pfring_pkthdr* hdr,
                         u_int8_t level /* L2..L4, 5 (tunnel) */,
                         u_int8_t add_timestamp /* 0,1 */,
                         u_int8_t add_hash /* 0,1 */);

#ifdef __cplusplus
}
#endif

#endif
