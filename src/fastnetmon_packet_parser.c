#include "fastnetmon_packet_parser.h"

/* This code is copy & paste from PF_RING user space library licensed under LGPL terms */

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h> // in6_addr
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
#include <sys/socket.h> // AF_INET6
#endif

// Fake fields
#define ipv4_tos ip_tos
#define ipv6_tos ip_tos
#define ipv4_src ip_src.v4
#define ipv4_dst ip_dst.v4
#define ipv6_src ip_src.v6
#define ipv6_dst ip_dst.v6
#define host4_low host_low.v4
#define host4_high host_high.v4
#define host6_low host_low.v6
#define host6_high host_high.v6
#define host4_peer_a host_peer_a.v4
#define host4_peer_b host_peer_b.v4
#define host6_peer_a host_peer_a.v6
#define host6_peer_b host_peer_b.v6

// GRE tunnels
#define GRE_HEADER_CHECKSUM 0x8000
#define GRE_HEADER_ROUTING 0x4000
#define GRE_HEADER_KEY 0x2000
#define GRE_HEADER_SEQ_NUM 0x1000
#define GRE_HEADER_VERSION 0x0007

struct gre_header {
    u_int16_t flags_and_version;
    u_int16_t proto;
    /* Optional fields */
};


// GTP tunnels
#define GTP_SIGNALING_PORT 2123
#define GTP_U_DATA_PORT 2152

#define GTP_VERSION_1 0x1
#define GTP_VERSION_2 0x2
#define GTP_PROTOCOL_TYPE 0x1

#define GTP_VERSION_1 0x1
#define GTP_VERSION_2 0x2
#define GTP_PROTOCOL_TYPE 0x1

struct gtp_v1_hdr {
#define GTP_FLAGS_VERSION 0xE0
#define GTP_FLAGS_VERSION_SHIFT 5
#define GTP_FLAGS_PROTOCOL_TYPE 0x10
#define GTP_FLAGS_RESERVED 0x08
#define GTP_FLAGS_EXTENSION 0x04
#define GTP_FLAGS_SEQ_NUM 0x02
#define GTP_FLAGS_NPDU_NUM 0x01
    u_int8_t flags;
    u_int8_t message_type;
    u_int16_t payload_len;
    u_int32_t teid;
} __attribute__((__packed__));

/* Optional: GTP_FLAGS_EXTENSION | GTP_FLAGS_SEQ_NUM | GTP_FLAGS_NPDU_NUM */
struct gtp_v1_opt_hdr {
    u_int16_t seq_num;
    u_int8_t npdu_num;
    u_int8_t next_ext_hdr;
} __attribute__((__packed__));

/* Optional: GTP_FLAGS_EXTENSION && next_ext_hdr != 0 */
struct gtp_v1_ext_hdr {
#define GTP_EXT_HDR_LEN_UNIT_BYTES 4
    u_int8_t len; /* 4-byte unit */
    /*
     * u_char   contents[len*4-2];
     * u_int8_t next_ext_hdr;
     */
} __attribute__((__packed__));

#define NO_TUNNEL_ID 0xFFFFFFFF

#define NEXTHDR_HOP 0
#define NEXTHDR_TCP 6
#define NEXTHDR_UDP 17
#define NEXTHDR_IPV6 41
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_ESP 50
#define NEXTHDR_AUTH 51
#define NEXTHDR_ICMP 58
#define NEXTHDR_NONE 59
#define NEXTHDR_DEST 60
#define NEXTHDR_MOBILITY 135

// TCP flags
#define TH_FIN_MULTIPLIER 0x01
#define TH_SYN_MULTIPLIER 0x02
#define TH_RST_MULTIPLIER 0x04
#define TH_PUSH_MULTIPLIER 0x08
#define TH_ACK_MULTIPLIER 0x10
#define TH_URG_MULTIPLIER 0x20

#define __LITTLE_ENDIAN_BITFIELD /* FIX */

struct tcphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u_int16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    u_int16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct udphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int16_t len;
    u_int16_t check;
};

struct eth_vlan_hdr {
    u_int16_t h_vlan_id; /* Tag Control Information (QoS, VLAN ID) */
    u_int16_t h_proto; /* packet type ID field */
};

struct kcompact_ipv6_hdr {
    u_int8_t priority : 4, version : 4;
    u_int8_t flow_lbl[3];
    u_int16_t payload_len;
    u_int8_t nexthdr;
    u_int8_t hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct kcompact_ipv6_opt_hdr {
    u_int8_t nexthdr;
    u_int8_t hdrlen;
    u_int8_t padding[6];
} __attribute__((packed));

#define __LITTLE_ENDIAN_BITFIELD /* FIX */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u_int8_t ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    u_int8_t version : 4, ihl : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
#define IP_CE 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

// Prototypes
char* etheraddr2string(const u_char* ep, char* buf);
char* intoa(unsigned int addr);
char* _intoa(unsigned int addr, char* buf, u_short bufLen);
static char* in6toa(struct in6_addr addr6);
char* proto2str(u_short proto);

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
/* This code from /usr/includes/linux/if_ether.h Linus file */
#define ETH_ALEN 6 /* Octets in one ethernet addr   */
#define ETH_P_IP 0x0800 /* Internet Protocol packet     */
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook           */


/*
 *      This is an Ethernet frame header.
 */

struct ethhdr {
    unsigned char h_dest[ETH_ALEN]; /* destination eth addr */
    unsigned char h_source[ETH_ALEN]; /* source ether addr    */
    u_int16_t h_proto; /* packet type ID field */
} __attribute__((packed));

#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
u_int32_t pfring_hash_pkt(struct pfring_pkthdr* hdr) {
    if (hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id == NO_TUNNEL_ID) {
        return hdr->extended_hdr.parsed_pkt.vlan_id + hdr->extended_hdr.parsed_pkt.l3_proto +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.__u6_addr.__u6_addr32[0] +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.__u6_addr.__u6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.__u6_addr.__u6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.__u6_addr.__u6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.__u6_addr.__u6_addr32[0] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.__u6_addr.__u6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.__u6_addr.__u6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.__u6_addr.__u6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.l4_src_port + hdr->extended_hdr.parsed_pkt.l4_dst_port;
    } else {
        return hdr->extended_hdr.parsed_pkt.vlan_id + hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.__u6_addr.__u6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.__u6_addr.__u6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.__u6_addr.__u6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.__u6_addr.__u6_addr32[0] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.__u6_addr.__u6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.__u6_addr.__u6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.__u6_addr.__u6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port;
    }
}
#else
u_int32_t pfring_hash_pkt(struct pfring_pkthdr* hdr) {
    if (hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id == NO_TUNNEL_ID) {
        return hdr->extended_hdr.parsed_pkt.vlan_id + hdr->extended_hdr.parsed_pkt.l3_proto +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[0] +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[0] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.l4_src_port + hdr->extended_hdr.parsed_pkt.l4_dst_port;
    } else {
        return hdr->extended_hdr.parsed_pkt.vlan_id + hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[0] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[1] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[2] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[3] +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port +
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port;
    }
}
#endif
static int __pfring_parse_tunneled_pkt(u_char* pkt, struct pfring_pkthdr* hdr, u_int16_t ip_version, u_int16_t tunnel_offset) {
    u_int32_t ip_len = 0;
    u_int16_t fragment_offset = 0;

    if (ip_version == 4 /* IPv4 */) {
        struct iphdr* tunneled_ip;

        if (hdr->caplen < (tunnel_offset + sizeof(struct iphdr))) return 0;

        tunneled_ip = (struct iphdr*)(&pkt[tunnel_offset]);

        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ip->protocol;
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4 = ntohl(tunneled_ip->saddr);
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4 = ntohl(tunneled_ip->daddr);

        fragment_offset =
        tunneled_ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
        ip_len = tunneled_ip->ihl * 4;
        tunnel_offset += ip_len;

    } else if (ip_version == 6 /* IPv6 */) {
        struct kcompact_ipv6_hdr* tunneled_ipv6;

        if (hdr->caplen < (tunnel_offset + sizeof(struct kcompact_ipv6_hdr))) return 0;

        tunneled_ipv6 = (struct kcompact_ipv6_hdr*)(&pkt[tunnel_offset]);

        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ipv6->nexthdr;

        /* Values of IPv6 addresses are stored as network byte order */
        memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6, &tunneled_ipv6->saddr,
               sizeof(tunneled_ipv6->saddr));
        memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6, &tunneled_ipv6->daddr,
               sizeof(tunneled_ipv6->daddr));

        ip_len = sizeof(struct kcompact_ipv6_hdr);

        /* Note: NEXTHDR_AUTH, NEXTHDR_ESP, NEXTHDR_IPV6, NEXTHDR_MOBILITY are not handled */
        while (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP ||
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST ||
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING ||
               hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_FRAGMENT) {
            struct kcompact_ipv6_opt_hdr* ipv6_opt;

            if (hdr->caplen < tunnel_offset + ip_len + sizeof(struct kcompact_ipv6_opt_hdr))
                return 1;

            ipv6_opt = (struct kcompact_ipv6_opt_hdr*)(&pkt[tunnel_offset + ip_len]);
            ip_len += sizeof(struct kcompact_ipv6_opt_hdr);
            fragment_offset = 0;
            if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP ||
                hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST ||
                hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING)
                ip_len += ipv6_opt->hdrlen * 8;

            hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = ipv6_opt->nexthdr;
        }

        if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_NONE)
            hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = 0;

        tunnel_offset += ip_len;

    } else
        return 0;

    if (fragment_offset) return 1;

    if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_TCP) {
        struct tcphdr* tcp;

        if (hdr->caplen < tunnel_offset + sizeof(struct tcphdr)) return 1;

        tcp = (struct tcphdr*)(&pkt[tunnel_offset]);

        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(tcp->source),
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(tcp->dest);
    } else if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_UDP) {
        struct udphdr* udp;

        if (hdr->caplen < tunnel_offset + sizeof(struct udphdr)) return 1;

        udp = (struct udphdr*)(&pkt[tunnel_offset]);

        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(udp->source),
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(udp->dest);
    }

    return 2;
}


int fastnetmon_parse_pkt(unsigned char* pkt,
                         struct pfring_pkthdr* hdr,
                         u_int8_t level /* L2..L4, 5 (tunnel) */,
                         u_int8_t add_timestamp /* 0,1 */,
                         u_int8_t add_hash /* 0,1 */) {
    struct ethhdr* eh = (struct ethhdr*)pkt;
    u_int32_t displ = 0, ip_len;
    u_int16_t analyzed = 0, fragment_offset = 0;

    hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = NO_TUNNEL_ID;

    /* Note: in order to optimize the computation, this function expects a zero-ed
     * or partially parsed pkthdr */
    // memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
    // hdr->extended_hdr.parsed_header_len = 0;

    if (hdr->extended_hdr.parsed_pkt.offset.l3_offset != 0) goto L3;

    memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest, sizeof(eh->h_dest));
    memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

    hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
    hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;
    hdr->extended_hdr.parsed_pkt.offset.vlan_offset = 0;
    hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */

    if (hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */) {
        struct eth_vlan_hdr* vh;
        hdr->extended_hdr.parsed_pkt.offset.vlan_offset = sizeof(struct ethhdr) - sizeof(struct eth_vlan_hdr);
        while (hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */) {
            hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
            vh = (struct eth_vlan_hdr*)&pkt[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
            hdr->extended_hdr.parsed_pkt.vlan_id = ntohs(vh->h_vlan_id) & 0x0fff;
            hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
            displ += sizeof(struct eth_vlan_hdr);
        }
    }

    hdr->extended_hdr.parsed_pkt.offset.l3_offset =
    hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + sizeof(struct ethhdr);

L3:

    analyzed = 2;

    if (level < 3) goto TIMESTAMP;

    if (hdr->extended_hdr.parsed_pkt.offset.l4_offset != 0) goto L4;

    if (hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */) {
        struct iphdr* ip;

        hdr->extended_hdr.parsed_pkt.ip_version = 4;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr))
            goto TIMESTAMP;

        ip = (struct iphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

        hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
        hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
        hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
        hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
        fragment_offset = ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
        ip_len = ip->ihl * 4;
        hdr->extended_hdr.parsed_pkt.ip_total_size = ntohs(ip->tot_len);
        // Parse fragmentation info:
        // Very good examples about IPv4 flags: http://lwn.net/Articles/136319/
        hdr->extended_hdr.parsed_pkt.ip_fragmented = 0;

        hdr->extended_hdr.parsed_pkt.ip_ttl = ip->ttl;

        int fast_frag_off = ntohs(ip->frag_off);
        int fast_offset = (fast_frag_off & IP_OFFSET);

        if (fast_frag_off & IP_MF) {
            // printf("Packet with MF flag\n");
            hdr->extended_hdr.parsed_pkt.ip_fragmented = 1;
        }

        if (fast_offset != 0) {
            // printf("Packet with non zero offset\n");
            hdr->extended_hdr.parsed_pkt.ip_fragmented = 1;
        }

    } else if (hdr->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6 */) {
        struct kcompact_ipv6_hdr* ipv6;

        hdr->extended_hdr.parsed_pkt.ip_version = 6;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct kcompact_ipv6_hdr))
            goto TIMESTAMP;

        ipv6 = (struct kcompact_ipv6_hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);
        ip_len = sizeof(struct kcompact_ipv6_hdr);

        /* Values of IPv6 addresses are stored as network byte order */
        memcpy(&hdr->extended_hdr.parsed_pkt.ipv6_src, &ipv6->saddr, sizeof(ipv6->saddr));
        memcpy(&hdr->extended_hdr.parsed_pkt.ipv6_dst, &ipv6->daddr, sizeof(ipv6->daddr));

        hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
        hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */

        /* Note: NEXTHDR_AUTH, NEXTHDR_ESP, NEXTHDR_IPV6, NEXTHDR_MOBILITY are not handled */
        while (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP ||
               hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST ||
               hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING ||
               hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT) {
            struct kcompact_ipv6_opt_hdr* ipv6_opt;

            if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len +
                              sizeof(struct kcompact_ipv6_opt_hdr))
                goto TIMESTAMP;

            ipv6_opt =
            (struct kcompact_ipv6_opt_hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len]);
            ip_len += sizeof(struct kcompact_ipv6_opt_hdr);
            if (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING)
                ip_len += ipv6_opt->hdrlen * 8;

            hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
        }

        if (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_NONE)
            hdr->extended_hdr.parsed_pkt.l3_proto = 0;
    } else {
        hdr->extended_hdr.parsed_pkt.l3_proto = 0;
        goto TIMESTAMP;
    }

    hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len;

L4:

    analyzed = 3;

    if (level < 4 || fragment_offset) goto TIMESTAMP;

    if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
        struct tcphdr* tcp;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr))
            goto TIMESTAMP;

        tcp = (struct tcphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source);
        hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
        hdr->extended_hdr.parsed_pkt.offset.payload_offset =
        hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
        hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
        hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
        hdr->extended_hdr.parsed_pkt.tcp.flags =
        (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) + (tcp->rst * TH_RST_MULTIPLIER) +
        (tcp->psh * TH_PUSH_MULTIPLIER) + (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

        analyzed = 4;
    } else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
        struct udphdr* udp;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr))
            goto TIMESTAMP;

        udp = (struct udphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source),
        hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
        hdr->extended_hdr.parsed_pkt.offset.payload_offset =
        hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);

        analyzed = 4;

        if (level < 5) goto TIMESTAMP;

        /* GTPv1 */
        if ((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_SIGNALING_PORT) ||
            (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_SIGNALING_PORT) ||
            (hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT) ||
            (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT)) {
            struct gtp_v1_hdr* gtp;
            u_int16_t gtp_len;

            if (hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + sizeof(struct gtp_v1_hdr)))
                goto TIMESTAMP;

            gtp = (struct gtp_v1_hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);
            gtp_len = sizeof(struct gtp_v1_hdr);

            if (((gtp->flags & GTP_FLAGS_VERSION) >> GTP_FLAGS_VERSION_SHIFT) == GTP_VERSION_1) {
                struct iphdr* tunneled_ip;

                hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(gtp->teid);

                if ((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT) ||
                    (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT)) {
                    if (gtp->flags & (GTP_FLAGS_EXTENSION | GTP_FLAGS_SEQ_NUM | GTP_FLAGS_NPDU_NUM)) {
                        struct gtp_v1_opt_hdr* gtpopt;

                        if (hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset +
                                           gtp_len + sizeof(struct gtp_v1_opt_hdr)))
                            goto TIMESTAMP;

                        gtpopt =
                        (struct gtp_v1_opt_hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);
                        gtp_len += sizeof(struct gtp_v1_opt_hdr);

                        if ((gtp->flags & GTP_FLAGS_EXTENSION) && gtpopt->next_ext_hdr) {
                            struct gtp_v1_ext_hdr* gtpext;
                            u_int8_t* next_ext_hdr;

                            do {
                                if (hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset +
                                                   gtp_len + 1 /* 8bit len field */))
                                    goto TIMESTAMP;
                                gtpext =
                                (struct gtp_v1_ext_hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);
                                gtp_len += (gtpext->len * GTP_EXT_HDR_LEN_UNIT_BYTES);
                                if (gtpext->len == 0 ||
                                    hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len))
                                    goto TIMESTAMP;
                                next_ext_hdr =
                                (u_int8_t*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len - 1 /* 8bit next_ext_hdr field*/]);
                            } while (*next_ext_hdr);
                        }
                    }

                    if (hdr->caplen < (hdr->extended_hdr.parsed_pkt.offset.payload_offset +
                                       gtp_len + sizeof(struct iphdr)))
                        goto TIMESTAMP;

                    tunneled_ip =
                    (struct iphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);

                    analyzed +=
                    __pfring_parse_tunneled_pkt(pkt, hdr, tunneled_ip->version,
                                                hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len);
                }
            }
        }
    } else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_GRE /* 0x47 */) {
        struct gre_header* gre = (struct gre_header*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);
        int gre_offset;

        gre->flags_and_version = ntohs(gre->flags_and_version);
        gre->proto = ntohs(gre->proto);

        gre_offset = sizeof(struct gre_header);

        if ((gre->flags_and_version & GRE_HEADER_VERSION) == 0) {
            if (gre->flags_and_version & (GRE_HEADER_CHECKSUM | GRE_HEADER_ROUTING))
                gre_offset += 4;
            if (gre->flags_and_version & GRE_HEADER_KEY) {
                u_int32_t* tunnel_id =
                (u_int32_t*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset + gre_offset]);
                gre_offset += 4;
                hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(*tunnel_id);
            }
            if (gre->flags_and_version & GRE_HEADER_SEQ_NUM) gre_offset += 4;

            hdr->extended_hdr.parsed_pkt.offset.payload_offset =
            hdr->extended_hdr.parsed_pkt.offset.l4_offset + gre_offset;

            analyzed = 4;

            if (level < 5) goto TIMESTAMP;

            if (gre->proto == ETH_P_IP /* IPv4 */ || gre->proto == ETH_P_IPV6 /* IPv6 */)
                analyzed += __pfring_parse_tunneled_pkt(pkt, hdr, gre->proto == ETH_P_IP ? 4 : 6,
                                                        hdr->extended_hdr.parsed_pkt.offset.payload_offset);

        } else { /* TODO handle other GRE versions */
            hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
        }
    } else {
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
        hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;
    }

TIMESTAMP:

    if (add_timestamp && hdr->ts.tv_sec == 0)
        gettimeofday(&hdr->ts,
                     NULL); /* TODO What about using clock_gettime(CLOCK_REALTIME, ts) ? */

    if (add_hash && hdr->extended_hdr.pkt_hash == 0)
        hdr->extended_hdr.pkt_hash = pfring_hash_pkt(hdr);

    return analyzed;
}

int fastnetmon_print_parsed_pkt(char* buff, u_int buff_len, const u_char* p, const struct pfring_pkthdr* h) {
    char buf1[32], buf2[32];
    int buff_used = 0;

    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[%s -> %s] ",
                          etheraddr2string(h->extended_hdr.parsed_pkt.smac, buf1),
                          etheraddr2string(h->extended_hdr.parsed_pkt.dmac, buf2));

    if (h->extended_hdr.parsed_pkt.offset.vlan_offset)
        buff_used +=
        snprintf(&buff[buff_used], buff_len - buff_used, "[vlan %u] ", h->extended_hdr.parsed_pkt.vlan_id);

    if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ||
        h->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6*/) {

        if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/) {
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[IPv4][%s:%d ",
                                  intoa(h->extended_hdr.parsed_pkt.ipv4_src),
                                  h->extended_hdr.parsed_pkt.l4_src_port);
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "-> %s:%d] ",
                                  intoa(h->extended_hdr.parsed_pkt.ipv4_dst),
                                  h->extended_hdr.parsed_pkt.l4_dst_port);
        } else {
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[IPv6][%s:%d ",
                                  in6toa(h->extended_hdr.parsed_pkt.ipv6_src),
                                  h->extended_hdr.parsed_pkt.l4_src_port);
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "-> %s:%d] ",
                                  in6toa(h->extended_hdr.parsed_pkt.ipv6_dst),
                                  h->extended_hdr.parsed_pkt.l4_dst_port);
        }

        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[l3_proto=%s]",
                              proto2str(h->extended_hdr.parsed_pkt.l3_proto));

        if (h->extended_hdr.parsed_pkt.tunnel.tunnel_id != NO_TUNNEL_ID) {
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used,
                                  "[TEID=0x%08X][tunneled_proto=%s]", h->extended_hdr.parsed_pkt.tunnel.tunnel_id,
                                  proto2str(h->extended_hdr.parsed_pkt.tunnel.tunneled_proto));

            if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/) {
                buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[IPv4][%s:%d ",
                                      intoa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4),
                                      h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port);
                buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "-> %s:%d] ",
                                      intoa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4),
                                      h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);
            } else {
                buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[IPv6][%s:%d ",
                                      in6toa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6),
                                      h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port);
                buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "-> %s:%d] ",
                                      in6toa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6),
                                      h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);
            }
        }

        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[ip_fragmented: %d]",
                              h->extended_hdr.parsed_pkt.ip_fragmented);

        buff_used += snprintf(&buff[buff_used], buff_len - buff_used,
                              "[hash=%u][tos=%d][tcp_seq_num=%u]", h->extended_hdr.pkt_hash,
                              h->extended_hdr.parsed_pkt.ipv4_tos, h->extended_hdr.parsed_pkt.tcp.seq_num);

    } else if (h->extended_hdr.parsed_pkt.eth_type == 0x0806 /* ARP */) {
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[ARP]");
        if (buff_len >= h->extended_hdr.parsed_pkt.offset.l3_offset + 30) {
            buff_used +=
            snprintf(&buff[buff_used], buff_len - buff_used, "[Sender=%s/%s]",
                     etheraddr2string(&p[h->extended_hdr.parsed_pkt.offset.l3_offset + 8], buf1),
                     intoa(ntohl(*((u_int32_t*)&p[h->extended_hdr.parsed_pkt.offset.l3_offset + 14]))));
            buff_used +=
            snprintf(&buff[buff_used], buff_len - buff_used, "[Target=%s/%s]",
                     etheraddr2string(&p[h->extended_hdr.parsed_pkt.offset.l3_offset + 18], buf2),
                     intoa(ntohl(*((u_int32_t*)&p[h->extended_hdr.parsed_pkt.offset.l3_offset + 24]))));
        }
    } else {
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[eth_type=0x%04X]",
                              h->extended_hdr.parsed_pkt.eth_type);
    }

    buff_used +=
    snprintf(&buff[buff_used], buff_len - buff_used, " [caplen=%d][len=%d][parsed_header_len=%d]["
                                                     "eth_offset=%d][l3_offset=%d][l4_offset=%d]["
                                                     "payload_offset=%d]\n",
             h->caplen, h->len, h->extended_hdr.parsed_header_len,
             h->extended_hdr.parsed_pkt.offset.eth_offset, h->extended_hdr.parsed_pkt.offset.l3_offset,
             h->extended_hdr.parsed_pkt.offset.l4_offset, h->extended_hdr.parsed_pkt.offset.payload_offset);

    return buff_used;
}

char* etheraddr2string(const u_char* ep, char* buf) {
    char* hex = "0123456789ABCDEF";
    u_int i, j;
    char* cp;

    cp = buf;
    if ((j = *ep >> 4) != 0)
        *cp++ = hex[j];
    else
        *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];

    for (i = 5; (int)--i >= 0;) {
        *cp++ = ':';
        if ((j = *ep >> 4) != 0)
            *cp++ = hex[j];
        else
            *cp++ = '0';

        *cp++ = hex[*ep++ & 0xf];
    }

    *cp = '\0';
    return (buf);
}

char* intoa(unsigned int addr) {
    static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
    return (_intoa(addr, buf, sizeof(buf)));
}

char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
    char* cp, *retStr;
    u_int byte;
    int n;

    cp = &buf[bufLen];
    *--cp = '\0';

    n = 4;
    do {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0) {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0) *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    retStr = (char*)(cp + 1);

    return (retStr);
}

static char* in6toa(struct in6_addr addr6) {
    static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
    char* ret = (char*)inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));

    if (ret == NULL) {
        // printf("Internal error (&buff[buff_used]r too short)");
        buf[0] = '\0';
    }

    return (ret);
}

char* proto2str(u_short proto) {
    static char protoName[8];

    switch (proto) {
    case IPPROTO_TCP:
        return ("TCP");
    case IPPROTO_UDP:
        return ("UDP");
    case IPPROTO_ICMP:
        return ("ICMP");
    case IPPROTO_GRE:
        return ("GRE");
    default:
        snprintf(protoName, sizeof(protoName), "%d", proto);
        return (protoName);
    }
}
