#pragma once

#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>

enum direction { INCOMING = 0, OUTGOING, INTERNAL, OTHER };
enum source_t { UNKNOWN = 0, MIRROR = 1, SFLOW = 2, NETFLOW = 3, TERAFLOW = 4 };

// simplified packet struct for lightweight save into memory
class simple_packet_t {
    public:
    simple_packet_t()
    : sample_ratio(1), src_ip(0), dst_ip(0), source_port(0), destination_port(0), protocol(0),
      length(0), flags(0), number_of_packets(1), ip_fragmented(false), ip_protocol_version(4),
      ttl(0), packet_payload_pointer(NULL), packet_payload_length(0), packet_direction(OTHER) {

        ts.tv_usec = 0;
        ts.tv_sec = 0;
    }
    // Source plugin for this traffic type
    source_t source = UNKNOWN;

    uint32_t sample_ratio;
    /* IPv4 */
    uint32_t src_ip;
    uint32_t dst_ip;
    /* IPv6 */
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;

    /* ASN's */
    uint32_t src_asn = 0;
    uint32_t dst_asn = 0;

    uint8_t ip_protocol_version; /* IPv4 or IPv6 */
    uint8_t ttl;
    uint16_t source_port;
    uint16_t destination_port;
    unsigned int protocol;
    
    uint64_t length;
    uint64_t ip_length = 0; /* IP packet total length. We use it in addition to length because flow spec rule need this length */

    uint64_t number_of_packets; /* for netflow */
    uint8_t flags; /* tcp flags */

    bool ip_fragmented; /* If IP packet fragmented */
    bool ip_dont_fragment               = false; /* If IP has don't fragment flag */

    struct timeval ts;
    void* packet_payload_pointer;
    int packet_payload_length;
    uint32_t packet_payload_full_length = 0; // In case of cropped packets we use this

    // vlan tag if we can extract it
    uint32_t vlan = 0;

    // We store packet direction here because direction calculation is very difficult task for cpu
    direction packet_direction;

    // IP address of device which send this flow
    uint32_t agent_ip_address = 0;
};

