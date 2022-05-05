#pragma once

#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>

enum direction_t { INCOMING = 0, OUTGOING, INTERNAL, OTHER };
enum source_t { UNKNOWN = 0, MIRROR = 1, SFLOW = 2, NETFLOW = 3, TERAFLOW = 4 };

// simplified packet struct for lightweight save into memory
class simple_packet_t {
    public:
    // Source plugin for this traffic type
    source_t source = UNKNOWN;

    uint32_t sample_ratio = 1;

    /* IPv4 in big endian, network byte order */
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;

    /* IPv6 */
    in6_addr src_ipv6{};
    in6_addr dst_ipv6{};

    /* ASN's */
    uint32_t src_asn = 0;
    uint32_t dst_asn = 0;

    /* Physical port numbers from network equipment */
    /* Added after 2.0.71 */
    uint32_t input_interface  = 0;
    uint32_t output_interface = 0;

    uint8_t ip_protocol_version = 4; /* IPv4 or IPv6 */
    uint8_t ttl                 = 0;
    uint16_t source_port        = 0;
    uint16_t destination_port   = 0;
    uint32_t protocol           = 0;
    uint64_t length             = 0;
    uint64_t ip_length = 0; /* IP packet total length. We use it in addition to length because flow spec rule need this length */
    uint64_t number_of_packets = 1; /* for netflow */
    uint8_t flags              = 0; /* tcp flags */
    bool ip_fragmented         = false; /* If IP packet fragmented */
    bool ip_dont_fragment      = false; /* If IP has don't fragment flag */

    // Time when we actually received this packet, we use quite rough and inaccurate but very fast time source for it
    time_t arrival_time = 0;

    // Timestamp of packet as reported by Netflow or IPFIX agent on device, it may be very inaccurate as nobody cares about time on equipment
    struct timeval ts = { 0, 0 };

    void* packet_payload_pointer        = nullptr;
    int32_t packet_payload_length       = 0;
    uint32_t packet_payload_full_length = 0; // In case of cropped packets we use this

    // vlan tag if we can extract it
    uint32_t vlan = 0;

    // Device uptime when flow started
    int64_t flow_start = 0;
    // Device uptime when flow fnishes
    int64_t flow_end = 0;

    // field too
    // We store packet direction here because direction calculation is very
    // difficult task for cpu
    direction_t packet_direction = OTHER;

    // IP address of device which send this flow
    uint32_t agent_ip_address = 0;
};
