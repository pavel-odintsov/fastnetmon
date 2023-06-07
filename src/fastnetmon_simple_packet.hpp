#pragma once

#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <in6addr.h>    // in6_addr
#else
#include <netinet/in.h> // in6_addr
#include <sys/socket.h>
#endif

#include <boost/beast/core/static_string.hpp>

enum direction_t { INCOMING = 0, OUTGOING = 1, INTERNAL = 2, OTHER = 3 };

enum source_t { UNKNOWN = 0, MIRROR = 1, SFLOW = 2, NETFLOW = 3, TERAFLOW = 4 };

// Forwarding status of packet
// IPFIX: https://datatracker.ietf.org/doc/html/rfc7270#section-4.12
// Netflow v9: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
enum class forwarding_status_t { unknown, forwarded, dropped, consumed };

// Our internal representation of all packet types
class simple_packet_t {
    public:
    // Source plugin for this traffic type
    source_t source = UNKNOWN;

    // Sampling rate
    uint32_t sample_ratio = 1;

    // IPv4 in big endian, network byte order
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;

    // IPv6 addresses
    in6_addr src_ipv6{};
    in6_addr dst_ipv6{};

    uint8_t source_mac[6]{};
    uint8_t destination_mac[6]{};

    // ASNs
    uint32_t src_asn = 0;
    uint32_t dst_asn = 0;

    // Countries
    // These strings are statically allocated and do not use dynamic memory
    boost::beast::static_string<2> src_country;
    boost::beast::static_string<2> dst_country;

    // Physical port numbers from network equipment
    uint32_t input_interface  = 0;
    uint32_t output_interface = 0;

    // IP protocol version: IPv4 or IPv6
    uint8_t ip_protocol_version = 4;

    uint8_t ttl               = 0;
    uint16_t source_port      = 0;
    uint16_t destination_port = 0;
    uint32_t protocol         = 0;
    uint64_t length           = 0;

    // The number of octets includes IP header(s) and IP payload.
    // We use it in addition to length because flow spec rule needs exactly it
    uint64_t ip_length = 0;

    // Any single simple flow may have multiple packets. It happens for all flow based protocols
    uint64_t number_of_packets = 1;

    // TCP flags
    uint8_t flags = 0;

    // If IP packet fragmented
    bool ip_fragmented = false;

    // We will have more fragments
    bool ip_more_fragments = false;

    // If IP has don't fragment flag
    bool ip_dont_fragment = false;

    // Fragment offset in bytes when fragmentation involved
    uint16_t ip_fragment_offset = 0;

    // Time when we actually received this packet, we use quite rough and inaccurate but very fast time source for it
    time_t arrival_time = 0;

    // Timestamp of packet as reported by Netflow or IPFIX agent on device, it may be very inaccurate as nobody cares about time on equipment
    struct timeval ts = { 0, 0 };

    void* payload_pointer  = nullptr;

    // Part of packet we captured from wire. It may not be full length of packet
    int32_t captured_payload_length = 0;

    // Full length of packet we observed. It may be larger then packet_captured_payload_length in case of cropped mirror or sFlow traffic
    uint32_t payload_full_length = 0;

    // Forwarding status
    forwarding_status_t forwarding_status = forwarding_status_t::unknown;

    // vlan tag if we can extract it
    uint32_t vlan = 0;

    // Device uptime when flow started
    int64_t flow_start = 0;

    // Device uptime when flow finished
    int64_t flow_end = 0;

    direction_t packet_direction = OTHER;

    // IP address of device which send this flow
    uint32_t agent_ip_address = 0;
};
