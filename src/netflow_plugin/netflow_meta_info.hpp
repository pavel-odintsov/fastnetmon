#pragma once

// Variable encoding may be single or two byte and we need to distinguish them explicitly
enum class variable_length_encoding_t { unknown, single_byte, two_byte };

// This class carries information which does not need to stay in simple_packet_t because we need it only for parsing
class netflow_meta_info_t {
    public:
    // Packets selected by sampler
    uint64_t selected_packets = 0;

    // Total number of packets on interface
    uint64_t observed_packets = 0;

    // Sampling rate is observed_packets / selected_packets

    // Full length of packet (Netflow Lite)
    uint64_t data_link_frame_size = 0;

    // Decoded nested packet
    simple_packet_t nested_packet;

    // Set to true when we were able to parse nested packet
    bool nested_packet_parsed = false;

    // The IPv4 address of the next IPv4 hop.
    uint32_t ip_next_hop_ipv4 = 0;

    // We set this flag when we read it from flow. We need it to distinguish one case when we receive 0.0.0.0 from
    // device. It's impossible without explicit flag because default value is already 0
    bool ip_next_hop_ipv4_set = false;

    // The IPv4 address of the next (adjacent) BGP hop.
    uint32_t bgp_next_hop_ipv4 = 0;

    // We set this flag when we read it from flow. We need it to distinguish one case when we receive 0.0.0.0 from
    // device. It's impossible without explicit flag because default value is already 0
    bool bgp_next_hop_ipv4_set = false;

    // Next hop flag for IPv6
    in6_addr bgp_next_hop_ipv6{};

    // Same as in case of IPv4
    bool bgp_next_hop_ipv6_set = false;

    // This flag is set when we explicitly received forwarding status
    bool received_forwarding_status = false;

    // Cisco ASA uses very unusual encoding when they encode incoming and outgoing traffic in single flow
    uint64_t bytes_from_source_to_destination = 0;
    uint64_t bytes_from_destination_to_source = 0;

    uint64_t packets_from_source_to_destination = 0;
    uint64_t packets_from_destination_to_source = 0;

    // Cisco ASA flow identifier
    uint64_t flow_id = 0;

    variable_length_encoding_t variable_field_length_encoding = variable_length_encoding_t::unknown;

    // Store variable field length here to avoid repeating parsing
    uint16_t variable_field_length = 0;
};
