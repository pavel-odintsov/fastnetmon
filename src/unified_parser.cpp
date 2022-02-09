#include "unified_parser.hpp"

#include "fastnetmon_packet_parser.h"

bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet, bool netmap_read_packet_length_from_ip_header) {

    struct pfring_pkthdr packet_header;

    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = len;

    // We do not calculate timestamps because timestamping is very CPU intensive operation:
    // https://github.com/ntop/PF_RING/issues/9
    u_int8_t timestamp = 0;
    u_int8_t add_hash = 0;
    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, timestamp, add_hash);

    // char print_buffer[512];
    // fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);
    // logger.info("%s", print_buffer);

    if (packet_header.extended_hdr.parsed_pkt.ip_version != 4 &&
        packet_header.extended_hdr.parsed_pkt.ip_version != 6) {
        return false;
    }

    // We need this for deep packet inspection
    packet.packet_payload_length = len;
    packet.packet_payload_pointer = (void*)buffer;

    packet.ip_protocol_version = packet_header.extended_hdr.parsed_pkt.ip_version;

    if (packet.ip_protocol_version == 4) {
        // IPv4

        /* PF_RING stores data in host byte order but we use network byte order */
        packet.src_ip = htonl(packet_header.extended_hdr.parsed_pkt.ip_src.v4);
        packet.dst_ip = htonl(packet_header.extended_hdr.parsed_pkt.ip_dst.v4);
    } else {
        // IPv6
        memcpy(packet.src_ipv6.s6_addr, packet_header.extended_hdr.parsed_pkt.ip_src.v6.s6_addr, 16);
        memcpy(packet.dst_ipv6.s6_addr, packet_header.extended_hdr.parsed_pkt.ip_dst.v6.s6_addr, 16);
    }

    packet.source_port = packet_header.extended_hdr.parsed_pkt.l4_src_port;
    packet.destination_port = packet_header.extended_hdr.parsed_pkt.l4_dst_port;

    if (netmap_read_packet_length_from_ip_header) {
        packet.length = packet_header.extended_hdr.parsed_pkt.ip_total_size;
    } else {
        packet.length = packet_header.len;
    }

    packet.protocol = packet_header.extended_hdr.parsed_pkt.l3_proto;
    packet.ts = packet_header.ts;

    packet.ip_fragmented = packet_header.extended_hdr.parsed_pkt.ip_fragmented;
    packet.ttl = packet_header.extended_hdr.parsed_pkt.ip_ttl;

    // Copy flags from PF_RING header to our pseudo header
    if (packet.protocol == IPPROTO_TCP) {
        packet.flags = packet_header.extended_hdr.parsed_pkt.tcp.flags;
    } else {
        packet.flags = 0;
    }

    return true;
}
