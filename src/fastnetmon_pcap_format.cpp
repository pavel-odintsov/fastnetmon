#include "fastnetmon_pcap_format.hpp"
#include <iostream>
#include <string.h>

int pcap_reader(const char* pcap_file_path, pcap_packet_parser_callback pcap_parse_packet_function_ptr) {
    int filedesc = open(pcap_file_path, O_RDONLY);

    if (filedesc <= 0) {
        printf("Can't open dump file, error: %s\n", strerror(errno));
        return -1;
    }

    fastnetmon_pcap_file_header_t pcap_header{};
    ssize_t file_header_readed_bytes = read(filedesc, &pcap_header, sizeof(fastnetmon_pcap_file_header_t));

    if (file_header_readed_bytes != sizeof(fastnetmon_pcap_file_header_t)) {
        printf("Can't read pcap file header");
    }

    // http://www.tcpdump.org/manpages/pcap-savefile.5.html
    if (pcap_header.magic == 0xa1b2c3d4 or pcap_header.magic == 0xd4c3b2a1) {
        // printf("Magic readed correctly\n");
    } else {
        printf("Magic in file header broken\n");
        return -2;
    }

    // Buffer for packets
    char packet_buffer[pcap_header.snaplen];

    unsigned int read_packets = 0;
    while (1) {
        // printf("Start packet %d processing\n", read_packets);
        fastnetmon_pcap_pkthdr_t pcap_packet_header;
        ssize_t packet_header_readed_bytes = read(filedesc, &pcap_packet_header, sizeof(fastnetmon_pcap_pkthdr_t));

        if (packet_header_readed_bytes != sizeof(fastnetmon_pcap_pkthdr_t)) {
            // We haven't any packets
            break;
        }

        if (pcap_packet_header.incl_len > pcap_header.snaplen) {
            printf("Please enlarge packet buffer! We got packet with size: %d but "
                   "our buffer is %d "
                   "bytes\n",
                   pcap_packet_header.incl_len, pcap_header.snaplen);
            return -4;
        }

        ssize_t packet_payload_readed_bytes = read(filedesc, packet_buffer, pcap_packet_header.incl_len);

        if (pcap_packet_header.incl_len != packet_payload_readed_bytes) {
            printf("I read packet header but can't read packet payload\n");
            return -3;
        }

        // printf("packet payload read\n");
        pcap_parse_packet_function_ptr(packet_buffer, pcap_packet_header.orig_len, pcap_packet_header.incl_len);

        // printf("Process packet %d\n", read_packets);
        read_packets++;
    }

    printf("I correctly read %d packets from this dump\n", read_packets);

    return 0;
}

// Move this code to constructor
bool fill_pcap_header(fastnetmon_pcap_file_header_t* pcap_header, uint32_t snap_length) {
    pcap_header->magic         = 0xa1b2c3d4;
    pcap_header->version_major = 2;
    pcap_header->version_minor = 4;
    pcap_header->thiszone      = 0;
    pcap_header->sigfigs       = 0;

    // Maximum really captured (not original packet) length for this file
    pcap_header->snaplen = snap_length;
    // http://www.tcpdump.org/linktypes.html
    // DLT_EN10MB = 1
    pcap_header->linktype = 1;

    return true;
}
