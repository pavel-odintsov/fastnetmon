#pragma once

#include <cstdint>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <log4cpp/Appender.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/Layout.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>

#include "fastnetmon_simple_packet.hpp"

/*
   pcap dump format:
    global header: pcap_file_header
    packet header: fastnetmon_pcap_pkthdr_t
*/

// We use copy and paste from pcap.h here because we do not want to link with
// pcap here
class __attribute__((__packed__)) fastnetmon_pcap_file_header_t {
    public:
    uint32_t magic         = 0;
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    int32_t thiszone       = 0; /* gmt to local correction */
    uint32_t sigfigs       = 0; /* accuracy of timestamps */
    uint32_t snaplen       = 0; /* max length saved portion of each pkt */
    uint32_t linktype      = 0; /* data link type (LINKTYPE_*) */
};

static_assert(sizeof(fastnetmon_pcap_file_header_t) == 24, "Bad size for fastnetmon_pcap_file_header_t");

// Link types for PCAP which we use in FastNetMon
#define FASTNETMON_PCAP_LINKTYPE_ETHERNET 1
#define FASTNETMON_PCAP_LINKTYPE_LINUX_SLL 113

// We can't use pcap_pkthdr from upstream because it uses 16 bytes timeval
// instead of 8 byte and
// broke everything
class __attribute__((__packed__)) fastnetmon_pcap_pkthdr_t {
    public:
    uint32_t ts_sec   = 0; /* timestamp seconds */
    uint32_t ts_usec  = 0; /* timestamp microseconds */
    uint32_t incl_len = 0; /* number of octets of packet saved in file */
    uint32_t orig_len = 0; /* actual length of packet */
};

static_assert(sizeof(fastnetmon_pcap_pkthdr_t) == 16, "Bad size for fastnetmon_pcap_pkthdr_t");


// This class consist of pcap header and payload in same place
class pcap_packet_information_t {
    public:
    uint32_t ts_sec  = 0; /* timestamp seconds */
    uint32_t ts_usec = 0; /* timestamp microseconds */

    uint32_t incl_len  = 0;
    uint32_t orig_len  = 0;
    char* data_pointer = nullptr;
};

typedef void (*pcap_packet_parser_callback)(char* buffer, uint32_t len, uint32_t snaplen);

int pcap_reader(const char* pcap_file_path, pcap_packet_parser_callback pcap_parse_packet_function_ptr);

bool fill_pcap_header(fastnetmon_pcap_file_header_t* pcap_header, uint32_t snap_length);

// Class for very convenient pcap file reading
class pcap_roller_t {
    public:
    pcap_roller_t(const std::string& pcap_file_path) {
        this->pcap_file_path = pcap_file_path;
    }

    ~pcap_roller_t() {
        if (filedesc > 0) {
            close(filedesc);
        }

        if (packet_buffer) {
            free(packet_buffer);
            packet_buffer = nullptr;
        }
    }

    bool open() {
        extern log4cpp::Category& logger;

        filedesc = ::open(pcap_file_path.c_str(), O_RDONLY);

        if (filedesc <= 0) {
            logger << log4cpp::Priority::ERROR << "Can't open dump file, error: " << strerror(errno);
            return false;
        }

        ssize_t file_header_readed_bytes = read(filedesc, &pcap_header, sizeof(fastnetmon_pcap_file_header_t));

        if (file_header_readed_bytes != sizeof(fastnetmon_pcap_file_header_t)) {
            logger << log4cpp::Priority::ERROR << "Can't read pcap file header";
            return false;
        }

        // http://www.tcpdump.org/manpages/pcap-savefile.5.html
        if (!(pcap_header.magic == 0xa1b2c3d4 or pcap_header.magic == 0xd4c3b2a1)) {
            logger << log4cpp::Priority::ERROR << "Magic in file header broken";
            return false;
        }

        // Allocate read buffer
        packet_buffer = (char*)malloc(pcap_header.snaplen);

        return true;
    }

    // Read on more packet from stream and returns false if we run out of packets
    bool read_next(pcap_packet_information_t& pcap_packet_information) {
        extern log4cpp::Category& logger;

        fastnetmon_pcap_pkthdr_t pcap_packet_header;
        ssize_t packet_header_readed_bytes = read(filedesc, &pcap_packet_header, sizeof(fastnetmon_pcap_pkthdr_t));

        if (packet_header_readed_bytes != sizeof(fastnetmon_pcap_pkthdr_t)) {
            // We have no more packets to read
            return false;
        }

        if (pcap_packet_header.incl_len > pcap_header.snaplen) {
            logger << log4cpp::Priority::ERROR << "Captured packet size for this dump exceed limit for pcap file";
            return false;
        }

        // Read included part of raw packet from file
        ssize_t packet_payload_readed_bytes = read(filedesc, packet_buffer, pcap_packet_header.incl_len);

        if (pcap_packet_header.incl_len != packet_payload_readed_bytes) {
            logger << log4cpp::Priority::ERROR << "We successfully read packet header but can't read packet payload";
            return false;
        }

        pcap_packet_information.incl_len     = pcap_packet_header.incl_len;
        pcap_packet_information.orig_len     = pcap_packet_header.orig_len;
        pcap_packet_information.ts_sec       = pcap_packet_header.ts_sec;
        pcap_packet_information.ts_usec      = pcap_packet_header.ts_usec;
        pcap_packet_information.data_pointer = packet_buffer;

        return true;
    }

    public:
    fastnetmon_pcap_file_header_t pcap_header{};

    private:
    std::string pcap_file_path = "";
    int filedesc               = 0;
    char* packet_buffer        = nullptr;
};
