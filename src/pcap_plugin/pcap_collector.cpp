#include <map>
#include <string>

#include "../fastnetmon_plugin.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_arp.h> // struct arphdr
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#endif

#include <pcap.h>

#include "../all_logcpp_libraries.hpp"

#include "../simple_packet_parser_ng.hpp"

#include "pcap_collector.hpp"

// Standard shift for type DLT_EN10MB, Ethernet
unsigned int DATA_SHIFT_VALUE = 14;

/* Complete list of ethertypes: http://en.wikipedia.org/wiki/EtherType */
/* This is the decimal equivalent of the VLAN tag's ether frame type */
#define VLAN_ETHERTYPE 0x8100
#define IP_ETHERTYPE 0x0800
#define IP6_ETHERTYPE 0x86dd
#define ARP_ETHERTYPE 0x0806
/* 802.1Q VLAN tags are 4 bytes long. */
#define VLAN_HDRLEN 4

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

extern log4cpp::Category& logger;
extern std::map<std::string, std::string> configuration_map;

// Pass unparsed packets number to main programme
extern uint64_t total_unparsed_packets;

// This variable name should be uniq for every plugin!
process_packet_pointer pcap_process_func_ptr = NULL;

// Enlarge receive buffer for PCAP for minimize packet drops
unsigned int pcap_buffer_size_mbytes = 10;

// pcap handler, we want it as global variable beacuse it used in singnal handler
pcap_t* descr = NULL;

// Data link layer type of active capture, set in pcap_main_loop before capture starts
int pcap_data_link_type = DLT_EN10MB;

char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr hdr;

// Prototypes
void parse_packet(u_char* user, struct pcap_pkthdr* packethdr, const u_char* packetptr);
void pcap_main_loop(const char* dev);

void start_pcap_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "Pcap plugin started";

    pcap_process_func_ptr = func_ptr;

    std::string interface_for_listening = "";

    if (configuration_map.count("interfaces") != 0) {
        interface_for_listening = configuration_map["interfaces"];
    }

    logger << log4cpp::Priority::INFO << "Pcap will sniff interface: " << interface_for_listening;

    pcap_main_loop(interface_for_listening.c_str());
}

void stop_pcap_collection() {
    // stop pcap loop
    pcap_breakloop(descr);
}

void parse_packet(u_char* user, struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    simple_packet_t current_packet;

    current_packet.source       = MIRROR;
    current_packet.arrival_time = current_inaccurate_time;
    current_packet.sample_ratio = 1;

    parser_options_t parser_options{};

    parser_code_t result;

    // We use the same shared parser as AF_PACKET plugin. It performs all required bounds checks internally.
    if (pcap_data_link_type == DLT_LINUX_SLL) {
        // Linux cooked capture (DLT_LINUX_SLL) header is 16 bytes and it is not an Ethernet header, so we cannot
        // feed it to the Ethernet aware parser. We strip it and dispatch to the IP level parsers based on the
        // protocol type field stored in the last two bytes of the SLL header.
        const unsigned int sll_header_length = 16;

        if (packethdr->caplen < sll_header_length) {
            total_unparsed_packets++;
            return;
        }

        // Protocol type (ethertype) is stored in network byte order at offset 14 of the SLL header
        uint16_t protocol_type = ntohs(*(const uint16_t*)(packetptr + 14));

        const uint8_t* ip_pointer          = (const uint8_t*)packetptr + sll_header_length;
        int length_before_sampling         = packethdr->len - sll_header_length;
        int captured_length                = packethdr->caplen - sll_header_length;

        if (protocol_type == IP_ETHERTYPE) {
            result = parse_raw_ipv4_packet_to_simple_packet_full(ip_pointer, length_before_sampling,
                                                                 captured_length, current_packet, parser_options);
        } else if (protocol_type == IP6_ETHERTYPE) {
            result = parse_raw_ipv6_packet_to_simple_packet_full(ip_pointer, length_before_sampling,
                                                                 captured_length, current_packet, parser_options);
        } else {
            // Non IP traffic (ARP and others), we do not account it
            return;
        }
    } else {
        // Ethernet framing, the parser expects a raw frame starting from Ethernet header
        result = parse_raw_packet_to_simple_packet_full((const uint8_t*)packetptr, packethdr->len,
                                                        packethdr->caplen, current_packet, parser_options);
    }

    if (result != parser_code_t::success) {
        total_unparsed_packets++;

        logger << log4cpp::Priority::DEBUG << "Cannot parse packet using ng parser: " << parser_code_to_string(result);
        return;
    }

    // Do packet processing
    pcap_process_func_ptr(current_packet);
}


void pcap_main_loop(const char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];
    /* open device for reading in promiscuous mode */
    int promisc = 1;

    bpf_u_int32 maskp; /* subnet mask */
    bpf_u_int32 netp; /* ip */

    logger << log4cpp::Priority::INFO << "Start listening on " << dev;

    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    descr = pcap_create(dev, errbuf);

    if (descr == NULL) {
        logger << log4cpp::Priority::ERROR << "pcap_create was failed with error: " << errbuf;
        exit(0);
    }

    // Setting up 1MB buffer
    int set_buffer_size_res = pcap_set_buffer_size(descr, pcap_buffer_size_mbytes * 1024 * 1024);
    if (set_buffer_size_res != 0) {
        if (set_buffer_size_res == PCAP_ERROR_ACTIVATED) {
            logger << log4cpp::Priority::ERROR << "Can't set buffer size because pcap already activated\n";
            exit(1);
        } else {
            logger << log4cpp::Priority::ERROR << "Can't set buffer size due to error: " << set_buffer_size_res;
            exit(1);
        }
    }

    if (pcap_set_promisc(descr, promisc) != 0) {
        logger << log4cpp::Priority::ERROR << "Can't activate promisc mode for interface: " << dev;
        exit(1);
    }

    if (pcap_activate(descr) != 0) {
        logger << log4cpp::Priority::ERROR << "Call pcap_activate was failed: " << pcap_geterr(descr);
        exit(1);
    }

    // man pcap-linktype
    int link_layer_header_type = pcap_datalink(descr);

    if (link_layer_header_type == DLT_EN10MB) {
        DATA_SHIFT_VALUE = 14;
    } else if (link_layer_header_type == DLT_LINUX_SLL) {
        DATA_SHIFT_VALUE = 16;
    } else {
        logger << log4cpp::Priority::INFO << "We did not support link type:" << link_layer_header_type;
        exit(0);
    }

    // Store link layer type so parse_packet knows how to interpret each frame
    pcap_data_link_type = link_layer_header_type;

    pcap_loop(descr, -1, (pcap_handler)parse_packet, NULL);
}

std::string get_pcap_stats() {
    std::stringstream output_buffer;

    struct pcap_stat current_pcap_stats;
    if (pcap_stats(descr, &current_pcap_stats) == 0) {
        output_buffer << "PCAP statistics"
                      << "\n"
                      << "Received packets: " << current_pcap_stats.ps_recv << "\n"
                      << "Dropped packets: " << current_pcap_stats.ps_drop << " ("
                      << int((double)current_pcap_stats.ps_drop / current_pcap_stats.ps_recv * 100) << "%)"
                      << "\n"
                      << "Dropped by driver or interface: " << current_pcap_stats.ps_ifdrop << "\n";
    }

    return output_buffer.str();
}
