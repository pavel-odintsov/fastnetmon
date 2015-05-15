#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

#include <map>
#include <string>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include "pcap_collector.h"

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

extern log4cpp::Category& logger;
extern std::map<std::string, std::string> configuration_map;

// This variable name should be uniq for every plugin!
process_packet_pointer pcap_process_func_ptr = NULL;

// Enlarge receive buffer for PCAP for minimize packet drops
unsigned int pcap_buffer_size_mbytes = 10;

// pcap handler, we want it as global variable beacuse it used in singnal handler
pcap_t* descr = NULL;

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

// We do not use this function now! It's buggy!
void parse_packet(u_char* user, struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    struct ip* iphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    struct ether_header* eptr; /* net/ethernet.h */
    eptr = (struct ether_header*)packetptr;

    if (ntohs(eptr->ether_type) == VLAN_ETHERTYPE) {
        // It's tagged traffic we should sjoft for 4 bytes for getting the data
        packetptr += DATA_SHIFT_VALUE + VLAN_HDRLEN;
    } else if (ntohs(eptr->ether_type) == IP_ETHERTYPE) {
        // Skip the datalink layer header and get the IP header fields.
        packetptr += DATA_SHIFT_VALUE;
    } else if (ntohs(eptr->ether_type) == IP6_ETHERTYPE or ntohs(eptr->ether_type) == ARP_ETHERTYPE) {
        // we know about it but does't not care now
    } else {
        // printf("Packet with non standard ethertype found: 0x%x\n", ntohs(eptr->ether_type));
    }

    iphdr = (struct ip*)packetptr;

    // src/dst UO is an in_addr, http://man7.org/linux/man-pages/man7/ip.7.html
    uint32_t src_ip = iphdr->ip_src.s_addr;
    uint32_t dst_ip = iphdr->ip_dst.s_addr;

    // The ntohs() function converts the unsigned short integer netshort from network byte order to
    // host byte order
    unsigned int packet_length = ntohs(iphdr->ip_len);

    simple_packet current_packet;

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp
    packetptr += 4 * iphdr->ip_hl;
    switch (iphdr->ip_p) {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
        current_packet.source_port = ntohs(tcphdr->th_sport);
#else
        current_packet.source_port = ntohs(tcphdr->source);
#endif

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
        current_packet.destination_port = ntohs(tcphdr->th_dport);
#else
        current_packet.destination_port = ntohs(tcphdr->dest);
#endif
        break;
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
        current_packet.source_port = ntohs(udphdr->uh_sport);
#else
        current_packet.source_port = ntohs(udphdr->source);
#endif

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
        current_packet.destination_port = ntohs(udphdr->uh_dport);
#else
        current_packet.destination_port = ntohs(udphdr->dest);
#endif
        break;
    case IPPROTO_ICMP:
        // there are no port for ICMP
        current_packet.source_port = 0;
        current_packet.destination_port = 0;
        break;
    }

    current_packet.protocol = iphdr->ip_p;
    current_packet.src_ip = src_ip;
    current_packet.dst_ip = dst_ip;
    current_packet.length = packet_length;

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
            logger << log4cpp::Priority::ERROR
                   << "Can't set buffer size because pcap already activated\n";
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
