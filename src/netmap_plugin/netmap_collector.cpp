// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include <boost/version.hpp>
#include <boost/algorithm/string.hpp>

#include "../fast_library.h"

// For support uint32_t, uint16_t
#include <sys/types.h>

// For config map operations
#include <string>
#include <map>

#include <stdio.h>
#include <iostream>
#include <string>
#define NETMAP_WITH_LIBS

// Disable debug messages from Netmap
#define NETMAP_NO_DEBUG
#include <net/netmap_user.h>
#include <boost/thread.hpp>

#if defined(__FreeBSD__)
// On FreeBSD function pthread_attr_setaffinity_np declared here
#include <pthread_np.h>

// Also we have different type name for cpu set's store
typedef cpuset_t cpu_set_t;
#endif

#include "../fastnetmon_packet_parser.h"

// For pooling operations
#include <poll.h>

// For support: IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "netmap_collector.h"

// By default we read packet size from link layer
// But in case of Juniper we could crop first X bytes from packet:
// maximum-packet-length 110;
// And this option become mandatory if we want correct bps speed in toolkit
bool netmap_read_packet_length_from_ip_header = false;

uint32_t netmap_sampling_ratio = 1;

/* prototypes */
void netmap_thread(struct nm_desc* netmap_descriptor, int netmap_thread);
void consume_pkt(u_char* buffer, int len, int thread_number);

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

// Pass unparsed packets number to main programm
extern uint64_t total_unparsed_packets;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

u_int num_cpus = 0;

// This variable name should be uniq for every plugin!
process_packet_pointer netmap_process_func_ptr = NULL;

bool execute_strict_cpu_affinity = true;

int receive_packets(struct netmap_ring* ring, int thread_number) {
    u_int cur, rx, n;

    cur = ring->cur;
    n = nm_ring_space(ring);

    for (rx = 0; rx < n; rx++) {
        struct netmap_slot* slot = &ring->slot[cur];
        char* p = NETMAP_BUF(ring, slot->buf_idx);

        // process data
        consume_pkt((u_char*)p, slot->len, thread_number);

        cur = nm_ring_next(ring, cur);
    }

    ring->head = ring->cur = cur;
    return (rx);
}

bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet) {
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

    if (packet_header.extended_hdr.parsed_pkt.ip_version != 4 && packet_header.extended_hdr.parsed_pkt.ip_version != 6) {
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

void consume_pkt(u_char* buffer, int len, int thread_number) {
    // We should fill this structure for passing to FastNetMon
    simple_packet packet;

    packet.sample_ratio = netmap_sampling_ratio;

    if (!parse_raw_packet_to_simple_packet(buffer, len, packet)) {
        total_unparsed_packets++;

        return;
    }   

    netmap_process_func_ptr(packet);
}

void receiver(std::string interface_for_listening) {
    struct nm_desc* netmap_descriptor;

    struct nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));

    // Magic from pkt-gen.c
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    std::string interface = "";
    std::string system_interface_name = "";
    // If we haven't netmap: prefix in interface name we will append it
    if (interface_for_listening.find("netmap:") == std::string::npos) {
        system_interface_name = interface_for_listening;

        interface = "netmap:" + interface_for_listening;
    } else {
        // We should skip netmap prefix
        system_interface_name = boost::replace_all_copy(interface_for_listening, "netmap:", "");

        interface = interface_for_listening;
    }

#ifdef __linux__
    manage_interface_promisc_mode(system_interface_name, true); 
    logger.warn("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off", system_interface_name.c_str());
#endif

    netmap_descriptor = nm_open(interface.c_str(), &base_nmd, 0, NULL);

    if (netmap_descriptor == NULL) {
        logger.error("Can't open netmap device %s", interface.c_str());
        exit(1);
        return;
    }

    logger.info("Mapped %dKB memory at %p", netmap_descriptor->req.nr_memsize >> 10, netmap_descriptor->mem);
    logger.info("We have %d tx and %d rx rings", netmap_descriptor->req.nr_tx_rings,
                netmap_descriptor->req.nr_rx_rings);

    if (num_cpus > netmap_descriptor->req.nr_rx_rings) {
        num_cpus = netmap_descriptor->req.nr_rx_rings;

        logger.info("We have number of CPUs bigger than number of NIC RX queues. Set number of "
                    "CPU's to number of threads");
    }

    /*
        protocol stack and may cause a reset of the card,
        which in turn may take some time for the PHY to
        reconfigure. We do the open here to have time to reset.
    */

    int wait_link = 2;
    logger.info("Wait %d seconds for NIC reset", wait_link);
    sleep(wait_link);

    boost::thread_group packet_receiver_thread_group;

    for (int i = 0; i < num_cpus; i++) {
        struct nm_desc nmd = *netmap_descriptor;
        // This operation is VERY important!
        nmd.self = &nmd;

        uint64_t nmd_flags = 0;

        if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
            logger.error("Ooops, main descriptor should be with NR_REG_ALL_NIC flag");
        }

        nmd.req.nr_flags = NR_REG_ONE_NIC;
        nmd.req.nr_ringid = i;

        /* Only touch one of the rings (rx is already ok) */
        nmd_flags |= NETMAP_NO_TX_POLL;

        struct nm_desc* new_nmd =
        nm_open(interface.c_str(), NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

        if (new_nmd == NULL) {
            logger.error("Can't open netmap descriptor for netmap per hardware queue thread");
            exit(1);
        }

        logger.info("My first ring is %d and last ring id is %d I'm thread %d",
                    new_nmd->first_rx_ring, new_nmd->last_rx_ring, i);


        /*
        logger<< log4cpp::Priority::INFO<< "We are using Boost "
            << BOOST_VERSION / 100000     << "."  // major version
            << BOOST_VERSION / 100 % 1000 << "."  // minior version
            << BOOST_VERSION % 100;
        */

        logger.info("Start new netmap thread %d", i);

// Well, we have thread attributes from Boost 1.50

#if defined(BOOST_THREAD_PLATFORM_PTHREAD) && BOOST_VERSION / 100 % 1000 >= 50 && !defined(__APPLE__)
        /* Bind to certain core */
        boost::thread::attributes thread_attrs;

        if (execute_strict_cpu_affinity) {
            cpu_set_t current_cpu_set;

            int cpu_to_bind = i % num_cpus;

            CPU_ZERO(&current_cpu_set);
            // We count cpus from zero
            CPU_SET(cpu_to_bind, &current_cpu_set);

            logger.info("I will bind this thread to logical CPU: %d", cpu_to_bind);

            int set_affinity_result =
            pthread_attr_setaffinity_np(thread_attrs.native_handle(), sizeof(cpu_set_t), &current_cpu_set);

            if (set_affinity_result != 0) {
                logger.error("Can't specify CPU affinity for netmap thread");
            }
        }

        // Start thread and pass netmap descriptor to it
        packet_receiver_thread_group.add_thread(
        new boost::thread(thread_attrs, boost::bind(netmap_thread, new_nmd, i)));
#else
        logger.error("Sorry but CPU affinity did not supported for your platform");
        packet_receiver_thread_group.add_thread(new boost::thread(netmap_thread, new_nmd, i));
#endif
    }

    // Wait all threads for completion
    packet_receiver_thread_group.join_all();
}

void netmap_thread(struct nm_desc* netmap_descriptor, int thread_number) {
    struct nm_pkthdr h;
    u_char* buf;
    struct pollfd fds;
    fds.fd = netmap_descriptor->fd; // NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    struct netmap_ring* rxring = NULL;
    struct netmap_if* nifp = netmap_descriptor->nifp;

    // printf("Reading from fd %d thread id: %d", netmap_descriptor->fd, thread_number);

    for (;;) {
        // We will wait 1000 microseconds for retry, for infinite timeout please use -1
        int poll_result = poll(&fds, 1, 1000);

        if (poll_result == 0) {
            // printf("poll return 0 return code");
            continue;
        }

        if (poll_result == -1) {
            logger.error("Netmap plugin: poll failed with return code -1");
        }

        for (int i = netmap_descriptor->first_rx_ring; i <= netmap_descriptor->last_rx_ring; i++) {
            // printf("Check ring %d from thread %d", i, thread_number);
            rxring = NETMAP_RXRING(nifp, i);

            if (nm_ring_empty(rxring)) {
                continue;
            }

            receive_packets(rxring, thread_number);
        }

        // TODO: this code could add performance degradation
        // Add interruption point for correct toolkit shutdown 
        // boost::this_thread::interruption_point();
    }

    // nm_close(netmap_descriptor);
}

void start_netmap_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "Netmap plugin started";
    netmap_process_func_ptr = func_ptr;

    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    logger.info("We have %d cpus", num_cpus);

    std::string interfaces_list = "";

    if (configuration_map.count("interfaces") != 0) {
        interfaces_list = configuration_map["interfaces"];
    }

    if (configuration_map.count("netmap_sampling_ratio") != 0) {
        netmap_sampling_ratio = convert_string_to_integer(configuration_map["netmap_sampling_ratio"]);
    }

    if (configuration_map.count("netmap_read_packet_length_from_ip_header") != 0) {
        netmap_read_packet_length_from_ip_header = configuration_map["netmap_read_packet_length_from_ip_header"] == "on";
    }

    std::vector<std::string> interfaces_for_listen;
    boost::split(interfaces_for_listen, interfaces_list, boost::is_any_of(","), boost::token_compress_on);

    logger << log4cpp::Priority::INFO << "netmap will listen on " << interfaces_for_listen.size() << " interfaces";

    // Thread group for all "master" processes
    boost::thread_group netmap_main_threads;

    for (std::vector<std::string>::iterator interface = interfaces_for_listen.begin();
        interface != interfaces_for_listen.end(); ++interface) {

        logger << log4cpp::Priority::INFO << "netmap will sniff interface: " << *interface;
        
        netmap_main_threads.add_thread( new boost::thread(receiver, *interface) );
    }

    netmap_main_threads.join_all();
}
