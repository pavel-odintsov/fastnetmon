// log4cpp logging facility
#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include <boost/algorithm/string.hpp>
#include <boost/version.hpp>

#include "../fast_library.h"

// For support uint32_t, uint16_t
#include <sys/types.h>

// For config map operations
#include <map>
#include <string>

#include <iostream>
#include <stdio.h>
#include <string>

#include "../fastnetmon_packet_parser.h"

// For support: IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "afpacket_collector.h"

#include <arpa/inet.h>
#include <boost/thread.hpp>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <linux/filter.h> // for struct sock_filter

#include "../unified_parser.hpp"

bool afpacket_read_packet_length_from_ip_header = false;

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

// Pass unparsed packets number to main programm
extern uint64_t total_unparsed_packets;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// This variable name should be uniq for every plugin!
process_packet_pointer afpacket_process_func_ptr = NULL;

// Default sampling rate
uint32_t mirror_af_packet_custom_sampling_rate = 1;

// 4194304 bytes
unsigned int blocksiz = 1 << 22;
// 2048 bytes
unsigned int framesiz = 1 << 11;
unsigned int blocknum = 64;

struct block_desc {
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

/*
 * - PACKET_FANOUT_HASH: schedule to socket by skb's packet hash
 * - PACKET_FANOUT_LB: schedule to socket by round-robin
 * - PACKET_FANOUT_CPU: schedule to socket by CPU packet arrives on
 * - PACKET_FANOUT_RND: schedule to socket by random selection
 * - PACKET_FANOUT_ROLLOVER: if one socket is full, rollover to another
 * - PACKET_FANOUT_QM: schedule to socket by skbs recorded queue_mapping
 */

int fanout_type = PACKET_FANOUT_CPU;

// Our kernel headers aren't so fresh and we need it
#ifndef PACKET_FANOUT_QM
#define PACKET_FANOUT_QM 5
#endif


int get_fanout_by_name(std::string fanout_name) {
    if (fanout_name == "" || fanout_name == "cpu") {
        // Default mode for backward compatibility
        return PACKET_FANOUT_CPU;
    } else if (fanout_name == "lb") {
        return PACKET_FANOUT_LB;
    } else if (fanout_name == "hash") {
        return PACKET_FANOUT_HASH;
    } else if (fanout_name == "random") {
        return PACKET_FANOUT_RND;
    } else if (fanout_name == "rollover") {
        return PACKET_FANOUT_ROLLOVER;
    } else if (fanout_name == "queue_mapping") {
        return PACKET_FANOUT_QM;
    } else {
        // Return default one
        logger << log4cpp::Priority::ERROR << "Unknown FANOUT mode: " << fanout_name << " switched to default (CPU)";
        return PACKET_FANOUT_CPU;
     }
}

// Get interface number by name
int get_interface_number_by_device_name(int socket_fd, std::string interface_name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (interface_name.size() > IFNAMSIZ) {
        return -1;
    }

    strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        return -1;
    }

    return ifr.ifr_ifindex;
}

void flush_block(struct block_desc* pbd) {
    pbd->h1.block_status = TP_STATUS_KERNEL;
}

void walk_block(struct block_desc* pbd, const int block_num) {
    int num_pkts = pbd->h1.num_pkts, i;
    unsigned long bytes = 0;
    struct tpacket3_hdr* ppd;

    ppd = (struct tpacket3_hdr*)((uint8_t*)pbd + pbd->h1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i) {
        bytes += ppd->tp_snaplen;

        // struct ethhdr *eth = (struct ethhdr *) ((uint8_t *) ppd + ppd->tp_mac);
        // Print packets

        struct pfring_pkthdr packet_header;
        memset(&packet_header, 0, sizeof(packet_header));
        packet_header.len = ppd->tp_snaplen;
        packet_header.caplen = ppd->tp_snaplen;

        u_int8_t timestamp = 0;
        u_int8_t add_hash = 0;

        u_char* data_pointer = (u_char*)((uint8_t*)ppd + ppd->tp_mac);

        simple_packet packet;
        int parser_result = parse_raw_packet_to_simple_packet((u_char*)data_pointer, ppd->tp_snaplen, packet,
                                                              afpacket_read_packet_length_from_ip_header);

        // Override default sample rate by rate specified in configuration
        if (mirror_af_packet_custom_sampling_rate > 1) {
            packet.sample_ratio = mirror_af_packet_custom_sampling_rate;
        }

        // char print_buffer[512];
        // fastnetmon_print_parsed_pkt(print_buffer, 512, data_pointer, &packet_header);
        // printf("%s\n", print_buffer);

        ppd = (struct tpacket3_hdr*)((uint8_t*)ppd + ppd->tp_next_offset);

        if (parser_result) {
            afpacket_process_func_ptr(packet);
        } else {
            total_unparsed_packets++;
        }
    }
}

bool setup_socket(std::string interface_name, bool enable_fanout, int fanout_group_id) {
    // More details here: http://man7.org/linux/man-pages/man7/packet.7.html
    // We could use SOCK_RAW or SOCK_DGRAM for second argument
    // SOCK_RAW - raw packets pass from the kernel
    // SOCK_DGRAM - some amount of processing
    // Third argument manage ether type of captured packets
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (packet_socket == -1) {
        logger << log4cpp::Priority::ERROR << "Can't create AF_PACKET socket";
        return false;
    }

    // We whould use V3 bcause it could read/pool in per block basis instead per packet
    int version = TPACKET_V3;
    int setsockopt_packet_version =
    setsockopt(packet_socket, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));

    if (setsockopt_packet_version < 0) {
        logger << log4cpp::Priority::ERROR << "Can't set packet v3 version";
        return false;
    }

    int interface_number = get_interface_number_by_device_name(packet_socket, interface_name);

    if (interface_number == -1) {
        logger << log4cpp::Priority::ERROR << "Can't get interface number by interface name for " << interface_name;
        return false;
    }

    // Switch to PROMISC mode
    struct packet_mreq sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = interface_number;

    int set_promisc = setsockopt(packet_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                                 (void*)&sock_params, sizeof(sock_params));

    if (set_promisc == -1) {
        logger << log4cpp::Priority::ERROR << "Can't enable promisc mode";
        return false;
    }

    struct sockaddr_ll bind_address;
    memset(&bind_address, 0, sizeof(bind_address));

    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = interface_number;

    // We will follow http://yusufonlinux.blogspot.ru/2010/11/data-link-access-and-zero-copy.html
    // And this: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));

    req.tp_block_size = blocksiz;
    req.tp_frame_size = framesiz;
    req.tp_block_nr = blocknum;
    req.tp_frame_nr = (blocksiz * blocknum) / framesiz;

    req.tp_retire_blk_tov = 60; // Timeout in msec
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    int setsockopt_rx_ring = setsockopt(packet_socket, SOL_PACKET, PACKET_RX_RING, (void*)&req, sizeof(req));

    if (setsockopt_rx_ring == -1) {
        logger << log4cpp::Priority::ERROR << "Can't enable RX_RING for AF_PACKET socket";
        return false;
    }

    // We use per thread structures
    uint8_t* mapped_buffer = NULL;
    struct iovec* rd = NULL;

    mapped_buffer = (uint8_t*)mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_LOCKED, packet_socket, 0);

    if (mapped_buffer == MAP_FAILED) {
        logger << log4cpp::Priority::ERROR << "MMAP failed errno: " << errno << " error: " << strerror(errno);
        return false;
    }

    // Allocate iov structure for each block
    rd = (struct iovec*)malloc(req.tp_block_nr * sizeof(struct iovec));

    // Initilize iov structures
    for (int i = 0; i < req.tp_block_nr; ++i) {
        rd[i].iov_base = mapped_buffer + (i * req.tp_block_size);
        rd[i].iov_len = req.tp_block_size;
    }

    int bind_result = bind(packet_socket, (struct sockaddr*)&bind_address, sizeof(bind_address));

    if (bind_result == -1) {
        logger << log4cpp::Priority::ERROR << "Can't bind to AF_PACKET socket";
        return false;
    }

    if (enable_fanout) {
        int fanout_arg = (fanout_group_id | (fanout_type << 16));

        int setsockopt_fanout =
        setsockopt(packet_socket, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));

        if (setsockopt_fanout < 0) {
            logger << log4cpp::Priority::ERROR << "Can't configure fanout error number: " << errno
                   << " error: " << strerror(errno);
            return false;
        }
    }

    unsigned int current_block_num = 0;

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = packet_socket;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;

    while (true) {
        struct block_desc* pbd = (struct block_desc*)rd[current_block_num].iov_base;

        if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
            poll(&pfd, 1, -1);

            continue;
        }

        walk_block(pbd, current_block_num);
        flush_block(pbd);
        current_block_num = (current_block_num + 1) % blocknum;
    }

    return true;
}

void start_af_packet_capture(std::string interface_name, bool enable_fanout, int fanout_group_id) {
    setup_socket(interface_name, enable_fanout, fanout_group_id);
}

void get_af_packet_stats() {
    // getsockopt PACKET_STATISTICS
}

// Could get some speed up on NUMA servers
bool afpacket_execute_strict_cpu_affinity = false;

void start_afpacket_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "AF_PACKET plugin started";
    afpacket_process_func_ptr = func_ptr;

    unsigned int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    logger.info("We have %d cpus for AF_PACKET", num_cpus);

    if (configuration_map.count("netmap_read_packet_length_from_ip_header") != 0) {
        afpacket_read_packet_length_from_ip_header =
        configuration_map["netmap_read_packet_length_from_ip_header"] == "on";
    }

    std::string interfaces_list = "";

    if (configuration_map.count("interfaces") != 0) {
        interfaces_list = configuration_map["interfaces"];
    }

    if (configuration_map.count("mirror_af_packet_custom_sampling_rate") != 0) {
        mirror_af_packet_custom_sampling_rate =
        convert_string_to_integer(configuration_map["mirror_af_packet_custom_sampling_rate"]);
    }

    if (configuration_map.count("mirror_af_packet_fanout_mode") != 0) {
	// Set FANOUT mode
        fanout_type = get_fanout_by_name(configuration_map["mirror_af_packet_fanout_mode"]);
    }

    std::vector<std::string> interfaces_for_listen;
    boost::split(interfaces_for_listen, interfaces_list, boost::is_any_of(","), boost::token_compress_on);

    logger << log4cpp::Priority::INFO << "AF_PACKET will listen on " << interfaces_for_listen.size()
           << " interfaces";

    if (interfaces_for_listen.size() == 0) {
        logger << log4cpp::Priority::ERROR << "Please specify intreface for AF_PACKET";
        return;
    }

    // Thread group for all "master" processes
    boost::thread_group af_packet_main_threads;

    for (int i = 0; i < interfaces_for_listen.size(); i++) {
        // Use process id to identify particular fanout group
        int group_identifier = getpid();

        // And add number for current interface to distinguish them
        group_identifier += i;

        int fanout_group_id = group_identifier & 0xffff;

        std::string capture_interface = interfaces_for_listen[i];

        logger << log4cpp::Priority::INFO << "AF_PACKET will listen on " << capture_interface << " interface";

        boost::thread* af_packet_interface_thread =
        new boost::thread(start_af_packet_capture_for_interface, capture_interface, fanout_group_id, num_cpus);

        af_packet_main_threads.add_thread(af_packet_interface_thread);
    }

    af_packet_main_threads.join_all();
}

// Starts traffic capture for particular interface
void start_af_packet_capture_for_interface(std::string capture_interface, int fanout_group_id, unsigned int num_cpus) {
    if (num_cpus == 1) {
        logger << log4cpp::Priority::INFO << "Disable AF_PACKET fanout because you have only single CPU";

        bool fanout = false;
        start_af_packet_capture(capture_interface, fanout, 0);
    } else {
        // We have two or more CPUs
        boost::thread_group packet_receiver_thread_group;

        for (int cpu = 0; cpu < num_cpus; cpu++) {
            logger << log4cpp::Priority::INFO << "Start AF_PACKET worker process for " << capture_interface
                   << " with fanout group id " << fanout_group_id << " on CPU " << cpu;

// Well, we have thread attributes from Boost 1.50
#if defined(BOOST_THREAD_PLATFORM_PTHREAD) && BOOST_VERSION / 100 % 1000 >= 50 && defined(__GLIBC__)
            boost::thread::attributes thread_attrs;

            if (afpacket_execute_strict_cpu_affinity) {
                cpu_set_t current_cpu_set;

                int cpu_to_bind = cpu % num_cpus;
                CPU_ZERO(&current_cpu_set);
                // We count cpus from zero
                CPU_SET(cpu_to_bind, &current_cpu_set);

                int set_affinity_result =
                pthread_attr_setaffinity_np(thread_attrs.native_handle(), sizeof(cpu_set_t), &current_cpu_set);

                if (set_affinity_result != 0) {
                    logger << log4cpp::Priority::ERROR << "Can't set CPU affinity for thread";
                }
            }

            bool fanout = true;

            packet_receiver_thread_group.add_thread(
            new boost::thread(thread_attrs, boost::bind(start_af_packet_capture, capture_interface,
                                                        fanout, fanout_group_id)));
#else
            bool fanout = true;

            logger.error("Sorry but CPU affinity did not supported for your platform");

            packet_receiver_thread_group.add_thread(
            new boost::thread(start_af_packet_capture, capture_interface, fanout, fanout_group_id));
#endif
        }

        // Wait all processes for finish
        packet_receiver_thread_group.join_all();
    }
}
