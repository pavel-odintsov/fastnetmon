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

#include "../fastnetmon_packet_parser.h"

// For support: IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "afpacket_collector.h"

#include <boost/thread.hpp>
#include <sys/mman.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

// Pass unparsed packets number to main programm
extern uint64_t total_unparsed_packets;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// This variable name should be uniq for every plugin!
process_packet_pointer afpacket_process_func_ptr = NULL;

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

// We will use this code from Global Symbols table (originally it's defined in netmap collector.cpp)
bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet);

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

void flush_block(struct block_desc *pbd) {
    pbd->h1.block_status = TP_STATUS_KERNEL;
}

void walk_block(struct block_desc *pbd, const int block_num) {
    int num_pkts = pbd->h1.num_pkts, i;
    unsigned long bytes = 0;
    struct tpacket3_hdr *ppd;

    ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
                       pbd->h1.offset_to_first_pkt);
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

        u_char* data_pointer = (u_char*)((uint8_t *) ppd + ppd->tp_mac);

        simple_packet packet;
        int parser_result = parse_raw_packet_to_simple_packet((u_char*)data_pointer, ppd->tp_snaplen, packet); 

        //char print_buffer[512];
        //fastnetmon_print_parsed_pkt(print_buffer, 512, data_pointer, &packet_header);
        //printf("%s\n", print_buffer);
 
        ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
                           ppd->tp_next_offset);

        if (parser_result) {
            afpacket_process_func_ptr(packet);
        } else {
            total_unparsed_packets++;
        }
    }
}

int setup_socket(std::string interface_name, int fanout_group_id) {
    // More details here: http://man7.org/linux/man-pages/man7/packet.7.html
    // We could use SOCK_RAW or SOCK_DGRAM for second argument
    // SOCK_RAW - raw packets pass from the kernel
    // SOCK_DGRAM - some amount of processing 
    // Third argument manage ether type of captured packets
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   
    if (packet_socket == -1) {
        logger << log4cpp::Priority::ERROR << "Can't create AF_PACKET socket";
        return -1;
    }

    // We whould use V3 bcause it could read/pool in per block basis instead per packet
    int version = TPACKET_V3;
    int setsockopt_packet_version = setsockopt(packet_socket, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));

    if (setsockopt_packet_version < 0) {
        logger << log4cpp::Priority::ERROR << "Can't set packet v3 version";
        return -1;
    }

    int interface_number = get_interface_number_by_device_name(packet_socket, interface_name);

    if (interface_number == -1) {
        logger << log4cpp::Priority::ERROR << "Can't get interface number by interface name for " << interface_name;
        return -1;
    }
 
    // Switch to PROMISC mode
    struct packet_mreq sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = interface_number;
    
    int set_promisc = setsockopt(packet_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&sock_params, sizeof(sock_params));

    if (set_promisc == -1) {
        logger << log4cpp::Priority::ERROR << "Can't enable promisc mode";
        return -1;
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

    int setsockopt_rx_ring = setsockopt(packet_socket, SOL_PACKET , PACKET_RX_RING , (void*)&req , sizeof(req));
    
    if (setsockopt_rx_ring == -1) {
        logger << log4cpp::Priority::ERROR << "Can't enable RX_RING for AF_PACKET socket";
        return -1;
    }

    // We use per thread structures
    uint8_t* mapped_buffer = NULL;
    struct iovec* rd = NULL;

    mapped_buffer = (uint8_t*)mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, packet_socket, 0);

    if (mapped_buffer == MAP_FAILED) {
        logger << log4cpp::Priority::ERROR << "MMAP failed";
        return -1;
    }

    // Allocate iov structure for each block
    rd = (struct iovec*)malloc(req.tp_block_nr * sizeof(struct iovec));

    // Initilize iov structures
    for (int i = 0; i < req.tp_block_nr; ++i) {
        rd[i].iov_base = mapped_buffer + (i * req.tp_block_size);
        rd[i].iov_len = req.tp_block_size;
    }

    int bind_result = bind(packet_socket, (struct sockaddr *)&bind_address, sizeof(bind_address));

    if (bind_result == -1) {
        logger << log4cpp::Priority::ERROR << "Can't bind to AF_PACKET socket";
        return -1;
    }
 
   if (fanout_group_id) {
        // PACKET_FANOUT_LB - round robin
        // PACKET_FANOUT_CPU - send packets to CPU where packet arrived
        int fanout_type = PACKET_FANOUT_CPU; 

        int fanout_arg = (fanout_group_id | (fanout_type << 16));

        int setsockopt_fanout = setsockopt(packet_socket, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));

        if (setsockopt_fanout < 0) {
            logger << log4cpp::Priority::ERROR << "Can't configure fanout error number: "<< errno << " error: " << strerror(errno);
            return -1;
        }
    }

    unsigned int current_block_num = 0;

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = packet_socket;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;
   
    while (true) {
        struct block_desc *pbd = (struct block_desc *) rd[current_block_num].iov_base;
 
        if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
            poll(&pfd, 1, -1);

            continue;
        }   

        walk_block(pbd, current_block_num);
        flush_block(pbd);
        current_block_num = (current_block_num + 1) % blocknum;
    }   

    return packet_socket;
}

void start_af_packet_capture(std::string interface_name, int fanout_group_id) {
    setup_socket(interface_name, fanout_group_id); 
}

void get_af_packet_stats() {
// getsockopt PACKET_STATISTICS
}

// Could get some speed up on NUMA servers
bool afpacket_execute_strict_cpu_affinity = true;

void start_afpacket_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "AF_PACKET plugin started";
    afpacket_process_func_ptr = func_ptr;

    std::string interfaces_list = "";

    if (configuration_map.count("interfaces") != 0) {
        interfaces_list = configuration_map["interfaces"];
    }

    std::vector<std::string> interfaces_for_listen;
    boost::split(interfaces_for_listen, interfaces_list, boost::is_any_of(","), boost::token_compress_on);

    logger << log4cpp::Priority::INFO << "AF_PACKET will listen on " << interfaces_for_listen.size() << " interfaces";

    if (interfaces_for_listen.size() == 0) {
        logger << log4cpp::Priority::ERROR << "Please specify intreface for AF_PACKET";
        return;
    }

    if (interfaces_for_listen.size() > 1) {
        logger << log4cpp::Priority::WARN << "We support only single interface for AF_PACKET, sorry!";
    }

    std::string capture_interface = interfaces_for_listen[0];

    int fanout_group_id = getpid() & 0xffff;

    unsigned int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);;
    logger.info("We have %d cpus for AF_PACKET", num_cpus);

    if (num_cpus > 1) {
        boost::thread_group packet_receiver_thread_group;

        for (int cpu = 0; cpu < num_cpus; cpu++) {

// Well, we have thread attributes from Boost 1.50
#if defined(BOOST_THREAD_PLATFORM_PTHREAD) && BOOST_VERSION / 100 % 1000 >= 50
            boost::thread::attributes thread_attrs;

            if (afpacket_execute_strict_cpu_affinity) {
                cpu_set_t current_cpu_set;

                int cpu_to_bind = cpu % num_cpus;
                CPU_ZERO(&current_cpu_set);
                // We count cpus from zero
                CPU_SET(cpu_to_bind, &current_cpu_set);

                int set_affinity_result = pthread_attr_setaffinity_np(thread_attrs.native_handle(), sizeof(cpu_set_t), &current_cpu_set);
    
                if (set_affinity_result != 0) {
                    logger << log4cpp::Priority::ERROR << "Can't set CPU affinity for thread";
                } 
            }

            packet_receiver_thread_group.add_thread(
                new boost::thread(thread_attrs, boost::bind(start_af_packet_capture, capture_interface, fanout_group_id))
            );
#else
            logger.error("Sorry but CPU affinity did not supported for your platform");

            packet_receiver_thread_group.add_thread(
                new boost::thread(start_af_packet_capture, capture_interface, fanout_group_id) 
            );
#endif
        }

        // Wait all processes for finish
        packet_receiver_thread_group.join_all();
    } else {    
        start_af_packet_capture(capture_interface, 0);
    }
}
