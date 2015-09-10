// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include "../fast_library.h"

// For support uint32_t, uint16_t
#include <sys/types.h>

#include <iostream>
#include <iomanip>

// For config map operations
#include <string>
#include <map>

// For support: IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "pfring_collector.h"

#include "pfring.h"

#ifdef PF_RING_ZC
#include "pfring_zc.h"
#endif

#include <numa.h>

uint32_t pfring_sampling_ratio = 1; 

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

extern uint64_t total_unparsed_packets;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// Interface name or interface list (delimitered by comma)
std::string work_on_interfaces = "";

// This variable name should be uniq for every plugin!
process_packet_pointer pfring_process_func_ptr = NULL;

// We can look inside L2TP packets with IP encapsulation
// And do it by default
bool do_unpack_l2tp_over_ip = true;

// Variable from PF_RING multi channel mode
int num_pfring_channels = 0;

// We can use software or hardware (in kernel module) packet parser
bool we_use_pf_ring_in_kernel_parser = true;

// By default we pool PF_RING on one thread
bool enable_pfring_multi_channel_mode = false;

struct thread_stats {
    u_int64_t __padding_0[8];

    u_int64_t numPkts;
    u_int64_t numBytes;

    pfring* ring;
    pthread_t pd_thread;
    int core_affinity;

    volatile u_int64_t do_shutdown;

    u_int64_t __padding_1[3];
};

struct thread_stats* threads;
pfring* pf_ring_descr = NULL;


// We can use ZC api
bool pf_ring_zc_api_mode = false;

#ifdef PF_RING_ZC
u_int32_t zc_num_threads = 0;
pthread_t* zc_threads;
pfring_zc_cluster* zc;
pfring_zc_worker* zw;
pfring_zc_queue** inzq;
pfring_zc_queue** outzq;
pfring_zc_multi_queue* outzmq; /* fanout */
pfring_zc_buffer_pool* wsp;
pfring_zc_pkt_buff** buffers;
#endif

// Prototypes
#ifdef PF_RING_ZC
bool zc_main_loop(const char* device);
#endif

bool pf_ring_main_loop(const char* dev);
bool pf_ring_main_loop_multi_channel(const char* dev);
void* pf_ring_packet_consumer_thread(void* _id);
void pfring_main_packet_process_task();

void start_pfring_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "PF_RING plugin started";
    pfring_process_func_ptr = func_ptr;

#ifdef PF_RING_ZC
    if (configuration_map.count("enable_pf_ring_zc_mode")) {
        if (configuration_map["enable_pf_ring_zc_mode"] == "on") {
            pf_ring_zc_api_mode = true;
        } else {
            pf_ring_zc_api_mode = false;
        }
    }
#endif

    if (configuration_map.count("interfaces") != 0) {
        work_on_interfaces = configuration_map["interfaces"];

        // We should check all interfaces and check zc flag for all
        if (work_on_interfaces.find("zc:") != std::string::npos) {
            we_use_pf_ring_in_kernel_parser = false;
            logger << log4cpp::Priority::INFO
                   << "We detect run in PF_RING Zero Copy or DNA mode and we enable packet parser!";
        }

        logger << log4cpp::Priority::INFO << "We selected interface:" << work_on_interfaces;
    }

    if (configuration_map.count("pfring_sampling_ratio") != 0) {
        pfring_sampling_ratio = convert_string_to_integer(configuration_map["pfring_sampling_ratio"]);
    }

    if (work_on_interfaces == "") {
        logger << log4cpp::Priority::ERROR << "Please specify interface";
        exit(1);
    }

    pfring_main_packet_process_task();
}


void stop_pfring_collection() {
    pfring_breakloop(pf_ring_descr);
}

void parse_packet_pf_ring(const struct pfring_pkthdr* h, const u_char* p, const u_char* user_bytes) {
    // Description of all fields: http://www.ntop.org/pfring_api/structpkt__parsing__info.html
    simple_packet packet;

    // We pass only one packet to processing
    packet.number_of_packets = 1;

    // Now we support only non sampled input from PF_RING
    packet.sample_ratio = pfring_sampling_ratio;

    if (!pf_ring_zc_api_mode) {
        if (!we_use_pf_ring_in_kernel_parser) {
            // In ZC (zc:eth0) mode you should manually add packet parsing here
            // Because it disabled by default: "parsing already disabled in zero-copy"
            // http://www.ntop.org/pfring_api/pfring_8h.html
            // Parse up to L3, no timestamp, no hashing
            // 1 - add timestamp, 0 - disable hash

            // We should zeroify packet header because PFRING ZC did not do this!
            memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(h->extended_hdr.parsed_pkt));

            // We do not calculate timestamps here because it's useless and consumes so much cpu
            // https://github.com/ntop/PF_RING/issues/9
            u_int8_t timestamp = 0;
            u_int8_t add_hash = 0;
            pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, timestamp, add_hash);
        }
    }

    if (do_unpack_l2tp_over_ip) {
        // 2014-12-08 13:36:53,537 [INFO] [00:1F:12:84:E2:E7 -> 90:E2:BA:49:85:C8]
        // [IPv4][5.254.105.102:0 -> 159.253.17.251:0]
        // [l3_proto=115][hash=2784721876][tos=32][tcp_seq_num=0]
        // [caplen=128][len=873][parsed_header_len=0][eth_offset=-14][l3_offset=14][l4_offset=34][payload_offset=0]
        // L2TP has an proto number 115
        if (h->extended_hdr.parsed_pkt.l3_proto == 115) {
            // pfring_parse_pkt expects that the hdr memory is either zeroed or contains valid
            // values
            // for the current packet, in order to avoid parsing twice the same packet headers.
            struct pfring_pkthdr l2tp_header;
            memset(&l2tp_header, 0, sizeof(l2tp_header));

            int16_t l4_offset = h->extended_hdr.parsed_pkt.offset.l4_offset;

            // L2TP has two headers: L2TP and default L2-Specific Sublayer: every header for 4bytes
            int16_t l2tp_header_size = 8;
            l2tp_header.len = h->len - (l4_offset + l2tp_header_size);
            l2tp_header.caplen = h->caplen - (l4_offset + l2tp_header_size);

            const u_char* l2tp_tunnel_payload = p + l4_offset + l2tp_header_size;
            // 1 - add timestamp, 0 - disable hash
            pfring_parse_pkt((u_char*)l2tp_tunnel_payload, &l2tp_header, 4, 1, 0);

            // Copy data back
            // TODO: it's not fine solution and I should redesign this code
            memcpy((struct pfring_pkthdr*)h, &l2tp_header, sizeof(l2tp_header));

            // TODO: Global pfring_print_parsed_pkt can fail because we did not shift 'p' pointer

            // Uncomment this line for deep inspection of all packets
            /*
            char buffer[512];
            pfring_print_parsed_pkt(buffer, 512, l2tp_tunnel_payload, h);
            logger<<log4cpp::Priority::INFO<<buffer;
            */
        }
    }

    if (h->extended_hdr.parsed_pkt.ip_version != 4 && h->extended_hdr.parsed_pkt.ip_version != 6) {
        total_unparsed_packets++;
        return;
    }

    packet.ip_protocol_version = h->extended_hdr.parsed_pkt.ip_version;

    if (packet.ip_protocol_version == 4) {
        // IPv4

        /* PF_RING stores data in host byte order but we use network byte order */
        packet.src_ip = htonl(h->extended_hdr.parsed_pkt.ip_src.v4);
        packet.dst_ip = htonl(h->extended_hdr.parsed_pkt.ip_dst.v4);
    } else {
        // IPv6

        memcpy(packet.src_ipv6.s6_addr, h->extended_hdr.parsed_pkt.ip_src.v6.s6_addr, 16);
        memcpy(packet.dst_ipv6.s6_addr, h->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr, 16);
    }
 

    packet.source_port = h->extended_hdr.parsed_pkt.l4_src_port;
    packet.destination_port = h->extended_hdr.parsed_pkt.l4_dst_port;

    // We need this for deep packet inspection
    packet.packet_payload_length = h->len;
    packet.packet_payload_pointer = (void*)p;

    packet.length = h->len;
    packet.protocol = h->extended_hdr.parsed_pkt.l3_proto;
    packet.ts = h->ts;

    // Copy flags from PF_RING header to our pseudo header
    if (packet.protocol == IPPROTO_TCP) {
        packet.flags = h->extended_hdr.parsed_pkt.tcp.flags;
    } else {
        packet.flags = 0;
    }

    pfring_process_func_ptr(packet);
}


// Main worker thread for packet handling
void pfring_main_packet_process_task() {
    const char* device_name = work_on_interfaces.c_str();

    bool pf_ring_init_result = false;

    if (pf_ring_zc_api_mode) {
#ifdef PF_RING_ZC
        pf_ring_init_result = zc_main_loop((char*)device_name);
#else
        logger << log4cpp::Priority::ERROR
               << "PF_RING library hasn't ZC support, please try SVN version";
#endif
    } else {
        if (enable_pfring_multi_channel_mode) {
            pf_ring_init_result = pf_ring_main_loop_multi_channel(device_name);
        } else {
            pf_ring_init_result = pf_ring_main_loop(device_name);
        }
    }

    if (!pf_ring_init_result) {
        // Internal error in PF_RING
        logger << log4cpp::Priority::ERROR << "PF_RING initilization failed, exit from programm";
        exit(1);
    }
}


std::string get_pf_ring_stats() {
    std::stringstream output_buffer;

    if (pf_ring_zc_api_mode) {
#ifdef PF_RING_ZC
        pfring_zc_stat stats;
        // We have elements in insq for every hardware device! We shoulw add ability to configure ot
        int stats_res = pfring_zc_stats(inzq[0], &stats);

        if (stats_res) {
            logger << log4cpp::Priority::ERROR << "Can't get PF_RING ZC stats for in queue";
        } else {
            double dropped_percent = 0;

            if (stats.recv + stats.sent > 0) {
                dropped_percent = (double)stats.drop / ((double)stats.recv + (double)stats.sent) * 100;
            }

            output_buffer << "\n";
            output_buffer << "PF_RING ZC in queue statistics\n";
            output_buffer << "Received:\t" << stats.recv << "\n";
            output_buffer << "Sent:\t\t" << stats.sent << "\n";
            output_buffer << "Dropped:\t" << stats.drop << "\n";
            output_buffer << "Dropped:\t" << std::fixed << std::setprecision(2) << dropped_percent << " %\n";
        }

        output_buffer << "\n";
        output_buffer << "PF_RING ZC out queue statistics\n";

        u_int64_t total_recv = 0;
        u_int64_t total_sent = 0;
        u_int64_t total_drop = 0;
        for (int i = 0; i < zc_num_threads; i++) {
            pfring_zc_stat outq_stats;

            int outq_stats_res = pfring_zc_stats(outzq[0], &outq_stats);
            if (stats_res) {
                logger << log4cpp::Priority::ERROR << "Can't get PF_RING ZC stats for out queue";
            } else {
                total_recv += outq_stats.recv;
                total_sent += outq_stats.sent;
                total_drop += outq_stats.drop;
            }
        }

        double total_drop_percent = 0;

        if (total_recv + total_sent > 0) {
            total_drop_percent = (double)total_drop / ((double)total_recv + (double)total_sent) * 100;
        }

        output_buffer << "Received:\t" << total_recv << "\n";
        output_buffer << "Sent:\t\t" << total_sent << "\n";
        output_buffer << "Dropped:\t" << total_drop << "\n";
        output_buffer << "Dropped:\t" << std::fixed << std::setprecision(2) << total_drop_percent << " %\n";
#endif
    }

    // Getting stats for multi channel mode is so complex task
    if (!enable_pfring_multi_channel_mode && !pf_ring_zc_api_mode) {
        pfring_stat pfring_status_data;

        if (pfring_stats(pf_ring_descr, &pfring_status_data) >= 0) {
            char stats_buffer[256];
            double packets_dropped_percent = 0;

            if (pfring_status_data.recv > 0) {
                packets_dropped_percent = (double)pfring_status_data.drop / pfring_status_data.recv * 100;
            }

            sprintf(stats_buffer, "Packets received:\t%lu\n"
                                  "Packets dropped:\t%lu\n"
                                  "Packets dropped:\t%.1f %%\n",
                    (long unsigned int)pfring_status_data.recv,
                    (long unsigned int)pfring_status_data.drop, packets_dropped_percent);
            output_buffer << stats_buffer;
        } else {
            logger << log4cpp::Priority::ERROR << "Can't get PF_RING stats";
        }
    }

    return output_buffer.str();
}

bool pf_ring_main_loop_multi_channel(const char* dev) {
    int MAX_NUM_THREADS = 64;

    if ((threads = (struct thread_stats*)calloc(MAX_NUM_THREADS, sizeof(struct thread_stats))) == NULL) {
        logger << log4cpp::Priority::ERROR << "Can't allocate memory for threads structure";
        return false;
    }

    u_int32_t flags = 0;

    flags |= PF_RING_PROMISC; /* hardcode: promisc=1 */
    flags |= PF_RING_DNA_SYMMETRIC_RSS; /* Note that symmetric RSS is ignored by non-DNA drivers */
    flags |= PF_RING_LONG_HEADER;

    packet_direction direction = rx_only_direction;

    pfring* ring_array[MAX_NUM_RX_CHANNELS];

    unsigned int snaplen = 128;
    num_pfring_channels = pfring_open_multichannel(dev, snaplen, flags, ring_array);

    if (num_pfring_channels <= 0) {
        logger << log4cpp::Priority::INFO << "pfring_open_multichannel returned: " << num_pfring_channels
               << " and error:" << strerror(errno);
        return false;
    }

    u_int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    logger << log4cpp::Priority::INFO << "We have: " << num_cpus << " logical cpus in this server";
    logger << log4cpp::Priority::INFO << "We have: " << num_pfring_channels
           << " channels from pf_ring NIC";

    // We should not start more processes then we have kernel cores
    // if (num_pfring_channels > num_cpus) {
    //    num_pfring_channels = num_cpus;
    //}

    for (int i = 0; i < num_pfring_channels; i++) {
        // char buf[32];

        threads[i].ring = ring_array[i];
        // threads[i].core_affinity = threads_core_affinity[i];

        int rc = 0;

        if ((rc = pfring_set_direction(threads[i].ring, direction)) != 0) {
            logger << log4cpp::Priority::INFO << "pfring_set_direction returned: " << rc;
        }

        if ((rc = pfring_set_socket_mode(threads[i].ring, recv_only_mode)) != 0) {
            logger << log4cpp::Priority::INFO << "pfring_set_socket_mode returned: " << rc;
        }

        int rehash_rss = 0;

        if (rehash_rss) pfring_enable_rss_rehash(threads[i].ring);

        int poll_duration = 0;
        if (poll_duration > 0) pfring_set_poll_duration(threads[i].ring, poll_duration);

        pfring_enable_ring(threads[i].ring);

        unsigned long thread_id = i;
        pthread_create(&threads[i].pd_thread, NULL, pf_ring_packet_consumer_thread, (void*)thread_id);
    }

    for (int i = 0; i < num_pfring_channels; i++) {
        pthread_join(threads[i].pd_thread, NULL);
        pfring_close(threads[i].ring);
    }

    return true;
}

void* pf_ring_packet_consumer_thread(void* _id) {
    long thread_id = (long)_id;
    int wait_for_packet = 1;

    // TODO: fix it
    bool do_shutdown = false;

    while (!do_shutdown) {
        u_char* buffer = NULL;
        struct pfring_pkthdr hdr;

        if (pfring_recv(threads[thread_id].ring, &buffer, 0, &hdr, wait_for_packet) > 0) {
            // TODO: pass (u_char*)thread_id)
            parse_packet_pf_ring(&hdr, buffer, 0);
        } else {
            if (wait_for_packet == 0) {
                usleep(1); // sched_yield();
            }
        }
    }

    return NULL;
}

#ifdef PF_RING_ZC
int rr = -1;
int32_t rr_distribution_func(pfring_zc_pkt_buff* pkt_handle, pfring_zc_queue* in_queue, void* user) {
    long num_out_queues = (long)user;

    if (++rr == num_out_queues) {
        rr = 0;
    }

    return rr;
}
#endif

#ifdef PF_RING_ZC
int bind2core(int core_id) {
    cpu_set_t cpuset;
    int s;

    if (core_id < 0) return -1;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
        logger << log4cpp::Priority::INFO << "Error while binding to core:" << core_id;
        return -1;
    } else {
        return 0;
    }
}
#endif

#ifdef PF_RING_ZC
void* zc_packet_consumer_thread(void* _id) {
    long id = (long)_id;
    pfring_zc_pkt_buff* b = buffers[id];

    // Bind to core with thread number
    bind2core(id);

    u_int8_t wait_for_packet = 1;

    struct pfring_pkthdr zc_header;
    memset(&zc_header, 0, sizeof(zc_header));

    while (true) {
        if (pfring_zc_recv_pkt(outzq[id], &b, wait_for_packet) > 0) {
            u_char* pkt_data = pfring_zc_pkt_buff_data(b, outzq[id]);

            memset(&zc_header, 0, sizeof(zc_header));
            zc_header.len = b->len;
            zc_header.caplen = b->len;

            pfring_parse_pkt(pkt_data, (struct pfring_pkthdr*)&zc_header, 4, 1, 0);

            parse_packet_pf_ring(&zc_header, pkt_data, 0);
        }
    }

    pfring_zc_sync_queue(outzq[id], rx_only);

    return NULL;
}
#endif

int max_packet_len(const char* device) {
    int max_len = 0;

    pfring* ring = pfring_open(device, 1536, PF_RING_PROMISC);

    if (ring == NULL) return 1536;

// pfring_get_card_settings have added in 6.0.3
// We should not use 6.0.3 API for PF_RING library from ntop because it announces "6.0.3" but lack
// of many 6.0.3 features
#if RING_VERSION_NUM >= 0x060003 and !defined(WE_USE_PFRING_FROM_NTOP)
    pfring_card_settings settings;
    pfring_get_card_settings(ring, &settings);
    max_len = settings.max_packet_size;
#else
    if (ring->dna.dna_mapped_device) {
        max_len = ring->dna.dna_dev.mem_info.rx.packet_memory_slot_len;
    } else {
        max_len = pfring_get_mtu_size(ring);
        if (max_len == 0) max_len = 9000 /* Jumbo */;
        max_len += 14 /* Eth */ + 4 /* VLAN */;
    }
#endif

    pfring_close(ring);

    return max_len;
}

#define MAX_CARD_SLOTS 32768
#define PREFETCH_BUFFERS 8
#define QUEUE_LEN 8192

#ifdef PF_RING_ZC
bool zc_main_loop(const char* device) {
    u_int32_t cluster_id = 0;
    int bind_core = -1;

    u_int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    logger << log4cpp::Priority::INFO << "We have: " << num_cpus << " logical cpus in this server";

    // TODO: add support for multiple devices!
    u_int32_t num_devices = 1;
    zc_num_threads = num_cpus - 1;
    logger << log4cpp::Priority::INFO << "We will start " << zc_num_threads << " worker threads";

    u_int32_t tot_num_buffers =
    (num_devices * MAX_CARD_SLOTS) + (zc_num_threads * QUEUE_LEN) + zc_num_threads + PREFETCH_BUFFERS;

    u_int32_t buffer_len = max_packet_len(device);
    logger << log4cpp::Priority::INFO << "We got max packet len from device: " << buffer_len;
    logger << log4cpp::Priority::INFO << "We will use total number of ZC buffers: " << tot_num_buffers;

    zc = pfring_zc_create_cluster(cluster_id, buffer_len, 0, tot_num_buffers,
                                  numa_node_of_cpu(bind_core), NULL /* auto hugetlb mountpoint */
                                  );

    if (zc == NULL) {
        logger << log4cpp::Priority::INFO << "pfring_zc_create_cluster error: " << strerror(errno)
               << " Please check that pf_ring.ko is loaded and hugetlb fs is mounted";
        return false;
    }

    zc_threads = (pthread_t*)calloc(zc_num_threads, sizeof(pthread_t));
    buffers = (pfring_zc_pkt_buff**)calloc(zc_num_threads, sizeof(pfring_zc_pkt_buff*));
    inzq = (pfring_zc_queue**)calloc(num_devices, sizeof(pfring_zc_queue*));
    outzq = (pfring_zc_queue**)calloc(zc_num_threads, sizeof(pfring_zc_queue*));

    for (int i = 0; i < zc_num_threads; i++) {
        buffers[i] = pfring_zc_get_packet_handle(zc);

        if (buffers[i] == NULL) {
            logger << log4cpp::Priority::ERROR << "pfring_zc_get_packet_handle failed";
            return false;
        }
    }


    for (int i = 0; i < num_devices; i++) {
        u_int32_t zc_flags = 0;
        inzq[i] = pfring_zc_open_device(zc, device, rx_only, zc_flags);

        if (inzq[i] == NULL) {
            logger << log4cpp::Priority::ERROR << "pfring_zc_open_device error " << strerror(errno)
                   << " Please check that device is up and not already used";
            return false;
        }

#if RING_VERSION_NUM >= 0x060003
        int pf_ring_license_state = pfring_zc_check_license();

        if (!pf_ring_license_state) {
            logger << log4cpp::Priority::WARN << "PF_RING ZC haven't license for device" << device
                   << " and running in trial mode and will work only 5 minutes! Please buy license "
                      "or switch to vanilla PF_RING";
        }
#endif
    }

    for (int i = 0; i < zc_num_threads; i++) {
        outzq[i] = pfring_zc_create_queue(zc, QUEUE_LEN);

        if (outzq[i] == NULL) {
            logger << log4cpp::Priority::ERROR << "pfring_zc_create_queue error: " << strerror(errno);
            return false;
        }
    }

    wsp = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);

    if (wsp == NULL) {
        logger << log4cpp::Priority::ERROR << "pfring_zc_create_buffer_pool error";
        return false;
    }

    logger << log4cpp::Priority::INFO << "We are starting balancer with: " << zc_num_threads
           << " threads";

    pfring_zc_distribution_func func = rr_distribution_func;

    u_int8_t wait_for_packet = 1;

    // We run balancer at last thread
    int32_t bind_worker_core = zc_num_threads;

    logger << log4cpp::Priority::INFO << "We will run balancer on core: " << bind_worker_core;

    zw = pfring_zc_run_balancer(inzq, outzq, num_devices, zc_num_threads, wsp,
                                round_robin_bursts_policy, NULL /* idle callback */, func,
                                (void*)((long)zc_num_threads), !wait_for_packet, bind_worker_core);

    if (zw == NULL) {
        logger << log4cpp::Priority::ERROR << "pfring_zc_run_balancer error:" << strerror(errno);
        return false;
    }

    for (int i = 0; i < zc_num_threads; i++) {
        pthread_create(&zc_threads[i], NULL, zc_packet_consumer_thread, (void*)(long)i);
    }

    for (int i = 0; i < zc_num_threads; i++) {
        pthread_join(zc_threads[i], NULL);
    }

    pfring_zc_kill_worker(zw);
    pfring_zc_destroy_cluster(zc);

    return true;
}
#endif

bool pf_ring_main_loop(const char* dev) {
    // We could pool device in multiple threads
    unsigned int num_threads = 1;

    bool promisc = true;
    /* This flag manages packet parser for extended_hdr */
    bool use_extended_pkt_header = true;
    bool enable_hw_timestamp = false;
    bool dont_strip_timestamps = false;

    u_int32_t flags = 0;
    if (num_threads > 1) flags |= PF_RING_REENTRANT;
    if (use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;
    if (promisc) flags |= PF_RING_PROMISC;
    if (enable_hw_timestamp) flags |= PF_RING_HW_TIMESTAMP;
    if (!dont_strip_timestamps) flags |= PF_RING_STRIP_HW_TIMESTAMP;

    if (!we_use_pf_ring_in_kernel_parser) {
        flags |= PF_RING_DO_NOT_PARSE;
    }

    flags |= PF_RING_DNA_SYMMETRIC_RSS; /* Note that symmetric RSS is ignored by non-DNA drivers */

    // use default value from pfcount.c
    unsigned int snaplen = 128;

    pf_ring_descr = pfring_open(dev, snaplen, flags);

    if (pf_ring_descr == NULL) {
        logger
        << log4cpp::Priority::INFO << "pfring_open error: " << strerror(errno)
        << " (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to: " << dev
        << ")";
        return false;
    }


    logger << log4cpp::Priority::INFO << "Successully binded to: " << dev;

    // We need cast to int because in other way it will be interpreted as char :(
    logger << log4cpp::Priority::INFO
           << "Device RX channels number: " << int(pfring_get_num_rx_channels(pf_ring_descr));

    u_int32_t version;
    // Set spplication name in /proc
    int pfring_set_application_name_result =
    pfring_set_application_name(pf_ring_descr, (char*)"fastnetmon");

    if (pfring_set_application_name_result != 0) {
        logger << log4cpp::Priority::ERROR
               << "Can't set programm name for PF_RING: pfring_set_application_name";
    }

    pfring_version(pf_ring_descr, &version);

    logger.info("Using PF_RING v.%d.%d.%d", (version & 0xFFFF0000) >> 16,
                (version & 0x0000FF00) >> 8, version & 0x000000FF);

    int pfring_set_socket_mode_result = pfring_set_socket_mode(pf_ring_descr, recv_only_mode);

    if (pfring_set_socket_mode_result != 0) {
        logger.info("pfring_set_socket_mode returned [rc=%d]\n", pfring_set_socket_mode_result);
    }

    // enable ring
    if (pfring_enable_ring(pf_ring_descr) != 0) {
        logger << log4cpp::Priority::INFO << "Unable to enable ring :-(";
        pfring_close(pf_ring_descr);
        return false;
    }

    // Active wait wor packets. But I did not know what is mean..
    u_int8_t wait_for_packet = 1;

    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);

    return true;
}
