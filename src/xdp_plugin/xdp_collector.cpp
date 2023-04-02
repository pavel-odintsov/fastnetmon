#include "xdp_collector.hpp"
#include "../fastnetmon_plugin.hpp"
#include <linux/bpf.h> // BPF_PROG_TYPE_XDP
#include <linux/if_link.h> // XDP_FLAGS_DRV_MODE
#include <linux/if_xdp.h> // sockaddr_xdp
#include <net/if.h> // if_nametoindex
#include <sys/mman.h> // mmap mode constants

#include <poll.h> // poll

#include <boost/algorithm/string.hpp>

// TODO: add support for multiple interfaces

// Only relatively fresh kernels have this type and we need to declare this type on older kernels to be able to compile
// libbpf On Ubuntu 20.04 and Debian 11
#ifdef DECLARE_FAKE_BPF_STATS

/* type for BPF_ENABLE_STATS */
enum bpf_stats_type {
    /* enabled run_time_ns and run_cnt */
    BPF_STATS_RUN_TIME = 0,
};

#endif

#ifdef DECLARE_FAKE_BPF_LINK_TYPE

enum bpf_link_type {
    BPF_LINK_TYPE_UNSPEC         = 0,
    BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
    BPF_LINK_TYPE_TRACING        = 2,
    BPF_LINK_TYPE_CGROUP         = 3,
    BPF_LINK_TYPE_ITER           = 4,
    BPF_LINK_TYPE_NETNS          = 5,
    BPF_LINK_TYPE_XDP            = 6,
    BPF_LINK_TYPE_PERF_EVENT     = 7,

    MAX_BPF_LINK_TYPE,
};

#endif

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

#include <sys/resource.h> // RLIM_INFINITY

// Our new generation parser
#include "../simple_packet_parser_ng.hpp"

extern time_t current_inaccurate_time;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

std::string packets_received_desc = "Total number of packets received by AF_XDP";
uint64_t packets_received         = 0;

std::string xdp_packets_unparsed_desc =
    "Total number of packets with parser issues. It may be broken packets or non IP traffic";
uint64_t xdp_packets_unparsed = 0;

// Evern 4.19 kernel does not have this declaration in headers
#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#define NUM_DESCS 1024

#define BATCH_SIZE 16

#define FILL_QUEUE_NUM_DESCS 1024
#define COMPLETION_QUEUE_NUM_DESCS 1024

#define NUM_FRAMES 131072
#define FRAME_SIZE 2048

// We do not need any headroom
#define FRAME_HEADROOM 0

// clang-format off
#define memory_barrier() __asm__ __volatile__("": : :"memory")
// clang-format on

process_packet_pointer xdp_process_func_ptr = nullptr;

class xdp_umem_uqueue {
    public:
    __u32 cached_prod = 0;
    __u32 cached_cons = 0;
    __u32 mask        = 0;
    __u32 size        = 0;
    __u32* producer   = nullptr;
    __u32* consumer   = nullptr;
    __u64* ring       = nullptr;
    void* map         = nullptr;
};

class xdp_uqueue {
    public:
    __u32 cached_prod = 0;
    __u32 cached_cons = 0;
    __u32 mask        = 0;
    __u32 size        = 0;
    __u32* producer   = nullptr;
    __u32* consumer   = nullptr;
    xdp_desc* ring    = nullptr;
    void* map         = nullptr;
};

// Keeps all information about memory for AF_XDP socket
class xsk_memory_configuration {
    public:
    xdp_umem_uqueue fill_queue{};
    xdp_umem_uqueue completion_queue{};
    char* buffer = nullptr;
};

std::vector<system_counter_t> get_xdp_stats() {
    std::vector<system_counter_t> system_counter;

    system_counter.push_back(system_counter_t("xdp_packets_received", packets_received, metric_type_t::counter, packets_received_desc));
    system_counter.push_back(system_counter_t("xdp_packets_unparsed", xdp_packets_unparsed, metric_type_t::counter,
                                              xdp_packets_unparsed_desc));
    return system_counter;
}

// Creates memory region for XDP socket
bool configure_memory_buffers(int xsk_handle, xsk_memory_configuration& memory_configuration) {
    int fill_queue_size       = FILL_QUEUE_NUM_DESCS;
    int completion_queue_size = COMPLETION_QUEUE_NUM_DESCS;

    void* buffer = nullptr;

    size_t allocation_size = NUM_FRAMES * FRAME_SIZE;
    logger << log4cpp::Priority::INFO << "Allocating " << allocation_size << " bytes";

    // Allocates aligned memory
    auto memalign_res = posix_memalign(&buffer, getpagesize(), allocation_size);

    if (memalign_res != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot allocate memory. Error code: " << memalign_res;
        return false;
    }

    xdp_umem_reg umem_register{};
    memset(&umem_register, 0, sizeof(xdp_umem_reg));

    umem_register.addr       = (__u64)buffer;
    umem_register.len        = NUM_FRAMES * FRAME_SIZE;
    umem_register.chunk_size = FRAME_SIZE;
    umem_register.headroom   = FRAME_HEADROOM;

    auto set_xdp_umem_reg = setsockopt(xsk_handle, SOL_XDP, XDP_UMEM_REG, &umem_register, sizeof(xdp_umem_reg));

    if (set_xdp_umem_reg != 0) {
        logger << log4cpp::Priority::ERROR << "setsockopt failed for XDP_UMEM_REG code: " << set_xdp_umem_reg;
        return false;
    }

    auto set_umem_fill_ring = setsockopt(xsk_handle, SOL_XDP, XDP_UMEM_FILL_RING, &fill_queue_size, sizeof(int));

    if (set_umem_fill_ring != 0) {
        logger << log4cpp::Priority::ERROR << "setsockopt failed for XDP_UMEM_FILL_RING code: " << set_umem_fill_ring;
        return false;
    }

    auto set_umem_completion_ring =
        setsockopt(xsk_handle, SOL_XDP, XDP_UMEM_COMPLETION_RING, &completion_queue_size, sizeof(int));

    if (set_umem_completion_ring != 0) {
        logger << log4cpp::Priority::ERROR << "setsockopt failed for XDP_UMEM_COMPLETION_RING code: " << set_umem_completion_ring;
        return false;
    }

    xdp_mmap_offsets mmap_offset;
    memset(&mmap_offset, 0, sizeof(xdp_mmap_offsets));

    socklen_t options_length = sizeof(xdp_mmap_offsets);

    auto set_mmap_offsets = getsockopt(xsk_handle, SOL_XDP, XDP_MMAP_OFFSETS, &mmap_offset, &options_length);

    if (set_mmap_offsets != 0) {
        logger << log4cpp::Priority::ERROR << "setsockopt failed for XDP_MMAP_OFFSETS code: " << set_mmap_offsets;
        return false;
    }

    // Configure fill queue
    xdp_umem_uqueue fill_queue_descriptor{};

    fill_queue_descriptor.map = mmap(0, mmap_offset.fr.desc + FILL_QUEUE_NUM_DESCS * sizeof(__u64), PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_POPULATE, xsk_handle, XDP_UMEM_PGOFF_FILL_RING);

    if (fill_queue_descriptor.map == MAP_FAILED) {
        logger << log4cpp::Priority::ERROR << "Fill queue mmap failed, error code: " << errno << " error: " << strerror(errno);
        return false;
    }

    fill_queue_descriptor.mask        = FILL_QUEUE_NUM_DESCS - 1;
    fill_queue_descriptor.size        = FILL_QUEUE_NUM_DESCS;
    fill_queue_descriptor.producer    = (__u32*)((unsigned char*)fill_queue_descriptor.map + mmap_offset.fr.producer);
    fill_queue_descriptor.consumer    = (__u32*)((unsigned char*)fill_queue_descriptor.map + mmap_offset.fr.consumer);
    fill_queue_descriptor.ring        = (__u64*)((unsigned char*)fill_queue_descriptor.map + mmap_offset.fr.desc);
    fill_queue_descriptor.cached_cons = FILL_QUEUE_NUM_DESCS;

    // Configure completion queue
    xdp_umem_uqueue completion_queue_descriptor{};

    completion_queue_descriptor.map = mmap(0, mmap_offset.cr.desc + COMPLETION_QUEUE_NUM_DESCS * sizeof(__u64), PROT_READ | PROT_WRITE,
                                           MAP_SHARED | MAP_POPULATE, xsk_handle, XDP_UMEM_PGOFF_COMPLETION_RING);

    if (completion_queue_descriptor.map == MAP_FAILED) {
        logger << log4cpp::Priority::ERROR << "Completion queue mmap failed, error code: " << errno
               << " error: " << strerror(errno);
        return false;
    }

    completion_queue_descriptor.mask = COMPLETION_QUEUE_NUM_DESCS - 1;
    completion_queue_descriptor.size = COMPLETION_QUEUE_NUM_DESCS;
    completion_queue_descriptor.producer = (__u32*)((unsigned char*)completion_queue_descriptor.map + mmap_offset.cr.producer);
    completion_queue_descriptor.consumer = (__u32*)((unsigned char*)completion_queue_descriptor.map + mmap_offset.cr.consumer);
    completion_queue_descriptor.ring = (__u64*)((unsigned char*)completion_queue_descriptor.map + mmap_offset.cr.desc);

    memory_configuration.fill_queue       = fill_queue_descriptor;
    memory_configuration.completion_queue = completion_queue_descriptor;
    memory_configuration.buffer           = (char*)buffer;

    return true;
}

uint32_t u_memory_nb_free(xdp_umem_uqueue* queue, uint32_t nb) {
    uint32_t free_entries = queue->cached_cons - queue->cached_prod;

    if (free_entries >= nb) {
        return free_entries;
    }

    /* Refresh reference */
    queue->cached_cons = *queue->consumer + queue->size;
    return queue->cached_cons - queue->cached_prod;
}

bool execute_fill_to_kernel(xdp_umem_uqueue* fill_queue, xdp_desc* desc, unsigned int number_of_packets) {
    auto free_entries = u_memory_nb_free(fill_queue, number_of_packets);

    if (free_entries < number_of_packets) {
        return false;
    }

    for (int i = 0; i < number_of_packets; i++) {
        uint32_t index = fill_queue->cached_prod++ & fill_queue->mask;

        fill_queue->ring[index] = desc[i].addr;
    }

    memory_barrier();
    *fill_queue->producer = fill_queue->cached_prod;
    return true;
}

bool execute_initial_memfill(xdp_umem_uqueue* fill_queue, int* d, size_t nb) {
    auto free_entries = u_memory_nb_free(fill_queue, nb);

    if (free_entries < nb) {
        return false;
    }

    for (int i = 0; i < nb; i++) {
        uint32_t index = fill_queue->cached_prod++ & fill_queue->mask;

        fill_queue->ring[index] = d[i];
    }

    memory_barrier();

    *fill_queue->producer = fill_queue->cached_prod;

    return true;
}

// Creates and configures XSK socket
bool create_and_configure_xsk_socket(int& xsk_socket_param,
                                     unsigned int ifindex,
                                     int queue_id,
                                     xsk_memory_configuration& mem_conf_param,
                                     xdp_uqueue& rx) {
    int xsk_handle = socket(AF_XDP, SOCK_RAW, 0);

    if (xsk_handle == -1) {
        logger << log4cpp::Priority::ERROR << "Cannot create socket. Error code: " << errno << " error: " << strerror(errno);
        return false;
    }


    // Allocate memory for buffers
    xsk_memory_configuration memory_configuration{};

    bool memory_configuration_res = configure_memory_buffers(xsk_handle, memory_configuration);

    if (!memory_configuration_res) {
        return false;
    }

    int number_of_descriptors = NUM_DESCS;

    auto set_rx_rings = setsockopt(xsk_handle, SOL_XDP, XDP_RX_RING, &number_of_descriptors, sizeof(int));

    if (set_rx_rings != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot set number of RX rings";
        return false;
    }

    auto set_tx_rings = setsockopt(xsk_handle, SOL_XDP, XDP_TX_RING, &number_of_descriptors, sizeof(int));

    if (set_tx_rings != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot set number of TX rings";
        return false;
    }


    xdp_mmap_offsets mmap_offset;
    memset(&mmap_offset, 0, sizeof(xdp_mmap_offsets));

    socklen_t optlen = sizeof(xdp_mmap_offsets);

    auto get_mmap_ffsets_res = getsockopt(xsk_handle, SOL_XDP, XDP_MMAP_OFFSETS, &mmap_offset, &optlen);

    if (get_mmap_ffsets_res != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot get XDP mmap offsets";
        return false;
    }

    // Return socket to caller
    xsk_socket_param = xsk_handle;

    rx.map = mmap(NULL, mmap_offset.rx.desc + NUM_DESCS * sizeof(xdp_desc), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, xsk_handle, XDP_PGOFF_RX_RING);

    if (rx.map == MAP_FAILED) {
        logger << log4cpp::Priority::ERROR << "Cannot mmap RX for XDP socket";
        return false;
    }

    for (int i = 0; i < NUM_DESCS * FRAME_SIZE; i += FRAME_SIZE) {
        auto memfill_res = execute_initial_memfill(&memory_configuration.fill_queue, &i, 1);

        if (!memfill_res) {
            logger << log4cpp::Priority::ERROR << "Cannot execute initial memory filling";
            return false;
        }
    }

    rx.mask     = NUM_DESCS - 1;
    rx.size     = NUM_DESCS;
    rx.producer = (__u32*)((unsigned char*)rx.map + mmap_offset.rx.producer);
    rx.consumer = (__u32*)((unsigned char*)rx.map + mmap_offset.rx.consumer);
    rx.ring     = (xdp_desc*)((unsigned char*)rx.map + mmap_offset.rx.desc);

    sockaddr_xdp sockaddr_xdp_descriptor;
    memset(&sockaddr_xdp_descriptor, 0, sizeof(sockaddr_xdp));

    sockaddr_xdp sxdp;
    memset(&sxdp, 0, sizeof(sockaddr_xdp));

    sockaddr_xdp_descriptor.sxdp_family   = AF_XDP;
    sockaddr_xdp_descriptor.sxdp_ifindex  = ifindex;
    sockaddr_xdp_descriptor.sxdp_queue_id = queue_id;

    __u32 bind_flags = 0;

    bool force_native_mode_xdp = configuration_map["force_native_mode_xdp"] == "on";

    bool zero_copy_xdp = configuration_map["zero_copy_xdp"] == "on";

    if (!force_native_mode_xdp) {
        // In copy mode we need one more additional option for bind process
        bind_flags |= XDP_COPY;
    } else {
        // For native mode we can enable ZERO COPY mode when customer requested it
        if (zero_copy_xdp) {
            bind_flags |= XDP_ZEROCOPY;
        }
    }

    sockaddr_xdp_descriptor.sxdp_flags = bind_flags;
    int bind_res = bind(xsk_handle, (sockaddr*)&sockaddr_xdp_descriptor, sizeof(sockaddr_xdp_descriptor));

    if (bind_res) {
        logger << log4cpp::Priority::ERROR << "Cannot bind to socket with error code " << errno << " error: " << strerror(errno);
        return false;
    }

    logger << log4cpp::Priority::INFO << "Correctly bind socket";

    // Return memory configuration to caller
    mem_conf_param = memory_configuration;

    return true;
}

// Returns true if we have any packets for processing
unsigned int packets_available(xdp_uqueue* rx, int number_of_descriptors) {
    auto entries = rx->cached_prod - rx->cached_cons;

    if (entries == 0) {
        rx->cached_prod = *rx->producer;

        entries = rx->cached_prod - rx->cached_cons;
    }

    if (entries > number_of_descriptors) {
        return number_of_descriptors;
    } else {
        return entries;
    }
}

unsigned int dequeue_packets(xdp_uqueue* rx, xdp_desc* descs, int number_of_descriptors) {
    int entries = packets_available(rx, number_of_descriptors);

    xdp_desc* r = rx->ring;

    memory_barrier();

    for (int i = 0; i < entries; i++) {
        unsigned int idx = rx->cached_cons++ & rx->mask;
        descs[i]         = r[idx];
    }

    if (entries > 0) {
        memory_barrier();

        *rx->consumer = rx->cached_cons;
    }

    return entries;
}

void xdp_process_traffic(int xdp_socket, xsk_memory_configuration* mem_configuration, xdp_uqueue* rx) {
    logger << log4cpp::Priority::INFO << "Start traffic processing";

    // Create structures for poll syscall
    pollfd monitored_fds[1];
    memset(monitored_fds, 0, sizeof(pollfd));

    monitored_fds[0].fd     = xdp_socket;
    monitored_fds[0].events = POLLIN;

    // Timeout in milliseconds
    int timeout_poll = 1000;

    nfds_t number_of_monitored_fds = 1;

    bool poll_mode_xdp = configuration_map["poll_mode_xdp"] == "on";

    bool xdp_read_packet_length_from_ip_header = configuration_map["xdp_read_packet_length_from_ip_header"] == "on";

    while (true) {
        if (poll_mode_xdp) {
            int poll_res = poll(monitored_fds, number_of_monitored_fds, timeout_poll);

            if (poll_res == 0) {
                // Timeout happened
                logger << log4cpp::Priority::DEBUG << "Timeout happened";
                continue;
            } else if (poll_res < 0) {
                // Error happened
                logger << log4cpp::Priority::ERROR << "Error during poll happened. Error code: " << errno
                       << " error: " << strerror(errno);
                continue;
            } else {
                // We got some data!
            }
        }

        xdp_desc descs[BATCH_SIZE];

        unsigned int received = dequeue_packets(rx, descs, BATCH_SIZE);

        if (received == 0) {
            continue;
        }

        // Iterate over all packets
        for (unsigned int i = 0; i < received; i++) {
            void* packet_data = &mem_configuration->buffer[descs[i].addr];

            simple_packet_t packet;
            packet.source       = MIRROR;
            packet.arrival_time = current_inaccurate_time;

            bool xdp_extract_tunnel_traffic = false;

            auto result = parse_raw_packet_to_simple_packet_full_ng((u_char*)packet_data, descs[i].len, descs[i].len,
                                                                    packet, xdp_extract_tunnel_traffic,
                                                                    xdp_read_packet_length_from_ip_header);

            if (result != network_data_stuctures::parser_code_t::success) {
                xdp_packets_unparsed++;

                logger << log4cpp::Priority::DEBUG
                       << "Cannot parse packet using ng parser: " << network_data_stuctures::parser_code_to_string(result);
            } else {
                // Successfully parsed packet
                xdp_process_func_ptr(packet);
            }
        }

        execute_fill_to_kernel(&mem_configuration->fill_queue, descs, received);
    }
}

void start_xdp_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "XDP plugin started";

    std::vector<std::string> interfaces_xdp;

    if (configuration_map.count("interfaces") != 0) {
        boost::split(interfaces_xdp, configuration_map["interfaces"], boost::is_any_of(","), boost::token_compress_on);
    }

    if (interfaces_xdp.size() == 0) {
        logger << log4cpp::Priority::ERROR << "Please specify interface for XDP";
        return;
    }

    xdp_process_func_ptr = func_ptr;

    // We should increase this limit because default one causes bpf map failures:
    // https://patchwork.ozlabs.org/patch/831562/
    rlimit rlimit_infinity = { RLIM_INFINITY, RLIM_INFINITY };

    if (setrlimit(RLIMIT_MEMLOCK, &rlimit_infinity) != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot set rlimit memlock with error " << strerror(errno);
        return;
    }

    // TODO: move it to resources or expose configuration option
    std::string bpf_microcode_path = configuration_map["microcode_xdp_path"];

    if (!file_exists(bpf_microcode_path)) {
        logger << log4cpp::Priority::ERROR << "Specified microcode path " << bpf_microcode_path << " does not exist";
        return;
    }

    bpf_object* obj = bpf_object__open_file(bpf_microcode_path.c_str(), NULL);

    int open_file_error_code = libbpf_get_error(obj);

    if (open_file_error_code) {
        // Documentation claims https://libbpf.readthedocs.io/en/latest/api.html that errno will be set too
        logger << log4cpp::Priority::ERROR << "Cannot open BPF file: " << bpf_microcode_path << " with error code "
               << open_file_error_code << " errno " << errno;
        return;
    }

    bpf_program* prog = bpf_object__next_program(obj, NULL);
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

    int bpf_load_res = bpf_object__load(obj);

    if (bpf_load_res != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot load BPF microcode code: " << bpf_load_res;
        return;
    }

    int prog_fd = bpf_program__fd(prog);

    if (prog_fd < 0) {
        logger << log4cpp::Priority::ERROR << "No BPF program found";
        return;
    }

    // Lookup queue configuration map
    bpf_map* queue_map = bpf_object__find_map_by_name(obj, "qidconf_map");

    int qidconf_map = bpf_map__fd(queue_map);

    if (qidconf_map < 0) {
        logger << log4cpp::Priority::ERROR << "Cannot find queue configuration map";
        return;
    }

    // TODO: make it configurable
    int queue_id = 0;

    // Lookup XSK map
    bpf_map* xsk_map = bpf_object__find_map_by_name(obj, "xsks_map");
    int xsks_map     = bpf_map__fd(xsk_map);

    if (xsks_map < 0) {
        logger << log4cpp::Priority::ERROR << "Cannot find XSP socket map";
        return;
    }

    std::string interface = interfaces_xdp[0];

    logger << log4cpp::Priority::INFO << "We support only single interface and will use " << interface;

    bool xdp_set_promisc = configuration_map["xdp_set_promisc"] == "on";

    // We should set interface to promisc mode because AF_XDP does not do it for us
    if (xdp_set_promisc) {
        manage_interface_promisc_mode(interface, true);
    }

    unsigned int ifindex = if_nametoindex(interface.c_str());

    if (ifindex == 0) {
        logger << log4cpp::Priority::ERROR << "Cannot get interface handler for " << interface << " error code "
               << errno << " error: " << strerror(errno);
        return;
    }

    __u32 opt_xdp_flags = 0;

    bool force_native_mode_xdp = configuration_map["force_native_mode_xdp"] == "on";

    if (force_native_mode_xdp) {
        opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
        logger << log4cpp::Priority::INFO << "Will use native XDP mode";
    } else {
        opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
        logger << log4cpp::Priority::INFO << "Will use copy/generic XDP mode";
    }

    // In version 1.x they've removed old interface completely
    // We keep this code only for EPEL 9 compatibility
#if LIBBPF_MAJOR_VERSION > 0
    int set_link_xdp_res = bpf_xdp_attach(ifindex, prog_fd, opt_xdp_flags, NULL);
#else
    int set_link_xdp_res = bpf_set_link_xdp_fd(ifindex, prog_fd, opt_xdp_flags);
#endif

    if (set_link_xdp_res < 0) {
        // Get human friendly code
        char buf[1024];
        libbpf_strerror(set_link_xdp_res, buf, 1024);

        logger << log4cpp::Priority::ERROR << "Cannot assign BPF microcode to interface "
               << interface << " error code: " << set_link_xdp_res << " error: " << buf;
        return;
    }

    int queue_key      = 0;
    int ret_update_map = bpf_map_update_elem(qidconf_map, &queue_key, &queue_id, 0);

    if (ret_update_map != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot update queue configuration map";
        return;
    }

    // Create socket
    int xsk_socket = 0;
    xsk_memory_configuration mem_configuration{};

    xdp_uqueue rx{};

    auto socket_res = create_and_configure_xsk_socket(xsk_socket, ifindex, queue_id, mem_configuration, rx);

    if (!socket_res) {
        logger << log4cpp::Priority::ERROR << "Cannot configure socket";
        return;
    }

    logger << log4cpp::Priority::INFO << "Correctly created socket: " << xsk_socket;

    // Let's add our AF_XDP socket as consumer for this XDP microcode
    int socket_map_key      = 0;
    auto xsk_map_update_res = bpf_map_update_elem(xsks_map, &socket_map_key, &xsk_socket, 0);

    if (xsk_map_update_res != 0) {
        logger << log4cpp::Priority::ERROR << "Cannot update socket configuration map";
        return;
    }

    xdp_process_traffic(xsk_socket, &mem_configuration, &rx);
}
