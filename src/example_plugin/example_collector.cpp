#include "../all_logcpp_libraries.h"

// For support uint32_t, uint16_t
#include <sys/types.h>

// For config map operations
#include <map>
#include <string>

// For support: IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "example_collector.h"

// Get log4cpp logger from main program
extern log4cpp::Category& logger;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// This variable name should be uniq for every plugin!
process_packet_pointer example_process_func_ptr = NULL;

void start_example_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "Example plugin started";
    example_process_func_ptr = func_ptr;

    std::string example_plugin_config_param = "";

    if (configuration_map.count("some_plugin_param_from_global_config") != 0) {
        example_plugin_config_param = configuration_map["some_plugin_param_from_global_config"];
    }

    // We should fill this structure for passing to FastNetMon
    simple_packet_t current_packet;

    current_packet.src_ip = 0;
    current_packet.dst_ip = 0;

    current_packet.ts.tv_sec  = 0;
    current_packet.ts.tv_usec = 0;
    current_packet.flags      = 0;

    // There we store packet length or total length of aggregated stream
    current_packet.length = 128;

    // Number of received packets, it's not equal to 1 only for aggregated data like netflow
    current_packet.number_of_packets = 1;

    // If your data sampled
    current_packet.sample_ratio = 1;

    /* ICMP */
    current_packet.protocol = IPPROTO_ICMP;

    /* TCP */
    current_packet.protocol         = IPPROTO_TCP;
    current_packet.source_port      = 0;
    current_packet.destination_port = 0;

    /* UDP */
    current_packet.protocol         = IPPROTO_UDP;
    current_packet.source_port      = 0;
    current_packet.destination_port = 0;

    example_process_func_ptr(current_packet);
}
