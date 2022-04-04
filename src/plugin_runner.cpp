#include <arpa/inet.h>
#include <inttypes.h>
#include <iterator>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "fast_library.h"
#include "fastnetmon_types.h"
#include "libpatricia/patricia.h"
#include "netflow_plugin/netflow_collector.h"
#include "pcap_plugin/pcap_collector.h"
#include "sflow_plugin/sflow_collector.h"

#ifdef FASTNETMON_ENABLE_AFPACKET
#include "afpacket_plugin/afpacket_collector.h"
#endif

#ifdef NETMAP_PLUGIN
#include "netmap_plugin/netmap_collector.h"
#endif

// log4cpp logging facility
#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include <fstream>

using namespace std;

uint64_t total_unparsed_packets = 0;

std::string log_file_path = "/tmp/fastnetmon_plugin_tester.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();

// #define DO_SUBNET_LOOKUP

#ifdef DO_SUBNET_LOOKUP
patricia_tree_t* lookup_tree;
#endif

// Global map with parsed config file
std::map<std::string, std::string> configuration_map;

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("%d [%p] %m%n");

    log4cpp::Appender* appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

void process_packet(simple_packet& current_packet) {
    std::cout << print_simple_packet(current_packet);
#ifdef DO_SUBNET_LOOKUP
    unsigned long subnet = 0;
    unsigned int subnet_cidr_mask = 0;

    direction packet_direction = get_packet_direction(lookup_tree, current_packet.src_ip,
                                                      current_packet.dst_ip, subnet, subnet_cidr_mask);
    std::cout << "direction: " << get_direction_name(packet_direction) << std::endl;
#endif
}

// Copy & paste from fastnetmon.cpp
std::vector<std::string> read_file_to_vector(std::string file_name) {
    std::vector<std::string> data;
    std::string line;

    std::ifstream reading_file;

    reading_file.open(file_name.c_str(), std::ifstream::in);
    if (reading_file.is_open()) {
        while (getline(reading_file, line)) {
            data.push_back(line);
        }
    } else {
        logger << log4cpp::Priority::ERROR << "Can't open file: " << file_name;
    }

    return data;
}

int main(int argc, char* argv[]) {
    init_logging();

    if (argc < 2) {
        std::cout << "Please specify sflow, netflow, raw, afpacket as param" << std::endl;
        return 1;
    }

#ifdef DO_SUBNET_LOOKUP
    lookup_tree = New_Patricia(32);

    std::vector<std::string> network_list_from_config = read_file_to_vector("/etc/networks_list");

    for (std::vector<std::string>::iterator ii = network_list_from_config.begin();
         ii != network_list_from_config.end(); ++ii) {
        std::string network_address_in_cidr_form = *ii;

        make_and_lookup(lookup_tree, const_cast<char*>(network_address_in_cidr_form.c_str()));
    }
#endif

    // Required by Netmap plugin
    // We use fake interface name here because netmap could make server unreachable :)
    configuration_map["interfaces"] = "ethXXX";

    if (strstr(argv[1], "sflow") != NULL) {
        std::cout << "Starting sflow" << std::endl;
        start_sflow_collection(process_packet);
    } else if (strstr(argv[1], "netflow") != NULL) {
        std::cout << "Starting netflow" << std::endl;
        start_netflow_collection(process_packet);
    } else if (strstr(argv[1], "pcap") != NULL) {
        std::cout << "Starting pcap" << std::endl;
        start_pcap_collection(process_packet);
    } else if (strstr(argv[1], "afpacket") != NULL) {
#ifdef FASTNETMON_ENABLE_AFPACKET
        std::cout << "Starting afpacket" << std::endl;
        start_afpacket_collection(process_packet);
#else
        printf("AF_PACKET is not supported here");
#endif
    } else if (strstr(argv[1], "netmap") != NULL) {
        std::cout << "Starting netmap" << std::endl;
        start_netmap_collection(process_packet);
    } else {
        std::cout << "Bad plugin name!" << std::endl;
    }
}
