#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <iterator>
#include <sstream>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "../fastnetmon_types.h"
#include "fast_library.h"
#include "plugins/netflow/netflow_collector.h"
#include "plugins/sflow/sflow_collector.h"
#include "plugins/pcap/pcap_collector.h"

#ifdef PF_RING
#include "plugins/pfring/pfring_collector.h"
#endif

#include "plugins/netmap/netmap_collector.h"

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

using namespace std;

uint64_t total_unparsed_packets = 0;

std::string log_file_path = "/tmp/fastnetmon_plugin_tester.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();

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
}

int main(int argc, char* argv[]) {
    init_logging();

    if (argc < 2) {
        std::cout << "Please specify sflow or netflow as param" << std::endl;
        return 1;
    }

    // Required by Netmap and PF_RING plugins
    configuration_map["interfaces"] = "eth0";

    if (strstr(argv[1], "sflow") != NULL) {
        std::cout << "Starting sflow" << std::endl;
        start_sflow_collection(process_packet);
    } else if (strstr(argv[1], "netflow") != NULL) {
        std::cout << "Starting netflow" << std::endl;
        start_netflow_collection(process_packet);
    } else if (strstr(argv[1], "pcap") != NULL) {
        std::cout << "Starting pcap" << std::endl;
        start_pcap_collection(process_packet);
    } else if (strstr(argv[1], "pfring") != NULL) {
#ifdef PF_RING
        std::cout << "Starting pf_ring" << std::endl;
        start_pfring_collection(process_packet);
#else
        std::cout << "PF_RING support disabled here" << std::endl; 
#endif
    } else if (strstr(argv[1], "netmap") != NULL) {
        std::cout << "Starting netmap" << std::endl;
        start_netmap_collection(process_packet);
    } else {
        std::cout << "Bad plugin name!" << std::endl;
    }
}
