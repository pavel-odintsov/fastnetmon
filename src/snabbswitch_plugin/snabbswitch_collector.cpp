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

#include "snabbswitch_collector.h"

#ifdef __cplusplus
extern "C" {
#endif

// This code defined in SnabbSwitch
int start_snabb_switch(int snabb_argc, const char **snabb_argv);

#ifdef __cplusplus
}
#endif

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

// Pass unparsed packets number to main programm
extern uint64_t total_unparsed_packets;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// This variable name should be uniq for every plugin!
process_packet_pointer snabbswitch_process_func_ptr = NULL;

inline void firehose_packet(const char *pciaddr, char *data, int length);

/* Intel 82599 "Legacy" receive descriptor format.
 * See Intel 82599 data sheet section 7.1.5.
 * http://www.intel.com/content/dam/www/public/us/en/documents/datasheets/82599-10-gbe-controller-datasheet.pdf
 */
struct firehose_rdesc {
    uint64_t address;
    uint16_t length;
    uint16_t cksum;
    uint8_t status;
    uint8_t errors;
    uint16_t vlan;
} __attribute__((packed));

// We will use this code from Global Symbols table (originally it's defined in netmap collector.cpp)
bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet);

void firehose_packet(const char *pciaddr, char *data, int length) {
    simple_packet packet;

    if (!parse_raw_packet_to_simple_packet((u_char*)data, length, packet)) {
        total_unparsed_packets++;

        return;
    }

    snabbswitch_process_func_ptr(packet);
}

#ifdef __cplusplus
extern "C" {
#endif

int firehose_callback_v1(const char *pciaddr, char **packets, struct firehose_rdesc *rxring, int ring_size, int index);

#ifdef __cplusplus
}
#endif

int firehose_callback_v1(const char *pciaddr, char **packets, struct firehose_rdesc *rxring, int ring_size, int index) {
    while (rxring[index].status & 1) {
        int next_index = (index + 1) & (ring_size-1);
        __builtin_prefetch(packets[next_index]);
        firehose_packet(pciaddr, packets[index], rxring[index].length);
        rxring[index].status = 0; /* reset descriptor for reuse */
        index = next_index;
    }

    return index;
}

void start_snabbswitch_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "SnabbSwitch plugin started";
    snabbswitch_process_func_ptr = func_ptr;

    std::string interfaces_list = "";

    if (configuration_map.count("interfaces_snabbswitch") != 0) {
        interfaces_list = configuration_map["interfaces_snabbswitch"];
    }

    std::vector<std::string> interfaces_for_capture;
    boost::split(interfaces_for_capture, interfaces_list, boost::is_any_of(","), boost::token_compress_on);

    if (interfaces_for_capture.size()  == 0) {
        logger << log4cpp::Priority::ERROR << "Please specify list of PCI-e addresses for SnabbSwitch capture";
    }

    logger << log4cpp::Priority::INFO << "SnabbSwitch will listen on " << interfaces_for_capture.size() << " interfaces";
  
    boost::thread_group snabbswitch_main_threads;

    for (std::vector<std::string>::iterator interface = interfaces_for_capture.begin(); 
        interface != interfaces_for_capture.end(); ++interface) {
     
        // We could specify multiple NIC's for single thread with multiple --input
        const char* cli_arguments[5];

        cli_arguments[0] = "snabb"; // emulate call of standard application
        cli_arguments[1] = "firehose";
        cli_arguments[2] = "--input";
        cli_arguments[3] = interface->c_str();
        cli_arguments[4] ="weird_data";

        int cli_number_of_arguments = sizeof(cli_arguments) / sizeof(char*);
    
        logger << log4cpp::Priority::INFO << "We are starting SnabbSwitch instance for PCIe interface " << *interface; 
        snabbswitch_main_threads.add_thread( new boost::thread(start_snabb_switch, cli_number_of_arguments, cli_arguments) );
        // We should sleep here because init code of SnabbSwitch is not thread safe
        sleep(10); 
    }

    snabbswitch_main_threads.join_all();
}

