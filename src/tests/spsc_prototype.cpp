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

#include "../libpatricia/patricia.h"
#include "../fastnetmon_types.h"
#include "../fast_library.h"
#include "../netflow_plugin/netflow_collector.h"
#include "../sflow_plugin/sflow_collector.h"
#include "../pcap_plugin/pcap_collector.h"

#ifdef PF_RING
#include "../pfring_plugin/pfring_collector.h"
#endif

#include "../netmap_plugin/netmap_collector.h"

#include <boost/thread/thread.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/atomic.hpp>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include <boost/thread/thread.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/atomic.hpp>
#include <unordered_map>

#include <fstream>

using namespace std;

typedef simple_packet* simple_packet_shared_ptr_t;
typedef boost::lockfree::spsc_queue< simple_packet_shared_ptr_t,  boost::lockfree::capacity<1048576> > my_spsc_queue_t;

uint64_t total_unparsed_packets = 0;

my_spsc_queue_t my_spsc_queue[8];

std::string log_file_path = "/tmp/fastnetmon_plugin_tester.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();

#include <boost/pool/pool_alloc.hpp>

extern boost::pool_allocator<simple_packet> alloc[8];

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

uint64_t received_packets = 0;

void process_packet(simple_packet& current_packet) {
    //__sync_fetch_and_add(&received_packets, 1);
    //std::cout << print_simple_packet(current_packet);
}


std::unordered_map<uint32_t, int> map_counter;
void traffic_processor() {
    simple_packet_shared_ptr_t packet;
    //map_counter.reserve(16000000);

    while (1) {
        for (int i = 0; i < 8; i ++) {
            // while (!my_spsc_queue[thread_number].push(packet));

            while (my_spsc_queue[i].pop(packet)) {
                //std::cout << print_simple_packet(packet);
                //map_counter[packet.src_ip]++;
                __sync_fetch_and_add(&received_packets, 1);
                delete packet;
                //alloc[i].deallocate(packet, 1);
            }
        }
    }
}

void speed_printer() {
    while (true) {
        uint64_t packets_before = received_packets;
        
        boost::this_thread::sleep(boost::posix_time::seconds(1));       
        
        uint64_t packets_after = received_packets;
        uint64_t pps = packets_after - packets_before;
 
        printf("We process: %llu pps\n", pps);
    }
}

int main(int argc, char* argv[]) {
    boost::thread speed_printer_thread( speed_printer );
    boost::thread traffic_processor_thread(traffic_processor); 

    init_logging();

    // Required by Netmap and PF_RING plugins
    // We use fake interface name here because netmap could make server unreachable :)
    configuration_map["interfaces"] = "eth5";
    start_netmap_collection(process_packet);
    
    traffic_processor_thread.join();
    speed_printer_thread.join();
}

