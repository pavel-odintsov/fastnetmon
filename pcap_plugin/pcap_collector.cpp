#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

extern log4cpp::Category& logger;

#include "pcap_collector.h"

// This variable name should be uniq for every plugin!
process_packet_pointer pcap_process_func_ptr = NULL;

void start_pcap_collection(process_packet_pointer func_ptr) {
    logger<< log4cpp::Priority::INFO<<"pcap plugin started";
}
