#ifndef PCAP_PLUGIN_H
#define PCAP_PLUGIN_H

#include "../fastnetmon_types.h"
#include <iostream>

void start_pcap_collection(process_packet_pointer func_ptr);
void stop_pcap_collection();
std::string get_pcap_stats();

#endif
