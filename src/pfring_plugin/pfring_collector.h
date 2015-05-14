#ifndef PFRING_PLUGIN_H
#define PFRING_PLUGIN_H

#include "../fastnetmon_types.h"

// This function should be implemented in plugin
void start_pfring_collection(process_packet_pointer func_ptr);
void stop_pfring_collection();
std::string get_pf_ring_stats();
#endif
