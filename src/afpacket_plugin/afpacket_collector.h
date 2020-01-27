#ifndef AFPACKET_PLUGIN_H
#define AFPACKET_PLUGIN_H

#include "../fastnetmon_types.h"

void start_afpacket_collection(process_packet_pointer func_ptr);
void start_af_packet_capture_for_interface(std::string capture_interface, int fanout_group_id, unsigned int num_cpus);

#endif
