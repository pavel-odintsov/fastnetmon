#ifndef SFLOW_PLUGIN_H
#define SFLOW_PLUGIN_H

#include "../fastnetmon_types.h"
#include "sflow_data.h"

void start_sflow_collection(process_packet_pointer func_ptr);

// For tests
void read_sflow_datagram(SFSample* sample);

#endif
