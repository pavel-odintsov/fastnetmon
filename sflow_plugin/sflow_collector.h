#ifndef _SFLOW_PLUGIN_H
#define _SFLOW_PLUGIN_H

#include "../fastnetmon_types.h"

typedef void (*process_packet_pointer)(simple_packet&);
void start_sflow_collection(process_packet_pointer func_ptr); 

#endif
