#ifndef _NETFLOW_PLUGIN_H
#define _NETFLOW_PLUGIN_H

/* netflow plugin header */

#include "../fastnetmon_types.h"

// For testing
void process_netflow_packet(u_int len, u_int8_t *packet);
void start_netflow_collection(process_packet_pointer func_ptr);

#endif
