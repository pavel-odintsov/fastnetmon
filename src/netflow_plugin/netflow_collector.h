#ifndef NETFLOW_PLUGIN_H
#define NETFLOW_PLUGIN_H

/* netflow plugin header */

#include "../fastnetmon_types.h"

// For testing
void process_netflow_packet(u_int8_t* packet, u_int len, std::string client_addres_in_string_format);
void start_netflow_collection(process_packet_pointer func_ptr);

#endif
