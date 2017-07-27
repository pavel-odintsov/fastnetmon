#pragma once

#include <stdint.h>
#include <sys/types.h>
#include "fastnetmon_types.h"

bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet, bool netmap_read_packet_length_from_ip_header);
