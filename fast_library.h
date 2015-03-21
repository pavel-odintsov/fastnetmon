#ifndef _FAST_LIBRARY_H
#define _FAST_LIBRARY_H

#include <stdint.h>
#include <sys/types.h>
#include <string>

int convert_string_to_integer(std::string line);

uint16_t fast_ntoh(uint16_t value);
uint32_t fast_ntoh(uint32_t value);
uint16_t fast_hton(uint16_t value);
uint32_t fast_hton(uint32_t value);

#endif
