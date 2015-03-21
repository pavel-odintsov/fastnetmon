#include "fast_library.h"
#include <arpa/inet.h>
#include <stdlib.h> // atoi

// convert string to integer
int convert_string_to_integer(std::string line) {
    return atoi(line.c_str());
}

// Type safe versions of ntohl, ntohs with type control
uint16_t fast_ntoh(uint16_t value) {
    return ntohs(value);
}

uint32_t fast_ntoh(uint32_t value) {
    return ntohl(value);
}

// Type safe version of htonl, htons
uint16_t fast_hton(uint16_t value) {
    return htons(value);
}

uint32_t fast_hton(uint32_t value) {
    return htonl(value);
}
