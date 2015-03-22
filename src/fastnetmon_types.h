#ifndef _FASTNETMON_TYPES_H
#define _FASTNETMON_TYPES_H

#include <utility>    // std::pair
#include <stdint.h>   // uint32_t
#include <sys/time.h> // struct timeval

// simplified packet struct for lightweight save into memory
class simple_packet {
public:
    simple_packet() : sample_ratio(1), src_ip(0), dst_ip(0), source_port(0), destination_port(0), protocol(0), length(0), flags(0), number_of_packets(1) { 
        ts.tv_usec = 0;
        ts.tv_sec = 0;
    }
    uint32_t     sample_ratio;
    uint32_t     src_ip;
    uint32_t     dst_ip;
    uint16_t     source_port;
    uint16_t     destination_port;
    unsigned     int protocol;
    unsigned     int length;
    unsigned     int number_of_packets; /* for netflow */
    uint8_t      flags; /* tcp flags */
    struct       timeval ts;
};

typedef std::pair<uint32_t, uint32_t> subnet;
typedef void (*process_packet_pointer)(simple_packet&);

#endif
