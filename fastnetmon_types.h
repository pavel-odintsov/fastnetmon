#ifndef _FASTNETMON_TYPES_H
#define _FASTNETMON_TYPES_H

// simplified packet struct for lightweight save into memory
struct simple_packet {
    uint32_t     src_ip;
    uint32_t     dst_ip;
    uint16_t     source_port;
    uint16_t     destination_port;
    unsigned     int protocol;
    unsigned     int length;
    uint8_t      flags; /* tcp flags */
    struct       timeval ts;
};

#endif 
