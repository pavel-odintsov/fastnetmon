#include "pfring.h"
#include <iostream>

/* How to compile me:
    g++ pfring_parser_zc_issue.c -I/opt/pf_ring/include -L/opt/pf_ring/lib/ -lpfring -lnuma
*/

void parse_packet_pf_ring(const struct pfring_pkthdr* h, const u_char* p, const u_char* user_bytes) {
    memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(h->extended_hdr.parsed_pkt));
    pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 1, 0);

    char buffer[512];
    pfring_print_parsed_pkt(buffer, 512, p, h);
    std::cout << buffer;
}

int main() {
    char* dev = "zc:eth3";
    // We could pool device in multiple threads
    unsigned int num_threads = 1;

    bool promisc = true;
    /* This flag manages packet parser for extended_hdr */
    bool use_extended_pkt_header = true;
    bool enable_hw_timestamp = false;
    bool dont_strip_timestamps = false;

    u_int32_t flags = 0;
    if (num_threads > 1) flags |= PF_RING_REENTRANT;
    if (use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;
    if (promisc) flags |= PF_RING_PROMISC;
    if (enable_hw_timestamp) flags |= PF_RING_HW_TIMESTAMP;
    if (!dont_strip_timestamps) flags |= PF_RING_STRIP_HW_TIMESTAMP;

    // if (!we_use_pf_ring_in_kernel_parser) {
    //    flags != PF_RING_DO_NOT_PARSE;
    //}

    // flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers
    // */

    // use default value from pfcount.c
    unsigned int snaplen = 128;

    pfring* pf_ring_descr = pfring_open(dev, snaplen, flags);

    if (pf_ring_descr == NULL) {
        std::cout
        << "pfring_open error: " << strerror(errno)
        << " (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to: " << dev
        << ")";
        return false;
    }


    u_int32_t version;
    // Set spplication name in /proc
    int pfring_set_application_name_result =
    pfring_set_application_name(pf_ring_descr, (char*)"fastnetmon");

    if (pfring_set_application_name_result != 0) {
        std::cout << "Can't set programm name for PF_RING: pfring_set_application_name";
    }

    pfring_version(pf_ring_descr, &version);

    int pfring_set_socket_mode_result = pfring_set_socket_mode(pf_ring_descr, recv_only_mode);

    // enable ring
    if (pfring_enable_ring(pf_ring_descr) != 0) {
        std::cout << "Unable to enable ring :-(";
        pfring_close(pf_ring_descr);
        return false;
    }

    u_int8_t wait_for_packet = 1;
    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);
}
