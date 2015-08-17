#ifndef FASTNETMON_PCAP_FORMAT_H
#define FASTNETMON_PCAP_FORMAT_H

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h> 

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
   pcap dump format:
    global header: struct pcap_file_header
    packet header: struct fastnetmon_pcap_pkthdr
*/

/*
 * Compatibility for systems that have a bpf.h that
 * predates the bpf typedefs for 64-bit support.
 */
#if BPF_RELEASE - 0 < 199406
typedef int bpf_int32;
typedef u_int bpf_u_int32;
#endif

// We use copy and paste from pcap.h here because we do not want to link with pcap here
struct fastnetmon_pcap_file_header {
        bpf_u_int32 magic;
        u_short version_major;
        u_short version_minor;
        bpf_int32 thiszone;     /* gmt to local correction */
        bpf_u_int32 sigfigs;    /* accuracy of timestamps */
        bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
};

/*
TODO: move to this code, get rid any bpf* custom types 
struct fastnetmon_pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};
*/


// We can't use pcap_pkthdr from upstream because it uses 16 bytes timeval instead of 8 byte and
// broke everything
struct fastnetmon_pcap_pkthdr {
    uint32_t ts_sec; /* timestamp seconds */
    uint32_t ts_usec; /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
};

typedef void (*pcap_packet_parser_callback)(char* buffer, uint32_t len, uint32_t snaplen);

int pcap_reader(const char* pcap_file_path, pcap_packet_parser_callback  pcap_parse_packet_function_ptr);

bool fill_pcap_header(struct fastnetmon_pcap_file_header* pcap_header, bpf_u_int32 snap_length);

#endif 
