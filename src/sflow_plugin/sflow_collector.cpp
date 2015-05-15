#include <iostream>
#include <sys/types.h>
#include <inttypes.h>

#include "sflow_collector.h"

// sflowtool-3.32
#include "sflow.h"

#include "../fast_library.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>

// UDP server
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <stdlib.h>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

// Get logger from main programm
extern log4cpp::Category& logger;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

/* same for tcp */
struct mytcphdr {
    uint16_t th_sport; /* source port */
    uint16_t th_dport; /* destination port */
    uint32_t th_seq; /* sequence number */
    uint32_t th_ack; /* acknowledgement number */
    uint8_t th_off_and_unused;
    uint8_t th_flags;
    uint16_t th_win; /* window */
    uint16_t th_sum; /* checksum */
    uint16_t th_urp; /* urgent pointer */
};

/* and UDP */
struct myudphdr {
    uint16_t uh_sport; /* source port */
    uint16_t uh_dport; /* destination port */
    uint16_t uh_ulen; /* udp length */
    uint16_t uh_sum; /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
    uint8_t type; /* message type */
    uint8_t code; /* type sub-code */
    /* ignore the rest */
};


/* define my own IP header struct - to ease portability */
struct myiphdr {
    uint8_t version_and_headerLen;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

typedef struct _SFSample {
    SFLAddress sourceIP;
    SFLAddress agent_addr;
    uint32_t agentSubId;

    /* the raw pdu */
    uint8_t* rawSample;
    uint32_t rawSampleLen;
    uint8_t* endp;
    time_t pcapTimestamp;

    /* decode cursor */
    uint32_t* datap;

    uint32_t datagramVersion;
    uint32_t sampleType;
    uint32_t elementType;
    uint32_t ds_class;
    uint32_t ds_index;

    /* generic interface counter sample */
    SFLIf_counters ifCounters;

    /* sample stream info */
    uint32_t sysUpTime;
    uint32_t sequenceNo;
    uint32_t sampledPacketSize;
    uint32_t samplesGenerated;
    uint32_t meanSkipCount;
    uint32_t samplePool;
    uint32_t dropEvents;

    /* the sampled header */
    uint32_t packet_data_tag;
    uint32_t headerProtocol;
    uint8_t* header;
    int headerLen;
    uint32_t stripped;

    /* header decode */
    int gotIPV4;
    int gotIPV4Struct;
    int offsetToIPV4;
    int gotIPV6;
    int gotIPV6Struct;
    int offsetToIPV6;
    int offsetToPayload;
    SFLAddress ipsrc;
    SFLAddress ipdst;
    uint32_t dcd_ipProtocol;
    uint32_t dcd_ipTos;
    uint32_t dcd_ipTTL;
    uint32_t dcd_sport;
    uint32_t dcd_dport;
    uint32_t dcd_tcpFlags;
    uint32_t ip_fragmentOffset;
    uint32_t udp_pduLen;

    /* ports */
    uint32_t inputPortFormat;
    uint32_t outputPortFormat;
    uint32_t inputPort;
    uint32_t outputPort;

    /* ethernet */
    uint32_t eth_type;
    uint32_t eth_len;
    uint8_t eth_src[8];
    uint8_t eth_dst[8];

    /* vlan */
    uint32_t in_vlan;
    uint32_t in_priority;
    uint32_t internalPriority;
    uint32_t out_vlan;
    uint32_t out_priority;
    int vlanFilterReject;

    /* extended data fields */
    uint32_t num_extended;
    uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096
#define SASAMPLE_EXTENDED_DATA_NAT_PORT 8192

    /* IP forwarding info */
    SFLAddress nextHop;
    uint32_t srcMask;
    uint32_t dstMask;

    /* BGP info */
    SFLAddress bgp_nextHop;
    uint32_t my_as;
    uint32_t src_as;
    uint32_t src_peer_as;
    uint32_t dst_as_path_len;
    uint32_t* dst_as_path;
    /* note: version 4 dst as path segments just get printed, not stored here, however
    * the dst_peer and dst_as are filled in, since those are used for netflow encoding
    */
    uint32_t dst_peer_as;
    uint32_t dst_as;

    uint32_t communities_len;
    uint32_t* communities;
    uint32_t localpref;

/* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
    uint32_t src_user_charset;
    uint32_t src_user_len;
    char src_user[SA_MAX_EXTENDED_USER_LEN + 1];
    uint32_t dst_user_charset;
    uint32_t dst_user_len;
    char dst_user[SA_MAX_EXTENDED_USER_LEN + 1];

/* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
    uint32_t url_direction;
    uint32_t url_len;
    char url[SA_MAX_EXTENDED_URL_LEN + 1];
    uint32_t host_len;
    char host[SA_MAX_EXTENDED_HOST_LEN + 1];

    /* mpls */
    SFLAddress mpls_nextHop;

    /* nat */
    SFLAddress nat_src;
    SFLAddress nat_dst;

    /* counter blocks */
    uint32_t statsSamplingInterval;
    uint32_t counterBlockVersion;

    /* exception handler context */
    jmp_buf env;

#define ERROUT stderr

#ifdef DEBUG
#define SFABORT(s, r) abort()
#undef ERROUT
#define ERROUT stdout
#else
#define SFABORT(s, r) longjmp((s)->env, (r))
#endif

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3
} SFSample;

void read_sflow_datagram(SFSample* sample);
uint32_t getData32(SFSample* sample);
void skipTLVRecord(SFSample* sample, uint32_t tag, uint32_t len);
void readFlowSample(SFSample* sample, int expanded);
void readFlowSample_header(SFSample* sample);
void decodeIPV4(SFSample* sample);
void print_simple_packet(struct simple_packet& packet);

process_packet_pointer process_func_ptr = NULL;

unsigned int sflow_port = 6343;
void start_sflow_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "sflow plugin started";
    std::string interface_for_binding = "0.0.0.0";

    if (configuration_map.count("sflow_port") != 0) {
        sflow_port = convert_string_to_integer(configuration_map["sflow_port"]);
    }

    if (configuration_map.count("sflow_host") != 0) {
        interface_for_binding = configuration_map["sflow_host"];
    }

    logger << log4cpp::Priority::INFO << "sflow plugin will listen on " << interface_for_binding
           << ":" << sflow_port << " udp port";

    process_func_ptr = func_ptr;

    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;

    if (interface_for_binding == "0.0.0.0") {
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        servaddr.sin_addr.s_addr = inet_addr(interface_for_binding.c_str());
    }

    servaddr.sin_port = htons(sflow_port);
    int bind_result = bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    if (bind_result) {
        logger << log4cpp::Priority::ERROR << "Can't listen port: " << sflow_port;
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    for (;;) {
        struct sockaddr_in cliaddr;
        socklen_t address_len = sizeof(cliaddr);

        int received_bytes =
        recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr*)&cliaddr, &address_len);

        if (received_bytes > 0) {
            // printf("We receive %d\n", received_bytes);

            SFSample sample;
            memset(&sample, 0, sizeof(sample));
            sample.rawSample = (uint8_t*)udp_buffer;
            sample.rawSampleLen = received_bytes;

            if (address_len == sizeof(struct sockaddr_in)) {
                struct sockaddr_in* peer4 = (struct sockaddr_in*)&peer;
                sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
                memcpy(&sample.sourceIP.address.ip_v4, &peer4->sin_addr, 4);

                read_sflow_datagram(&sample);
            } else {
                // We do not support an IPv6
            }
        } else {
            logger << log4cpp::Priority::ERROR << "Data receive failed";
        }
    }
}

uint32_t getData32_nobswap(SFSample* sample) {
    uint32_t ans = *(sample->datap)++;
    // make sure we didn't run off the end of the datagram.  Thanks to
    // Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before.
    if ((uint8_t*)sample->datap > sample->endp) {
        // SFABORT(sample, SF_ABORT_EOS);
        // Error!!!
        logger << log4cpp::Priority::ERROR << "We tried to read data in bad place! Fault!";
        return 0;
    }

    return ans;
}

void skipBytes(SFSample* sample, uint32_t skip) {
    int quads = (skip + 3) / 4;
    sample->datap += quads;
    if (skip > sample->rawSampleLen || (uint8_t*)sample->datap > sample->endp) {
        // SFABORT(sample, SF_ABORT_EOS);
        logger << log4cpp::Priority::ERROR << "Internal error!!!";
        exit(0);
    }
}

uint32_t getAddress(SFSample* sample, SFLAddress* address) {
    address->type = getData32(sample);
    if (address->type == SFLADDRESSTYPE_IP_V4) {
        address->address.ip_v4.addr = getData32_nobswap(sample);
    } else {
        memcpy(&address->address.ip_v6.addr, sample->datap, 16);
        skipBytes(sample, 16);
    }

    return address->type;
}

uint32_t getData32(SFSample* sample) {
    return ntohl(getData32_nobswap(sample));
}


void read_sflow_datagram(SFSample* sample) {
    sample->datap = (uint32_t*)sample->rawSample;
    sample->endp = (uint8_t*)sample->rawSample + sample->rawSampleLen;

    sample->datagramVersion = getData32(sample);
    // printf("sFLOW version %d\n", sample->datagramVersion);

    if (sample->datagramVersion != 5) {
        logger << log4cpp::Priority::ERROR
               << "We do not support old sFLOW protocols. Please change version to sFLOW 5";
        return;
    }

    /* get the agent address */
    getAddress(sample, &sample->agent_addr);

    /* version 5 has an agent sub-id as well */
    if (sample->datagramVersion >= 5) {
        sample->agentSubId = getData32(sample);
        // sf_log(sample,"agentSubId %u\n", sample->agentSubId);
    }

    sample->sequenceNo = getData32(sample); /* this is the packet sequence number */
    sample->sysUpTime = getData32(sample);
    uint32_t samplesInPacket = getData32(sample);

    // printf("We have %d samples in packet\n", samplesInPacket);

    uint32_t samp = 0;
    for (; samp < samplesInPacket; samp++) {
        if ((uint8_t*)sample->datap >= sample->endp) {
            logger
            << log4cpp::Priority::INFO
            << "We try to read data outside packet! It's very dangerous, we stop all operations";
            exit(0);
            return;
        }

        // printf("Sample #%d\n", samp);

        /* just read the tag, then call the approriate decode fn */
        sample->sampleType = getData32(sample);
        if (sample->datagramVersion >= 5) {
            switch (sample->sampleType) {
            case SFLFLOW_SAMPLE:
                // printf("SFLFLOW_SAMPLE\n");
                // skipBytes(sample, getData32(sample));
                readFlowSample(sample, 0);
                break;
            case SFLCOUNTERS_SAMPLE:
                // We do not need counters for our task, skip it
                skipBytes(sample, getData32(sample));
                // printf("SFLCOUNTERS_SAMPLE\n");
                break;
            case SFLFLOW_SAMPLE_EXPANDED:
                // printf("SFLFLOW_SAMPLE_EXPANDED\n");
                // skipBytes(sample, getData32(sample));
                readFlowSample(sample, 1);
                break;
            case SFLCOUNTERS_SAMPLE_EXPANDED:
                // We do not need counters for our task, skip it
                skipBytes(sample, getData32(sample));
                // printf("SFLCOUNTERS_SAMPLE_EXPANDED\n");
                break;
            default:
                // printf("skip TLV record\n");
                skipTLVRecord(sample, sample->sampleType, getData32(sample));
                break;
            }
        }
    }
}

void skipTLVRecord(SFSample* sample, uint32_t tag, uint32_t len) {
    skipBytes(sample, len);
}


void readFlowSample(SFSample* sample, int expanded) {
    uint32_t num_elements, sampleLength;
    uint8_t* sampleStart;

    sampleLength = getData32(sample);
    sampleStart = (uint8_t*)sample->datap;
    sample->samplesGenerated = getData32(sample);

    if (expanded) {
        sample->ds_class = getData32(sample);
        sample->ds_index = getData32(sample);
    } else {
        uint32_t samplerId = getData32(sample);
        sample->ds_class = samplerId >> 24;
        sample->ds_index = samplerId & 0x00ffffff;
    }

    sample->meanSkipCount = getData32(sample);
    // printf("Sample ratio: %d\n", sample->meanSkipCount);
    sample->samplePool = getData32(sample);
    sample->dropEvents = getData32(sample);

    if (expanded) {
        sample->inputPortFormat = getData32(sample);
        sample->inputPort = getData32(sample);
        sample->outputPortFormat = getData32(sample);
        sample->outputPort = getData32(sample);
    } else {
        uint32_t inp, outp;
        inp = getData32(sample);
        outp = getData32(sample);
        sample->inputPortFormat = inp >> 30;
        sample->outputPortFormat = outp >> 30;
        sample->inputPort = inp & 0x3fffffff;
        sample->outputPort = outp & 0x3fffffff;
    }

    num_elements = getData32(sample);
    uint32_t el;
    for (el = 0; el < num_elements; el++) {
        uint32_t tag, length;
        uint8_t* start;
        char buf[51];
        tag = sample->elementType = getData32(sample);

        length = getData32(sample);
        start = (uint8_t*)sample->datap;

        // tag analyze
        if (tag == SFLFLOW_HEADER) {
            // process data
            readFlowSample_header(sample);
        } else {
            skipTLVRecord(sample, tag, length);
        }
    }
}

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

void decodeLinkLayer(SFSample* sample) {
    uint8_t* start = (uint8_t*)sample->header;
    uint8_t* end = start + sample->headerLen;
    uint8_t* ptr = start;
    uint16_t type_len;

    /* assume not found */
    sample->gotIPV4 = 0;
    sample->gotIPV6 = 0;

    if (sample->headerLen < NFT_ETHHDR_SIZ) {
        /* not enough for an Ethernet header */
        return;
    }

    // sf_log(sample,"dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4],
    // ptr[5]);
    memcpy(sample->eth_dst, ptr, 6);
    ptr += 6;

    // sf_log(sample,"srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4],
    // ptr[5]);
    memcpy(sample->eth_src, ptr, 6);
    ptr += 6;
    type_len = (ptr[0] << 8) + ptr[1];
    ptr += 2;

    if (type_len == 0x8100) {
        /* VLAN  - next two bytes */
        uint32_t vlanData = (ptr[0] << 8) + ptr[1];
        uint32_t vlan = vlanData & 0x0fff;
        uint32_t priority = vlanData >> 13;
        ptr += 2;

        /*  _____________________________________ */
        /* |   pri  | c |         vlan-id        | */
        /*  ------------------------------------- */
        /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
        // sf_log(sample,"decodedVLAN %u\n", vlan);
        // sf_log(sample,"decodedPriority %u\n", priority);
        sample->in_vlan = vlan;
        /* now get the type_len again (next two bytes) */
        type_len = (ptr[0] << 8) + ptr[1];
        ptr += 2;
    }

    /* assume type_len is an ethernet-type now */
    sample->eth_type = type_len;

    if (type_len == 0x0800) {
        /* IPV4 */
        if ((end - ptr) < sizeof(struct myiphdr)) {
            return;
        }

        /* look at first byte of header.... */
        /*  ___________________________ */
        /* |   version   |    hdrlen   | */
        /*  --------------------------- */

        if ((*ptr >> 4) != 4) return; /* not version 4 */
        if ((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */

        /* survived all the tests - store the offset to the start of the ip header */
        sample->gotIPV4 = 1;
        sample->offsetToIPV4 = (ptr - start);
    }

    // printf("vlan: %d\n",sample->in_vlan);
}

void readFlowSample_header(SFSample* sample) {
    sample->headerProtocol = getData32(sample);
    sample->sampledPacketSize = getData32(sample);

    if (sample->datagramVersion > 4) {
        /* stripped count introduced in sFlow version 5 */
        sample->stripped = getData32(sample);
    }

    sample->headerLen = getData32(sample);
    sample->header = (uint8_t*)sample->datap; /* just point at the header */
    skipBytes(sample, sample->headerLen);

    if (sample->headerProtocol == SFLHEADER_ETHERNET_ISO8023) {
        decodeLinkLayer(sample);

        // if we found IPv4
        decodeIPV4(sample);
    } else {
        logger << log4cpp::Priority::ERROR << "Not supported protocol: " << sample->headerProtocol;
        return;
    }
}

char* IP_to_a(uint32_t ipaddr, char* buf) {
    uint8_t* ip = (uint8_t*)&ipaddr;
    /* should really be: snprintf(buf, buflen,...) but snprintf() is not always available */
    sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

char* printAddress(SFLAddress* address, char* buf) {
    switch (address->type) {
    case SFLADDRESSTYPE_IP_V4:
        IP_to_a(address->address.ip_v4.addr, buf);
        break;
    case SFLADDRESSTYPE_IP_V6: {
        uint8_t* b = address->address.ip_v6.addr;
        /* should really be: snprintf(buf, buflen,...) but snprintf() is not always available */
        sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
                b[13], b[14], b[15]);
    } break;
    default:
        sprintf(buf, "-");
    }

    return buf;
}

void decodeIPLayer4(SFSample* sample, uint8_t* ptr) {
    uint8_t* end = sample->header + sample->headerLen;

    if (ptr > (end - 8)) {
        /* not enough header bytes left */
        return;
    }

    simple_packet current_packet;
    current_packet.src_ip = sample->ipsrc.address.ip_v4.addr;
    current_packet.dst_ip = sample->ipdst.address.ip_v4.addr;

    // Because sFLOW data is near real time we could get current time
    gettimeofday(&current_packet.ts, NULL);

    current_packet.flags = 0;
    current_packet.number_of_packets = 1;
    current_packet.length = sample->sampledPacketSize;
    current_packet.sample_ratio = sample->meanSkipCount;

    switch (sample->dcd_ipProtocol) {
    case 1: {
        // ICMP
        current_packet.protocol = IPPROTO_ICMP;
        struct myicmphdr icmp;
        memcpy(&icmp, ptr, sizeof(icmp));
        // printf("ICMPType %u\n", icmp.type);
        // printf("ICMPCode %u\n", icmp.code);
        sample->dcd_sport = icmp.type;
        sample->dcd_dport = icmp.code;
        sample->offsetToPayload = ptr + sizeof(icmp) - sample->header;
    } break;
    case 6: {
        // TCP
        current_packet.protocol = IPPROTO_TCP;
        struct mytcphdr tcp;
        int headerBytes;
        memcpy(&tcp, ptr, sizeof(tcp));
        sample->dcd_sport = ntohs(tcp.th_sport);
        sample->dcd_dport = ntohs(tcp.th_dport);

        current_packet.source_port = sample->dcd_sport;
        current_packet.destination_port = sample->dcd_dport;
        // TODO: флаги могут быть бажные!!! наш парсер флагов расчитан на формат, используемый в
        // PF_RING
        current_packet.flags = tcp.th_flags;

        sample->dcd_tcpFlags = tcp.th_flags;
        // printf("TCPSrcPort %u\n", sample->dcd_sport);
        // printf("TCPDstPort %u\n",sample->dcd_dport);
        // printf("TCPFlags %u\n", sample->dcd_tcpFlags);
        headerBytes = (tcp.th_off_and_unused >> 4) * 4;
        ptr += headerBytes;
        sample->offsetToPayload = ptr - sample->header;
    } break;
    case 17: {
        // UDP
        current_packet.protocol = IPPROTO_UDP;
        struct myudphdr udp;
        memcpy(&udp, ptr, sizeof(udp));
        sample->dcd_sport = ntohs(udp.uh_sport);
        sample->dcd_dport = ntohs(udp.uh_dport);

        current_packet.source_port = sample->dcd_sport;
        current_packet.destination_port = sample->dcd_dport;

        sample->udp_pduLen = ntohs(udp.uh_ulen);
        // printf("UDPSrcPort %u\n", sample->dcd_sport);
        // printf("UDPDstPort %u\n", sample->dcd_dport);
        // printf("UDPBytes %u\n", sample->udp_pduLen);
        sample->offsetToPayload = ptr + sizeof(udp) - sample->header;
    } break;
    default: /* some other protcol */
        sample->offsetToPayload = ptr - sample->header;
        break;
    }

    // Call external handler function
    process_func_ptr(current_packet);
}


void decodeIPV4(SFSample* sample) {
    if (sample->gotIPV4) {
        char buf[51];
        uint8_t* ptr = sample->header + sample->offsetToIPV4;
        /* Create a local copy of the IP header (cannot overlay structure in case it is not
           quad-aligned...some
            platforms would core-dump if we tried that).  It's OK coz this probably performs just as
           well anyway. */
        struct myiphdr ip;
        memcpy(&ip, ptr, sizeof(ip));
        /* Value copy all ip elements into sample */
        sample->ipsrc.type = SFLADDRESSTYPE_IP_V4;
        sample->ipsrc.address.ip_v4.addr = ip.saddr;
        sample->ipdst.type = SFLADDRESSTYPE_IP_V4;
        sample->ipdst.address.ip_v4.addr = ip.daddr;
        sample->dcd_ipProtocol = ip.protocol;
        sample->dcd_ipTos = ip.tos;
        sample->dcd_ipTTL = ip.ttl;

        // printf("ip.tot_len %d\n", ntohs(ip.tot_len));
        /* Log out the decoded IP fields */
        // printf("srcIP %s\n", printAddress(&sample->ipsrc, buf));
        // printf("dstIP %s\n", printAddress(&sample->ipdst, buf));
        // printf("IPProtocol %u\n", sample->dcd_ipProtocol);
        // printf("IPTOS %u\n", sample->dcd_ipTos);
        // printf("IPTTL %u\n", sample->dcd_ipTTL);
        /* check for fragments */
        sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
        if (sample->ip_fragmentOffset > 0) {
            // printf("IPFragmentOffset %u\n", sample->ip_fragmentOffset);
        } else {
            /* advance the pointer to the next protocol layer */
            /* ip headerLen is expressed as a number of quads */
            ptr += (ip.version_and_headerLen & 0x0f) * 4;
            decodeIPLayer4(sample, ptr);
        }
    }
}
