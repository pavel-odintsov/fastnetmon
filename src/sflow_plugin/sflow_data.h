#ifndef SFLOW_DATA_H
#define SFLOW_DATA_H

#include "sflow.h"
#include <setjmp.h>

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

#endif // SFLOW_DATA_H
