#include <sys/types.h>
#include <inttypes.h>

// sflowtool-3.32
#include "sflow.h"

// UDP server
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

typedef struct _SFSample {
  SFLAddress sourceIP;
  SFLAddress agent_addr;
  uint32_t agentSubId;

  /* the raw pdu */
  uint8_t *rawSample;
  uint32_t rawSampleLen;
  uint8_t *endp;
  time_t pcapTimestamp;

  /* decode cursor */
  uint32_t *datap;

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
  uint8_t *header;
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
  uint32_t *dst_as_path;
  /* note: version 4 dst as path segments just get printed, not stored here, however
   * the dst_peer and dst_as are filled in, since those are used for netflow encoding
   */
  uint32_t dst_peer_as;
  uint32_t dst_as;
  
  uint32_t communities_len;
  uint32_t *communities;
  uint32_t localpref;

  /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
  uint32_t src_user_charset;
  uint32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  uint32_t dst_user_charset;
  uint32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  uint32_t url_direction;
  uint32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  uint32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

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
# define SFABORT(s, r) abort()
# undef ERROUT
# define ERROUT stdout
#else
# define SFABORT(s, r) longjmp((s)->env, (r))
#endif

#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

} SFSample;

void read_sflow_datagram(SFSample* sample);
uint32_t getData32(SFSample *sample);

int main() {
    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port = htons(6343);
    bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    for (;;) {
        struct sockaddr_in cliaddr;
        socklen_t address_len = sizeof(cliaddr);
    
        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr *)&cliaddr, &address_len); 
   
        if (received_bytes > 0) {
            printf("We receive %d\n", received_bytes);

            SFSample sample;
            memset(&sample, 0, sizeof(sample));
            sample.rawSample = (uint8_t *)udp_buffer;
            sample.rawSampleLen = received_bytes;

            if (address_len == sizeof(struct sockaddr_in)) {
                struct sockaddr_in *peer4 = (struct sockaddr_in *)&peer;
                sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
                memcpy(&sample.sourceIP.address.ip_v4, &peer4->sin_addr, 4);

                read_sflow_datagram(&sample);
            } else {
                // We do not support an IPv6 
            }
        } else {
            printf("Data receive failed\n");
        }
    }
}

uint32_t getData32_nobswap(SFSample *sample) {
    uint32_t ans = *(sample->datap)++;
    // make sure we didn't run off the end of the datagram.  Thanks to
    // Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before.
    if((uint8_t *)sample->datap > sample->endp) {
        // SFABORT(sample, SF_ABORT_EOS);
        // Error!!!
        printf("We tried to read data in bad place! Fault!\n");
        return 0;
    }
  
    return ans; 
}

void skipBytes(SFSample *sample, uint32_t skip) {
  int quads = (skip + 3) / 4;
  sample->datap += quads;
  if(skip > sample->rawSampleLen || (uint8_t *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
}

uint32_t getAddress(SFSample *sample, SFLAddress *address) {
  address->type = getData32(sample);
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.addr = getData32_nobswap(sample);
  else {
    memcpy(&address->address.ip_v6.addr, sample->datap, 16);
    skipBytes(sample, 16);
  }
  return address->type;
}

uint32_t getData32(SFSample *sample) {
    return ntohl(getData32_nobswap(sample));
}


void read_sflow_datagram(SFSample* sample) {
    sample->datap = (uint32_t *)sample->rawSample;
    sample->endp = (uint8_t *)sample->rawSample + sample->rawSampleLen;

    sample->datagramVersion = getData32(sample);
    printf("sFLOW version %d\n", sample->datagramVersion);

    if (sample->datagramVersion != 5) {
        printf("We do not support old sFLOW protocols. Please change version to sFLOW 5");
        return;
    }
   
    /* get the agent address */
    getAddress(sample, &sample->agent_addr); 

    /* version 5 has an agent sub-id as well */
    if(sample->datagramVersion >= 5) {
        sample->agentSubId = getData32(sample);
        //sf_log(sample,"agentSubId %u\n", sample->agentSubId);
    }

    sample->sequenceNo = getData32(sample);  /* this is the packet sequence number */
    sample->sysUpTime = getData32(sample);
    uint32_t samplesInPacket = getData32(sample);

    printf("We have %d samples in packet\n", samplesInPacket); 
}
