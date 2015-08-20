#include <iostream>
#include <sys/types.h>
#include <inttypes.h>

#include "sflow_collector.h"

// sflowtool-3.32
#include "sflow.h"
// custom sFLOW data structures
#include "sflow_data.h"

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

#ifdef ENABLE_LUA_HOOKS
lua_State* sflow_lua_state = NULL;

bool sflow_lua_hooks_enabled = false;
std::string sflow_lua_hooks_path = "/usr/src/fastnetmon/src/sflow_hooks.lua";
#endif

// sFLOW v4 specification: http://www.sflow.org/rfc3176.txt

std::string plugin_name = "sflow";
std::string plugin_log_prefix = plugin_name + ": ";

// Get logger from main programm
extern log4cpp::Category& logger;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// Enable debug messages in log
bool debug_sflow_parser = false;

uint32_t getData32(SFSample* sample);
bool skipTLVRecord(SFSample* sample, uint32_t tag, uint32_t len);
bool readFlowSample(SFSample* sample, int expanded);
void readFlowSample_header(SFSample* sample);
void decode_ipv4_protocol(SFSample* sample);
void decode_ipv6_protocol(SFSample* sample);
void print_simple_packet(struct simple_packet& packet);

process_packet_pointer sflow_process_func_ptr = NULL;

// #include <sys/prctl.h>

void start_sflow_collector(std::string interface_for_binding, unsigned int sflow_port);

void start_sflow_collection(process_packet_pointer func_ptr) {
    std::string interface_for_binding = "0.0.0.0";
    std::string sflow_ports = "";

    logger << log4cpp::Priority::INFO << plugin_log_prefix << "plugin started";
    // prctl(PR_SET_NAME,"fastnetmon_sflow", 0, 0, 0);

    sflow_process_func_ptr = func_ptr;

    if (configuration_map.count("sflow_port") != 0) {
        sflow_ports = configuration_map["sflow_port"];
    }

    if (configuration_map.count("sflow_host") != 0) {
        interface_for_binding = configuration_map["sflow_host"];
    }

#ifdef ENABLE_LUA_HOOKS
    if (configuration_map.count("sflow_lua_hooks_path") != 0) {
        sflow_lua_hooks_path = configuration_map["sflow_lua_hooks_path"];

        sflow_lua_hooks_enabled = true;
    }
#endif
  
#ifdef ENABLE_LUA_HOOKS
    if (sflow_lua_hooks_enabled) {
        sflow_lua_state = init_lua_jit(sflow_lua_hooks_path);

        if (sflow_lua_state == NULL) {
            sflow_lua_hooks_enabled = false;
        }
    }
#endif

    boost::thread_group sflow_collector_threads;

    std::vector<std::string> ports_for_listen;    
    boost::split(ports_for_listen, sflow_ports, boost::is_any_of(","), boost::token_compress_on);

    logger << log4cpp::Priority::INFO << plugin_log_prefix << "We will listen on " << ports_for_listen.size() << " ports";

    for (std::vector<std::string>::iterator port = ports_for_listen.begin(); port != ports_for_listen.end(); ++port) {
        unsigned int sflow_port = convert_string_to_integer(*port); 

        if (sflow_port == 0) {
            sflow_port = 6343;
        }

        sflow_collector_threads.add_thread( new  boost::thread(start_sflow_collector,
            interface_for_binding,
            sflow_port
        ));
    }

    sflow_collector_threads.join_all();
}

void start_sflow_collector(std::string interface_for_binding, unsigned int sflow_port) {

    logger << log4cpp::Priority::INFO << plugin_log_prefix << "plugin will listen on " << interface_for_binding
           << ":" << sflow_port << " udp port";

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
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "can't listen port: " << sflow_port;
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    /* We should specify timeout there for correct toolkit shutdown */
    /* Because otherwise recvfrom will stay in blocked mode forever */
    struct timeval tv;
    tv.tv_sec  = 5;  /* X Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

    while (true) {
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
                struct sockaddr_in* peer4 = (struct sockaddr_in*)&cliaddr;
                sample.sourceIP.type = SFLADDRESSTYPE_IP_V4;
                memcpy(&sample.sourceIP.address.ip_v4, &peer4->sin_addr, 4);

                read_sflow_datagram(&sample);
            } else {
                // We do not support an IPv6
            }
        } else {
            if (received_bytes == -1) {

                if (errno == EAGAIN) {
                    // We got timeout, it's OK!
                } else {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "data receive failed";
                }
            }
        }

        // Add interruption point for correct application shutdown
        boost::this_thread::interruption_point();
    }
}

uint32_t getData32_nobswap(SFSample* sample) {
    uint32_t ans = *(sample->datap)++;
    // make sure we didn't run off the end of the datagram.  Thanks to
    // Sven Eschenberg for spotting a bug/overrun-vulnerabilty that was here before.
    if ((uint8_t*)sample->datap > sample->endp) {
        // SFABORT(sample, SF_ABORT_EOS);
        // Error!!!
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we tried to read data in bad place! Fault!";
        return 0;
    }

    return ans;
}

bool skipBytes(SFSample* sample, uint32_t skip) {
    int quads = (skip + 3) / 4;
    sample->datap += quads;
    if (skip > sample->rawSampleLen || (uint8_t*)sample->datap > sample->endp) {
        // SFABORT(sample, SF_ABORT_EOS);
        logger << log4cpp::Priority::ERROR << plugin_log_prefix
            << "very dangerous error from skipBytes function! We try to read from restricted memory region";
        
        return false;
    }

    return true;
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

bool readFlowSample_v2v4(SFSample *sample) {
    sample->samplesGenerated = getData32(sample);
    
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;

    sample->meanSkipCount = getData32(sample);
    sample->samplePool = getData32(sample);
    sample->dropEvents = getData32(sample);
    sample->inputPort = getData32(sample);
    sample->outputPort = getData32(sample);

    sample->packet_data_tag = getData32(sample);
    
    switch(sample->packet_data_tag) {

        case INMPACKETTYPE_HEADER:
            readFlowSample_header(sample);

            break;
        case INMPACKETTYPE_IPV4:
            logger << log4cpp::Priority::ERROR << plugin_log_prefix << "hit INMPACKETTYPE_IPV4, very strange";
            return false;

            break;
        case INMPACKETTYPE_IPV6:
            logger << log4cpp::Priority::ERROR << plugin_log_prefix << "hit INMPACKETTYPE_IPV6, very strange";
            return false;

            break;
        default:
            logger << log4cpp::Priority::ERROR << plugin_log_prefix << "unexpected packet_data_tag";
            return false;

            break;
    }

    sample->extended_data_tag = 0; 

    // We should read this data
    sample->num_extended = getData32(sample);
    
    if (sample->num_extended > 0) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we have " << sample->num_extended << " extended fields";
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "and sorry we haven't support for it :("; 

        return false;
    }

    return true;
}

void read_sflow_datagram(SFSample* sample) {
    sample->datap = (uint32_t*)sample->rawSample;
    sample->endp = (uint8_t*)sample->rawSample + sample->rawSampleLen;

    sample->datagramVersion = getData32(sample);
    // printf("sFLOW version %d\n", sample->datagramVersion);

    if (sample->datagramVersion != 5 && sample->datagramVersion != 4) {
        logger << log4cpp::Priority::ERROR
               << plugin_log_prefix 
               << "we do not support sFLOW v<< "<< sample->datagramVersion
               << " because it's too old. Please change version to sFLOW 4 or 5";
        return;
    }

    /* get the agent address */
    getAddress(sample, &sample->agent_addr);

    /* version 5 has an agent sub-id as well */
    if (sample->datagramVersion >= 5) {
        sample->agentSubId = getData32(sample);
        // sf_log(sample,"agentSubId %u\n", sample->agentSubId);
    } else {
        sample->agentSubId = 0;
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
            << plugin_log_prefix
            << "we tried to read data outside packet! It's very dangerous, we stop all operations";
            return;
        }

        // printf("Sample #%d\n", samp);

        /* just read the tag, then call the approriate decode fn */
        sample->sampleType = getData32(sample);
        if (sample->datagramVersion >= 5) {
            switch (sample->sampleType) {
            case SFLFLOW_SAMPLE:
                // skipBytes(sample, getData32(sample));
                if (!readFlowSample(sample, 0)) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we failed in SFLFLOW_SAMPLE handler";
                    return;
                }

                break;
            case SFLCOUNTERS_SAMPLE:
                // We do not need counters for our task, skip it
                if (!skipBytes(sample, getData32(sample))) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we failed in SFLCOUNTERS_SAMPLE handler";
                    return;
                }

                break;
            case SFLFLOW_SAMPLE_EXPANDED:
                // skipBytes(sample, getData32(sample));
                if (!readFlowSample(sample, 1)) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we failed in SFLFLOW_SAMPLE_EXPANDED handler";
                    return;
                }
                
                break;
            case SFLCOUNTERS_SAMPLE_EXPANDED:
                // We do not need counters for our task, skip it
                if (!skipBytes(sample, getData32(sample))) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we failed in SFLCOUNTERS_SAMPLE_EXPANDED handler";
                    return;
                }
                
                break;
            default:
                if (!skipTLVRecord(sample, sample->sampleType, getData32(sample))) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we failed in default handler in skipTLVRecord";
                    return;
                }
                break;
            }
        } else {
            // sFLOW v2 or v4 here
            switch(sample->sampleType) {
                case FLOWSAMPLE:
                    if (!readFlowSample_v2v4(sample)) {
                        // We have some troubles with old sFLOW parser 
                        return;
                    }
                    break;
                case COUNTERSSAMPLE:
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we haven't support for COUNTERSSAMPLE for "
                        << "sFLOW v4 and ignore it completely";
                    return; 
                    break;
                default:
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "unexpected sample type: " << sample->sampleType;
                    return;
                    break;
            }
        }
    }
}

bool skipTLVRecord(SFSample* sample, uint32_t tag, uint32_t len) {
    return skipBytes(sample, len);
}


bool length_check(SFSample *sample, const char *description, uint8_t *start, int len) {
    uint32_t actualLen = (uint8_t *)sample->datap - start;
    uint32_t adjustedLen = ((len + 3) >> 2) << 2;
  
    if (actualLen != adjustedLen) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << description
            << " length error: expected " << len << " found " << actualLen;
        return false;
    }

    return true;
}

bool readFlowSample(SFSample* sample, int expanded) {
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
            if (!skipTLVRecord(sample, tag, length)) {
                return false;
            }
        }

        if (!length_check(sample, "flow_sample_element", start, length)) {
            return false;
        }
    }

    if (!length_check(sample, "flow_sample", sampleStart, sampleLength)) {
        return false;
    }

    return true;
}

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

void decode_link_layer(SFSample* sample) {
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

    if (type_len == 0x86DD) {
        /* IPV6 */
        /* look at first byte of header.... */

        if ((*ptr >> 4) != 6) return; /* not version 6 */

        /* survived all the tests - store the offset to the start of the ip6 header */
        sample->gotIPV6 = 1;
        sample->offsetToIPV6 = (ptr - start);
        
        printf("IPv6\n"); 
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
        // Detect IPv4 or IPv6 here
        decode_link_layer(sample);

        // Process IP packets next
        if (sample->gotIPV4) {
            decode_ipv4_protocol(sample);
        }

        if (sample->gotIPV6) {
            decode_ipv6_protocol(sample);
        }
    } else {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "not supported protocol: " << sample->headerProtocol;
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
    
    if (sample->gotIPV6) {
        current_packet.ip_protocol_version = 6;

        memcpy(current_packet.src_ipv6.s6_addr, sample->ipsrc.address.ip_v6.addr, 16);
        memcpy(current_packet.dst_ipv6.s6_addr, sample->ipdst.address.ip_v6.addr, 16);
    } else {
        current_packet.ip_protocol_version = 4;

        current_packet.src_ip = sample->ipsrc.address.ip_v4.addr;
        current_packet.dst_ip = sample->ipdst.address.ip_v4.addr;
    }

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
        // TODO: flags could be broken because our flags parser implemented with PF_RING style flags
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

#ifdef ENABLE_LUA_HOOKS
    //sample->inputPort  = fast_ntoh(sample->inputPort);
    //sample->outputPort = fast_ntoh(sample->outputPort);

    if (sflow_lua_hooks_enabled) {
        // This code could be used only for tests with pcap_reader
        if (sflow_lua_state == NULL) {
            sflow_lua_state = init_lua_jit(sflow_lua_hooks_path); 
        }  

        if (call_lua_function("process_sflow", sflow_lua_state,
            convert_ip_as_uint_to_string(sample->sourceIP.address.ip_v4.addr), (void*)sample)) {
            // We will process this packet
        } else {
            logger << log4cpp::Priority::DEBUG << "We will drop this packets because LUA script decided to do it";
            return;
        }    
    }    
#endif

    // Call external handler function
    sflow_process_func_ptr(current_packet);
}

void decode_ipv6_protocol(SFSample* sample) { 
    uint8_t *ptr = sample->header + sample->offsetToIPV6;   
    uint8_t *end = sample->header + sample->headerLen;

    int ipVersion = (*ptr >> 4);
    
    if (ipVersion != 6) { 
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "sFLOW header decode error: unexpected IP version: " << ipVersion;
        return;
    }

    /* get the tos (priority) */
    sample->dcd_ipTos = *ptr++ & 15;

    if (debug_sflow_parser) {
        logger << log4cpp::Priority::INFO << plugin_log_prefix << "IPTOS: " << sample->dcd_ipTos;
    }

    /* 24-bit label */
    uint32_t label = *ptr++;
    label <<= 8;
    label += *ptr++;
    label <<= 8;
    label += *ptr++;

    if (debug_sflow_parser) {
        logger << log4cpp::Priority::INFO << plugin_log_prefix << "IP6_label: " << label;
    }

    /* payload */
    uint16_t payloadLen = (ptr[0] << 8) + ptr[1];
    ptr += 2;

    /* if payload is zero, that implies a jumbo payload */
    if (debug_sflow_parser) {
        if (payloadLen == 0) {
            logger << log4cpp::Priority::INFO << plugin_log_prefix << "IPV6_payloadLen <jumbo>";
        } else {
            logger << log4cpp::Priority::INFO << plugin_log_prefix << "IPV6_payloadLen " << payloadLen;
        }
    }

    /* next header */
    uint32_t nextHeader = *ptr++;

    /* TTL */
    sample->dcd_ipTTL = *ptr++;
    //sf_log(sample,"IPTTL %u\n", sample->dcd_ipTTL);

    /* src and dst address */
    // char buf[101];
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipsrc.address, ptr, 16);
    ptr +=16;
     
    if (debug_sflow_parser) {
        char buf[101];
        logger << log4cpp::Priority::INFO << plugin_log_prefix << "srcIP6: " << printAddress(&sample->ipsrc, buf);
    }

    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipdst.address, ptr, 16);
    ptr +=16;

    if (debug_sflow_parser) {
        char buf[101];
        logger << log4cpp::Priority::INFO << plugin_log_prefix << "dstIP6: " << printAddress(&sample->ipdst, buf);
    }

    /* skip over some common header extensions...
       http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html */
    while(nextHeader == 0 ||  /* hop */
          nextHeader == 43 || /* routing */
          nextHeader == 44 || /* fragment */
          /* nextHeader == 50 => encryption - don't bother coz we'll not be able to read any further */
          nextHeader == 51 || /* auth */
          nextHeader == 60) { /* destination options */
        
        uint32_t optionLen, skip;

        if (debug_sflow_parser) {
            logger << log4cpp::Priority::INFO << plugin_log_prefix << "IP6HeaderExtension: " << nextHeader;
        }

        nextHeader = ptr[0];
        optionLen = 8 * (ptr[1] + 1);  /* second byte gives option len in 8-byte chunks, not counting first 8 */
        skip = optionLen - 2;
        ptr += skip;
        if (ptr > end) return; /* ran off the end of the header */
    }

    /* now that we have eliminated the extension headers, nextHeader should have what we want to
       remember as the ip protocol... */
    sample->dcd_ipProtocol = nextHeader;

    if (debug_sflow_parser) {
        logger << log4cpp::Priority::INFO << plugin_log_prefix << "IPProtocol: " << sample->dcd_ipProtocol;
    }
    
    decodeIPLayer4(sample, ptr);
}

void decode_ipv4_protocol(SFSample* sample) {
    char buf[51];
    uint8_t* ptr = sample->header + sample->offsetToIPV4;
    /* Create a local copy of the IP header (cannot overlay structure in case it is not
        quad-aligned...some platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
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
