/* netflow plugin body */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

#include <vector>
#include <map>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

// Get it from main programm
extern log4cpp::Category& logger;

#include "netflow_collector.h"
#include "netflow.h"

// TODO: add per source uniq templates support

process_packet_pointer netflow_process_func_ptr = NULL;

std::map<u_int, struct peer_nf9_template> global_templates_array;

/* Prototypes */
int nf9_rec_to_flow(u_int record_type, u_int record_length, u_int8_t *data, simple_packet& packet, netflow9_template_records_map& template_records);

struct peer_nf9_template* peer_nf9_find_template(u_int32_t source_id, u_int flowset_id) {
    // TODO: we ignore source_id !!! FIX IT

    if (global_templates_array.count(flowset_id) > 0) {
        return &global_templates_array[flowset_id];  
    } else {
        return NULL;
    }
}

int process_netflow_v9_template(u_int8_t *pkt, size_t len, u_int32_t source_id) {
    struct NF9_FLOWSET_HEADER_COMMON *template_header = (struct NF9_FLOWSET_HEADER_COMMON *)pkt;
    struct peer_nf9_template field_template;

    if (len < sizeof(*template_header)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow v9 flowset template header";
        return 1;
    }

    if (ntohs(template_header->flowset_id) != NF9_TEMPLATE_FLOWSET_ID) {
        logger<< log4cpp::Priority::ERROR
            <<"Function process_netflow_v9_template expects only NF9_TEMPLATE_FLOWSET_ID but got another id: "
            <<ntohs(template_header->flowset_id);
        return 1;
    }

    for (u_int offset = sizeof(*template_header); offset < len;) {
        struct NF9_TEMPLATE_FLOWSET_HEADER *tmplh = (struct NF9_TEMPLATE_FLOWSET_HEADER *)(pkt + offset);

        u_int template_id = ntohs(tmplh->template_id);
        u_int count = ntohs(tmplh->count);
        offset += sizeof(*tmplh);

        //logger<< log4cpp::Priority::INFO<<"Template template_id is:"<<template_id;  
 
        u_int total_size = 0;

        netflow9_template_records_map template_records_map;
        for (u_int i = 0; i < count; i++) { 
            if (offset >= len) {
                logger<< log4cpp::Priority::ERROR<<"short netflow v.9 flowset  template";
                return 1;
            }

            struct NF9_TEMPLATE_FLOWSET_RECORD *tmplr = (struct NF9_TEMPLATE_FLOWSET_RECORD *)(pkt + offset);

            u_int record_type   = ntohs(tmplr->type);
            u_int record_length = ntohs(tmplr->length);

            struct peer_nf9_record current_record;
            current_record.type = record_type;
            current_record.len  = record_length;

            template_records_map.push_back(current_record);

            //logger<< log4cpp::Priority::INFO<<"Learn new template type: "<<ntohs(tmplr->type)<<" length:"<<ntohs(tmplr->length);
 
            offset += sizeof(*tmplr);
            total_size += record_length;

            // TODO: introduce nf9_check_rec_len
        } 

        field_template.num_records = count;
        field_template.total_len = total_size; 
  
        field_template.records = template_records_map;
 
        // TODO: update time to time template data
        if (peer_nf9_find_template(source_id, template_id) != NULL) {
            // logger<< log4cpp::Priority::INFO<<"We already have information about this template with id:"<<template_id;
            continue;
        } else {
            global_templates_array[ template_id ] = field_template;
        }
    }

    return 0;
}

int nf9_rec_to_flow(u_int record_type, u_int record_length, u_int8_t *data, simple_packet& packet) {
        /* XXX: use a table-based interpreter */
        switch (record_type) {

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - record_length), data, record_length);

#define V9_FIELD(v9_field, store_field, flow_field) \
        case v9_field: \
                BE_COPY(packet.flow_field); \
                break
#define V9_FIELD_ADDR(v9_field, store_field, flow_field) \
        case v9_field: \
                memcpy(&packet.flow_field, data, record_length); \
                break
        V9_FIELD(NF9_IN_BYTES,    OCTETS,           length);
        V9_FIELD(NF9_IN_PACKETS,  PACKETS,          number_of_packets);
        V9_FIELD(NF9_IN_PROTOCOL, PROTO_FLAGS_TOS,  protocol);
        V9_FIELD(NF9_TCP_FLAGS,   PROTO_FLAGS_TOS,  flags);
        V9_FIELD(NF9_L4_SRC_PORT, SRCDST_PORT,      source_port);
        V9_FIELD(NF9_L4_DST_PORT, SRCDST_PORT,      destination_port);
      
        V9_FIELD_ADDR(NF9_IPV4_SRC_ADDR, SRC_ADDR4, src_ip);
        V9_FIELD_ADDR(NF9_IPV4_DST_ADDR, DST_ADDR4, dst_ip);

        //V9_FIELD(NF9_SRC_TOS, PROTO_FLAGS_TOS, pft.tos);
        //V9_FIELD(NF9_SRC_MASK, AS_INFO, asinf.src_mask);
        //V9_FIELD(NF9_INPUT_SNMP, IF_INDICES, ifndx.if_index_in);
        //V9_FIELD(NF9_DST_MASK, AS_INFO, asinf.dst_mask);
        //V9_FIELD(NF9_OUTPUT_SNMP, IF_INDICES, ifndx.if_index_out);
        //V9_FIELD(NF9_SRC_AS, AS_INFO, asinf.src_as);
        //V9_FIELD(NF9_DST_AS, AS_INFO, asinf.dst_as);
        //V9_FIELD(NF9_LAST_SWITCHED, FLOW_TIMES, ftimes.flow_finish);
        //V9_FIELD(NF9_FIRST_SWITCHED, FLOW_TIMES, ftimes.flow_start);
        //V9_FIELD(NF9_IPV6_SRC_MASK, AS_INFO, asinf.src_mask);
        //V9_FIELD(NF9_IPV6_DST_MASK, AS_INFO, asinf.dst_mask);
        //V9_FIELD(NF9_ENGINE_TYPE, FLOW_ENGINE_INFO, finf.engine_type);
        //V9_FIELD(NF9_ENGINE_ID, FLOW_ENGINE_INFO, finf.engine_id);
        //V9_FIELD_ADDR(NF9_IPV4_NEXT_HOP, GATEWAY_ADDR4, gateway_addr, 4, INET);
        //V9_FIELD_ADDR(NF9_IPV6_SRC_ADDR, SRC_ADDR6, src_addr, 6, INET6);
        //V9_FIELD_ADDR(NF9_IPV6_DST_ADDR, DST_ADDR6, dst_addr, 6, INET6);
        //V9_FIELD_ADDR(NF9_IPV6_NEXT_HOP, GATEWAY_ADDR6, gateway_addr, 6, INET6);

#undef V9_FIELD
#undef V9_FIELD_ADDR
#undef BE_COPY
        }
        return 0;
}

int nf9_flowset_to_store(u_int8_t *pkt, size_t len, struct NF9_HEADER *nf9_hdr, netflow9_template_records_map& template_records) {
    //if (template->total_len > len)
    //    return 1;

    u_int offset = 0;

    simple_packet packet;
    packet.ts.tv_sec = ntohl(nf9_hdr->time_sec);

    // We should iterate over all available template fields
    for (netflow9_template_records_map::iterator iter = template_records.begin(); iter != template_records.end(); iter++) {
        u_int record_type   = iter->type;
        u_int record_length = iter->len;

        nf9_rec_to_flow(record_type, record_length, pkt + offset, packet);
        //logger<< log4cpp::Priority::INFO<<"Read data with type: "<<record_type<<" and length:"<<record_length;

        offset += record_length;
    }

    // decode data in network byte order to host byte order
    packet.length            = ntohl(packet.length);
    packet.number_of_packets = ntohl(packet.number_of_packets);

    packet.protocol = ntohl(packet.protocol);

    // Set protocol
    switch (packet.protocol) {
        case 1: {
            packet.protocol = IPPROTO_ICMP;
            
            packet.source_port = 0;
            packet.destination_port = 0;
        }
        break;

        case 6: {
            packet.protocol = IPPROTO_TCP;
        }
        break;

        case 17: {
            packet.protocol = IPPROTO_UDP;
        }
        break;
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
}

int process_netflow_v9_data(u_int8_t *pkt, size_t len, struct NF9_HEADER *nf9_hdr, u_int32_t source_id) {
    struct NF9_DATA_FLOWSET_HEADER *dath = (struct NF9_DATA_FLOWSET_HEADER *)pkt;

    if (len < sizeof(*dath)) {
        logger<< log4cpp::Priority::INFO<<"Short netflow v9 data flowset header";
        return 1;
    }

    u_int flowset_id = ntohs(dath->c.flowset_id);
    //logger<< log4cpp::Priority::INFO<<"We have data with flowset_id: "<<flowset_id;

    // We should find template here
    struct peer_nf9_template *flowset_template = peer_nf9_find_template(source_id, flowset_id); 
    
    if (flowset_template == NULL) {
        logger<< log4cpp::Priority::INFO<<"We haven't template for flowset_id: "<<flowset_id
            <<" but it's not an error if this message go away in 5-10 seconds. We need some time to learn it!";
        return 0;
    }

    if (flowset_template->records.size() == 0) {
        logger<< log4cpp::Priority::ERROR<<"Blank records in template"; 
        return 1;
    }

    u_int offset = sizeof(*dath);
    u_int num_flowsets = (len - offset) / flowset_template->total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logger<< log4cpp::Priority::ERROR<<"Invalid number of data flowset, strange number of flows: "<<num_flowsets;
        return 1;
    }

    for (u_int i = 0; i < num_flowsets; i++) {
        // process whole flowset
        nf9_flowset_to_store(pkt + offset, flowset_template->total_len, nf9_hdr, flowset_template->records);

        offset += flowset_template->total_len;
    }

    return 0;
}

void process_netflow_packet_v9(u_int len, u_int8_t *packet) {
    //logger<< log4cpp::Priority::INFO<<"We get v9 netflow packet!";

    struct NF9_HEADER *nf9_hdr = (struct NF9_HEADER*)packet;
    struct NF9_FLOWSET_HEADER_COMMON *flowset;
    u_int32_t count, flowset_id, flowset_len, flowset_flows;
    u_int32_t offset, source_id, total_flows;

    if (len < sizeof(*nf9_hdr)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow v9 header";
        return; 
    }
   
    count = ntohs(nf9_hdr->c.flows);
    source_id = ntohl(nf9_hdr->source_id);

    // logger<< log4cpp::Priority::INFO<<"Template source id: "<<source_id;

    offset = sizeof(*nf9_hdr);
    total_flows = 0;

    for (u_int32_t i = 0;; i++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= len) {
            logger<< log4cpp::Priority::ERROR<<"We tried to read from address outside netflow packet";
            return;
        }

        flowset = (struct NF9_FLOWSET_HEADER_COMMON *)(packet + offset);

        flowset_id  = ntohs(flowset->flowset_id);
        flowset_len = ntohs(flowset->length);

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */
        
        if (offset + flowset_len > len) {
            logger<< log4cpp::Priority::ERROR<<"We tried to read from address outside netflow's packet flowset";
            return;
        }

        switch (flowset_id) {
            case NF9_TEMPLATE_FLOWSET_ID:
                // logger<< log4cpp::Priority::INFO<<"We read template";
                if (process_netflow_v9_template(packet + offset, flowset_len, source_id) != 0) {
                    logger<<log4cpp::Priority::ERROR<<"Function process_netflow_v9_template executed with errors";
                    break;
                }
                break;
            case NF9_OPTIONS_FLOWSET_ID:
                /* Not implemented yet */
                break;
            default:
                if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                    logger<< log4cpp::Priority::ERROR<<"Received unknown netflow v9 reserved flowset type "<<flowset_id;
                    break;
                }

                // logger<< log4cpp::Priority::INFO<<"We read data";

                if (process_netflow_v9_data(packet + offset, flowset_len, nf9_hdr, source_id) != 0) {
                    logger<< log4cpp::Priority::ERROR<<"Can't process function process_netflow_v9_data correctly";
                    return;
                }

                break;
        }

        offset += flowset_len;
        if (offset == len) {
            break;
        }
    } 
}

void process_netflow_packet_v5(u_int len, u_int8_t *packet) {
    //logger<< log4cpp::Priority::INFO<<"We get v5 netflow packet!";
    
    struct NF5_HEADER* nf5_hdr = (struct NF5_HEADER*)packet;

    if (len < sizeof(*nf5_hdr)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow v5 packet "<<len;
        return;
    }

    u_int nflows = ntohs(nf5_hdr->c.flows);
    if (nflows == 0 || nflows > NF5_MAXFLOWS) {
        logger<< log4cpp::Priority::ERROR<<"Invalid number of flows in netflow "<<nflows;
        return;
    }
    
    for (u_int i = 0; i < nflows; i++) {
        size_t offset = NF5_PACKET_SIZE(i);
        struct NF5_FLOW* nf5_flow = (struct NF5_FLOW *)(packet + offset);

        // convert netflow to simple packet form
        simple_packet current_packet;
  
        current_packet.src_ip = nf5_flow->src_ip;
        current_packet.dst_ip = nf5_flow->dest_ip;
        current_packet.ts.tv_sec  = ntohl(nf5_hdr->time_sec);
        current_packet.ts.tv_usec = ntohl(nf5_hdr->time_nanosec);
        current_packet.flags = 0;

        current_packet.source_port = 0;
        current_packet.destination_port = 0;

        // TODO: we should pass data about "flow" structure of this data
    
        // htobe64 removed
        current_packet.length            = ntohl(nf5_flow->flow_octets);
        current_packet.number_of_packets = ntohl(nf5_flow->flow_packets);

        // netflow did not support sampling
        current_packet.sample_ratio = 1;

        switch (nf5_flow->protocol) {
            case 1: {
                //ICMP
                current_packet.protocol = IPPROTO_ICMP; 
            }
            break;

            case 6: { 
                // TCP
                current_packet.protocol = IPPROTO_TCP;

                current_packet.source_port      = nf5_flow->src_port;
                current_packet.destination_port = nf5_flow->dest_port;

                // TODO: flags can be in another format!
                current_packet.flags = nf5_flow->tcp_flags;
            }
            break;

            case 17: {
                // UDP
                current_packet.protocol = IPPROTO_UDP;

                current_packet.source_port      = nf5_flow->src_port;
                current_packet.destination_port = nf5_flow->dest_port;
            }
            break;
        }
   
        // Call processing function for every flow in packet
        netflow_process_func_ptr(current_packet);
    }
}

void process_netflow_packet(u_int len, u_int8_t *packet) {
    struct NF_HEADER_COMMON *hdr = (struct NF_HEADER_COMMON *)packet;

    switch (ntohs(hdr->version)) {
        case 5:
            process_netflow_packet_v5(len, packet);
            break;
        case 9:
            process_netflow_packet_v9(len, packet);
            break;
        default:
            logger<< log4cpp::Priority::ERROR<<"We did not support this version of netflow "<<ntohs(hdr->version);
            break;    
    }
}

void start_netflow_collection(process_packet_pointer func_ptr) {
    logger<< log4cpp::Priority::INFO<<"netflow plugin started";
    netflow_process_func_ptr = func_ptr;

    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
   
    unsigned int netflow_port = 2055;
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(netflow_port);
    
    int bind_result = bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (bind_result) {
        logger<< log4cpp::Priority::ERROR<<"Can't listen port: "<<netflow_port;
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    for (;;) {
        struct sockaddr_in cliaddr;
        socklen_t address_len = sizeof(cliaddr);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr *)&cliaddr, &address_len); 

        if (received_bytes > 0) {
            // printf("We receive %d\n", received_bytes);
            process_netflow_packet(received_bytes, (u_int8_t*)udp_buffer);
        } else {
            logger<< log4cpp::Priority::ERROR<<"netflow data receive failed";
        }
    }
}

