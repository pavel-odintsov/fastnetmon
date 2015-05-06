/* netflow plugin body */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
#include <netdb.h>

#include <vector>
#include <map>

#include "../fast_library.h"
#include "../ipfix_rfc.h"

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

// Global configuration map 
extern std::map<std::string, std::string> configuration_map;

// Sampling rate for all netflow agents
unsigned int sampling_rate = 1;

ipfix_information_database ipfix_db_instance;

#include "netflow_collector.h"
#include "netflow.h"

// If we wan't listen on IPv4 and IPv6 i nsame time we need listen multiple sockets. Not good, right.

// TODO: add per source uniq templates support

process_packet_pointer netflow_process_func_ptr = NULL;

typedef std::map<u_int, struct peer_nf9_template> template_storage_t;
typedef std::map<std::string, template_storage_t> global_template_storage_t;

global_template_storage_t global_netflow9_templates;
global_template_storage_t global_netflow10_templates; 

/* Prototypes */
void add_peer_template(global_template_storage_t& table_for_add, u_int32_t source_id,
    u_int template_id, std::string client_addres_in_string_format, struct peer_nf9_template& field_template);

int nf9_rec_to_flow(u_int record_type, u_int record_length, u_int8_t *data,
    simple_packet& packet, netflow9_template_records_map& template_records);

struct peer_nf9_template* peer_find_template(global_template_storage_t& table_for_lookup, u_int32_t source_id,
    u_int template_id, std::string client_addres_in_string_format) {

    // We use source_id for distinguish multiple netflow agents with same IP
    std::string key = client_addres_in_string_format + "_" + convert_int_to_string(source_id);  

    global_template_storage_t::iterator itr = table_for_lookup.find(key);

    if (itr == table_for_lookup.end()) {
        return NULL;
    }

    // Well, we find it!
    if (itr->second.count(template_id) > 0) {
        return &itr->second[template_id];
    } else {
        return NULL;
    }
}

// Wrapper functions
struct peer_nf9_template* peer_nf9_find_template(u_int32_t source_id, u_int template_id, std::string client_addres_in_string_format) {
    return peer_find_template(global_netflow9_templates, source_id, template_id, client_addres_in_string_format);
}

struct peer_nf9_template* peer_nf10_find_template(u_int32_t source_id, u_int template_id, std::string client_addres_in_string_format) {
     return peer_find_template(global_netflow10_templates, source_id, template_id, client_addres_in_string_format);
}

std::string print_peer_nf9_template(struct peer_nf9_template& field_template) {
    std::stringstream buffer;

    buffer
        <<"template_id: "<<field_template.template_id<<"\n"
        <<"num records: "<<field_template.num_records<<"\n"
        <<"total len: "  <<field_template.total_len<<"\n";

    for (netflow9_template_records_map::iterator itr = field_template.records.begin(); itr != field_template.records.end(); ++itr) {
        buffer<<"Records\n";
        unsigned int length_from_database = ipfix_db_instance.get_length_by_id(itr->type);

        buffer<<"type: "<<itr->type<<"\n";
        buffer<<"len: "<<itr->len<<"\n";
        buffer<<"name from database: "<<ipfix_db_instance.get_name_by_id(itr->type)<<"\n";
        buffer<<"length from database: "<<length_from_database<<"\n";

        if (length_from_database != itr->len) {
            buffer<<"ATTENTION!!!! Length from database is not equal to length from received from the device\n";
        }
        
        buffer<<"\n";
    } 

    return buffer.str();
}

struct NF10_OPTIONS_HEADER_COMMON {
    u_int16_t flowset_id;
    u_int16_t length;
};

struct NF10_OPTIONS_HEADER {
    u_int16_t template_id;
    u_int16_t field_count;
    u_int16_t scope_field_count;
};

// https://tools.ietf.org/html/rfc5101#page-18
int process_netflow_v10_options_template(u_int8_t *pkt, size_t len, u_int32_t source_id) {
    struct NF10_OPTIONS_HEADER_COMMON* options_template_header = (struct NF10_OPTIONS_HEADER_COMMON*)pkt;

    if (len < sizeof(*options_template_header)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow ipfix options template header";
        return 1;
    }

    if (ntohs(options_template_header->flowset_id) != NF10_OPTIONS_FLOWSET_ID) {
        logger<< log4cpp::Priority::ERROR
            <<"Function process_netflow_v10_options_template expects only NF10_OPTIONS_FLOWSET_ID but got another id: "
            <<ntohs(options_template_header->flowset_id); 
        return 1;
    }

    struct NF10_OPTIONS_HEADER* options_nested_header = (struct NF10_OPTIONS_HEADER*)(pkt + sizeof(struct NF10_OPTIONS_HEADER_COMMON*));

    // Yes, I should convert it to host byter order but it broke it!
    // WTF?? 
    u_int16_t template_id = options_nested_header->template_id;

    if (template_id <= 255) {
        logger<< log4cpp::Priority::ERROR<<"Template ID for options template should be bigger then 255";
        return 1;
    }

    u_int16_t field_count = ntohs(options_nested_header->field_count);
    u_int16_t scope_field_count = ntohs(options_nested_header->scope_field_count);

    logger<< log4cpp::Priority::INFO<<"Options template id: "<<template_id<<" field_count: "<<field_count<<" scope_field_count: "<<scope_field_count;
    
    return 0;
}

int process_netflow_v10_template(u_int8_t *pkt, size_t len, u_int32_t source_id, std::string client_addres_in_string_format) {
    struct NF10_FLOWSET_HEADER_COMMON *template_header = (struct NF10_FLOWSET_HEADER_COMMON *)pkt;
    // We use same struct as netflow v9 because netflow v9 and v10 (ipfix) is compatible
    struct peer_nf9_template field_template;

    if (len < sizeof(*template_header)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow ipfix flowset template header";
        return 1;
    }

    if (ntohs(template_header->flowset_id) != NF10_TEMPLATE_FLOWSET_ID) {
        logger<< log4cpp::Priority::ERROR
            <<"Function process_netflow_v10_template expects only NF10_TEMPLATE_FLOWSET_ID but got another id: "
            <<ntohs(template_header->flowset_id);
        return 1;
    }

    for (u_int offset = sizeof(*template_header); offset < len;) {
        struct NF10_TEMPLATE_FLOWSET_HEADER* tmplh = (struct NF10_TEMPLATE_FLOWSET_HEADER*)(pkt + offset);

        u_int template_id = ntohs(tmplh->template_id);
        u_int count = ntohs(tmplh->count);
        offset += sizeof(*tmplh);

        netflow9_template_records_map template_records_map;
        u_int total_size = 0;
        for (u_int i = 0; i < count; i++) { 
            if (offset >= len) {
                logger<< log4cpp::Priority::ERROR<<"short netflow v.10 flowset  template";
                return 1;
            }

            struct NF10_TEMPLATE_FLOWSET_RECORD *tmplr =  (struct NF10_TEMPLATE_FLOWSET_RECORD *)(pkt + offset);
            u_int record_type   = ntohs(tmplr->type);
            u_int record_length = ntohs(tmplr->length);

            struct peer_nf9_record current_record;
            current_record.type = record_type;
            current_record.len  = record_length;

            template_records_map.push_back(current_record);            

            offset += sizeof(*tmplr);
            if (record_type & NF10_ENTERPRISE) {
                 offset += sizeof(u_int32_t);    /* XXX -- ? */
            }

            total_size += record_length;
            // add check: if (total_size > peers->max_template_len)
        }
    
        field_template.num_records = count;
        field_template.total_len = total_size; 
        field_template.records = template_records_map;

        add_peer_template(global_netflow10_templates, source_id, template_id, client_addres_in_string_format, field_template);
    }

    return 0;
}

int process_netflow_v9_template(u_int8_t *pkt, size_t len, u_int32_t source_id, std::string client_addres_in_string_format) {
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

        // Add/update template 
        add_peer_template(global_netflow9_templates, source_id, template_id, client_addres_in_string_format, field_template);
    }        
    
    return 0;
}

void add_peer_template(global_template_storage_t& table_for_add, u_int32_t source_id,
    u_int template_id, std::string client_addres_in_string_format, struct peer_nf9_template& field_template) { 

    std::string key = client_addres_in_string_format + "_" + convert_int_to_string(source_id);

    logger<< log4cpp::Priority::INFO<<"It's new option template "<<template_id<<" for host: "<<client_addres_in_string_format
        <<" with source id: "<<source_id; 

    global_template_storage_t::iterator itr = table_for_add.find(key); 
    
    if (itr != table_for_add.end()) {
        if (itr->second.count(template_id) > 0) {
            //logger<< log4cpp::Priority::INFO<<"We already have information about this template with id:"
            //    <<template_id<<" for host: "<<client_addres_in_string_format;

            // TODO: update time to time template data
            itr->second[template_id] = field_template;
        } else {
            //logger<< log4cpp::Priority::INFO<<"It's new option template "<<template_id<<" for host: "<<client_addres_in_string_format;
            itr->second[template_id] = field_template;    
        }
    } else {
        template_storage_t temp_template_storage;
        temp_template_storage[template_id] = field_template;

        table_for_add[key] = temp_template_storage;   
    }
    
    return;
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

	// Sampling rate
	// We use NULL as second argument because it's suelles for us
	// It did not help us because looks like sampling rate implemented with OPTIONS flowset
	// V9_FIELD(NF9_SAMPLING_INTERVAL, NULL, sample_ratio);

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

//#undef V9_FIELD
//#undef V9_FIELD_ADDR
//#undef BE_COPY
        }
        return 0;
}

int nf10_rec_to_flow(u_int record_type, u_int record_length, u_int8_t *data, simple_packet& packet) { 
    /* XXX: use a table-based interpreter */
    switch (record_type) {
        V9_FIELD(NF10_IN_BYTES,    OCTETS,           length);
        V9_FIELD(NF10_IN_PACKETS,  PACKETS,          number_of_packets);
        V9_FIELD(NF10_IN_PROTOCOL, PROTO_FLAGS_TOS,  protocol);
        V9_FIELD(NF10_TCP_FLAGS,   PROTO_FLAGS_TOS,  flags);
        V9_FIELD(NF10_L4_SRC_PORT, SRCDST_PORT,      source_port);
        V9_FIELD(NF10_L4_DST_PORT, SRCDST_PORT,      destination_port);
      
        V9_FIELD_ADDR(NF10_IPV4_SRC_ADDR, SRC_ADDR4, src_ip);
        V9_FIELD_ADDR(NF10_IPV4_DST_ADDR, DST_ADDR4, dst_ip);
    }

    return 0;
}

// We use maximum possible variable langth
// But devices can send shoretr data to us 
typedef struct netflow_ipfix_struct {
    uint32_t sourceIPv4Address;
    uint32_t destinationIPv4Address;
    uint16_t sourceTransportPort;
    uint16_t destinationTransportPort;
    uint16_t tcpControlBits;
    uint8_t  protocolIdentifier;
    uint64_t octetDeltaCount;
    uint64_t packetDeltaCount;
} netflow_ipfix_struct;

// We should rewrite nf9_flowset_to_store accroding to fixes here
void nf10_flowset_to_store(u_int8_t *pkt, size_t len, struct NF10_HEADER *nf10_hdr, struct peer_nf9_template* field_template) {
    u_int offset = 0;

    if (len < field_template->total_len) {
        logger<< log4cpp::Priority::ERROR<<"Total len from template bigger than packet len";
        return;
    }

    simple_packet packet;
    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec = ntohl(nf10_hdr->time_sec);

    packet.sample_ratio = sampling_rate;

    netflow_ipfix_struct data_in_ipfix_format;
    memset(&data_in_ipfix_format, sizeof(netflow_ipfix_struct), 0);

    for (netflow9_template_records_map::iterator iter = field_template->records.begin(); iter != field_template->records.end(); iter++) {
        u_int record_type   = iter->type;
        u_int record_length = iter->len;

        nf10_rec_to_flow(record_type, record_length, pkt + offset, packet);
    
        // New code
        /*
        unsigned int field_id = record_type;
        std::string field_name = ipfix_db_instance.get_name_by_id(field_id);

        if (field_name == "octetDeltaCount") {
            unsigned int reference_field_length = sizeof(data_in_ipfix_format.octetDeltaCount);

            if (reference_field_length == record_length) {
                // We use standard copy
                memcpy(&data_in_ipfix_format.octetDeltaCount, pkt + offset, record_length);

                // Convert to host byte order
                data_in_ipfix_format.octetDeltaCount = fast_ntoh(data_in_ipfix_format.octetDeltaCount);
            } else if (record_length < reference_field_length) {
                logger<< log4cpp::Priority::ERROR<<"We can't copy data because magic memcpy is not implemented yet";
                // We use copy memcpy for netfowrk byte order
            } else {
                // Holy cow! It's impossible!
                logger<< log4cpp::Priority::ERROR<<"We can't copy data because receiver data is bigger than our storage.";
                return;           
            }
            
            logger<< log4cpp::Priority::INFO<<"We received packet size with new parser: "<<data_in_ipfix_format.octetDeltaCount;
        }
        */

        offset += record_length;
    }

    // decode data in network byte order to host byte order
    packet.length            = fast_ntoh(packet.length);

    packet.number_of_packets = fast_ntoh(packet.number_of_packets);
    packet.protocol = fast_ntoh(packet.protocol);

    // We should convert ports to host byte order too
    packet.source_port      = fast_ntoh(packet.source_port);
    packet.destination_port = fast_ntoh(packet.destination_port);

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

void nf9_flowset_to_store(u_int8_t *pkt, size_t len, struct NF9_HEADER *nf9_hdr, netflow9_template_records_map& template_records) {
    // Should be done according to https://github.com/FastVPSEestiOu/fastnetmon/issues/147
    //if (template->total_len > len)
    //    return 1;

    u_int offset = 0;

    simple_packet packet;
    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec = ntohl(nf9_hdr->time_sec);

    packet.sample_ratio = sampling_rate;

    // We should iterate over all available template fields
    for (netflow9_template_records_map::iterator iter = template_records.begin(); iter != template_records.end(); iter++) {
        u_int record_type   = iter->type;
        u_int record_length = iter->len;

        nf9_rec_to_flow(record_type, record_length, pkt + offset, packet);
        //logger<< log4cpp::Priority::INFO<<"Read data with type: "<<record_type<<" and length:"<<record_length;

        offset += record_length;
    }

    // decode data in network byte order to host byte order
    packet.length            = fast_ntoh(packet.length);
    packet.number_of_packets = fast_ntoh(packet.number_of_packets);

    packet.protocol = fast_ntoh(packet.protocol);

    // We should convert ports to host byte order too
    packet.source_port      = fast_ntoh(packet.source_port);
    packet.destination_port = fast_ntoh(packet.destination_port);

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

int process_netflow_v10_data(u_int8_t *pkt, size_t len, struct NF10_HEADER *nf10_hdr,
    u_int32_t source_id, std::string client_addres_in_string_format) {

    struct NF10_DATA_FLOWSET_HEADER *dath = (struct NF10_DATA_FLOWSET_HEADER *)pkt;

    if (len < sizeof(*dath)) {
        logger<< log4cpp::Priority::INFO<<"Short netflow v10 data flowset header";
        return 1;
    }

    u_int flowset_id = ntohs(dath->c.flowset_id);

    struct peer_nf9_template *flowset_template = peer_nf10_find_template(source_id, flowset_id, client_addres_in_string_format);

    if (flowset_template == NULL) {
        logger<< log4cpp::Priority::INFO<<"We haven't template for flowset_id: "<<flowset_id
            <<" but it's not an error if this message go away in 5-10 seconds. We need some time to learn it!";

        return 1;
    }

    if (flowset_template->records.empty()) {
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
        nf10_flowset_to_store(pkt + offset, flowset_template->total_len, nf10_hdr, flowset_template);

        offset += flowset_template->total_len; 
    }  

    return 0;
}

int process_netflow_v9_data(u_int8_t *pkt, size_t len, struct NF9_HEADER *nf9_hdr, u_int32_t source_id, std::string client_addres_in_string_format) {
    struct NF9_DATA_FLOWSET_HEADER *dath = (struct NF9_DATA_FLOWSET_HEADER *)pkt;

    if (len < sizeof(*dath)) {
        logger<< log4cpp::Priority::INFO<<"Short netflow v9 data flowset header";
        return 1;
    }

    u_int flowset_id = ntohs(dath->c.flowset_id);
    //logger<< log4cpp::Priority::INFO<<"We have data with flowset_id: "<<flowset_id;

    // We should find template here
    struct peer_nf9_template *flowset_template = peer_nf9_find_template(source_id, flowset_id, client_addres_in_string_format); 
    
    if (flowset_template == NULL) {
        logger<< log4cpp::Priority::INFO<<"We haven't template for flowset_id: "<<flowset_id
            <<" but it's not an error if this message go away in 5-10 seconds. We need some time to learn it!";
        return 0;
    }

    if (flowset_template->records.empty()) {
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

void process_netflow_packet_v10(u_int8_t *packet, u_int len, std::string client_addres_in_string_format) {
    struct NF10_HEADER *nf10_hdr = (struct NF10_HEADER *)packet;
    struct NF10_FLOWSET_HEADER_COMMON *flowset; 

    u_int32_t i, pktlen, flowset_id, flowset_len, flowset_flows;
    u_int32_t offset, source_id, total_flows;

    if (len < sizeof(*nf10_hdr)) {
        logger<< log4cpp::Priority::ERROR<<"Short netflow v10 header";
        return;
    }

    /* v10 uses pkt length, not # of flows */
    pktlen = ntohs(nf10_hdr->c.flows);
    source_id = ntohl(nf10_hdr->source_id);

    offset = sizeof(*nf10_hdr);
    total_flows = 0;

    for (i = 0;; i++) {
        if (offset >= len) {
            logger<< log4cpp::Priority::ERROR<<"We tried to read from address outside netflow packet";
            return;
        }

        flowset = (struct NF10_FLOWSET_HEADER_COMMON *)(packet + offset);
        flowset_id = ntohs(flowset->flowset_id);
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
            case NF10_TEMPLATE_FLOWSET_ID:
                if (process_netflow_v10_template(packet + offset, flowset_len, source_id, client_addres_in_string_format) != 0) {
                    logger<<log4cpp::Priority::ERROR<<"Function process_netflow_v10_template executed with errors";
                    break;
                }
                break;
            case NF10_OPTIONS_FLOWSET_ID:
                //process_netflow_v10_options_template(packet + offset, flowset_len, source_id);
                logger<< log4cpp::Priority::INFO<<"I received ipfix options flowset id but I haven't support for it";
                /* Not implemented yet */
                break;
            default:
                if (flowset_id < NF10_MIN_RECORD_FLOWSET_ID) {
                    logger<< log4cpp::Priority::ERROR<<"Received unknown netflow v10 reserved flowset type "<<flowset_id;
                    break;
                }

                if (process_netflow_v10_data(packet + offset, flowset_len, nf10_hdr, source_id, client_addres_in_string_format) != 0) { 
                    //logger<< log4cpp::Priority::ERROR<<"Can't process function process_netflow_v10_data correctly";
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

void process_netflow_packet_v9(u_int8_t *packet, u_int len, std::string client_addres_in_string_format) {
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
                if (process_netflow_v9_template(packet + offset, flowset_len, source_id, client_addres_in_string_format) != 0) {
                    logger<<log4cpp::Priority::ERROR<<"Function process_netflow_v9_template executed with errors";
                    break;
                }
                break;
            case NF9_OPTIONS_FLOWSET_ID:
                logger<< log4cpp::Priority::INFO<<"I received netflow v9 options flowset id but I haven't support for it";
                /* Not implemented yet */
                break;
            default:
                if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                    logger<< log4cpp::Priority::ERROR<<"Received unknown netflow v9 reserved flowset type "<<flowset_id;
                    break;
                }

                // logger<< log4cpp::Priority::INFO<<"We read data";

                if (process_netflow_v9_data(packet + offset, flowset_len, nf9_hdr, source_id, client_addres_in_string_format) != 0) {
                    //logger<< log4cpp::Priority::ERROR<<"Can't process function process_netflow_v9_data correctly";
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

void process_netflow_packet_v5(u_int8_t *packet, u_int len) {
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

        /* Check packet bounds */
        if (offset + sizeof(struct NF5_FLOW) > len) {
            logger<< log4cpp::Priority::ERROR<<"Error! You will try to read outside the packet";
        } 

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
        current_packet.length            = fast_ntoh(nf5_flow->flow_octets);
        current_packet.number_of_packets = fast_ntoh(nf5_flow->flow_packets);

        current_packet.sample_ratio = sampling_rate;

        current_packet.source_port      = fast_ntoh(nf5_flow->src_port);
        current_packet.destination_port = fast_ntoh(nf5_flow->dest_port);

        switch (nf5_flow->protocol) {
            case 1: {
                //ICMP
                current_packet.protocol = IPPROTO_ICMP; 
            }
            break;

            case 6: { 
                // TCP
                current_packet.protocol = IPPROTO_TCP;

                // TODO: flags can be in another format!
                current_packet.flags = nf5_flow->tcp_flags;
            }
            break;

            case 17: {
                // UDP
                current_packet.protocol = IPPROTO_UDP;
            }
            break;
        }
   
        // Call processing function for every flow in packet
        netflow_process_func_ptr(current_packet);
    }
}

void process_netflow_packet(u_int8_t *packet, u_int len, std::string client_addres_in_string_format) {
    struct NF_HEADER_COMMON *hdr = (struct NF_HEADER_COMMON *)packet;

    switch (ntohs(hdr->version)) {
        case 5:
            process_netflow_packet_v5(packet, len);
            break;
        case 9:
            process_netflow_packet_v9(packet, len, client_addres_in_string_format);
            break;
        case 10:
            process_netflow_packet_v10(packet, len, client_addres_in_string_format);
            break;
        default:
            logger<< log4cpp::Priority::ERROR<<"We did not support this version of netflow "<<ntohs(hdr->version);
            break;    
    }
}

unsigned int netflow_port = 2055;

void start_netflow_collection(process_packet_pointer func_ptr) {
    logger<< log4cpp::Priority::INFO<<"netflow plugin started";
    netflow_process_func_ptr = func_ptr;

    // By default we listen on IPv4
    std::string netflow_host = "0.0.0.0";

    if (configuration_map.count("netflow_port") != 0) {
        netflow_port = convert_string_to_integer(configuration_map["netflow_port"]);
    }

    if (configuration_map.count("netflow_host") != 0) {
        netflow_host = configuration_map["netflow_host"];
    }

    if (configuration_map.count("netflow_sampling_ratio") != 0) {
        sampling_rate = convert_string_to_integer(configuration_map["netflow_sampling_ratio"]);
       
        logger<< log4cpp::Priority::INFO<<"We use custom sampling ratio for netflow: "<<sampling_rate;
    }


    logger<< log4cpp::Priority::INFO<<"netflow plugin will listen on "<<netflow_host<<":"<<netflow_port<< " udp port"; 

    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);

    // Could be AF_INET6 or AF_INET
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    // This flag will generate wildcard IP address if we not specified certain IP address for binding
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    struct addrinfo *servinfo = NULL; 

    const char* address_for_binding = NULL;

    if (!netflow_host.empty()) {
        address_for_binding = netflow_host.c_str();
    }

    char port_as_string[16];
    sprintf(port_as_string, "%d", netflow_port); 
   
    int getaddrinfo_result =  getaddrinfo(address_for_binding, port_as_string, &hints, &servinfo);

    if (getaddrinfo_result != 0) {
        logger<< log4cpp::Priority::ERROR<<"Netflow getaddrinfo function failed with code: "<<getaddrinfo_result<<" please check netflow_host";
        exit(1);
    } 
    
    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
 
    int bind_result = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);

    if (bind_result) {
        logger<< log4cpp::Priority::ERROR<<"Can't listen port: "<<netflow_port<<" on host "<<netflow_host<<" errno:"<<errno<< " error: "<<strerror(errno);
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    for (;;) {
        // This approach provide ability to store both IPv4 and IPv6 client's addresses
        struct sockaddr_storage client_address;
        // It's MUST
        memset(&client_address, 0, sizeof(struct sockaddr_storage));
        socklen_t address_len = sizeof(struct sockaddr_storage);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr *)&client_address, &address_len); 

        if (received_bytes > 0) {
            // Pass host and port as numbers without any conversion
            int getnameinfo_flags = NI_NUMERICSERV | NI_NUMERICHOST;
            char host[NI_MAXHOST];
            char service[NI_MAXSERV];
            int result = getnameinfo((struct sockaddr *) &client_address, address_len, host, NI_MAXHOST, service, NI_MAXSERV, getnameinfo_flags);
          
            // We sill store client's IP address as string for allowing IPv4 and IPv6 processing in same time
            std::string client_addres_in_string_format = std::string(host); 
            // logger<< log4cpp::Priority::INFO<<"We receive packet from IP: "<<client_addres_in_string_format; 

            // printf("We receive %d\n", received_bytes);
            process_netflow_packet((u_int8_t*)udp_buffer, received_bytes, client_addres_in_string_format);
        } else {
            logger<< log4cpp::Priority::ERROR<<"netflow data receive failed";
        }
    }

    freeaddrinfo(servinfo);
}

