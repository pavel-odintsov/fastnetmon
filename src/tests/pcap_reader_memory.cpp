#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <iomanip>

#include "../fastnetmon_pcap_format.h"
#include "../packet_storage.h"
#include "../fastnetmon_types.h"
#include "../fast_dpi.h"
#include "../fastnetmon_packet_parser.h"

#include <libndpi/ndpi_typedefs.h>

u_int32_t ndpi_size_flow_struct = 0;
u_int32_t ndpi_size_id_struct = 0;

struct ndpi_detection_module_struct* my_ndpi_struct = NULL;

ndpi_protocol dpi_parse_packet(char* buffer, uint32_t len, uint32_t snap_len, struct ndpi_id_struct *src, struct ndpi_id_struct *dst, struct ndpi_flow_struct *flow, std::string& parsed_packet_as_string, pkt_parsing_info& pkt_info) {
    struct pfring_pkthdr packet_header;
    memset(&packet_header, 0, sizeof(packet_header));
    packet_header.len = len;
    packet_header.caplen = snap_len;

    fastnetmon_parse_pkt((u_char*)buffer, &packet_header, 4, 1, 0);

    pkt_info = packet_header.extended_hdr.parsed_pkt;
    
    uint32_t current_tickt = 0;
    uint8_t* iph = (uint8_t*)(&buffer[packet_header.extended_hdr.parsed_pkt.offset.l3_offset]);
    unsigned int ipsize = packet_header.len;

    ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, flow, iph, ipsize, current_tickt, src, dst);

    // So bad approach :( 
    char print_buffer[512];
    fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &packet_header);

    parsed_packet_as_string = std::string(print_buffer);
 
    return detected_protocol;
}



void launch_bgp_flow_spec_rule(amplification_attack_type_t attack_type, std::string client_ip_as_string) {
    std::cout << "launch_bgp_flow_spec_rules(" << attack_type << ", " << client_ip_as_string << ")" << std::endl << "further processing of the flow spec rules not available in test mode" << std::endl;
}


void produce_dpi_dump_for_pcap_dump(struct attack_details& current_attack, std::string client_ip_as_string) {

    typedef unsigned short int port_counter[65535];
    
    port_counter *src_port_counters = (port_counter *) malloc(sizeof(port_counter));
    std::cout << "sizeof(port_counter)" << sizeof(port_counter) << std::endl;
    memset(src_port_counters, 0, sizeof(port_counter));

    port_counter *dst_port_counters = (port_counter *) malloc(sizeof(port_counter));
    memset(dst_port_counters, 0, sizeof(port_counter));

    ssize_t read_bytes;
    struct fastnetmon_pcap_file_header pcap_file_header;
            
    
    // the read_pos pointer should be on the buffer start because no one should read from the buffer. 
    //current_attack.pcap_attack_dump.rewind_read_pos();
    if (! current_attack.pcap_attack_dump.read_header(pcap_file_header) ) {
        std::cout << "produce_dpi_dump_for_pcap_dump: error reading pcap header. Stored bytes in pcap buffer:" << current_attack.pcap_attack_dump.get_used_memory() << std::endl;
        return;
    };
            
    
    // Buffer for packets
    char packet_buffer[pcap_file_header.snaplen];

    uint64_t total_packets_number       = 0;
    uint64_t dns_amplification_packets  = 0;
    uint64_t ntp_amplification_packets  = 0;
    uint64_t ssdp_amplification_packets = 0;
    uint64_t snmp_amplification_packets = 0;

    struct ndpi_id_struct *src = NULL;
    struct ndpi_id_struct *dst = NULL;
    struct ndpi_flow_struct *flow = NULL;
    
    src = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    dst = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    flow = (struct ndpi_flow_struct *)malloc(ndpi_size_flow_struct);

    while ( current_attack.pcap_attack_dump.bytes_to_read() ) {
        struct fastnetmon_pcap_pkthdr pcap_packet_header;
        
        if (! current_attack.pcap_attack_dump.read_packet_header(pcap_packet_header) ) {
            std::cout << "produce_dpi_dump_for_pcap_dump: error reading packet header" << std::endl;
            break;
        }
        
        if (! current_attack.pcap_attack_dump.read_packet_payload(&packet_buffer, sizeof(packet_buffer), pcap_packet_header.incl_len, &read_bytes) ) {
            if ( pcap_packet_header.incl_len != read_bytes ) {
                std::cout << "produce_dpi_dump_for_pcap_dump: error reading packet payload";
                break;
            }
        }
        
        memset(src, 0, ndpi_size_id_struct);
        memset(dst, 0, ndpi_size_id_struct);

        std::string parsed_packet_as_string;

        pkt_parsing_info pkt_info;
    
        // the flow must be reset to zero state - in other case the DPI will not detect all packets properly. 
        // To use flow properly there must be much more complicated code (with flow buffer for each flow probably)           
        // following code is copied from ndpi_free_flow() just to be sure there will be no memory leaks due to memset()
        if (flow->http.url) {
            ndpi_free(flow->http.url);
        };
        if (flow->http.content_type) {
            ndpi_free(flow->http.content_type);
        }
        //
        memset(flow, 0, ndpi_size_flow_struct);
        
        ndpi_protocol detected_protocol = dpi_parse_packet(packet_buffer, pcap_packet_header.orig_len, pcap_packet_header.incl_len, src, dst, flow, parsed_packet_as_string, pkt_info);

        char* protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.protocol);
        char* master_protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol);

        std::cout << parsed_packet_as_string << std::endl;
        std::cout << " protocol:" << protocol_name << ", master_protocol: " << master_protocol_name << std::endl;
        
        if (detected_protocol.protocol == NDPI_PROTOCOL_DNS) {
            // It's answer for ANY request with so much
            if (flow->protos.dns.query_type == 255 && flow->protos.dns.num_queries < flow->protos.dns.num_answers) {
                dns_amplification_packets++;
            }

        } else if (detected_protocol.protocol == NDPI_PROTOCOL_NTP) {
            // Detect packets with type MON_GETLIST_1
            if (flow->protos.ntp.version == 2 && flow->protos.ntp.request_code == 42) {
                ntp_amplification_packets++;
            }
        } else if (detected_protocol.protocol == NDPI_PROTOCOL_SSDP) {
            // So, this protocol completely unexpected in WAN networks
            ssdp_amplification_packets++;
        } else if (detected_protocol.protocol == NDPI_PROTOCOL_SNMP) {
            // TODO: we need detailed tests for SNMP!
            snmp_amplification_packets++;
        }

//        ss << parsed_packet_as_string << " protocol: " << protocol_name << " master_protocol: " << master_protocol_name << "\n";

        total_packets_number++;
        
        (*src_port_counters)[pkt_info.l4_src_port]++;
        (*dst_port_counters)[pkt_info.l4_dst_port]++;
        
    }

    // Free up all memory
    ndpi_free_flow(flow);
    free(dst);
    free(src);

    std::cout << "\n\nSrc and Dst port statistics (inactive ports skipped):\n";
    std::cout<< " Port |Src count|Dst count\n";
    
    for (int i = 0; i <= 65535; i++) {
        if ( ((*src_port_counters)[i] != 0) || ((*dst_port_counters)[i] != 0) ) {
            std::cout << std::setw(6) << i << "|" << std::setw(9) << (*src_port_counters)[i] << "|" << std::setw(9) << (*dst_port_counters)[i] << std::endl;
        };
    }

    amplification_attack_type_t attack_type;

    // Attack type in unknown by default
    attack_type = AMPLIFICATION_ATTACK_UNKNOWN;

    char buff[256];
                   
    snprintf(&buff[0],sizeof(buff)-1,"\nDPI pkt stats: total:%llu DNS:%llu NTP:%llu SSDP:%llu SNMP:%llu",
                                                  total_packets_number,
                                                  dns_amplification_packets,
                                                  ntp_amplification_packets,
                                                  ssdp_amplification_packets,
                                                  snmp_amplification_packets);
    std::cout << buff << std::endl;
                                                      
//    logger << log4cpp::Priority::INFO << buff;

    // Detect amplification attack type
    if ( (double)dns_amplification_packets / (double)total_packets_number > 0.1) {
//        attack_type = AMPLIFICATION_ATTACK_DNS;
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_DNS, client_ip_as_string);        
    } else if ( (double)ntp_amplification_packets / (double)total_packets_number > 0.1) {
//        attack_type = AMPLIFICATION_ATTACK_NTP;
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_NTP, client_ip_as_string);        
    } else if ( (double)ssdp_amplification_packets / (double)total_packets_number > 0.1) {
//        attack_type = AMPLIFICATION_ATTACK_SSDP;
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_SSDP, client_ip_as_string);        
    } else if ( (double)snmp_amplification_packets / (double)total_packets_number > 0.1) {
//        attack_type = AMPLIFICATION_ATTACK_SNMP;
        launch_bgp_flow_spec_rule(AMPLIFICATION_ATTACK_SNMP, client_ip_as_string);        
    } else {
        std::cout << "We can't detect attack type with DPI it's not so critical, only for your information";
        
/*TODO 
  - full IP ban should be announced here !        
  - and maybe some prptocol/port based statistics could be used to filter new/unknown attacks...
*/
    }
    
}

int main() {


    std::string file_path="/var/log/fastnetmon_attacks/test.pcap";
    std::string client_ip_as_string = "1.2.3.4";
    
    std::cout << "aaaa" << std::endl;
    
    ndpi_size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct(); 

    my_ndpi_struct = init_ndpi();   
                
    struct attack_details current_attack;  
    
    if (!current_attack.pcap_attack_dump.load_from_pcap_file(file_path)) {
        std::cout << "error reading file" << std::endl;
    };
                      
    produce_dpi_dump_for_pcap_dump(current_attack, client_ip_as_string);

    return(0);
}
