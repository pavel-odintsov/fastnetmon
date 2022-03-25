#include <climits>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <sys/types.h>
#include <type_traits>

#include "../libsflow/libsflow.h"
#include "sflow_collector.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// UDP server
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../fast_library.h"

#include "../all_logcpp_libraries.h"

extern log4cpp::Category& logger;

#include "../simple_packet_parser_ng.h"

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// Number of raw packets received without any errors
uint64_t raw_udp_packets_received = 0;


// We have an option to use IP length from the packet header because some vendors may lie about it: https://github.com/pavel-odintsov/fastnetmon/issues/893
bool sflow_read_packet_length_from_ip_header = false;

// Number of failed receives
uint64_t udp_receive_errors = 0;

// sFLOW v4 specification: http://www.sflow.org/rfc3176.txt

std::string plugin_name       = "sflow";
std::string plugin_log_prefix = plugin_name + ": ";

uint64_t sflow_total_packets = 0;

// Incorrectly crafted sflow packets
uint64_t sflow_bad_packets = 0;

// Number of flow samples, i.e. with packet headers
uint64_t sflow_flow_samples = 0;

// Number of broken flow samples
uint64_t sflow_bad_flow_samples = 0;

// Number of packets where we have padding at the end of packet
uint64_t sflow_with_padding_at_the_end_of_packet = 0;

// Number of packets with padding inside flow sample
uint64_t sflow_padding_flow_sample = 0;

// Number of packet headers from flow samples which could not be decoded correctly
uint64_t sflow_parse_error_nested_header = 0;

// Number of counter samples, i.e. with port counters
uint64_t sflow_counter_sample = 0;

uint64_t sflow_raw_packet_headers_total = 0;

// Number of records with extended information from routers
uint64_t sflow_extended_router_data_records = 0;

// For switch data
uint64_t sflow_extended_switch_data_records = 0;

// For gateway data
uint64_t sflow_extended_gateway_data_records = 0;

// Prototypes

bool process_sflow_counter_sample(uint8_t* data_pointer,
                                  size_t data_length,
                                  bool expanded,
                                  const sflow_packet_header_unified_accessor& sflow_header_accessor);
process_packet_pointer sflow_process_func_ptr = NULL;

void start_sflow_collector(std::string interface_for_binding, unsigned int sflow_port);

// Initialize sflow module, we need it for allocation per module structures
void init_sflow_module() {
}

// Deinitilize sflow module, we need it for deallocation module structures
void deinit_sflow_module() {
}

void start_sflow_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << plugin_log_prefix << "plugin started";
    sflow_process_func_ptr = func_ptr;

    
    std::string sflow_ports_string = "";

    if (configuration_map.count("sflow_port") != 0) {
        sflow_ports_string = configuration_map["sflow_port"];
    }

    std::vector<std::string> sflow_ports_for_listen;
    boost::split(sflow_ports_for_listen, sflow_ports_string, boost::is_any_of(","), boost::token_compress_on);

    std::vector<unsigned int> sflow_ports;

    for (auto port_string: sflow_ports_for_listen) {
        unsigned int sflow_port = convert_string_to_integer(port_string);

	    if (sflow_port == 0) {
	         logger << log4cpp::Priority::ERROR << plugin_log_prefix << "Cannot parse port: " << port_string;
             continue; 
	    }

    	sflow_ports.push_back(sflow_port);
    }

    if (sflow_ports.size() == 0) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "Please specify least single port for sflow_port field!";
        return;
    }

    logger << log4cpp::Priority::INFO << plugin_log_prefix << "We parsed "
           << sflow_ports.size() << " ports for sflow";

    boost::thread_group sflow_collector_threads;

    logger << log4cpp::Priority::INFO << plugin_log_prefix << "We will listen on "
           << sflow_ports.size() << " ports";

    std::string sflow_host;

    if (configuration_map.count("sflow_host") != 0) {
        sflow_host = configuration_map["sflow_host"];
    }

    if (configuration_map.count("sflow_read_packet_length_from_ip_header") != 0) {
        sflow_read_packet_length_from_ip_header =
        configuration_map["sflow_read_packet_length_from_ip_header"] == "on";
    }

    for (auto sflow_port: sflow_ports) {
        sflow_collector_threads.add_thread(
            new boost::thread(start_sflow_collector, sflow_host, sflow_port));
    }

    sflow_collector_threads.join_all();
}

void start_sflow_collector(std::string interface_for_binding, unsigned int sflow_port) {

    logger << log4cpp::Priority::INFO << plugin_log_prefix << "plugin will listen on " << interface_for_binding << ":"
           << sflow_port << " udp port";

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
    int bind_result   = bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    if (bind_result) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "can't listen port: " << sflow_port << " on host "
               << interface_for_binding;
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    /* We should specify timeout there for correct toolkit shutdown */
    /* Because otherwise recvfrom will stay in blocked mode forever */
    struct timeval tv;
    tv.tv_sec  = 1; /* X Secs Timeout */
    tv.tv_usec = 0; // Not init'ing this can cause strange errors

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t address_len = sizeof(client_addr);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr*)&client_addr, &address_len);

        if (received_bytes > 0) {
            raw_udp_packets_received++;

            uint32_t client_ipv4_address = 0;

            if (client_addr.sin_family == AF_INET) {
                client_ipv4_address = client_addr.sin_addr.s_addr;
                // logger << log4cpp::Priority::ERROR << "client ip: " << convert_ip_as_uint_to_string(client_ipv4_address);
            } else if (client_addr.sin_family == AF_INET6) {
                // We do not support them now
            } else {
                // Should not happen
            }

            parse_sflow_v5_packet((uint8_t*)udp_buffer, received_bytes, client_ipv4_address);
        } else {
            udp_receive_errors++;

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

bool process_sflow_flow_sample(uint8_t* data_pointer,
                               size_t data_length,
                               bool expanded,
                               const sflow_packet_header_unified_accessor& sflow_header_accessor,
                               uint32_t client_ipv4_address) {
    uint8_t* current_packet_end = data_pointer + data_length;

    sflow_sample_header_unified_accessor_t sflow_sample_header_unified_accessor;

    bool read_sflow_sample_header_unified_result =
        read_sflow_sample_header_unified(sflow_sample_header_unified_accessor, data_pointer, data_length, expanded);

    if (!read_sflow_sample_header_unified_result) {
        sflow_bad_flow_samples++;
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "could not read sample header from the packet";
        return false;
    }

    if (sflow_sample_header_unified_accessor.get_number_of_flow_records() == 0) {
        sflow_bad_flow_samples++;
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "for some strange reasons we got zero flow records";
        return false;
    }

    uint8_t* flow_record_zone_start = data_pointer + sflow_sample_header_unified_accessor.get_original_payload_length();

    vector_tuple_t vector_tuple;

    bool padding_found = false;

    bool get_records_result =
        get_records(vector_tuple, flow_record_zone_start,
                    sflow_sample_header_unified_accessor.get_number_of_flow_records(), current_packet_end, padding_found);

    // I think that it's pretty important to have counter for this case
    if (padding_found) {
        sflow_padding_flow_sample++;
    }

    if (!get_records_result) {
        sflow_bad_flow_samples++;
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "Could not get records for some reasons";
        return false;
    }

    simple_packet_t packet;
    packet.source = SFLOW;

    packet.agent_ip_address = client_ipv4_address;

    for (auto record : vector_tuple) {
        int32_t record_type   = std::get<0>(record);
        uint8_t* payload_ptr  = std::get<1>(record);
        int32_t record_length = std::get<2>(record);

        // std::cout << "flow record " << " record_type: " << record_type
        //    << " record_length: " << record_length << std::endl;

        // raw packet header we support only it
        if (record_type == SFLOW_RECORD_TYPE_RAW_PACKET_HEADER) {
            sflow_raw_packet_headers_total++;

            sflow_raw_protocol_header_t sflow_raw_protocol_header;
            memcpy(&sflow_raw_protocol_header, payload_ptr, sizeof(sflow_raw_protocol_header_t));

            sflow_raw_protocol_header.network_to_host_byte_order();
            sflow_raw_protocol_header.print();

            uint8_t* header_payload_pointer = payload_ptr + sizeof(sflow_raw_protocol_header_t);

  	        // We could enable this new parser for testing purposes
	        auto result = parse_raw_packet_to_simple_packet_full_ng(header_payload_pointer,
								sflow_raw_protocol_header.frame_length_before_sampling,
								sflow_raw_protocol_header.header_size, packet,
								sflow_read_packet_length_from_ip_header);

	        if (result != network_data_stuctures::parser_code_t::success) {
	            sflow_parse_error_nested_header++;

	            logger << log4cpp::Priority::DEBUG << plugin_log_prefix
		            << "Cannot parse nested packet using ng parser: " << parser_code_to_string(result);

	            return false;
            }

            // Pass pointer to raw header to FastNetMon processing functions
            packet.packet_payload_pointer     = header_payload_pointer;
            packet.packet_payload_full_length = sflow_raw_protocol_header.frame_length_before_sampling;
            packet.packet_payload_length      = sflow_raw_protocol_header.header_size;

            packet.sample_ratio = sflow_sample_header_unified_accessor.sampling_rate;

            // std::cout << print_simple_packet(packet) << std::endl;

        } else if (record_type == SFLOW_RECORD_TYPE_EXTENDED_ROUTER_DATA) {
            sflow_extended_router_data_records++;
        } else if (record_type == SFLOW_RECORD_TYPE_EXTENDED_SWITCH_DATA) {
            sflow_extended_switch_data_records++;
        } else if (record_type == SFLOW_RECORD_TYPE_EXTENDED_GATEWAY_DATA) {
            sflow_extended_gateway_data_records++;

            if (record_length < sizeof(uint32_t)) {
                logger << log4cpp::Priority::ERROR << "Extended gateway data is too short: " << record_length;

                return false;
            }

            // First field here is address type for nexthop
            uint32_t nexthop_address_type = 0;

            memcpy(&nexthop_address_type, payload_ptr, sizeof(uint32_t));

            if (fast_ntoh(nexthop_address_type) == SFLOW_ADDRESS_TYPE_IPv4) {
                // We can parse first more important for us fields from gateway structure
                if (record_length < sizeof(sflow_extended_gateway_information_t)) {
                    logger << log4cpp::Priority::ERROR << "Extended gateway data is too short for IPv structure: " << record_length;
                    return false;
                }

                // We're ready to parse it
                sflow_extended_gateway_information_t* gateway_details = (sflow_extended_gateway_information_t*)payload_ptr;

                packet.src_asn = fast_ntoh(gateway_details->router_asn);
                packet.dst_asn = fast_ntoh(gateway_details->source_asn);
            }

            // logger << log4cpp::Priority::DEBUG << "Address type: " << fast_ntoh(*address_type);
        } else {
            // unknown type
        }
    }

    sflow_process_func_ptr(packet);

    return true;
}

// Read sFLOW packet header
// Awesome description about v5 format from AMX-IX folks:
// Header structure from AMS-IX folks:
// http://www.sflow.org/developers/diagrams/sFlowV5Datagram.pdf
void parse_sflow_v5_packet(uint8_t* payload_ptr, unsigned int payload_length, uint32_t client_ipv4_address) {
    sflow_packet_header_unified_accessor sflow_header_accessor;
    uint8_t* total_packet_end = payload_ptr + payload_length;

    // Increase total number of packets
    sflow_total_packets++;

    bool read_sflow_header_result = read_sflow_header(payload_ptr, payload_length, sflow_header_accessor);

    if (!read_sflow_header_result) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "could not read sflow packet header correctly";
        sflow_bad_packets++;
        return;
    }

    if (sflow_header_accessor.get_datagram_samples_count() <= 0) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix
               << "Strange number of sFLOW samples: " << sflow_header_accessor.get_datagram_samples_count();
        sflow_bad_packets++;
        return;
    }

    vector_sample_tuple_t samples_vector;

    uint8_t* samples_block_start = payload_ptr + sflow_header_accessor.get_original_payload_length();

    bool discovered_padding = false;

    bool get_all_samples_result = get_all_samples(samples_vector, samples_block_start, total_packet_end,
                                                  sflow_header_accessor.get_datagram_samples_count(), discovered_padding);

    if (!get_all_samples_result) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we could not extract all samples from packet";
        sflow_bad_packets++;
        return;
    }

    if (discovered_padding) {
        sflow_with_padding_at_the_end_of_packet++;
    }

    for (auto sample : samples_vector) {
        // enterprise, sample_format, data start address, data region length
        // std::cout << "We process #" << i << " sample with format " << format
        //    << " enterprise " << enterprise
        //    << " and length " << sample_length << std::endl;

        int32_t enterprise     = std::get<0>(sample);
        int32_t integer_format = std::get<1>(sample);
        uint8_t* data_pointer  = std::get<2>(sample);
        size_t data_length     = std::get<3>(sample);

        uint8_t* current_packet_end = data_pointer + data_length;

        if (enterprise == 0) {
            sflow_sample_type_t sample_format = sflow_sample_type_from_integer(integer_format);

            if (sample_format == sflow_sample_type_t::BROKEN_TYPE) {
                logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we got broken format type number: " << integer_format;

                return;
            }

            // Move this code to separate function!!!
            if (sample_format == sflow_sample_type_t::FLOW_SAMPLE) {
                // std::cout << "We got flow sample" << std::endl;
                process_sflow_flow_sample(data_pointer, data_length, false, sflow_header_accessor, client_ipv4_address);
                sflow_flow_samples++;
            } else if (sample_format == sflow_sample_type_t::COUNTER_SAMPLE) {
                // std::cout << "We got counter sample" << std::endl;
                // TODO: add support for sflow counetrs
                // process_sflow_counter_sample(data_pointer, data_length, false, sflow_header_accessor);
                sflow_counter_sample++;
            } else if (sample_format == sflow_sample_type_t::EXPANDED_FLOW_SAMPLE) {
                // std::cout << "We got expanded flow sample" << std::endl;
                process_sflow_flow_sample(data_pointer, data_length, true, sflow_header_accessor, client_ipv4_address);
                sflow_flow_samples++;
            } else if (sample_format == sflow_sample_type_t::EXPANDED_COUNTER_SAMPLE) {
                // TODO:add support for sflow counetrs
                // std::cout << "We got expanded counter sample" << std::endl;
                ////process_sflow_counter_sample(data_pointer, data_length, true, sflow_header_accessor);
                sflow_counter_sample++;
            } else {
                logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we got broken format type: " << integer_format;
            }
        } else {
            // do nothing because we haven't support for custom sFLOW data formats
        }
    }
}

bool process_sflow_counter_sample(uint8_t* data_pointer,
                                  size_t data_length,
                                  bool expanded,
                                  const sflow_packet_header_unified_accessor& sflow_header_accessor) {
    sflow_counter_header_unified_accessor_t sflow_counter_header_unified_accessor;

    bool read_sflow_counter_header_result =
        read_sflow_counter_header(data_pointer, data_length, expanded, sflow_counter_header_unified_accessor);

    if (!read_sflow_counter_header_result) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "could not read sflow counter header";
        return false;
    }

    if (sflow_counter_header_unified_accessor.get_number_of_counter_records() == 0) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "get zero number of counter records";
        return false;
    }

    counter_record_sample_vector_t counter_record_sample_vector;

    bool get_all_counter_records_result =
        get_all_counter_records(counter_record_sample_vector,
                                data_pointer + sflow_counter_header_unified_accessor.get_original_payload_length(),
                                data_pointer + data_length,
                                sflow_counter_header_unified_accessor.get_number_of_counter_records());

    if (!get_all_counter_records_result) {
        logger << log4cpp::Priority::ERROR << plugin_log_prefix << "could not get all counter records";
        return false;
    }

    for (auto counter_record : counter_record_sample_vector) {
        uint32_t enterprise   = 0;
        uint32_t format       = 0;
        ssize_t length        = 0;
        uint8_t* data_pointer = nullptr;

        std::tie(enterprise, format, length, data_pointer) = counter_record;

        if (enterprise == 0) {
            sample_counter_types_t sample_type = sample_counter_types_t::BROKEN_COUNTER;
            ;

            if (format == 1) {
                sample_type = sample_counter_types_t::GENERIC_INTERFACE_COUNTERS;
            } else if (format == 2) {
                sample_type = sample_counter_types_t::ETHERNET_INTERFACE_COUNTERS;
            }

            if (sample_type == sample_counter_types_t::ETHERNET_INTERFACE_COUNTERS) {
                // std::cout << "ETHERNET_INTERFACE_COUNTERS" << std::endl;

                if (sizeof(ethernet_sflow_interface_counters_t) != length) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we haven't enough data for ethernet counter packet";
                    return false;
                }

                ethernet_sflow_interface_counters_t ethernet_counters(data_pointer);
                // std::cout << ethernet_counters.print() << std::endl;
            }

            if (sample_type == sample_counter_types_t::GENERIC_INTERFACE_COUNTERS) {
                // std::cout << "GENERIC_INTERFACE_COUNTERS" << std::endl;

                if (sizeof(generic_sflow_interface_counters_t) != length) {
                    logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we haven't enough data for generic packet";
                    return false;
                }

                generic_sflow_interface_counters_t generic_sflow_interface_counters(data_pointer);
                // std::cout << generic_sflow_interface_counters.print() << std::endl;
            }
        } else {
            logger << log4cpp::Priority::ERROR << plugin_log_prefix << "we do not support vendor specific enterprise numbers";
        }

        // std::cout << "Counter record" << std::endl;
    }

    return true;
}
