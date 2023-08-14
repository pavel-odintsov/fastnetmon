#include "libsflow.hpp"

#include <sstream>

// log4cpp logging facility
#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

extern log4cpp::Category& logger;

std::string sflow_parser_log_prefix = "sflow_parser ";

#define FMT_HEADER_ONLY
#include "../fmt/compile.h"
#include "../fmt/format.h"

// Convert scoped enum to internal integer representation
unsigned int get_flow_enum_type_as_number(const sflow_sample_type_t& value) {
    return static_cast<std::underlying_type<sflow_sample_type_t>::type>(value);
}

void build_ipv4_address_from_array(std::array<uint8_t, 4> ipv4_array_address, std::string& output_string) {
    // Use most efficient way to implement this transformation
    output_string = fmt::format(FMT_COMPILE("{}.{}.{}.{}"), int(ipv4_array_address[0]), int(ipv4_array_address[1]),
                                int(ipv4_array_address[2]), int(ipv4_array_address[3]));
}

std::string build_ipv6_address_from_array(std::array<uint8_t, 16> ipv6_array_address) {
    std::stringstream buffer;

    for (int index = 0; index < 16; index++) {
        buffer << std::ios_base::hex << int(ipv6_array_address[index]);

        if (index + 1 != 16) {
            buffer << ":";
        }
    }

    return buffer.str();
}

std::tuple<int32_t, int32_t> split_mixed_enterprise_and_format(int32_t enterprise_and_format) {
    // Get first 20 bits as enterprise
    int32_t enterprise = enterprise_and_format >> 12;

    // Get last 12 bits
    int32_t integer_format = enterprise_and_format & 0b00000000000000000000111111111111;

    return std::make_tuple(enterprise, integer_format);
}

// Convert arbitrary flow record structure with record samples to well formed
// data
bool get_records(std::vector<record_tuple_t>& vector_tuple,
                 uint8_t* flow_record_zone_start,
                 uint32_t number_of_flow_records,
                 uint8_t* current_packet_end,
                 bool& padding_found) {
    uint8_t* flow_record_start = flow_record_zone_start;

    for (uint32_t i = 0; i < number_of_flow_records; i++) {
        // Check that we have at least 2 4 byte integers here
        if (current_packet_end - flow_record_start < 8) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix
                   << "do not have enough space in packet to read flow type and length";
            return false;
        }

        int32_t element_type   = get_int_value_by_32bit_shift(flow_record_start, 0);
        int32_t element_length = get_int_value_by_32bit_shift(flow_record_start, 1);


        // sFlow v5 standard does not constrain size of each sample but
        // we need to apply some reasonable limits on this value to avoid possible integer overflows in boundary checks
        // code below and I've decided to limit sample size by maximum UDP packet size
        if (element_length > max_udp_packet_size) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "Element length " << element_length
                   << " exceeds maximum allowed size: " << max_udp_packet_size;

            return false;
        }

        uint8_t* flow_record_data_ptr = flow_record_start + sizeof(element_type) + sizeof(element_length);
        uint8_t* flow_record_end      = flow_record_data_ptr + element_length;

        if (flow_record_end > current_packet_end) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "flow record payload is outside packet bounds";
            return false;
        }

        vector_tuple.push_back(std::make_tuple(element_type, flow_record_data_ptr, element_length));

        flow_record_start = flow_record_end;
    }

    // Well, I do not think that we need this kind of check because it should be blocked in previous section but let's keep it
    int64_t packet_padding = current_packet_end - flow_record_start;

    if (packet_padding < 0) {
        logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "negative padding is not possible";
        return false;
    }

    // Return information that we found padding. Just for information purposes
    if (packet_padding != 0) {
        padding_found = true;
    }

    /*
     * I just discovered that Brocade devices (Brocade ICX6610) could add 4 byte padding at the end of packet.
     * So I see no reasons to return error here.
     */

    return true;
}

// Convert arbitrary data structure with samples to vector with meta data and
// pointers to real data
bool get_all_samples(std::vector<sample_tuple_t>& vector_sample,
                     uint8_t* samples_block_start,
                     uint8_t* total_packet_end,
                     int32_t samples_count,
                     bool& discovered_padding) {
    uint8_t* sample_start = samples_block_start;

    for (int i = 0; i < samples_count; i++) {
        if (total_packet_end - sample_start < 8) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "we do not have sample format and length information here";
            return false;
        }

        int32_t enterprise_with_format = get_int_value_by_32bit_shift(sample_start, 0);
        int32_t sample_length          = get_int_value_by_32bit_shift(sample_start, 1);

        // sFlow v5 standard does not constrain size of each sample but
        // we need to apply some reasonable limits on this value to avoid possible integer overflows in boundary checks
        // code below and I've decided to limit sample size by maximum UDP packet size
        if (sample_length > max_udp_packet_size) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "Sample length " << sample_length
                   << " exceeds maximum allowed size: " << max_udp_packet_size;

            return false;
        }

        // Get first 20 bits as enterprise
        int32_t enterprise = enterprise_with_format >> 12;

        // Get last 12 bits as format, zeroify first 20 bits
        int32_t integer_format = enterprise_with_format & 0b00000000000000000000111111111111;

        uint8_t* data_block_start = sample_start + sizeof(enterprise_with_format) + sizeof(sample_length);
        // Skip format,length and data
        uint8_t* this_sample_end = data_block_start + sample_length;

        // Check sample bounds inside packet
        if (this_sample_end > total_packet_end) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "we have tried to read outside the packet";

            return false;
        }

        vector_sample.push_back(std::make_tuple(enterprise, integer_format, data_block_start, sample_length));

        // This sample end become next sample start
        sample_start = this_sample_end;
    }

    // Sanity check! We should achieve end of whole packet in any case
    // We discovered that Brocade MLXe-4 adds 20 bytes at the end of sFlow packet and this check prevent FastNetMon from
    // correct work
    // And I do not think that this change could harm other customers
    if (sample_start != total_packet_end) {
        // logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix
        //       << "We haven't acheived end of whole packed due to some reasons! "
        //          "Some samples skipped";

        discovered_padding = true;
    }

    return true;
}

int32_t get_int_value_by_32bit_shift(uint8_t* payload_ptr, unsigned int shift) {
    return fast_ntoh(*(int32_t*)(payload_ptr + shift * 4));
}

bool get_all_counter_records(std::vector<counter_record_sample_t>& counter_record_sample_vector,
                             uint8_t* data_block_start,
                             uint8_t* data_block_end,
                             uint32_t number_of_records) {

    uint8_t* record_start = data_block_start;

    for (uint32_t i = 0; i < number_of_records; i++) {
        uint8_t* payload_ptr = record_start + sizeof(uint32_t) + sizeof(uint32_t);

        if (payload_ptr >= data_block_end) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "we could not read flow counter record, too short packet";
            return false;
        }

        int32_t enterprise_and_format = get_int_value_by_32bit_shift(record_start, 0);
        uint32_t record_length        = get_int_value_by_32bit_shift(record_start, 1);

        // sFlow v5 standard does not constrain size of each sample but
        // we need to apply some reasonable limits on this value to avoid possible integer overflows in boundary checks
        // code below and I've decided to limit sample size by maximum UDP packet size
        if (record_length > max_udp_packet_size) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "Record length " << record_length
                   << " exceeds maximum allowed size: " << max_udp_packet_size;

            return false;
        }

        uint8_t* current_record_end = payload_ptr + record_length;

        if (current_record_end > data_block_end) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "record payload is outside of record border";
            return false;
        }

        int32_t enterprise     = 0;
        int32_t integer_format = 0;

        std::tie(enterprise, integer_format) = split_mixed_enterprise_and_format(enterprise_and_format);

        // std::cout << "enterprise: " << enterprise << " integer_format: " <<
        // integer_format <<
        // std::endl;

        counter_record_sample_vector.push_back(std::make_tuple(enterprise, integer_format, record_length, payload_ptr));

        record_start = current_record_end;
    }

    if (record_start != data_block_end) {
        logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix
               << "we haven't read whole packet in counter record: " << record_start - data_block_end;
        return false;
    }

    return true;
}

sflow_sample_type_t sflow_sample_type_from_integer(int32_t format_as_integer) {
    if (format_as_integer < get_flow_enum_type_as_number(sflow_sample_type_t::FLOW_SAMPLE) ||
        format_as_integer > get_flow_enum_type_as_number(sflow_sample_type_t::EXPANDED_COUNTER_SAMPLE)) {

        return sflow_sample_type_t::BROKEN_TYPE;
    }

    return static_cast<sflow_sample_type_t>(format_as_integer);
}

bool read_sflow_header(uint8_t* payload_ptr, unsigned int payload_length, sflow_packet_header_unified_accessor& sflow_header_accessor) {
    // zero sized packet
    if (payload_ptr == NULL || payload_length == 0) {
        logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "zero sized packet could not be parsed";
        return false;
    }

    // if received packet is smaller than smallest possible header size
    if (payload_length < sizeof(sflow_packet_header_v4_t)) {
        logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "received packet too small. It shorter than sFlow header";
        return false;
    }

    int32_t sflow_version = get_int_value_by_32bit_shift(payload_ptr, 0);

    if (sflow_version != 5) {
        logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "We do not support sFlow version " << sflow_version;
        return false;
    }

    int32_t ip_protocol_version = get_int_value_by_32bit_shift(payload_ptr, 1);

    if (ip_protocol_version == 1) {
        // IPv4
        sflow_packet_header_v4_t sflow_v4_header_struct;
        memcpy(&sflow_v4_header_struct, payload_ptr, sizeof(sflow_v4_header_struct));

        // Convert all 32 bit values from network byte order to host byte order
        sflow_v4_header_struct.network_to_host_byte_order();

        // sflow_v4_header_struct.print();

        sflow_header_accessor = sflow_v4_header_struct;
    } else if (ip_protocol_version == 2) {
        // IPv6

        // Check for packet length
        if (payload_length < sizeof(sflow_packet_header_v6_t)) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "received packet too small for IPv6 sFlow packet.";
            return false;
        }

        sflow_packet_header_v6_t sflow_v6_header_struct;
        memcpy(&sflow_v6_header_struct, payload_ptr, sizeof(sflow_v6_header_struct));

        sflow_v6_header_struct.network_to_host_byte_order();

        // Create unified accessor format
        sflow_header_accessor = sflow_v6_header_struct;
    } else {
        logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "Unknown ip protocol version for sFlow: " << ip_protocol_version;
        return false;
    }

    return true;
}

std::string print_counter_record_sample_vector(const std::vector<counter_record_sample_t>& counter_record_sample_vector) {
    std::stringstream buffer;

    int index = 0;
    for (auto counter_record_sample : counter_record_sample_vector) {
        buffer << "index: " << index << " enterprise: " << std::get<0>(counter_record_sample)
               << " format: " << std::get<1>(counter_record_sample) << " length: "
               << std::get<2>(counter_record_sample)
               //<< " pointer: " << (void*)std::get<3>(counter_record_sample);
               << " pointer: "
               << "XXX";

        index++;

        if (counter_record_sample_vector.size() != index) {
            buffer << ",";
        }
    }

    return buffer.str();
}

std::string print_vector_sample_tuple(const std::vector<sample_tuple_t>& vector_sample_tuple) {
    std::stringstream buffer;

    int index = 0;
    for (auto sample_tuple : vector_sample_tuple) {
        buffer << "index: " << index << " enterprise: " << std::get<0>(sample_tuple) << " format: "
               << std::get<1>(sample_tuple)
               //<< " pointer: " << (void*)std::get<2>(sample_tuple)
               << " pointer: "
               << "XXX"
               << " length: " << std::get<3>(sample_tuple);

        index++;

        if (vector_sample_tuple.size() != index) {
            buffer << ",";
        }
    }

    return buffer.str();
}

bool read_sflow_counter_header(uint8_t* data_pointer,
                               size_t data_length,
                               bool expanded,
                               sflow_counter_header_unified_accessor_t& sflow_counter_header_unified_accessor) {

    if (expanded) {
        // Expanded format

        if (data_length < sizeof(sflow_counter_expanded_header_t)) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "could not read counter_sample reader, too short packet";
            return false;
        }

        sflow_counter_expanded_header_t sflow_counter_expanded_header;
        memcpy(&sflow_counter_expanded_header, data_pointer, sizeof(sflow_counter_expanded_header_t));

        sflow_counter_expanded_header.network_to_host_byte_order();
        // sflow_counter_expanded_header.print();

        sflow_counter_header_unified_accessor = sflow_counter_expanded_header;
    } else {
        // Not expanded format

        if (data_length < sizeof(sflow_counter_header_t)) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "could not read counter_sample reader, too short packet";
            return false;
        }

        sflow_counter_header_t sflow_counter_header;
        memcpy(&sflow_counter_header, data_pointer, sizeof(sflow_counter_header_t));

        sflow_counter_header.network_to_host_byte_order();
        // sflow_counter_header.print();

        sflow_counter_header_unified_accessor = sflow_counter_header;
    }

    return true;
}

std::tuple<uint32_t, uint32_t> split_32bit_integer_by_8_and_24_bits(uint32_t original_data) {
    uint32_t extracted_8bit_data   = original_data >> 24;
    uint32_t extracted_24_bit_data = original_data & 0x0fffffff;

    return std::make_tuple(extracted_8bit_data, extracted_24_bit_data);
}

std::tuple<uint32_t, uint32_t> split_32bit_integer_by_2_and_30_bits(uint32_t original_data) {
    uint32_t extracted_2bit_data  = original_data >> 30;
    uint32_t extracted_30bit_data = original_data & 0b00111111111111111111111111111111;

    return std::make_tuple(extracted_2bit_data, extracted_30bit_data);
}

bool read_sflow_sample_header_unified(sflow_sample_header_unified_accessor_t& sflow_sample_header_unified_accessor,
                                      uint8_t* data_pointer,
                                      size_t data_length,
                                      bool expanded) {

    if (expanded) {
        if (data_length < sizeof(sflow_sample_expanded_header_t)) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "we have so short packet for FLOW_SAMPLE";
            return false;
        }

        sflow_sample_expanded_header_t sflow_sample_expanded_header;
        memcpy(&sflow_sample_expanded_header, data_pointer, sizeof(sflow_sample_expanded_header_t));
        sflow_sample_expanded_header.network_to_host_byte_order();

        sflow_sample_header_unified_accessor = sflow_sample_expanded_header;
    } else {
        // So short data block length
        if (data_length < sizeof(sflow_sample_header_t)) {
            logger << log4cpp::Priority::ERROR << sflow_parser_log_prefix << "we have so short packet for FLOW_SAMPLE";
            return false;
        }

        sflow_sample_header_t flow_sample_header;
        memcpy(&flow_sample_header, data_pointer, sizeof(flow_sample_header));
        flow_sample_header.network_to_host_byte_order();

        sflow_sample_header_unified_accessor = flow_sample_header;
    }

    return true;
}

std::string print_vector_tuple(const std::vector<record_tuple_t>& vector_tuple) {
    std::stringstream buffer;

    int index = 0;

    for (record_tuple_t record_tuple : vector_tuple) {

        buffer << "index: " << index << " "
               << "type: " << std::get<0>(record_tuple) << " "
               << "length: " << std::get<2>(record_tuple);

        index++;

        if (vector_tuple.size() != index) {
            buffer << ",";
        }
    }

    return buffer.str();
}
