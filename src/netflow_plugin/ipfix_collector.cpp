#include <cstdint>
#include <fstream>
#include <string>

#include "../fast_library.hpp"

#include "netflow.hpp"

#include "ipfix_metrics.hpp"

#include "netflow_template.hpp"

#include "netflow_meta_info.hpp"

// We use structures defined in netflow_meta_info.hpp here
#include "ipfix.hpp"

#include "netflow_v9.hpp"

#include "../ipfix_fields/ipfix_rfc.hpp"

#include "../simple_packet_parser_ng.hpp"

#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>

#include <boost/archive/xml_iarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>

#include "../fastnetmon_configuration_scheme.hpp"

// TODO: get rid of such tricks

const template_t* peer_find_template(const std::map<std::string, std::map<uint32_t, template_t>>& table_for_lookup,
                                     std::mutex& table_for_lookup_mutex,
                                     uint32_t source_id,
                                     uint32_t template_id,
                                     const std::string& client_addres_in_string_format);

void add_update_peer_template(const netflow_protocol_version_t& netflow_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_addres_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template);

void update_device_flow_timeouts(const device_timeouts_t& device_timeouts,
                                 std::mutex& structure_mutex,
                                 std::map<std::string, device_timeouts_t>& timeout_storage,
                                 const std::string& client_addres_in_string_format,
                                 const netflow_protocol_version_t& netflow_protocol_version);

void override_packet_fields_from_nested_packet(simple_packet_t& packet, const simple_packet_t& nested_packet);

ipfix_information_database ipfix_db_instance;

extern uint64_t template_netflow_ipfix_disk_writes;

extern uint64_t netflow_ignored_long_flows;

extern uint64_t netflow_ipfix_all_protocols_total_flows;

extern uint64_t sets_per_packet_maximum_number;

extern process_packet_pointer netflow_process_func_ptr;

// Prototypes
void save_ipfix_sampling_rates_to_disk();

// Access to inaccurate but fast time
extern time_t current_inaccurate_time;

extern log4cpp::Category& logger;

extern fastnetmon_configuration_t fastnetmon_global_configuration;

void update_ipfix_sampling_rate(uint32_t sampling_rate, const std::string& client_addres_in_string_format);

std::mutex global_ipfix_templates_mutex;
std::map<std::string, std::map<uint32_t, template_t>> global_ipfix_templates;

// IPFIX Sampling rates
std::mutex ipfix_sampling_rates_mutex;
std::map<std::string, uint32_t> ipfix_sampling_rates;

// IPFIX per device timeouts
std::mutex ipfix_per_device_flow_timeouts_mutex;
std::map<std::string, device_timeouts_t> ipfix_per_device_flow_timeouts;

// TODO: get rid of it ASAP
// Copy an int (possibly shorter than the target) keeping their LSBs aligned
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - record_length), data, record_length);

// Return sampling rate for each device which sends data to us
std::vector<system_counter_t> get_ipfix_sampling_rates() {
    std::vector<system_counter_t> system_counters;

    // It should be enough in common cases
    system_counters.reserve(15);

    {
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);

        // Copy all elements to output
        for (auto& elem : ipfix_sampling_rates) {
            system_counters.push_back(system_counter_t(elem.first, (uint64_t)elem.second, metric_type_t::gauge, "Sampling rate"));
        }
    }

    return system_counters;
}

std::vector<system_counter_t> get_ipfix_stats() {
    std::vector<system_counter_t> system_counter;

    system_counter.push_back(system_counter_t("ipfix_total_flows", ipfix_total_flows, metric_type_t::counter, ipfix_total_flows_desc));
    system_counter.push_back(
        system_counter_t("ipfix_total_packets", ipfix_total_packets, metric_type_t::counter, ipfix_total_packets_desc));
    system_counter.push_back(system_counter_t("ipfix_total_ipv4_flows", ipfix_total_ipv4_flows, metric_type_t::counter,
                                              ipfix_total_ipv4_flows_desc));
    system_counter.push_back(system_counter_t("ipfix_total_ipv6_flows", ipfix_total_ipv6_flows, metric_type_t::counter,
                                              ipfix_total_ipv6_flows_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_0_seconds", ipfix_duration_0_seconds,
                                              metric_type_t::counter, ipfix_duration_0_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_less_1_seconds", ipfix_duration_less_1_seconds,
                                              metric_type_t::counter, ipfix_duration_less_1_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_less_2_seconds", ipfix_duration_less_2_seconds,
                                              metric_type_t::counter, ipfix_duration_less_2_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_less_3_seconds", ipfix_duration_less_3_seconds,
                                              metric_type_t::counter, ipfix_duration_less_3_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_less_5_seconds", ipfix_duration_less_5_seconds,
                                              metric_type_t::counter, ipfix_duration_less_5_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_less_10_seconds", ipfix_duration_less_10_seconds,
                                              metric_type_t::counter, ipfix_duration_less_10_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_less_15_seconds", ipfix_duration_less_15_seconds,
                                              metric_type_t::counter, ipfix_duration_less_15_seconds_desc));
    system_counter.push_back(system_counter_t("ipfix_duration_less_30_seconds", ipfix_duration_less_30_seconds,
                                              metric_type_t::counter, ipfix_duration_less_30_seconds_desc));
    system_counter.push_back(system_counter_t("ipfix_duration_less_60_seconds", ipfix_duration_less_60_seconds,
                                              metric_type_t::counter, ipfix_duration_less_60_seconds_desc));
    system_counter.push_back(system_counter_t("ipfix_duration_less_90_seconds", ipfix_duration_less_90_seconds,
                                              metric_type_t::counter, ipfix_duration_less_90_seconds_desc));
    system_counter.push_back(system_counter_t("ipfix_duration_less_180_seconds", ipfix_duration_less_180_seconds,
                                              metric_type_t::counter, ipfix_duration_less_180_seconds_desc));
    system_counter.push_back(system_counter_t("ipfix_duration_exceed_180_seconds", ipfix_duration_exceed_180_seconds,
                                              metric_type_t::counter, ipfix_duration_exceed_180_seconds_desc));

    system_counter.push_back(system_counter_t("ipfix_duration_negative", ipfix_duration_negative,
                                              metric_type_t::counter, ipfix_duration_negative_desc));

    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_idle_timeout", ipfix_flows_end_reason_idle_timeout,
                                              metric_type_t::counter, ipfix_flows_end_reason_idle_timeout_desc));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_active_timeout", ipfix_flows_end_reason_active_timeout,
                                              metric_type_t::counter, ipfix_flows_end_reason_active_timeout_desc));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_end_of_flow_timeout", ipfix_flows_end_reason_end_of_flow_timeout,
                                              metric_type_t::counter, ipfix_flows_end_reason_end_of_flow_timeout_desc));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_force_end_timeout", ipfix_flows_end_reason_force_end_timeout,
                                              metric_type_t::counter, ipfix_flows_end_reason_force_end_timeout_desc));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_lack_of_resource_timeout",
                                              ipfix_flows_end_reason_lack_of_resource_timeout, metric_type_t::counter,
                                              ipfix_flows_end_reason_lack_of_resource_timeout_desc));

    system_counter.push_back(system_counter_t("ipfix_data_packet_number", ipfix_data_packet_number,
                                              metric_type_t::counter, ipfix_data_packet_number_desc));
    system_counter.push_back(system_counter_t("ipfix_data_templates_number", ipfix_data_templates_number,
                                              metric_type_t::counter, ipfix_data_templates_number_desc));
    system_counter.push_back(system_counter_t("ipfix_options_templates_number", ipfix_options_templates_number,
                                              metric_type_t::counter, ipfix_options_templates_number_desc));
    system_counter.push_back(system_counter_t("ipfix_options_packet_number", ipfix_options_packet_number,
                                              metric_type_t::counter, ipfix_options_packet_number_desc));
    system_counter.push_back(system_counter_t("ipfix_packets_with_unknown_templates", ipfix_packets_with_unknown_templates,
                                              metric_type_t::counter, ipfix_packets_with_unknown_templates_desc));
    system_counter.push_back(system_counter_t("ipfix_custom_sampling_rate_received", ipfix_custom_sampling_rate_received,
                                              metric_type_t::counter, ipfix_custom_sampling_rate_received_desc));
    system_counter.push_back(system_counter_t("ipfix_sampling_rate_changes", ipfix_sampling_rate_changes,
                                              metric_type_t::counter, ipfix_sampling_rate_changes_desc));
    system_counter.push_back(system_counter_t("ipfix_marked_zero_next_hop_and_zero_output_as_dropped",
                                              ipfix_marked_zero_next_hop_and_zero_output_as_dropped, metric_type_t::counter,
                                              ipfix_marked_zero_next_hop_and_zero_output_as_dropped_desc));
    system_counter.push_back(system_counter_t("ipfix_template_updates_number_due_to_real_changes", ipfix_template_data_updates,
                                              metric_type_t::counter, ipfix_template_data_updates_desc));
    system_counter.push_back(system_counter_t("ipfix_packets_with_padding", ipfix_packets_with_padding,
                                              metric_type_t::counter, ipfix_packets_with_padding_desc));
    system_counter.push_back(system_counter_t("ipfix_inline_headers", ipfix_inline_headers, metric_type_t::counter,
                                              ipfix_inline_headers_desc));
    system_counter.push_back(system_counter_t("ipfix_protocol_version_adjustments", ipfix_protocol_version_adjustments,
                                              metric_type_t::counter, ipfix_protocol_version_adjustments_desc));
    system_counter.push_back(system_counter_t("ipfix_too_large_field", ipfix_too_large_field, metric_type_t::counter,
                                              ipfix_too_large_field_desc));
    system_counter.push_back(system_counter_t("ipfix_forwarding_status", ipfix_forwarding_status,
                                              metric_type_t::counter, ipfix_forwarding_status_desc));
    system_counter.push_back(system_counter_t("ipfix_inline_header_parser_error", ipfix_inline_header_parser_error,
                                              metric_type_t::counter, ipfix_inline_header_parser_error_desc));

    system_counter.push_back(system_counter_t("ipfix_inline_encoding_error", ipfix_inline_encoding_error,
                                              metric_type_t::counter, ipfix_inline_encoding_error_desc));

    system_counter.push_back(system_counter_t("ipfix_inline_header_parser_success", ipfix_inline_header_parser_success,
                                              metric_type_t::counter, ipfix_inline_header_parser_success_desc));

    system_counter.push_back(system_counter_t("ipfix_active_flow_timeout_received", ipfix_active_flow_timeout_received,
                                              metric_type_t::counter, ipfix_active_flow_timeout_received_desc));
    system_counter.push_back(system_counter_t("ipfix_inactive_flow_timeout_received", ipfix_inactive_flow_timeout_received,
                                              metric_type_t::counter, ipfix_inactive_flow_timeout_received_desc));

    system_counter.push_back(system_counter_t("ipfix_sets_with_anomaly_padding", ipfix_sets_with_anomaly_padding,
                                              metric_type_t::counter, ipfix_sets_with_anomaly_padding_desc));

    return system_counter;
}

// Checks that all bytes in range are zero
bool are_all_padding_bytes_are_zero(const uint8_t* padding_start_in_packet, int64_t padding_length) {
    logger << log4cpp::Priority::DEBUG << "Detected " << padding_length << " byte long padding";

    for (int padding_byte_index = 0; padding_byte_index < padding_length; padding_byte_index++) {
	const uint8_t* padding_byte_ptr = (const uint8_t*)(padding_start_in_packet + padding_byte_index);

	logger << log4cpp::Priority::DEBUG << padding_byte_index << "nd padding byte value " << uint32_t(*padding_byte_ptr);
	
	if (*padding_byte_ptr != 0) {
	    return false;
	}
    }

    // All bytes in range are zero
    return true;
}


bool read_ipfix_options_template(const uint8_t* packet,
                                 uint32_t offset,
                                 uint32_t set_length,
                                 bool& template_cache_update_required,
                                 uint32_t source_id,
                                 const std::string& client_addres_in_string_format,
                                 uint32_t& template_total_read_length);

// Read options template set
// https://tools.ietf.org/html/rfc5101#page-18
bool process_ipfix_options_template_set(const uint8_t* packet, uint32_t set_length, uint32_t source_id, const std::string& client_addres_in_string_format) {

    // Ensure that we have enough data to read set header
    if (set_length < sizeof(ipfix_set_header_common_t)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX options template header " << set_length << " bytes. "
               << "Agent IP: " << client_addres_in_string_format;
        return false;
    }

    // Read generic set header
    const ipfix_set_header_common_t* options_set_header = (ipfix_set_header_common_t*)packet;

    uint16_t set_id = options_set_header->get_set_id_host_byte_order();

    // Yes, we have flow set length in options_template_header->length but we've read it on previous step and we can use it from argument of this function instead

    // Ensure that we're dealing with options set
    if (set_id != IPFIX_OPTIONS_SET_ID) {
        logger << log4cpp::Priority::ERROR << "For options template we expect " << IPFIX_OPTIONS_SET_ID
               << "set_id but got "
                  "another id: "
               << set_id << "Agent IP: " << client_addres_in_string_format;

        return false;
    }

    // Shift pointer to length of set header
    uint32_t offset = sizeof(ipfix_set_header_common_t);

    bool template_cache_update_required = false;

    // That's time to read all available templates in set
    for (; offset < set_length;) {
        uint32_t options_template_total_read_length = 0;

        bool read_options_template_res =
            read_ipfix_options_template(packet, offset, set_length, template_cache_update_required, source_id,
                                        client_addres_in_string_format, options_template_total_read_length);

        if (!read_options_template_res) {
            return false;
        }

        logger << log4cpp::Priority::DEBUG << "Correcly read " << options_template_total_read_length << " bytes long options template";

        // Move forward on length of read section
        offset += options_template_total_read_length;

        // Time to process padding, we may have some zero bytes here and we need to ensure that they're zeroes as RFC requires
        // https://datatracker.ietf.org/doc/html/rfc7011#page-18
        // In case of options template padding may be 1, 2, 3, 4, 5 bytes only due to length of ipfix_options_template_record_header_t (6 bytes)
        // and if we have 1..5 bytes on end of packet and all of them are zero then we can stop this loop without triggering error

        // Use larger signed type to be sure about careful subtraction
        int64_t padding_length = set_length - offset;

        const uint8_t* padding_start_in_packet = (const uint8_t*)(packet + offset);

	if (padding_length >= 1 && padding_length <= 5) {
            logger << log4cpp::Priority::DEBUG << "Detected " << padding_length << " byte long padding";


	    bool all_padding_bytes_are_zero = are_all_padding_bytes_are_zero(padding_start_in_packet, padding_length);

            if (all_padding_bytes_are_zero) {
	        logger << log4cpp::Priority::DEBUG << "All padding bytes are zero, feel free to correctly stop processing";

	        // Stop loop correctly without triggering error
	        break;
            } else {
	        logger << log4cpp::Priority::ERROR << "Non zero padding bytes, semething is wrong with packet";

	        // We have to report error
	        return false;
           }
        }
    }

    return true;
}

// Reads single IPFIX options template
// This function designed same way as read_ipfix_data_template
// please keep it this way for clarity reasons as both of them are too complex on it's own and we need to
// use simpilar design to simplify them
// In case of successful read it will set amount of read data in template_total_read_length
bool read_ipfix_options_template(const uint8_t* packet,
                                 uint32_t template_records_start_offset,
                                 uint32_t set_length,
                                 bool& template_cache_update_required,
                                 uint32_t source_id,
                                 const std::string& client_addres_in_string_format,
                                 uint32_t& template_total_read_length) {

    // Start from offset where we expect template record header
    uint32_t offset = template_records_start_offset;

    // logger << log4cpp::Priority::INFO << "set_id " << set_id << " set_length: " << set_length;

    // Check that we have enough space in packet to read ipfix_options_template_record_header_t
    if (offset + sizeof(ipfix_options_template_record_header_t) > set_length) {
        logger << log4cpp::Priority::ERROR << "Could not read options templete header for IPFIX options template. "
               << "Agent IP: " << client_addres_in_string_format << " offset: " << offset << " set_length: " << set_length;
        return false;
    }

    const ipfix_options_template_record_header_t* ipfix_options_template_record_header =
        (const ipfix_options_template_record_header_t*)(packet + offset);

    // logger << log4cpp::Priority::INFO << "raw undecoded data template_id: " << options_nested_header->template_id <<
    // " field_count: " << options_nested_header->field_count
    //    << " scope_field_count: " << options_nested_header->scope_field_count;

    // Get all fields from options_nested_header
    uint16_t template_id       = ipfix_options_template_record_header->get_template_id_host_byte_order();
    uint16_t field_count       = ipfix_options_template_record_header->get_field_count_host_byte_order();
    uint16_t scope_field_count = ipfix_options_template_record_header->get_scope_field_count_host_byte_order();

    // According to RFC scope_field_count must not be zero but I'll assume that some vendors may fail to implement it
    // https://tools.ietf.org/html/rfc7011#page-24

    // logger << log4cpp::Priority::INFO << "Options template id: " << template_id << " field_count: " << field_count
    //       << " scope_field_count: " << scope_field_count;

    if (template_id <= 255) {
        logger << log4cpp::Priority::ERROR << "Template ID for IPFIX options template should be bigger than 255, got "
               << template_id << " Agent IP: " << client_addres_in_string_format;
        return false;
    }

    logger << log4cpp::Priority::DEBUG << "Options template id: " << template_id << " field_count: " << field_count
           << " scope_field_count: " << scope_field_count;

    // According to RFC field_count includes scope_field_count
    // https://tools.ietf.org/html/rfc7011#page-24 "Number of all fields in this Options Template Record, including the Scope Fields."

    if (scope_field_count > field_count) {
        logger << log4cpp::Priority::ERROR << "Number of scope fields " << scope_field_count
               << " cannot exceed number of all fields: " << field_count << " Agent IP: " << client_addres_in_string_format;
        return false;
    }

    // Calculate number of all normal fields
    uint16_t normal_field_count = field_count - scope_field_count;

    // Shift pointer on length of header
    offset += sizeof(ipfix_options_template_record_header_t);

    uint32_t scopes_total_size = 0;

    uint32_t scopes_payload_total_size = 0;

    // Then we have scope fields in packet, I'm not going to process them, I'll just skip them
    for (int scope_index = 0; scope_index < scope_field_count; scope_index++) {
        // Check that our attempt to read ipfix_field_specifier_t will not exceed packet length
        if (offset + sizeof(ipfix_field_specifier_t) > set_length) {
            logger << log4cpp::Priority::ERROR << "Attempt to read IPFIX set_record outside of packet. "
                   << "Agent IP: " << client_addres_in_string_format;
            return false;
        }

        const ipfix_field_specifier_t* current_scopes_record = (const ipfix_field_specifier_t*)(packet + offset);

        uint16_t scope_field_size = current_scopes_record->get_length_host_byte_order();
        uint16_t scope_field_type = current_scopes_record->get_type_host_byte_order();

        logger << log4cpp::Priority::DEBUG << "Reading scope section with size " << scope_field_size << " and type: " << scope_field_type;

        // Increment scopes size
        scopes_total_size += sizeof(ipfix_field_specifier_t);

        // Increment payload size
        scopes_payload_total_size += scope_field_size;

        // Shift pointer to the end of current scope field
        offset += sizeof(ipfix_field_specifier_t);
    }

    // We've reached normal fields section
    uint32_t normal_fields_total_size = 0;

    std::vector<template_record_t> template_records_map;

    uint32_t normal_fields_payload_total_size = 0;

    // These fields use quite complicated encoding and we need to identify them first
    bool ipfix_variable_length_elements_used = false;

    // Try to read all normal fields
    for (int field_index = 0; field_index < normal_field_count; field_index++) {
        // Check that our attempt to read ipfix_field_specifier_t will not exceed packet length
        if (offset + sizeof(ipfix_field_specifier_t) > set_length) {
            logger << log4cpp::Priority::ERROR << "Attempt to read IPFIX set_record outside of packet for normal field. "
                   << "Agent IP: " << client_addres_in_string_format;
            return false;
        }

        const ipfix_field_specifier_t* current_normal_record = (const ipfix_field_specifier_t*)(packet + offset);

        template_record_t current_record{};

        current_record.record_type   = current_normal_record->get_type_host_byte_order();
        current_record.record_length = current_normal_record->get_length_host_byte_order();

        // it's special size which actually means that variable length encoding was used for this field
        // https://datatracker.ietf.org/doc/html/rfc7011#page-37
        if (current_record.record_length == 65535) {
            ipfix_variable_length_elements_used = true;
        }

        logger << log4cpp::Priority::DEBUG << "Reading IPFIX options field with type " << current_record.record_type
               << " and length: " << current_record.record_length << " enterprise flag "
               << current_record.enterprise_bit << " enterprise number: " << current_record.enterprise_number;

        // Increment total field size
        normal_fields_total_size += sizeof(ipfix_field_specifier_t);

        // Increment total payload size
        normal_fields_payload_total_size += current_record.record_length;

        // Shift pointer to the end of current normal field
        offset += sizeof(ipfix_field_specifier_t);

        // If we have Enterprise flag then it means that we have 4 byte long Enterprise Number next after and we need to
        // skip it https://datatracker.ietf.org/doc/html/rfc7011#page-17
        if (current_record.record_type & IPFIX_ENTERPRISE) {
            current_record.enterprise_bit = true;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::INFO << "Enterprise field detected for field specified with type "
                       << current_record.record_type;
            }

            // Ensure that we can read Enterprise Number
            if (offset + sizeof(uint32_t) > set_length) {
                logger << log4cpp::Priority::ERROR << "IPFIX template set is too short " << set_length
                       << " to read enterprise number. Agent IP: " << client_addres_in_string_format << " offset: " << offset;
                return false;
            }

            // Read enterprise number
            current_record.enterprise_number = fast_ntoh(*(uint32_t*)(packet + offset));

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::INFO << "Enterprise field detected for field specified with type "
                       << current_record.record_type << " and enterprise number is " << current_record.enterprise_number;
            }

            // Jump one byte forward
            offset += sizeof(uint32_t);
        }


        template_records_map.push_back(current_record);
    }

    template_t field_template{};

    field_template.template_id = template_id;
    field_template.records     = template_records_map;

    // I do not think that we use it in our logic but I think it's reasonable to set it to number of normal fields
    field_template.num_records = normal_field_count;

    field_template.total_length                        = normal_fields_payload_total_size + scopes_payload_total_size;
    field_template.type                                = netflow_template_type_t::Options;
    field_template.ipfix_variable_length_elements_used = ipfix_variable_length_elements_used;

    field_template.option_scope_length = scopes_payload_total_size;

    // We need to know when we received it
    field_template.timestamp = current_inaccurate_time;

    // logger << log4cpp::Priority::INFO << "Read options template:" << print_template(field_template);

    // Add/update template
    bool updated                   = false;
    bool updated_existing_template = false;

    add_update_peer_template(netflow_protocol_version_t::ipfix, global_ipfix_templates, global_ipfix_templates_mutex, source_id,
                             template_id, client_addres_in_string_format, field_template, updated, updated_existing_template);

    // This code is not perfect from locks perspective as we read global_ipfix_templates without any locks below

    // NB! Please be careful with changing name of variable as it's part of serialisation protocol

    if (updated_existing_template) {
        ipfix_template_data_updates++;
    }

    // If we have any changes for this template, let's flush them to disk
    if (updated) {
        template_cache_update_required = true;
    }

    // Calculate amount of data we read in this function
    template_total_read_length = offset - template_records_start_offset;

    return true;
}

bool read_ipfix_data_template(const uint8_t* packet,
                              uint32_t offset,
                              uint32_t set_length,
                              bool& template_cache_update_required,
                              uint32_t template_sequence_number,
                              uint32_t source_id,
                              const std::string& client_addres_in_string_format,
                              uint32_t& template_total_read_length);

// Process IPFIX data template set
bool process_ipfix_data_template_set(const uint8_t* packet, uint32_t set_length, uint32_t source_id, const std::string& client_addres_in_string_format) {
    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Starting process_ipfix_data_template_set for set_length " << set_length;
    }

    // Ensure that we have enough data to read set header
    if (set_length < sizeof(ipfix_set_header_common_t)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX set template header " << set_length
               << " bytes. Agent IP: " << client_addres_in_string_format;
        return false;
    }

    const ipfix_set_header_common_t* template_set_header = (const ipfix_set_header_common_t*)packet;

    // Additional sanity check that set_id is for data template
    if (template_set_header->get_set_id_host_byte_order() != IPFIX_TEMPLATE_SET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_ipfix_data_template_set expects only "
                  "IPFIX_TEMPLATE_SET_ID but "
                  "got another id: "
               << template_set_header->get_set_id_host_byte_order() << " Agent IP: " << client_addres_in_string_format;

        return false;
    }

    bool template_cache_update_required = false;

    // To count number of templates we read
    uint32_t template_sequence_number = 0;

    // Shift pointer to length of set header
    uint32_t offset = sizeof(ipfix_set_header_common_t);

    // That's time to read all available templates in set
    for (; offset < set_length;) {
        template_sequence_number++;

        uint32_t template_total_read_length = 0;

        bool read_remplate_result =
            read_ipfix_data_template(packet, offset, set_length, template_cache_update_required, template_sequence_number,
                                     source_id, client_addres_in_string_format, template_total_read_length);

        if (!read_remplate_result) {
            logger << log4cpp::Priority::ERROR << "Cannot read template correctly";
            return false;
        }

        // Move forward on length of read section
        offset += template_total_read_length;
    }

    return true;
}

// In case of successful read of template function will set amount of read data in template_total_read_length
bool read_ipfix_data_template(const uint8_t* packet,
                              uint32_t template_records_start_offset,
                              uint32_t set_length,
                              bool& template_cache_update_required,
                              uint32_t template_sequence_number,
                              uint32_t source_id,
                              const std::string& client_addres_in_string_format,
                              uint32_t& template_total_read_length) {

    // Start from offset where we expect template record header
    uint32_t offset = template_records_start_offset;

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Starting read_ipfix_data_template for set_length " << set_length;
    }

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Reading template sequence number " << template_sequence_number;
    }

    // We need to ensure that we have enough space for reading template record header
    if (offset + sizeof(ipfix_template_record_header_t) > set_length) {
        logger << log4cpp::Priority::ERROR << "Set is too short to read IPFIX template header with length "
               << sizeof(ipfix_template_record_header_t) << " bytes. Offset: " << offset;
        return false;
    }

    const ipfix_template_record_header_t* template_record_header = (const ipfix_template_record_header_t*)(packet + offset);

    uint32_t template_id  = template_record_header->get_template_id_host_byte_order();
    uint32_t record_count = template_record_header->get_field_count_host_byte_order();

    // Shift pointer on length of header
    offset += sizeof(ipfix_template_record_header_t);

    std::vector<template_record_t> template_records_map;
    uint32_t total_template_data_size = 0;

    // These fields use quite complicated encoding and we need to identify them first
    bool ipfix_variable_length_elements_used = false;

    // Read all field specifiers
    for (uint32_t i = 0; i < record_count; i++) {
        // Ensure that we have enough space to read field specifier structure
        if (offset + sizeof(ipfix_field_specifier_t) > set_length) {
            logger << log4cpp::Priority::ERROR << "Short IPFIX set template. Agent IP: " << client_addres_in_string_format;
            return false;
        }

        const ipfix_field_specifier_t* field_specifier = (const ipfix_field_specifier_t*)(packet + offset);

        uint32_t record_type   = field_specifier->get_type_host_byte_order();
        uint32_t record_length = field_specifier->get_length_host_byte_order();

        template_record_t current_record;
        current_record.record_type   = record_type;
        current_record.record_length = record_length;

        // it's special size which actually means that variable length encoding was used for this field
        // https://datatracker.ietf.org/doc/html/rfc7011#page-37
        if (record_length == 65535) {
            ipfix_variable_length_elements_used = true;
        }

        // Move next on length of template record
        offset += sizeof(ipfix_field_specifier_t);

        // If we have Enterprise flag then it means that we have 4 byte long Enterprise Number next after and we need to
        // skip it https://datatracker.ietf.org/doc/html/rfc7011#page-17
        if (record_type & IPFIX_ENTERPRISE) {
            current_record.enterprise_bit = true;

            // Ensure that we can read Enterprise Number
            if (offset + sizeof(uint32_t) > set_length) {
                logger << log4cpp::Priority::ERROR << "IPFIX template set is too short " << set_length
                       << " to read enterprise number. Agent IP: " << client_addres_in_string_format << " offset: " << offset;
                return false;
            }

            // Read enterprise number
            current_record.enterprise_number = fast_ntoh(*(uint32_t*)(packet + offset));

            offset += sizeof(uint32_t);
        }

        template_records_map.push_back(current_record);

	// We increment template data size only when we have only fixed fields
	// We ensure that we never use this value in case when variable field encoding is used
	if (!ipfix_variable_length_elements_used) {
            total_template_data_size += record_length;
	}
    }

    // We use same struct as Netflow v9 because Netflow v9 and IPFIX use similar fields
    template_t field_template;

    field_template.template_id                         = template_id;
    field_template.num_records                         = record_count;
    field_template.total_length                        = total_template_data_size;
    field_template.records                             = template_records_map;
    field_template.type                                = netflow_template_type_t::Data;
    field_template.ipfix_variable_length_elements_used = ipfix_variable_length_elements_used;

    // We need to know when we received it
    field_template.timestamp = current_inaccurate_time;

    bool updated                   = false;
    bool updated_existing_template = false;

    add_update_peer_template(netflow_protocol_version_t::ipfix, global_ipfix_templates, global_ipfix_templates_mutex, source_id,
                             template_id, client_addres_in_string_format, field_template, updated, updated_existing_template);

    // If we have any changes for this template, let's flush them to disk
    if (updated) {
        template_cache_update_required = true;
    }

    if (updated_existing_template) {
        ipfix_template_data_updates++;
    }

    // Calculate amount of data we read in this function
    template_total_read_length = offset - template_records_start_offset;

    return true;
}

bool ipfix_record_to_flow(uint32_t record_type, uint32_t record_length, const uint8_t* data, simple_packet_t& packet, netflow_meta_info_t& flow_meta) {
    switch (record_type) {
    case IPFIX_IN_BYTES:
        if (record_length > sizeof(packet.length)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IN_BYTES: " << record_length;
            }
        } else {
            BE_COPY(packet.length);

            // decode data in network byte order to host byte order
            packet.length = fast_ntoh(packet.length);

            // IPFIX carries only information about number of octets including IP headers and IP payload
            // which is exactly what we need for ip_length field
            packet.ip_length = packet.length;
        }

        break;
    case IPFIX_IN_PACKETS:
        if (record_length > sizeof(packet.number_of_packets)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IN_PACKETS: " << record_length;
            }

        } else {
            BE_COPY(packet.number_of_packets);

            packet.number_of_packets = fast_ntoh(packet.number_of_packets);
        }

        break;
    case IPFIX_IN_PROTOCOL:
        if (record_length > sizeof(packet.protocol)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IN_PROTOCOL: " << record_length;
            }

        } else {
            BE_COPY(packet.protocol);

            packet.protocol = fast_ntoh(packet.protocol);
        }

        break;
    case IPFIX_TCP_FLAGS:
        if (record_length == 1) {
            BE_COPY(packet.flags);
        } else if (record_length == 2) {
            // If exported as a single octet with reduced-size encoding, this Information Element covers the low-order
            // octet of this field (i.e, bits 0x80 to 0x01), omitting the ECN Nonce Sum and the three Future Use bits.
            // https://www.iana.org/assignments/ipfix/ipfix.xhtml
            // So we just copy second byte which carries same information as when it encoded with 1 byte
            memcpy(&packet.flags, data + 1, 1);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_TCP_FLAGS: " << record_length;
            }
        }

        break;
    case IPFIX_L4_SRC_PORT:
        if (record_length > sizeof(packet.source_port)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_L4_SRC_PORT: " << record_length;
            }

        } else {
            BE_COPY(packet.source_port);

            // We should convert port to host byte order
            packet.source_port = fast_ntoh(packet.source_port);
        }

        break;
    case IPFIX_L4_DST_PORT:
        if (record_length > sizeof(packet.destination_port)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_L4_DST_PORT: " << record_length;
            }

        } else {
            BE_COPY(packet.destination_port);

            // We should convert port to host byte order
            packet.destination_port = fast_ntoh(packet.destination_port);
        }

        break;
    case IPFIX_TCP_SOURCE_PORT:
        // This is unusual encoding used only by AMD Pensando
        // We enable it only we know that packet is TCP
        if (packet.protocol == IPPROTO_TCP) {

            if (record_length == 2) {
                uint16_t port = 0;
                memcpy(&port, data, record_length);

                packet.source_port = fast_ntoh(port);
            } else {
                ipfix_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_TCP_SOURCE_PORT: " << record_length;
                }
            }
        }

        break;
    case IPFIX_TCP_DESTINATION_PORT:
        // This is unusual encoding used only by AMD Pensando
        // We enable it only we know that packet is TCP
        if (packet.protocol == IPPROTO_TCP) {

            if (record_length == 2) {
                uint16_t port = 0;
                memcpy(&port, data, record_length);

                packet.destination_port = fast_ntoh(port);
            } else {
                ipfix_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_TCP_DESTINATION_PORT: " << record_length;
                }
            }
        }

        break;
    case IPFIX_UDP_SOURCE_PORT:
        // This is unusual encoding used only by AMD Pensando
        // We enable it only we know that packet is UDP
        if (packet.protocol == IPPROTO_UDP) {

            if (record_length == 2) {
                uint16_t port = 0;
                memcpy(&port, data, record_length);

                packet.source_port = fast_ntoh(port);
            } else {
                ipfix_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_UDP_SOURCE_PORT: " << record_length;
                }
            }
        }

        break;
    case IPFIX_UDP_DESTINATION_PORT:
        // This is unusual encoding used only by AMD Pensando
        // We enable it only we know that packet is UDP
        if (packet.protocol == IPPROTO_UDP) {

            if (record_length == 2) {
                uint16_t port = 0;
                memcpy(&port, data, record_length);

                packet.destination_port = fast_ntoh(port);
            } else {
                ipfix_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_UDP_DESTINATION_PORT: " << record_length;
                }
            }
        }
        break;
    case IPFIX_IPV4_SRC_ADDR:
        if (record_length > sizeof(packet.src_ip)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV4_SRC_ADDR: " << record_length;
            }

        } else {
            memcpy(&packet.src_ip, data, record_length);
        }

        break;
    case IPFIX_IPV4_DST_ADDR:
        if (record_length > sizeof(packet.dst_ip)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV4_DST_ADDR: " << record_length;
            }

        } else {
            memcpy(&packet.dst_ip, data, record_length);
        }

        break;
    // There is a similar field IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS but with slightly different meaning
    case IPFIX_IPV4_NEXT_HOP:
        if (record_length == 4) {
            uint32_t ip_next_hop_ipv4 = 0;
            memcpy(&ip_next_hop_ipv4, data, record_length);

            flow_meta.ip_next_hop_ipv4_set = true;
            flow_meta.ip_next_hop_ipv4     = ip_next_hop_ipv4;

            // std::cout << "IP next hop: " << convert_ip_as_uint_to_string(ip_next_hop_ipv4) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV4_NEXT_HOP: " << record_length;
            }
        }

        break;
    // There is a similar field IPFIX_IPV4_NEXT_HOP but with slightly different meaning
    case IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS:
        // Juniper MX uses this field
        if (record_length == 4) {
            uint32_t bgp_next_hop_ipv4 = 0;
            memcpy(&bgp_next_hop_ipv4, data, record_length);

            flow_meta.bgp_next_hop_ipv4_set = true;
            flow_meta.bgp_next_hop_ipv4     = bgp_next_hop_ipv4;

            // std::cout << "BGP next hop: " << convert_ip_as_uint_to_string(bgp_next_hop_ipv4) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS: " << record_length;
            }
        }

        break;
    case IPFIX_IPV6_NEXT_HOP:
        // Juniper MX uses this field
        if (record_length == 16) {
            in6_addr bgp_next_hop_ipv6{};
            memcpy(&bgp_next_hop_ipv6, data, record_length);

            flow_meta.bgp_next_hop_ipv6_set = true;
            flow_meta.bgp_next_hop_ipv6     = bgp_next_hop_ipv6;

            // std::cout << "bgp next hop: " << print_ipv6_address(ipv6_next_hop) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV6_NEXT_HOP: " << record_length;
            }
        }


        break;
    // According to https://www.iana.org/assignments/ipfix/ipfix.xhtml ASN can be 4 byte only
    // Unfortunately, customer (Intermedia) shared pcap with ASNs encoded as 2 byte values :(
    case IPFIX_SRC_AS:
        if (record_length == 4) {
            uint32_t src_asn = 0;
            memcpy(&src_asn, data, record_length);

            src_asn        = fast_ntoh(src_asn);
            packet.src_asn = src_asn;
        } else if (record_length == 2) {
            uint16_t src_asn = 0;
            memcpy(&src_asn, data, record_length);

            src_asn        = fast_ntoh(src_asn);
            packet.src_asn = src_asn;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_SRC_AS: " << record_length;
            }
        }

        break;
    case IPFIX_DST_AS:
        if (record_length == 4) {
            uint32_t dst_asn = 0;
            memcpy(&dst_asn, data, record_length);

            dst_asn        = fast_ntoh(dst_asn);
            packet.dst_asn = dst_asn;
        } else if (record_length == 2) {
            uint16_t dst_asn = 0;
            memcpy(&dst_asn, data, record_length);

            dst_asn        = fast_ntoh(dst_asn);
            packet.dst_asn = dst_asn;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_DST_AS: " << record_length;
            }
        }

        break;
    case IPFIX_SOURCE_MAC_ADDRESS:
        if (record_length == 6) {
            // Copy it directly to packet structure
            memcpy(&packet.source_mac, data, record_length);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for IPFIX_SOURCE_MAC_ADDRESS";
            }
        }
        break;
    case IPFIX_DESTINATION_MAC_ADDRESS:
        if (record_length == 6) {
            // Copy it directly to packet structure
            memcpy(&packet.destination_mac, data, record_length);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for IPFIX_DESTINATION_MAC_ADDRESS";
            }
        }
        break;
    // According to https://www.iana.org/assignments/ipfix/ipfix.xhtml interfaces can be 4 byte only
    case IPFIX_INPUT_SNMP:
        if (record_length == 4) {
            uint32_t input_interface = 0;
            memcpy(&input_interface, data, record_length);

            input_interface        = fast_ntoh(input_interface);
            packet.input_interface = input_interface;
        } else if (record_length == 2) {
            uint16_t input_interface = 0;
            memcpy(&input_interface, data, record_length);

            input_interface        = fast_ntoh(input_interface);
            packet.input_interface = input_interface;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_INPUT_SNMP: " << record_length;
            }
        }

        break;
    case IPFIX_OUTPUT_SNMP:
        if (record_length == 4) {
            uint32_t output_interface = 0;
            memcpy(&output_interface, data, record_length);

            output_interface        = fast_ntoh(output_interface);
            packet.output_interface = output_interface;
        } else if (record_length == 2) {
            uint16_t output_interface = 0;
            memcpy(&output_interface, data, record_length);

            output_interface        = fast_ntoh(output_interface);
            packet.output_interface = output_interface;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_OUTPUT_SNMP: " << record_length;
            }
        }

        break;
    case IPFIX_IPV6_SRC_ADDR:
        // It should be 16 bytes only
        if (true) {

            if (record_length == 16) {
                memcpy(&packet.src_ipv6, data, record_length);
                // Set protocol version to IPv6
                packet.ip_protocol_version = 6;
            } else {
                ipfix_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV6_SRC_ADDR: " << record_length;
                }
            }
        }

        break;
    case IPFIX_IPV6_DST_ADDR:
        // It should be 16 bytes only
        if (true) {
            if (record_length == 16) {
                memcpy(&packet.dst_ipv6, data, record_length);
                // Set protocol version to IPv6
                packet.ip_protocol_version = 6;
            } else {
                ipfix_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV6_DST_ADDR: " << record_length;
                }
            }
        }
        break;
    case IPFIX_FIRST_SWITCHED:
        // Mikrotik uses this encoding
        if (record_length == 4) {
            uint32_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            packet.flow_start = flow_started;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FIRST_SWITCHED: " << record_length;
            }
        }

        break;
    case IPFIX_LAST_SWITCHED:
        // Mikrotik uses this encoding
        if (record_length == 4) {
            uint32_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            packet.flow_end = flow_finished;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_LAST_SWITCHED: " << record_length;
            }
        }

        break;
        // Juniper uses IPFIX_FLOW_START_MILLISECONDS and IPFIX_FLOW_END_MILLISECONDS
    case IPFIX_FLOW_START_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            // We cast unsigned to signed and it may cause issues
            packet.flow_start = flow_started;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_START_MILLISECONDS: " << record_length;
            }
        }

        break;
    case IPFIX_FLOW_END_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            // We cast unsigned to signed and it may cause issues
            packet.flow_end = flow_finished;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_END_MILLISECONDS: " << record_length;
            }
        }

        break;
        // Netgate TNSR uses IPFIX_FLOW_START_NANOSECONDS and IPFIX_FLOW_END_NANOSECONDS
    case IPFIX_FLOW_START_NANOSECONDS:
        if (record_length == 8) {
            uint64_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            // We cast unsigned to signed and it may cause issues
            packet.flow_start = flow_started;

            // Convert to milliseconds
            packet.flow_start = packet.flow_start / 1000000;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_START_NANOSECONDS: " << record_length;
            }
        }

        break;
    case IPFIX_FLOW_END_NANOSECONDS:
        if (record_length == 8) {
            uint64_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            // We cast unsigned to signed and it may cause issues
            packet.flow_end = flow_finished;

            // Convert to milliseconds
            packet.flow_end = packet.flow_end / 1000000;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_END_NANOSECONDS: " << record_length;
            }
        }

        break;

    case IPFIX_FORWARDING_STATUS:
        // TODO: we did using theoretical information and did not test it at all
        // Documented here: https://www.iana.org/assignments/ipfix/ipfix.xhtml#forwarding-status
        // Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
        if (record_length == 1) {
            uint8_t forwarding_status = 0;

            memcpy(&forwarding_status, data, record_length);

            const netflow9_forwarding_status_t* forwarding_status_structure = (const netflow9_forwarding_status_t*)&forwarding_status;

            // Decode numbers into forwarding statuses
            packet.forwarding_status             = forwarding_status_from_integer(forwarding_status_structure->status);
            flow_meta.received_forwarding_status = true;

            ipfix_forwarding_status++;

            // logger << log4cpp::Priority::DEBUG << "Forwarding status: " << int(forwarding_status_structure->status) << " reason code: " << int(forwarding_status_structure->reason_code);
        } else if (record_length == 4) {
            // We received 4 byte encoding from  Cisco ASR9006 running IOS XR 6.4.2
            // It's new format which was added by RFC bugfix: https://datatracker.ietf.org/doc/draft-ietf-opsawg-ipfix-fixes/12/
            // We still have only single byte with information but whole structure is larger
            ipfix_forwarding_status_4_bytes_t forwarding_status{};

            memcpy(&forwarding_status, data, record_length);

            // Decode numbers into forwarding statuses
            packet.forwarding_status             = forwarding_status_from_integer(forwarding_status.status);
            flow_meta.received_forwarding_status = true;

            ipfix_forwarding_status++;

            // logger << log4cpp::Priority::DEBUG << "Forwarding status: " << int(forwarding_status.status) << " reason code: " << int(forwarding_status.reason_code);
        } else {
            // It must be exactly one byte
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FORWARDING_STATUS: " << record_length;
            }
        }

        break;
    case IPFIX_DATALINK_FRAME_SIZE:
        if (record_length == 2) {
            uint16_t datalink_frame_size = 0;

            memcpy(&datalink_frame_size, data, record_length);
            flow_meta.data_link_frame_size = fast_ntoh(datalink_frame_size);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_DATALINK_FRAME_SIZE: " << record_length;
            }
        }

        break;
    case IPFIX_DATALINK_FRAME_SECTION: {
        // Element 315: https://www.iana.org/assignments/ipfix/ipfix.xhtml

        // It's packet header as is in variable length encoding
        ipfix_inline_headers++;

        // This packet is ended using IPFIX variable length encoding and it may have two possible ways of length
        // encoding https://datatracker.ietf.org/doc/html/rfc7011#section-7
        if (flow_meta.variable_field_length_encoding == variable_length_encoding_t::single_byte ||
            flow_meta.variable_field_length_encoding == variable_length_encoding_t::two_byte) {

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Packet header length: " << flow_meta.variable_field_length;
            }

            if (flow_meta.variable_field_length != 0) {
                const uint8_t* payload_shift = nullptr;

                if (flow_meta.variable_field_length_encoding == variable_length_encoding_t::single_byte) {
                    payload_shift = data + sizeof(uint8_t);
                } else if (flow_meta.variable_field_length_encoding == variable_length_encoding_t::two_byte) {
                    payload_shift = data + sizeof(uint8_t) + sizeof(uint16_t);
                }

                auto result = parse_raw_packet_to_simple_packet_full_ng(payload_shift, flow_meta.variable_field_length,
                                                                        flow_meta.variable_field_length,
                                                                        flow_meta.nested_packet, false, true);

                if (result != network_data_stuctures::parser_code_t::success) {
                    // Cannot decode data
                    ipfix_inline_header_parser_error++;

                    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                        logger << log4cpp::Priority::DEBUG << "Cannot parse packet header with error: "
                               << network_data_stuctures::parser_code_to_string(result);
                    }

                } else {
                    // Successfully decoded data
                    ipfix_inline_header_parser_success++;

                    flow_meta.nested_packet_parsed = true;
                    // logger << log4cpp::Priority::DEBUG << "IPFIX inline extracted packet: " << print_simple_packet(flow_meta.nested_packet);
                }
            } else {
                ipfix_inline_encoding_error++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Zero length variable fields are not supported";
                }
            }
        } else {
            ipfix_inline_encoding_error++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unknown variable field encoding type";
            }
        }
        break;
    }
    case IPFIX_FLOW_DIRECTION:
        // It should be 1 byte value
        if (record_length == 1) {
            uint8_t flow_direction = 0;
            memcpy(&flow_direction, data, record_length);

            // According to RFC only two values possible: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            // 0x00: ingress flow
            // 0x01: egress flow
            // Juniper MX uses 255 to report unknown direction
            // std::cout << "Flow direction: " << int(flow_direction) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_DIRECTION: " << record_length;
            }
        }

        break;

    case IPFIX_FLOW_END_REASON:
        // It should be 1 byte value
        if (record_length == 1) {
            uint8_t flow_end_reason = 0;

            memcpy(&flow_end_reason, data, record_length);

            // https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason
            if (flow_end_reason == 1) {
                ipfix_flows_end_reason_idle_timeout++;
            } else if (flow_end_reason == 2) {
                ipfix_flows_end_reason_active_timeout++;
            } else if (flow_end_reason == 3) {
                ipfix_flows_end_reason_end_of_flow_timeout++;
            } else if (flow_end_reason == 4) {
                ipfix_flows_end_reason_force_end_timeout++;
            } else if (flow_end_reason == 5) {
                ipfix_flows_end_reason_lack_of_resource_timeout++;
            }
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_END_REASON: " << record_length;
            }
        }

        break;
    case IPFIX_FRAGMENT_IDENTIFICATION:
        //
        // Specification: https://www.rfc-editor.org/rfc/rfc5102.html#section-5.4.23
        //
        // IPFIX uses 32 bit values to accommodate following cases:
        //  - 16 bit IPv4 identification field https://www.rfc-editor.org/rfc/rfc791
        //  - 32 bit IPv6 identification field https://en.wikipedia.org/wiki/IPv6_packet#Fragment
        //
        // Juniper uses it on J MX platforms but they do not have much information about it:
        // https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/inline-sampling-overview.html
        // I asked https://t.me/dgubin about it
        //
        // I did review of dump from J MX and I can confirm that values for IPv4 do not exceed maximum value for uint16_t (65535)
        //
        // J MX is doing something fun with this field. I got dump in hands and in this dump of 42421 packets only 2337 have non zero value of this field.
        // Clearly they violate RFC and do not populate this field unconditionally as RFC dictates.
        //
        // I see cases like this which is very likely non first fragment of fragmented series of packets as we do not have ports:
        // Identification: 20203 ipv4:0 > ipv4:0 protocol: udp frag: 0  packets: 1 size: 352 bytes ip size: 352 bytes ttl: 0 sample ratio: 1
        //
        // And I see packets like this which may be first packet in fragmented series of packets as we do indeed have ports here and packet length is high:
        // Identification: 2710 ipv4:53 > ipv4:45134 protocol: udp frag: 0  packets: 1 size: 1476 bytes ip size: 1476 bytes ttl: 0 sample ratio: 1
        //
        // And majority of packets looks this way:
        // Identification: 0 ipv4:80 > ipv4:50179 protocol: tcp flags: ack frag: 0  packets: 1 size: 40 bytes ip size: 40 bytes ttl: 0 sample ratio: 1
        //
        // We clearly can distinguish first fragmented packet and non first fragmented packet
        //
        // TODO: this logic must be enabled via flag only as this is non RFC compliant behavior and we need to have confirmation from J
        //
        // We have this guide from J: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/services-ipfix-flow-aggregation-ipv6-extended-attributes.html
        // but it's written in exceptionally weird way and raises more questions then answers
        //

        // It's exactly 4 bytes
        if (record_length == 4) {
            uint32_t fragment_identification = 0;

            memcpy(&fragment_identification, data, record_length);

            fragment_identification = fast_ntoh(fragment_identification);

            // logger << log4cpp::Priority::INFO << "Fragment identification: " << fragment_identification;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FRAGMENT_IDENTIFICATION: " << record_length;
            }
        }

        break;
    }

    return true;
}

// Read options data packet with known template
bool ipfix_options_set_to_store(const uint8_t* packet,
                                const ipfix_header_t* ipfix_header,
                                const template_t* flow_template,
                                const std::string& client_addres_in_string_format) {

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Starting ipfix_options_set_to_store";
    }


    // Skip scope fields, I really do not want to parse this information
    packet += flow_template->option_scope_length;

    uint32_t sampling_rate = 0;

    // Field shift in memory
    uint32_t offset = 0;

    // Sampling algorithm for exotic sampling types
    uint16_t sampling_selector_algorithm = 0;

    // We use these fields to work with systematic count-based Sampling Selector on Nokia
    uint32_t sampling_packet_space    = 0;
    uint32_t sampling_packet_interval = 0;

    device_timeouts_t device_timeouts{};

    for (const auto& elem : flow_template->records) {
        const uint8_t* data_shift = packet + offset;

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Processing field type " << elem.record_type << " with field length " << elem.record_length; 
        }

        // Time to extract sampling rate
        if (elem.record_type == IPFIX_SAMPLING_INTERVAL) {
            // RFC suggest that this field is 4 byte: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            if (elem.record_length == 4) {
                uint32_t current_sampling_rate = 0;
                memcpy(&current_sampling_rate, data_shift, elem.record_length);

                // TODO: we do not convert value to little endian as sampling update function expects big endian / network byte order

                sampling_rate = current_sampling_rate;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "4 byte encoded IPFIX_SAMPLING_INTERVAL sampling rate: " << sampling_rate
                           << " from " << client_addres_in_string_format;
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_SAMPLING_INTERVAL: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }
        } else if (elem.record_type == IPFIX_SAMPLING_PACKET_INTERVAL) {
            // RFC suggest that this field is 4 byte: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            if (elem.record_length == 4) {
                uint32_t current_sampling_packet_interval = 0;

                memcpy(&current_sampling_packet_interval, data_shift, elem.record_length);

                current_sampling_packet_interval = fast_ntoh(current_sampling_packet_interval);

                // Well, we need this information to deal with systematic count-based Sampling Selector on Nokia
                sampling_packet_interval = current_sampling_packet_interval;

                // And we need this value to use as regular sampling rate on Cisco NSC
                // We need to return it to big endian again we sampling logic in IPFIX uses big endian / network byte order
                sampling_rate = fast_hton(sampling_packet_interval);
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "Unexpectedly big size for IPFIX_SAMPLING_PACKET_INTERVAL: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }
        } else if (elem.record_type == IPFIX_SAMPLING_PACKET_SPACE) {
            // RFC requires this field to be 4 byte long
            if (elem.record_length == 4) {
                memcpy(&sampling_packet_space, data_shift, elem.record_length);

                sampling_packet_space = fast_ntoh(sampling_packet_space);
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpected size for IPFIX_SAMPLING_PACKET_SPACE: " << elem.record_length;
                }

                ipfix_too_large_field++;

                // We're OK to continue process, we should not stop it
            }

        } else if (elem.record_type == IPFIX_SAMPLING_SELECTOR_ALGORITHM) {
            // RFC requires this field to be 2 byte long
            // You can find all possible values for it here: https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xhtml
            if (elem.record_length == 2) {
                memcpy(&sampling_selector_algorithm, data_shift, elem.record_length);

                sampling_selector_algorithm = fast_ntoh(sampling_selector_algorithm);

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Decoded sampling selector algorithm " << sampling_selector_algorithm;
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "Unexpected size for IPFIX_SAMPLING_SELECTOR_ALGORITM: " << elem.record_length;
                }

                ipfix_too_large_field++;

                // We're OK to continue process, we should not stop it
            }

        } else if (elem.record_type == IPFIX_ACTIVE_TIMEOUT) {
            uint16_t active_timeout = 0;

            // J MX204 with JunOS 19 encodes it with 2 bytes as RFC requires
            if (elem.record_length == 2) {
                memcpy(&active_timeout, data_shift, elem.record_length);
                active_timeout = fast_ntoh(active_timeout);

                ipfix_active_flow_timeout_received++;
                device_timeouts.active_timeout = active_timeout;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got active timeout: " << active_timeout << " seconds";
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpected size for IPFIX_ACTIVE_TIMEOUT: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }

        } else if (elem.record_type == IPFIX_INACTIVE_TIMEOUT) {
            uint16_t inactive_timeout = 0;

            // J MX204 with JunOS 19 encodes it with 2 bytes as RFC requires
            if (elem.record_length == 2) {
                memcpy(&inactive_timeout, data_shift, elem.record_length);
                inactive_timeout = fast_ntoh(inactive_timeout);

                ipfix_inactive_flow_timeout_received++;
                device_timeouts.inactive_timeout = inactive_timeout;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got inactive timeout: " << inactive_timeout << " seconds";
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpected size for IPFIX_INACTIVE_TIMEOUT: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }
        }

        offset += elem.record_length;
    }

    // Additional logic to deal with systematic count-based Sampling Selector on Nokia Nokia 7750 SR
    // https://www.rfc-editor.org/rfc/rfc5476.html#section-6.5.2.1
    // We check that sampler selected non zero number of packets as additional sanity check that we deal with this
    // specific type of sampler and to avoid division by zero
    if (sampling_selector_algorithm == IPFIX_SAMPLER_TYPE_SYSTEMATIC_COUNT_BASED_SAMPLING && sampling_packet_interval != 0) {
        // We have seen following cases from Nokia:
        // Packet space: 999 packet interval 1
        // Packet space: 9999 packet interval 1
        //
        // Packet interval is the number of packets selected from whole packet space
        //

        //
        // We never seen packet interval which is not set to 1 but I prefer to cover this case too
        // For values of  packet interval after 1 we need to divide whole amount of observed packets
        // (sampling_packet_space + sampling_packet_interval) by number of selected packets
        //
        uint32_t systematic_count_based_sampling_rate =
            uint32_t(double(sampling_packet_space + sampling_packet_interval) / double(sampling_packet_interval));

        // Update sampling rate
        sampling_rate = fast_hton(systematic_count_based_sampling_rate);

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Packet space: " << sampling_packet_space << " packet interval "
                   << sampling_packet_interval << " sampling " << systematic_count_based_sampling_rate;
        }
    }

    update_ipfix_sampling_rate(sampling_rate, client_addres_in_string_format);

    // Update flow timeouts in our store
    update_device_flow_timeouts(device_timeouts, ipfix_per_device_flow_timeouts_mutex, ipfix_per_device_flow_timeouts,
                                client_addres_in_string_format, netflow_protocol_version_t::ipfix);

    return true;
}


// That's kind of histogram emulation
void increment_duration_counters_ipfix(int64_t duration) {
    if (duration == 0) {
        ipfix_duration_0_seconds++;
    } else if (duration <= 1) {
        ipfix_duration_less_1_seconds++;
    } else if (duration <= 2) {
        ipfix_duration_less_2_seconds++;
    } else if (duration <= 3) {
        ipfix_duration_less_3_seconds++;
    } else if (duration <= 5) {
        ipfix_duration_less_5_seconds++;
    } else if (duration <= 10) {
        ipfix_duration_less_10_seconds++;
    } else if (duration <= 15) {
        ipfix_duration_less_15_seconds++;
    } else if (duration <= 30) {
        ipfix_duration_less_30_seconds++;
    } else if (duration <= 60) {
        ipfix_duration_less_60_seconds++;
    } else if (duration <= 90) {
        ipfix_duration_less_90_seconds++;
    } else if (duration <= 180) {
        ipfix_duration_less_180_seconds++;
    } else {
        ipfix_duration_exceed_180_seconds++;
    }

    return;
}

// In case of success it fills fields in variable_length_encoding_info
bool read_ipfix_variable_length_field(const uint8_t* packet, uint32_t offset, uint32_t set_length,
    variable_length_encoding_info_t& variable_length_encoding_info) {

    // We need to have at least one byte to read data
    if (offset + sizeof(uint8_t) > set_length) {
        logger << log4cpp::Priority::ERROR << "Attempt to read data after end of set for variable field length";
        return false;
    }

    const uint8_t* field_length_ptr = (const uint8_t*)(packet + offset);

    if (*field_length_ptr == 0) {
        logger << log4cpp::Priority::ERROR << "Zero length variable fields are not supported";
        ipfix_inline_encoding_error++;
        return false;
    }

    if (*field_length_ptr == 255) {
        // 255 is special and it means that packet length is encoded in two following bytes
        // Juniper PTX routers use this encoding even in case when packet length does not exceed 255 bytes

        // RFC reference https://datatracker.ietf.org/doc/html/rfc7011#page-37
        // In this case, the first octet of the
        // Length field MUST be 255, and the length is carried in the second and
        // third octets, as shown in Figure S.

        // We need to have at least three bytes to read data
        if (offset + sizeof(uint8_t) + sizeof(uint16_t) > set_length) {
            logger << log4cpp::Priority::ERROR << "Attempt to read data after end of set for variable field length";
            return false;
        }

        // Read 2 byte length by skipping placeholder byte with 255
        const uint16_t* two_byte_field_length_ptr = (const uint16_t*)(packet + offset + sizeof(uint8_t));

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Two byte variable length encoding detected. Retrieved packet length: "
                   << fast_ntoh(*two_byte_field_length_ptr);
        }

        // Pass variable payload length
        variable_length_encoding_info.variable_field_length = fast_ntoh(*two_byte_field_length_ptr);

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Two byte variable length encoding detected. Retrieved packet length: "
                   << variable_length_encoding_info.variable_field_length;
        }

        // Override field length with length extracted from two bytes + length of placeholder byte itself
        variable_length_encoding_info.record_full_length = variable_length_encoding_info.variable_field_length + sizeof(uint8_t) + sizeof(uint16_t);

        // Specify length encoding type as it's required for payload retrieval process
        variable_length_encoding_info.variable_field_length_encoding = variable_length_encoding_t::two_byte;
    } else {
        // Pass variable payload length
        variable_length_encoding_info.variable_field_length = *field_length_ptr;

        // Override field length with length extracted from leading byte
        variable_length_encoding_info.record_full_length = variable_length_encoding_info.variable_field_length + sizeof(uint8_t);

        // Specify length encoding type as it's required for payload retrieval process
        variable_length_encoding_info.variable_field_length_encoding = variable_length_encoding_t::single_byte;
    }
  
    // Ensure that we have enough space to read whole variable field
    if (offset + variable_length_encoding_info.record_full_length > set_length) {
        logger << log4cpp::Priority::ERROR << "Attempt to read data after end of set for variable field length";
        return false;
    }

    return true;
}


// This function reads data set using passed template
// In case of irrecoverable errors it returns false
bool ipfix_data_set_to_store(const uint8_t* packet_ptr,
                             const ipfix_header_t* ipfix_header,
                             uint32_t set_maximum_length,
                             const template_t* field_template,
                             uint32_t client_ipv4_address,
                             uint32_t& set_length,
                             const std::string& client_addres_in_string_format) {
    simple_packet_t packet;
    packet.source       = NETFLOW;
    packet.arrival_time = current_inaccurate_time;

    packet.agent_ip_address = client_ipv4_address;

    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec         = ipfix_header->get_time_sec_host_byte_order();

    {
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);
        auto itr = ipfix_sampling_rates.find(client_addres_in_string_format);

        if (itr == ipfix_sampling_rates.end()) {
            // Use global value
            packet.sample_ratio = fastnetmon_global_configuration.netflow_sampling_ratio;
        } else {
            packet.sample_ratio = itr->second;
        }
    }

    // By default, assume IPv4 traffic here
    // But code below can switch it to IPv6
    packet.ip_protocol_version = 4; //-V1048

    // Place to keep meta information which is not needed in simple_simple_packet_t structure
    netflow_meta_info_t flow_meta;

    uint32_t offset = 0;

    for (auto iter = field_template->records.begin(); iter != field_template->records.end(); iter++) {
        uint32_t record_type   = iter->record_type;
        uint32_t record_length = iter->record_length;

        // logger << log4cpp::Priority::DEBUG << "Reading record with type " << record_type << " and length " << record_length;

        if (record_length == 65535) {
            // OK, we're facing variable length field and it's damn complex
            // We need to calculate field length here and then use this length in ipfix_record_to_flow
		
	    variable_length_encoding_info_t variable_length_encoding_info{};

	    bool read_ipfix_variable_length_field_result = read_ipfix_variable_length_field(packet_ptr, offset, set_maximum_length, variable_length_encoding_info);

	    if (!read_ipfix_variable_length_field_result) {
                return false;
	    }

	    // Copy meta informatiom about variable length encoding to flow_meta
	    // TODO: I'm not sure that this information is needed in flow_meta as it's specific only for field we parse right now
	    flow_meta.variable_field_length_encoding = variable_length_encoding_info.variable_field_length_encoding;
            flow_meta.variable_field_length = variable_length_encoding_info.variable_field_length;
                
	    // Override record_length as we need full length to jump to another record
	    record_length = variable_length_encoding_info.record_full_length;
        }

        // We do not need this check when we have only fixed length fields in template
        // but this function is versatile and must handle all cases.
        if (offset + record_length > set_maximum_length) {
            logger << log4cpp::Priority::ERROR << "Attempt to read data after end of set. Offset: " << offset
                   << " record length: " << record_length << " set_maximum_length: " << set_maximum_length;
            return false;
        }

        bool ipfix_record_to_flow_result = ipfix_record_to_flow(record_type, record_length, packet_ptr + offset, packet, flow_meta);

        // In case of serious errors we stop loop completely
        if (!ipfix_record_to_flow_result) {
            return false;
        }

        offset += record_length;
    }

    // At this moment offset carries full length of all fields
    set_length = offset;

    // If we were able to decode nested packet then it means that it was Netflow Lite and we can overwrite information in packet
    if (flow_meta.nested_packet_parsed) {
        // Override most of the fields from nested packet as we need to use them instead
        override_packet_fields_from_nested_packet(packet, flow_meta.nested_packet);
    }


    if (false) {
        //
        // For Juniper routers we need fancy logic to mark packets as dropped as it does not use RFC compliant IPFIX field for it
        //

        //
        // The only reliable information we have from Juniper documentation is about Netflow v9
        // https://apps.juniper.net/feature-explorer/feature-info.html?fKey=7679&fn=Enhancements%20to%20inline%20flow%20monitoring
        // and we have no idea how it behaves in IPFIX mode.
        //
        // I think previously we had Juniper routers which set output interface to zero and both bgp_next_hop_ipv4 and
        // ip_next_hop_ipv4 to zero values to report dropped and we checked only bgp_next_hop_ipv4 to identify dropped
        // traffic. It worked well enough until we got flows explained below where bgp_next_hop_ipv4 is not 0.0.0.0 but
        // ip_next_hop_ipv4 and output interface were set to zeroes.
        //
        // In May 2023 got dumps in Google drive "MX10003 and MX 480 dropped traffic" which confirms that Juniper MX
        // 10003 / MX480 with JUNOS 20.4R3-S4.8 encode it using zero output interface and zero ip_next_hop_ipv4. In same
        // time these dumps have bgp_next_hop_ipv4 set to real non zero value of next router. To address this issue we
        // added alternative section to check for zeroe
        //
        // I posted question on LinkedIN: https://www.linkedin.com/feed/update/urn:li:activity:7062447441895141376/
        //

        // We will apply it only if we have no forwarding_status in packet
        if (!flow_meta.received_forwarding_status) {
            // We need to confirm that TWO rules are TRUE:
            // - Output interface is 0
            // - Next hop for IPv4 is set and set to 0 OR next hop for IPv6 set and set to zero
            if (packet.output_interface == 0 &&
                ((flow_meta.bgp_next_hop_ipv4_set && flow_meta.bgp_next_hop_ipv4 == 0) ||
                 (flow_meta.ip_next_hop_ipv4_set && flow_meta.ip_next_hop_ipv4 == 0) ||
                 (flow_meta.bgp_next_hop_ipv6_set && is_zero_ipv6_address(flow_meta.bgp_next_hop_ipv6)))) {

                packet.forwarding_status = forwarding_status_t::dropped;
                ipfix_marked_zero_next_hop_and_zero_output_as_dropped++;
            }
        }
    }

    // std::cout << "bgp next hop: " << convert_ip_as_uint_to_string(flow_meta.bgp_next_hop_ipv4) << " set " << flow_meta.bgp_next_hop_ipv4_set
    //    << " " << print_ipv6_address(flow_meta.bgp_next_hop_ipv6) << " set " << flow_meta.bgp_next_hop_ipv6_set  << " output interface: " << packet.output_interface <<  std::endl;

    netflow_ipfix_all_protocols_total_flows++;

    ipfix_total_flows++;

    // We may have cases like this from previous step:
    // :0000:443 > :0000:61444 protocol: tcp flags: psh,ack frag: 0  packets: 1 size: 205 bytes ip size: 205 bytes ttl:
    // 0 sample ratio: 1000 It happens when router sends IPv4 and zero IPv6 fields in same packet
    if (packet.ip_protocol_version == 6 && is_zero_ipv6_address(packet.src_ipv6) &&
        is_zero_ipv6_address(packet.dst_ipv6) && packet.src_ip != 0 && packet.dst_ip != 0) {

        ipfix_protocol_version_adjustments++;
        packet.ip_protocol_version = 4;
    }

    if (packet.ip_protocol_version == 4) {
        ipfix_total_ipv4_flows++;
    } else if (packet.ip_protocol_version == 6) {
        ipfix_total_ipv6_flows++;
    }

    double duration_float = packet.flow_end - packet.flow_start;

    // Well, it does happen with Juniper QFX
    if (duration_float < 0) {
        ipfix_duration_negative++;

        // I see no reasons to track duration of such cases because they're definitely broken
    } else {
        // Covert milliseconds to seconds
        duration_float = duration_float / 1000;

        int64_t duration = int64_t(duration_float);

        // Increments duration counters
        increment_duration_counters_ipfix(duration);

        // logger<< log4cpp::Priority::INFO<< "Flow start: " << packet.flow_start << " end: " << packet.flow_end << " duration: " << duration;
    }

    // logger<< log4cpp::Priority::INFO<<"src asn: " << packet.src_asn << " " << "dst asn: " << packet.dst_asn;

    // logger<< log4cpp::Priority::INFO<<"output: " << packet.output_interface << " " << " input: " << packet.input_interface;


    // Logical sources of this logic are unknown but I'm sure we had reasons to do so
    if (packet.protocol == IPPROTO_ICMP) {
        // Explicitly set ports to zeros even if device sent something in these fields
        packet.source_port      = 0;
        packet.destination_port = 0;
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
    return true;
}

bool process_ipfix_regular_data_set(const uint8_t* packet,
                                    uint32_t offset,
                                    uint32_t set_id,
                                    uint32_t set_length,
                                    const ipfix_header_t* ipfix_header,
                                    uint32_t source_id,
                                    const std::string& client_addres_in_string_format,
                                    uint32_t client_ipv4_address,
                                    const template_t* field_template);

bool process_ipfix_options_data_set(const uint8_t* packet,
                                    uint32_t offset,
                                    uint32_t set_id,
                                    uint32_t set_length,
                                    const ipfix_header_t* ipfix_header,
                                    uint32_t source_id,
                                    const std::string& client_addres_in_string_format,
                                    uint32_t client_ipv4_address,
                                    const template_t* field_template,
                                    const uint8_t* set_end);

bool process_ipfix_data_set(const uint8_t* packet,
                            uint32_t set_length,
                            const ipfix_header_t* ipfix_header,
                            uint32_t source_id,
                            const std::string& client_addres_in_string_format,
                            uint32_t client_ipv4_address) {

    const ipfix_set_header_common_t* set_header = (const ipfix_set_header_common_t*)packet;

    if (set_length < sizeof(ipfix_set_header_common_t)) {
        logger << log4cpp::Priority::ERROR << "Too short IPFIX set with not enough space for set header: " << set_length
               << " Agent: " << client_addres_in_string_format;
        return false;
    }

    // Store packet end, it's useful for sanity checks
    const uint8_t* set_end = packet + set_length;

    uint32_t set_id = set_header->get_set_id_host_byte_order();

    const template_t* field_template = peer_find_template(global_ipfix_templates, global_ipfix_templates_mutex,
                                                          source_id, set_id, client_addres_in_string_format);

    if (field_template == NULL) {
        ipfix_packets_with_unknown_templates++;

        logger << log4cpp::Priority::DEBUG << "We don't have a IPFIX template for set_id: " << set_id << " client "
               << client_addres_in_string_format << " source_id: " << source_id
               << " but it's not an error if this message disappears in some time "
                  "seconds. We need some time to learn them";

        return false;
    }

    if (field_template->records.empty()) {
        logger << log4cpp::Priority::ERROR << "There are no records in IPFIX template. Agent: " << client_addres_in_string_format;
        return false;
    }

    uint32_t offset = sizeof(ipfix_set_header_common_t);

    if (field_template->type == netflow_template_type_t::Data) {
        bool regular_ipfix_set_result =
            process_ipfix_regular_data_set(packet, offset, set_id, set_length, ipfix_header, source_id,
                                           client_addres_in_string_format, client_ipv4_address, field_template);

        if (!regular_ipfix_set_result) {
            return false;
        }
    } else if (field_template->type == netflow_template_type_t::Options) {
        bool options_ipfix_set_result =
            process_ipfix_options_data_set(packet, offset, set_id, set_length, ipfix_header, source_id,
                                           client_addres_in_string_format, client_ipv4_address, field_template, set_end);

        if (!options_ipfix_set_result) {
            return false;
        }
    }

    return true;
}

// Process regular data set which carries options data
bool process_ipfix_options_data_set(const uint8_t* packet,
                                    uint32_t offset,
                                    uint32_t set_id,
                                    uint32_t set_length,
                                    const ipfix_header_t* ipfix_header,
                                    uint32_t source_id,
                                    const std::string& client_addres_in_string_format,
                                    uint32_t client_ipv4_address,
                                    const template_t* field_template,
                                    const uint8_t* set_end) {
    ipfix_options_packet_number++;

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Starting process_ipfix_options_data_set for set_length " << set_length;
    }

    if (field_template->ipfix_variable_length_elements_used) {
        // We do not have logic to decode such encoding yet, it's used by Arista and we have dumps in lab
        logger << log4cpp::Priority::ERROR << "IPFIX variable field encoding is not supported. Agent: " << client_addres_in_string_format
               << " IPFIX sequence: " << ipfix_header->get_package_sequence_host_byte_order() << " set id: " << set_id;
        
	// We intentionally return true here as it's not internal consistency error and we need to continue processing other sets in packet
	return true;
    } else {

        // Check that we will not read outside of packet
        if (packet + offset + field_template->total_length > set_end) {
            logger << log4cpp::Priority::ERROR << "We tried to read data outside packet for IPFIX options. "
                   << "Agent: " << client_addres_in_string_format
                   << " IPFIX sequence: " << ipfix_header->get_package_sequence_host_byte_order() << " set id: " << set_id
                   << " set_length: " << set_length << " template total length: " << field_template->total_length
                   << " ipfix_variable_length_elements_used: " << field_template->ipfix_variable_length_elements_used;
            return false;
        }

        // Process options packet
        ipfix_options_set_to_store(packet + offset, ipfix_header, field_template, client_addres_in_string_format);
    }

    return true;
}

// Process regular data set which usually carries flows
bool process_ipfix_regular_data_set(const uint8_t* packet,
                                    uint32_t offset,
                                    uint32_t set_id,
                                    uint32_t set_length,
                                    const ipfix_header_t* ipfix_header,
                                    uint32_t source_id,
                                    const std::string& client_addres_in_string_format,
                                    uint32_t client_ipv4_address,
                                    const template_t* field_template) {
    if (field_template->ipfix_variable_length_elements_used) {
        // When we have variable length fields we need to use different logic which relies on flow length calculated during process of reading flow

        // Get clean sets length to use it as limit for our parser
        ssize_t current_set_length_no_header = set_length - sizeof(ipfix_set_header_common_t);

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "IPFIX variable field element was used";
        }

        // Where all flows start in packet
        const uint8_t* flow_section_start = packet + sizeof(ipfix_set_header_common_t);

        // Offset where flow starts
        uint32_t flow_offset = 0;

        // How much data we have in current flow set
        uint32_t maximum_data_available_to_read = current_set_length_no_header;

        // Run this loop until flow_offset reaches end of packet
        while (flow_offset < current_set_length_no_header) {
            // When variable fields present we need to read all fields before getting total length of flow
            uint32_t read_flow_length = 0;

            // In many cases we have just single flow per UDP packet but Juniper PTX uses multiple flows per packet
            bool floset_processing_result =
                ipfix_data_set_to_store(flow_section_start + flow_offset, ipfix_header, maximum_data_available_to_read,
                                        field_template, client_ipv4_address, read_flow_length, client_addres_in_string_format);

            // If we cannot process this set then we must stop processing here because we need correct value of set_length to jump to next record
            if (!floset_processing_result) {
                return false;
            }

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Total flow length: " << read_flow_length;
            }

            // Shift set offset by length of data read in this iteration
            flow_offset += read_flow_length;

            // And in the same time reduce amount of available to read data
            maximum_data_available_to_read -= read_flow_length;

	    // Check if amount of data we still have in packet is less then minimum length of data record
	    // Please note that as we use variable length fields we do not know exact length
	    // Instead it's minimum length
            if (maximum_data_available_to_read < field_template->total_length) {

	        // It may be padding but sadly we do not have any reasonable explanation about padding length for data records in RFC
		// https://datatracker.ietf.org/doc/html/rfc7011
		// Cisco ASR 9000 is doing 2 byte padding with presence of variable field records 
               
	        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
		    logger << log4cpp::Priority::DEBUG << "Got " << maximum_data_available_to_read << " byte padding on end of data set";
                }

		// I think we must report it as it may be curious case to look on and capture pcaps
		if (maximum_data_available_to_read > 5) {
                    logger << log4cpp::Priority::WARN << "Got too long " << maximum_data_available_to_read << " on end of data set";
		}

		const uint8_t* padding_start_in_packet = (const uint8_t*)(flow_section_start + flow_offset);

                bool all_padding_bytes_are_zero = are_all_padding_bytes_are_zero(padding_start_in_packet, maximum_data_available_to_read);
   
                if (all_padding_bytes_are_zero) {
	            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                        logger << log4cpp::Priority::DEBUG << "All padding bytes are zero, feel free to correctly stop processing";
                    }

                    // Stop loop correctly without triggering error
                    break;
                } else {
                    logger << log4cpp::Priority::ERROR << "Non zero " << maximum_data_available_to_read <<  " padding bytes, semething is wrong with packet";
                    // We have to report error
                    return false;
                }
	    } else {
                // All fine, we can try reading next record
	    }
        }
    } else {
        // We use this logic only if we have only fixed length field specifiers in template

        // Check that template total length is not zero as we're going to divide by it
        if (field_template->total_length == 0) {
            logger << log4cpp::Priority::ERROR << "Zero IPFIX template length is not valid "
                   << "client " << client_addres_in_string_format << " source_id: " << source_id;

            return false;
        }

        // This logic is pretty reliable but it works only if we do not have variable sized fields in template
        // In that case it's completely not applicable
        // But I prefer to keep it as it's very predictable and works great for fields fields
        // Templates with only fixed fields are 99% of our installations and variable fields are very rare
        // Consider this path as attempt to optimise things

        uint32_t number_of_records = (set_length - offset) / field_template->total_length;

        // We need to calculate padding value
        // IPFIX RFC explains it following way:
        // https://datatracker.ietf.org/doc/html/rfc7011?ref=pavel.network#section-3.3.1
        uint32_t set_padding = (set_length - offset) % field_template->total_length;

        // Very likely data will be aligned by 4 byte boundaries and will have padding 1, 2, 3 bytes
        // To be on safe side we assume that padding may be up to 7 bytes to achieve 8 byte boundaries
        // All other values may be sign of some kind of issues. For example, it may be template conflicts
        // https://pavel.network/its-just-wrong-to-update-ipfix-templates/
        if (set_padding > 7) {
            ipfix_sets_with_anomaly_padding++;
        }

        if (number_of_records > 0x4000) {
            logger << log4cpp::Priority::ERROR << "Very high number of IPFIX data records in set " << number_of_records
                   << " Agent: " << client_addres_in_string_format << " set template length: " << field_template->total_length;

            return false;
        }

        if (number_of_records == 0) {
            logger << log4cpp::Priority::ERROR << "Unexpected zero number of sets "
                   << " agent: " << client_addres_in_string_format << " set template length: " << field_template->total_length
                   << " set length " << set_length << " source_id " << source_id << " set_id: " << set_id;

            return false;
        }

        for (uint32_t record_index = 0; record_index < number_of_records; record_index++) {
            // We do not use it as we can use total_length directly instead of calculating it
            uint32_t read_data_length_discarded = 0;

            // We apply constraint that maximum potential length of flow set cannot exceed length of all fields in
            // template In this case we have no fields with variable length which may affect it and we're safe
            // We do not check response code as we can jump to next flow even if previous one failed
            ipfix_data_set_to_store(packet + offset, ipfix_header, field_template->total_length, field_template,
                                    client_ipv4_address, read_data_length_discarded, client_addres_in_string_format);

            offset += field_template->total_length;
        }
    }

    return true;
}

bool process_ipfix_sets(uint32_t offset,
                        const uint8_t* packet,
                        const std::string& client_addres_in_string_format,
                        uint32_t client_ipv4_address,
                        uint32_t ipfix_packet_length,
                        const ipfix_header_t* ipfix_header);

// Process IPFIX packet
bool process_ipfix_packet(const uint8_t* packet,
                          uint32_t udp_packet_length,
                          const std::string& client_addres_in_string_format,
                          uint32_t client_ipv4_address) {
    ipfix_total_packets++;

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Starting reading IPFIX UDP packet with length " << udp_packet_length;
    }

    // Ensure that we have enough bytes to read IPFIX packet header
    if (udp_packet_length < sizeof(ipfix_header_t)) {
        logger << log4cpp::Priority::ERROR << "Packet is too short to accommodate IPFIX header " << udp_packet_length
               << " bytes which requires at least " << sizeof(ipfix_header_t) << " bytes";
        return false;
    }

    const ipfix_header_t* ipfix_header = (const ipfix_header_t*)packet;

    // In compare with Netflow v9 IPFIX uses packet length instead of explicitly specified number of sets
    // https://datatracker.ietf.org/doc/html/rfc7011#section-3.1
    // Total length of the IPFIX Message, measured in octets, including Message Header and Set(s).
    uint32_t ipfix_packet_length = ipfix_header->get_length_host_byte_order();

    if (udp_packet_length == ipfix_packet_length) {
        // Under normal circumstances udp_packet_length must be equal to ipfix_packet_length
    } else {
        // If they're different we need to do more careful checks

        if (udp_packet_length > ipfix_packet_length) {
            // Theoretically it may happen if we have some padding on the end of packet
            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "udp_packet_length exceeds ipfix_packet_length, suspect padding";
            }

            ipfix_packets_with_padding++;
        }

        // And this case we cannot tolerate
        if (udp_packet_length < ipfix_packet_length) {
            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "UDP packet it shorter (" << udp_packet_length << ")"
                       << " then IPFIX data (" << ipfix_packet_length << "). Malformed packet";
            }

            return false;
        }
    }

    // We will start reading IPFIX sets right after IPFIX header
    uint32_t offset = sizeof(*ipfix_header);

    // This function will read all kinds of sets from packet
    bool result = process_ipfix_sets(offset, packet, client_addres_in_string_format, client_ipv4_address,
                                     ipfix_packet_length, ipfix_header);

    if (!result) {
        logger << log4cpp::Priority::ERROR << "process_ipfix_sets returned error";
        return false;
    }

    return true;
}

// This function will read all kinds of sets from packet
bool process_ipfix_sets(uint32_t offset,
                        const uint8_t* packet,
                        const std::string& client_addres_in_string_format,
                        uint32_t client_ipv4_address,
                        uint32_t ipfix_packet_length,
                        const ipfix_header_t* ipfix_header) {
    // We will use it to count number of sets
    uint64_t set_sequence_number = 0;

    uint32_t source_id = ipfix_header->get_source_id_host_byte_order();

    // Yes, it's infinite loop but we apply boundaries inside to limit it
    while (true) {
        set_sequence_number++;

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Reading set number " << set_sequence_number;
        }

        // We limit number of flow sets in packet and also use it for infinite loop prevention
        if (set_sequence_number > sets_per_packet_maximum_number) {
            logger << log4cpp::Priority::ERROR << "Infinite loop prevention triggered or we have so many sets inside IPFIX packet";
            return false;
        }

        if (offset >= ipfix_packet_length) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside of IPFIX packet agent IP: " << client_addres_in_string_format;
            return false;
        }

        // Check that we have enough space in packet to read set header
        if (offset + sizeof(ipfix_set_header_common_t) > ipfix_packet_length) {
            logger << log4cpp::Priority::ERROR << "Flowset is too short: we do not have space for set header. "
                   << "IPFIX packet agent IP:" << client_addres_in_string_format << " set number: " << set_sequence_number
                   << " offset: " << offset << " packet_length: " << ipfix_packet_length;
            return false;
        }

        const ipfix_set_header_common_t* set_header = (const ipfix_set_header_common_t*)(packet + offset);

        uint32_t set_id     = set_header->get_set_id_host_byte_order();
        uint32_t set_length = set_header->get_length_host_byte_order();

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Reading set ID: " << set_id << " with length " << set_length;
        }

        // One more check to ensure that we have enough space in packet to read whole set
        if (offset + set_length > ipfix_packet_length) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside IPFIX packet set agent IP: " << client_addres_in_string_format;
            return false;
        }

        switch (set_id) {
        case IPFIX_TEMPLATE_SET_ID:
            ipfix_data_templates_number++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Starting process_ipfix_data_template_set";
            }

            if (!process_ipfix_data_template_set(packet + offset, set_length, source_id, client_addres_in_string_format)) {
                return false;
            }
            break;
        case IPFIX_OPTIONS_SET_ID:
            ipfix_options_templates_number++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Starting process_ipfix_options_template_set";
            }

            if (!process_ipfix_options_template_set(packet + offset, set_length, source_id, client_addres_in_string_format)) {
                return false;
            }

            break;
        default:
            if (set_id < IPFIX_MIN_RECORD_SET_ID) {
                logger << log4cpp::Priority::ERROR << "Received unknown IPFIX reserved set type " << set_id;
                break; // interrupts only switch!
            }

            ipfix_data_packet_number++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Starting process_ipfix_data";
            }

            if (!process_ipfix_data_set(packet + offset, set_length, ipfix_header, source_id,
                                        client_addres_in_string_format, client_ipv4_address)) {
                return false;
            }

            break;
        }

        // Shift on length of processed set
        offset += set_length;

        if (offset == ipfix_packet_length) {
            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Interrupt IPFIX set reader logic as offset reached end of IPFIX packet";
            }

            break;
        }
    }

    return true;
}

void update_ipfix_sampling_rate(uint32_t sampling_rate, const std::string& client_addres_in_string_format) {
    if (sampling_rate == 0) {
        return;
    }

    // NB! Incoming sampling rate is big endian / network byte order
    auto new_sampling_rate = fast_ntoh(sampling_rate);

    ipfix_custom_sampling_rate_received++;

    logger << log4cpp::Priority::DEBUG << "I extracted sampling rate: " << new_sampling_rate << " for " << client_addres_in_string_format;

    bool any_changes_for_sampling = false;

    {
        // Replace old sampling rate value
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);

        auto known_sampling_rate = ipfix_sampling_rates.find(client_addres_in_string_format);

        if (known_sampling_rate == ipfix_sampling_rates.end()) {
            // We had no sampling rates before
            ipfix_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

            ipfix_sampling_rate_changes++;

            logger << log4cpp::Priority::INFO << "Learnt new IPFIX sampling rate " << new_sampling_rate << " for "
                   << client_addres_in_string_format;

            any_changes_for_sampling = true;
        } else {
            auto old_sampling_rate = known_sampling_rate->second;

            if (old_sampling_rate != new_sampling_rate) {
                ipfix_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

                ipfix_sampling_rate_changes++;

                logger << log4cpp::Priority::INFO << "Detected IPFIX sampling rate change from " << old_sampling_rate
                       << " to " << new_sampling_rate << " for " << client_addres_in_string_format;

                any_changes_for_sampling = true;
            }
        }
    }
}
