/* netflow plugin body */

// TODO: add timestamp to netflow templates stored at disk
// TODO: do not kill disk with netflow template writes to disk

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <fstream>
#include <map>
#include <vector>
#include <mutex>

#include "../fast_library.h"
#include "../ipfix_rfc.h"

#include "../all_logcpp_libraries.h"

#include "netflow.hpp"
#include "netflow_collector.h"

#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>

#include <boost/archive/xml_iarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>

// Get it from main programm
extern log4cpp::Category& logger;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;

// Sampling rate for Netflow v9 and IPFIX
unsigned int netflow_sampling_ratio = 1;

// Sampling rates extracted from Netflow
std::mutex netflow9_sampling_rates_mutex;
std::map<std::string, uint32_t> netflow9_sampling_rates;

// and IPFIX
std::mutex ipfix_sampling_rates_mutex;
std::map<std::string, uint32_t> ipfix_sampling_rates;

std::string netflow_plugin_name       = "netflow";
std::string netflow_plugin_log_prefix = netflow_plugin_name + ": ";

ipfix_information_database ipfix_db_instance;

uint64_t netflow_total_packets = 0;
// Number of incoming UDP packets
uint64_t netflow_v5_total_packets = 0;
// Number of flows in these packets (multiple in each packet)
uint64_t netflow_v5_total_flows = 0;

uint64_t netflow_v9_total_packets = 0;

// Multiple in each UDP packet
uint64_t netflow_v9_total_flows        = 0;
uint64_t netflow_v9_total_ipv4_packets = 0;
uint64_t netflow_v9_total_ipv6_packets = 0;

uint64_t netflow_ipfix_total_packets = 0;

// Total number of flows summarized for all kinds of Netflow and IPFIX
uint64_t netflow_all_protocols_total_flows = 0;

// Multiple in each UDP packet
uint64_t netflow_ipfix_total_flows        = 0;
uint64_t netflow_ipfix_total_ipv4_packets = 0;
uint64_t netflow_ipfix_total_ipv6_packets = 0;

uint64_t netflow_broken_packets = 0;

// Netflow9 counters
uint64_t netflow9_data_packet_number       = 0;
uint64_t netflow9_data_templates_number    = 0;
uint64_t netflow9_options_templates_number = 0;
// Number of times we received sampling rate from Netflow agent
uint64_t netflow9_custom_sampling_rate_received = 0;
uint64_t netflow9_options_packet_number         = 0;

// How much times we changed sampling rate for same agent
// As change we also count when we recived it for the first time
uint64_t netflow9_sampling_rate_changes = 0;

// How much times we changed sampling rate for same agent
// As change we also count when we recived it for the first time
uint64_t ipfix_sampling_rate_changes = 0;

// Number of dropped packets due to unknown template in message
uint64_t netflow9_packets_with_unknown_templates = 0;

// Duration counters for Netflow v9
uint64_t netflow9_duration_less_15_seconds    = 0;
uint64_t netflow9_duration_less_30_seconds    = 0;
uint64_t netflow9_duration_less_60_seconds    = 0;
uint64_t netflow9_duration_less_90_seconds    = 0;
uint64_t netflow9_duration_less_180_seconds   = 0;
uint64_t netflow9_duration_exceed_180_seconds = 0;

// Duration counter for IPFIX
uint64_t ipfix_duration_less_15_seconds    = 0;
uint64_t ipfix_duration_less_30_seconds    = 0;
uint64_t ipfix_duration_less_60_seconds    = 0;
uint64_t ipfix_duration_less_90_seconds    = 0;
uint64_t ipfix_duration_less_180_seconds   = 0;
uint64_t ipfix_duration_exceed_180_seconds = 0;

uint64_t ipfix_custom_sampling_rate_received = 0;

uint64_t ipfix_duration_negative = 0;

uint64_t netflow5_duration_less_15_seconds    = 0;
uint64_t netflow5_duration_less_30_seconds    = 0;
uint64_t netflow5_duration_less_60_seconds    = 0;
uint64_t netflow5_duration_less_90_seconds    = 0;
uint64_t netflow5_duration_less_180_seconds   = 0;
uint64_t netflow5_duration_exceed_180_seconds = 0;

// IPFIX counters
uint64_t ipfix_data_packet_number       = 0;
uint64_t ipfix_data_templates_number    = 0;
uint64_t ipfix_options_templates_number = 0;
uint64_t ipfix_options_packet_number    = 0;
// Number of dropped packets due to unknown template in message
uint64_t ipfix_packets_with_unknown_templates = 0;

// https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason
uint64_t ipfix_flows_end_reason_idle_timeout             = 0;
uint64_t ipfix_flows_end_reason_active_timeout           = 0;
uint64_t ipfix_flows_end_reason_end_of_flow_timeout      = 0;
uint64_t ipfix_flows_end_reason_force_end_timeout        = 0;
uint64_t ipfix_flows_end_reason_lack_of_resource_timeout = 0;

// Number of template updates when actual template content was changed
uint64_t template_updates_number_due_to_real_changes = 0;

// Number of templates received with same data as inside known by FastNetMon templates
uint64_t template_update_attempts_with_same_template_data = 0;

// Number of times when we write netflow / ipfix templates to disk
uint64_t template_netflow_ipfix_disk_writes = 0;


// Number of flows which exceed specified limit in configuration
uint64_t netflow_ignored_long_flows = 0;

// If we wan't listen on IPv4 and IPv6 in same time we need listen multiple
// sockets. Not good,
// right.

void increment_duration_counters_ipfix(int64_t duration);

// We limit number of flowsets in packet Netflow v9 / IPFIX packets with some reasonable number to reduce possible attack's surface and reduce probablity of infinite loop
uint64_t flowsets_per_packet_maximum_number = 256;

// TODO: add per source uniq templates support
process_packet_pointer netflow_process_func_ptr = NULL;

global_template_storage_t global_netflow9_templates;
global_template_storage_t global_netflow10_templates;

std::vector<system_counter_t> get_netflow_stats() {
    std::vector<system_counter_t> system_counter;

    system_counter.push_back(system_counter_t("netflow_total_packets", netflow_total_packets));

    // Netflow v5
    system_counter.push_back(system_counter_t("netflow_v5_total_packets", netflow_v5_total_packets));
    system_counter.push_back(system_counter_t("netflow_v5_total_flows", netflow_v5_total_flows));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_15_seconds", netflow5_duration_less_15_seconds));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_30_seconds", netflow5_duration_less_30_seconds));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_60_seconds", netflow5_duration_less_60_seconds));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_90_seconds", netflow5_duration_less_90_seconds));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_180_seconds", netflow5_duration_less_180_seconds));
    system_counter.push_back(system_counter_t("netflow_v5_duraion_exceed_180_seconds", netflow5_duration_exceed_180_seconds));

    // Netflow v9
    system_counter.push_back(system_counter_t("netflow_v9_total_packets", netflow_v9_total_packets));

    system_counter.push_back(system_counter_t("netflow_v9_total_flows", netflow_v9_total_flows));
    system_counter.push_back(system_counter_t("netflow_v9_total_ipv4_packets", netflow_v9_total_ipv4_packets));
    system_counter.push_back(system_counter_t("netflow_v9_total_ipv6_packets", netflow_v9_total_ipv6_packets));

    system_counter.push_back(system_counter_t("netflow_v9_duration_less_15_seconds", netflow9_duration_less_15_seconds));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_30_seconds", netflow9_duration_less_30_seconds));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_60_seconds", netflow9_duration_less_60_seconds));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_90_seconds", netflow9_duration_less_90_seconds));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_180_seconds", netflow9_duration_less_180_seconds));
    system_counter.push_back(system_counter_t("netflow_v9_duraion_exceed_180_seconds", netflow9_duration_exceed_180_seconds));

    system_counter.push_back(system_counter_t("ipfix_duration_less_15_seconds", ipfix_duration_less_15_seconds));
    system_counter.push_back(system_counter_t("ipfix_duration_less_30_seconds", ipfix_duration_less_30_seconds));
    system_counter.push_back(system_counter_t("ipfix_duration_less_60_seconds", ipfix_duration_less_60_seconds));
    system_counter.push_back(system_counter_t("ipfix_duration_less_90_seconds", ipfix_duration_less_90_seconds));
    system_counter.push_back(system_counter_t("ipfix_duration_less_180_seconds", ipfix_duration_less_180_seconds));
    system_counter.push_back(system_counter_t("ipfix_duraion_exceed_180_seconds", ipfix_duration_exceed_180_seconds));
    system_counter.push_back(system_counter_t("ipfix_duration_negative", ipfix_duration_negative));

    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_idle_timeout", ipfix_flows_end_reason_idle_timeout));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_active_timeout", ipfix_flows_end_reason_active_timeout));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_end_of_flow_timeout", ipfix_flows_end_reason_end_of_flow_timeout));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_force_end_timeout", ipfix_flows_end_reason_force_end_timeout));
    system_counter.push_back(system_counter_t("ipfix_flows_end_reason_lack_of_resource_timeout",
                                              ipfix_flows_end_reason_lack_of_resource_timeout));

    system_counter.push_back(system_counter_t("netflow_ipfix_total_packets", netflow_ipfix_total_packets));
    system_counter.push_back(system_counter_t("netflow_ipfix_total_flows", netflow_ipfix_total_flows));
    system_counter.push_back(system_counter_t("netflow_ipfix_total_ipv4_packets", netflow_ipfix_total_ipv4_packets));
    system_counter.push_back(system_counter_t("netflow_ipfix_total_ipv6_packets", netflow_ipfix_total_ipv6_packets));

    system_counter.push_back(system_counter_t("netflow_all_protocols_total_flows", netflow_all_protocols_total_flows));

    system_counter.push_back(system_counter_t("netflow_broken_packets", netflow_broken_packets));
    system_counter.push_back(system_counter_t("template_updates_number_due_to_real_changes", template_updates_number_due_to_real_changes));
    system_counter.push_back(system_counter_t("template_update_attempts_with_same_template_data",
                                              template_update_attempts_with_same_template_data));
    system_counter.push_back(system_counter_t("ipfix_data_packet_number", ipfix_data_packet_number));
    system_counter.push_back(system_counter_t("ipfix_data_templates_number", ipfix_data_templates_number));
    system_counter.push_back(system_counter_t("ipfix_options_templates_number", ipfix_options_templates_number));
    system_counter.push_back(system_counter_t("ipfix_options_packet_number", ipfix_options_packet_number));
    system_counter.push_back(system_counter_t("ipfix_packets_with_unknown_templates", ipfix_packets_with_unknown_templates));
    system_counter.push_back(system_counter_t("ipfix_custom_sampling_rate_received", ipfix_custom_sampling_rate_received));
    system_counter.push_back(system_counter_t("ipfix_sampling_rate_changes", ipfix_sampling_rate_changes));

    system_counter.push_back(system_counter_t("netflow9_data_packet_number", netflow9_data_packet_number));
    system_counter.push_back(system_counter_t("netflow9_data_templates_number", netflow9_data_templates_number));
    system_counter.push_back(system_counter_t("netflow9_options_templates_number", netflow9_options_templates_number));
    system_counter.push_back(system_counter_t("netflow9_options_packet_number", netflow9_options_packet_number));
    system_counter.push_back(system_counter_t("netflow9_packets_with_unknown_templates", netflow9_packets_with_unknown_templates));
    system_counter.push_back(system_counter_t("netflow9_custom_sampling_rate_received", netflow9_custom_sampling_rate_received));
    system_counter.push_back(system_counter_t("netflow9_sampling_rate_changes", netflow9_sampling_rate_changes));
    system_counter.push_back(system_counter_t("netflow_ignored_long_flows", netflow_ignored_long_flows));

    system_counter.push_back(system_counter_t("template_netflow_ipfix_disk_writes", template_netflow_ipfix_disk_writes));

    return system_counter;
}


/* Prototypes */
void add_update_peer_template(global_template_storage_t& table_for_add,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_addres_in_string_format,
                              peer_nf9_template& field_template,
                              bool& updated);

// This class carries information which does not need to stay in simple_packet_t because we need it only for parsing
class netflow_meta_info_t {
    public:
    // Packets selected by sampler
    uint64_t selected_packets = 0; 

    // Total number of packets on interface
    uint64_t observed_packets = 0; 

    // Sampling rate is observed_packets / selected_packets

    // Full length of packet (Netflow Lite)
    uint64_t data_link_frame_size = 0; 

    // Decoded nested packet
    simple_packet_t nested_packet;

    // Set to true when we were able to parse nested packet
    bool nested_packet_parsed = false;
};

int nf9_rec_to_flow(uint32_t record_type, uint32_t record_length, uint8_t* data, simple_packet_t& packet, std::vector<peer_nf9_record_t> & template_records, netflow_meta_info_t& flow_meta);

peer_nf9_template*
peer_find_template(global_template_storage_t& table_for_lookup, uint32_t source_id, uint32_t template_id, std::string client_addres_in_string_format) {

    // We use source_id for distinguish multiple netflow agents with same IP
    std::string key = client_addres_in_string_format + "_" + std::to_string(source_id);

    global_template_storage_t::iterator itr = table_for_lookup.find(key);

    if (itr == table_for_lookup.end()) {
        return NULL;
    }

    // Well, we found it!
    if (itr->second.count(template_id) > 0) {
        return &itr->second[template_id];
    } else {
        return NULL;
    }
}

// Wrapper functions
peer_nf9_template* peer_nf9_find_template(uint32_t source_id, uint32_t template_id, std::string client_addres_in_string_format) {
    return peer_find_template(global_netflow9_templates, source_id, template_id, client_addres_in_string_format);
}

peer_nf9_template* peer_nf10_find_template(uint32_t source_id, uint32_t template_id, std::string client_addres_in_string_format) {
    return peer_find_template(global_netflow10_templates, source_id, template_id, client_addres_in_string_format);
}

// This function reads all available options templates
// http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
bool process_netflow_v9_options_template(uint8_t* pkt, size_t len, uint32_t source_id, const std::string& client_addres_in_string_format) {
    nf9_options_header_common_t* options_template_header = (nf9_options_header_common_t*)pkt;

    if (len < sizeof(*options_template_header)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 options template header " << len << " bytes";
        return false;
    }

    if (ntohs(options_template_header->flowset_id) != NF9_OPTIONS_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_netflow_v9_options_template "
                  "expects only NF9_OPTIONS_FLOWSET_ID but got "
                  "another id: "
               << ntohs(options_template_header->flowset_id);
        return false;
    }

    nf9_options_header_t* options_nested_header = (nf9_options_header_t*)(pkt + sizeof(*options_template_header));


    if (len < sizeof(*options_template_header) + sizeof(*options_nested_header)) {
        logger << log4cpp::Priority::ERROR << "Could not read specific header for netflow v9 options template";
        return false;
    }

    uint16_t template_id = fast_ntoh(options_nested_header->template_id);

    if (len < sizeof(*options_template_header) + sizeof(*options_nested_header) + fast_ntoh(options_nested_header->option_scope_length)) {
        logger << log4cpp::Priority::ERROR << "Could not read specific header for netflow v9 options template: need more space for scope";
        return false;
    }

    // I'm going to skip scope processing right now
    uint8_t* zone_address = pkt + sizeof(*options_template_header) + sizeof(*options_nested_header);

    uint32_t scopes_offset     = 0;
    uint32_t scopes_total_size = 0;

    // Here I should read all available scopes and calculate total size!
    for (; scopes_offset < fast_ntoh(options_nested_header->option_scope_length);) {
        nf9_template_flowset_record_t* tmplr = (nf9_template_flowset_record_t*)(zone_address + scopes_offset);

        scopes_total_size += fast_ntoh(tmplr->length);
        scopes_offset += sizeof(*tmplr);
    }

    uint8_t* zone_address_without_skopes = zone_address + fast_ntoh(options_nested_header->option_scope_length);

    uint32_t offset         = 0;
    uint32_t records_number = 0;
    
    std::vector<peer_nf9_record_t> template_records_map;
    uint32_t total_size = 0;

    for (; offset < fast_ntoh(options_nested_header->option_length);) {
        records_number++;
        nf9_template_flowset_record_t* tmplr = (nf9_template_flowset_record_t*)(zone_address_without_skopes + offset);

        uint32_t record_type   = fast_ntoh(tmplr->type);
        uint32_t record_length = fast_ntoh(tmplr->length);

        peer_nf9_record_t current_record;
        current_record.record_type = record_type;
        current_record.record_length  = record_length;

        template_records_map.push_back(current_record);

        // logger << log4cpp::Priority::ERROR << "Got type " << record_type << " with length " << record_length;
        offset += sizeof(*tmplr);
        total_size += record_length;
    }

    peer_nf9_template field_template;

    field_template.template_id = template_id;
    field_template.records     = template_records_map;
    field_template.num_records = records_number;
    field_template.total_len   = total_size + scopes_total_size;
    field_template.type        = netflow9_template_type::Options;

    field_template.option_scope_length = scopes_total_size;

    // logger << log4cpp::Priority::INFO << "Read options template:" << print_peer_nf9_template(field_template);

    // Add/update template
    bool updated = false;
    add_update_peer_template(global_netflow9_templates, source_id, template_id, client_addres_in_string_format,
                             field_template, updated);

    return true;
}

// https://tools.ietf.org/html/rfc5101#page-18
bool process_ipfix_options_template(uint8_t* pkt, size_t len, uint32_t source_id, std::string client_addres_in_string_format) {
    ipfix_options_header_common_t* options_template_header = (ipfix_options_header_common_t*)pkt;

    if (len < sizeof(ipfix_options_header_common_t)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX options template header " << len << " bytes. "
               << "Agent IP: " << client_addres_in_string_format;
        return false;
    }

    uint16_t flowset_id     = fast_ntoh(options_template_header->flowset_id);
    uint16_t flowset_length = fast_ntoh(options_template_header->length);

    if (flowset_id != NF10_OPTIONS_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR << "For options template we expect " << NF10_OPTIONS_FLOWSET_ID
               << "flowset_id but got "
                  "another id: "
               << flowset_id << "Agent IP: " << client_addres_in_string_format;

        return false;
    }

    // logger << log4cpp::Priority::INFO << "flowset_id " << flowset_id << " flowset_length: " << flowset_length;

    ipfix_options_header_t* options_nested_header = (ipfix_options_header_t*)(pkt + sizeof(ipfix_options_header_common_t));

    // Check that we have enough space in packet to read ipfix_options_header_t
    if (len < sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t)) {
        logger << log4cpp::Priority::ERROR << "Could not read specific header for IPFIX options template."
               << "Agent IP: " << client_addres_in_string_format;
        return false;
    }

    // logger << log4cpp::Priority::INFO << "raw undecoded data template_id: " << options_nested_header->template_id <<
    // " field_count: " << options_nested_header->field_count
    //    << " scope_field_count: " << options_nested_header->scope_field_count;

    // Get all fields from options_nested_header
    uint16_t template_id       = fast_ntoh(options_nested_header->template_id);
    uint16_t field_count       = fast_ntoh(options_nested_header->field_count);
    uint16_t scope_field_count = fast_ntoh(options_nested_header->scope_field_count);

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

    // Shift our temporary pointer to place where scope section begins
    uint8_t* current_pointer_in_packet = (uint8_t*)(pkt + sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t));

    uint32_t scopes_total_size = 0;

    uint32_t scopes_payload_total_size = 0;

    // Then we have scope fields in packet, I'm not going to process them, I'll just skip them
    for (int scope_index = 0; scope_index < scope_field_count; scope_index++) {
        nf10_template_flowset_record_t* current_scopes_record = (nf10_template_flowset_record_t*)(current_pointer_in_packet);

        // Check that our attempt to read nf10_template_flowset_record_t will not exceed packet length
        if (len < sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t) + sizeof(nf10_template_flowset_record_t)) {
            logger << log4cpp::Priority::ERROR << "Attempt to read IPFIX flowset_record outside of packet. "
                   << "Agent IP: " << client_addres_in_string_format;
            return false;
        }

        uint16_t scope_field_size = fast_ntoh(current_scopes_record->length);
        uint16_t scope_field_type = fast_ntoh(current_scopes_record->type);

        logger << log4cpp::Priority::DEBUG << "Reading scope section with size " << scope_field_size << " and type: " << scope_field_type;

        // Increment scopes size
        scopes_total_size += sizeof(nf10_template_flowset_record_t);

        // Increment paylaod size
        scopes_payload_total_size += scope_field_size;

        // Shift pointer to the end of current scope field
        current_pointer_in_packet = (uint8_t*)(current_pointer_in_packet + sizeof(nf10_template_flowset_record_t));
    }

    // We've reached normal fields section
    uint32_t normal_fields_total_size = 0;

    std::vector<peer_nf9_record_t> template_records_map;

    uint32_t normal_fields_payload_total_size = 0;

    // Try to read all normal fields
    for (int field_index = 0; field_index < normal_field_count; field_index++) {
        nf10_template_flowset_record_t* current_normal_record = (nf10_template_flowset_record_t*)(current_pointer_in_packet);

        // Check that our attempt to read nf10_template_flowset_record_t will not exceed packet length
        if (len < sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t) + scopes_total_size +
                      sizeof(nf10_template_flowset_record_t)) {
            logger << log4cpp::Priority::ERROR << "Attempt to read IPFIX flowset_record outside of packet for normal field. "
                   << "Agent IP: " << client_addres_in_string_format;
            return false;
        }

        uint16_t normal_field_size = fast_ntoh(current_normal_record->length);
        uint16_t normal_field_type = fast_ntoh(current_normal_record->type);

        peer_nf9_record_t current_record;
        current_record.record_type   = normal_field_type;
        current_record.record_length = normal_field_size;

        template_records_map.push_back(current_record);

        logger << log4cpp::Priority::DEBUG << "Reading IPFIX options field with size " << normal_field_size
               << " and type: " << normal_field_type;

        // Increment total field size
        normal_fields_total_size += sizeof(nf10_template_flowset_record_t);

        // Increment toital payload size
        normal_fields_payload_total_size += normal_field_size;

        // Shift pointer to the end of current normal field
        current_pointer_in_packet = (uint8_t*)(current_pointer_in_packet + sizeof(nf10_template_flowset_record_t));
    }

    peer_nf9_template field_template;

    field_template.template_id = template_id;
    field_template.records     = template_records_map;

    // I do not think that we use it in our logic but I think it's reasonable to set it to number of normal fields
    field_template.num_records = normal_field_count;

    field_template.total_len = normal_fields_payload_total_size + scopes_payload_total_size;
    field_template.type      = netflow9_template_type::Options;

    field_template.option_scope_length = scopes_payload_total_size;

    // logger << log4cpp::Priority::INFO << "Read options template:" << print_peer_nf9_template(field_template);

    // Add/update template
    bool updated = false;
    add_update_peer_template(global_netflow10_templates, source_id, template_id, client_addres_in_string_format,
                             field_template, updated);

    return true;
}

bool process_netflow_v10_template(uint8_t* pkt, size_t len, uint32_t source_id, const std::string& client_addres_in_string_format) {
    nf10_flowset_header_common_t* template_header = (nf10_flowset_header_common_t*)pkt;
    // We use same struct as netflow v9 because netflow v9 and v10 (ipfix) is
    // compatible
    peer_nf9_template field_template;

    if (len < sizeof(*template_header)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX flowset template header " << len << " bytes";
        return false;
    }

    if (ntohs(template_header->flowset_id) != NF10_TEMPLATE_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_netflow_v10_template expects only "
                  "NF10_TEMPLATE_FLOWSET_ID but "
                  "got another id: "
               << ntohs(template_header->flowset_id);

        return false;
    }

    bool template_cache_update_required = false;

    for (uint32_t offset = sizeof(*template_header); offset < len;) {
        nf10_template_flowset_header_t* tmplh = (nf10_template_flowset_header_t*)(pkt + offset);

        uint32_t template_id = ntohs(tmplh->template_id);
        uint32_t count       = ntohs(tmplh->count);
        offset += sizeof(*tmplh);

        std::vector<peer_nf9_record_t> template_records_map;
        uint32_t total_size = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (offset >= len) {
                logger << log4cpp::Priority::ERROR << "short netflow v.10 flowset template";
                return false;
            }

            nf10_template_flowset_record_t* tmplr = (nf10_template_flowset_record_t*)(pkt + offset);
            uint32_t record_type                     = ntohs(tmplr->type);
            uint32_t record_length                   = ntohs(tmplr->length);

            peer_nf9_record_t current_record;
            current_record.record_type = record_type;
            current_record.record_length  = record_length;

            template_records_map.push_back(current_record);

            offset += sizeof(*tmplr);
            if (record_type & NF10_ENTERPRISE) {
                offset += sizeof(uint32_t); /* XXX -- ? */
            }

            total_size += record_length;
            // add check: if (total_size > peers->max_template_len)
        }

        field_template.template_id = template_id;
        field_template.num_records = count;
        field_template.total_len   = total_size;
        field_template.records     = template_records_map;
        field_template.type        = netflow9_template_type::Data;

        bool updated = false;
        add_update_peer_template(global_netflow10_templates, source_id, template_id, client_addres_in_string_format,
                                 field_template, updated);

        // If we have any changes for this template, let's flush them to disk
        if (updated) {
            template_cache_update_required = true;
        }
    }

    return true;
}

bool process_netflow_v9_template(uint8_t* pkt, size_t len, uint32_t source_id, const std::string& client_addres_in_string_format, uint64_t flowset_number) {
    nf9_flowset_header_common_t* template_header = (nf9_flowset_header_common_t*)pkt;
    peer_nf9_template field_template;

    if (len < sizeof(*template_header)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 flowset template header " << len
               << " bytes agent IP: " << client_addres_in_string_format;
        return false;
    }

    if (fast_ntoh(template_header->flowset_id) != NF9_TEMPLATE_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_netflow_v9_template expects only "
                  "NF9_TEMPLATE_FLOWSET_ID but "
                  "got another id: "
               << ntohs(template_header->flowset_id);
        return false;
    }

    bool template_cache_update_required = false;

    for (uint32_t offset = sizeof(*template_header); offset < len;) {
        nf9_template_flowset_header_t* tmplh = (nf9_template_flowset_header_t*)(pkt + offset);

        uint32_t template_id = ntohs(tmplh->template_id);
        uint32_t count       = ntohs(tmplh->count);
        offset += sizeof(*tmplh);

        // logger<< log4cpp::Priority::INFO<<"Template template_id
        // is:"<<template_id;

        uint32_t total_size = 0;

        std::vector<peer_nf9_record_t> template_records_map;
        for (uint32_t i = 0; i < count; i++) {
            if (offset >= len) {
                logger << log4cpp::Priority::ERROR << "Short Netflow v9 flowset template";
                return false;
            }

            nf9_template_flowset_record_t* tmplr = (nf9_template_flowset_record_t*)(pkt + offset);

            uint32_t record_type   = ntohs(tmplr->type);
            uint32_t record_length = ntohs(tmplr->length);

            peer_nf9_record_t current_record;
            current_record.record_type = record_type;
            current_record.record_length  = record_length;

            template_records_map.push_back(current_record);

            // logger<< log4cpp::Priority::INFO<<"Learn new template type:
            // "<<ntohs(tmplr->type)<<"
            // length:"<<ntohs(tmplr->length);

            offset += sizeof(*tmplr);
            total_size += record_length;

            // TODO: introduce nf9_check_rec_len
        }

        field_template.template_id = template_id;
        field_template.num_records = count;
        field_template.total_len   = total_size;
        field_template.records     = template_records_map;
        field_template.type        = netflow9_template_type::Data;

        // Add/update template
        bool updated = false;
        add_update_peer_template(global_netflow9_templates, source_id, template_id, client_addres_in_string_format,
                                 field_template, updated);

        // If we have any changes for this template, let's flush them to disk
        if (updated) {
            template_cache_update_required = true;
        }
    }

    // for (auto elem: global_netflow9_templates) {
    //    logger << log4cpp::Priority::INFO  << "Template ident: " << elem.first << " content: " <<
    //    print_peer_nf9_template(elem.second);
    //}

    return true;
}

void add_update_peer_template(global_template_storage_t& table_for_add,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_addres_in_string_format,
                              peer_nf9_template& field_template,
                              bool& updated) {

    std::string key = client_addres_in_string_format + "_" + std::to_string(source_id);

    // logger<< log4cpp::Priority::INFO<<"It's new option template
    // "<<template_id<<" for host:
    // "<<client_addres_in_string_format
    //    <<" with source id: "<<source_id;

    global_template_storage_t::iterator itr = table_for_add.find(key);

    if (itr != table_for_add.end()) {
        // We have information block about this agent

        // Try to find actual template id here
        if (itr->second.count(template_id) > 0) {
            // logger<< log4cpp::Priority::INFO<<"We already have information about
            // this template
            // with id:"
            //    <<template_id<<" for host: "<<client_addres_in_string_format;

            // Should I track timestamp here and drop old templates after some time?
            if (itr->second[template_id] != field_template) {
                itr->second[template_id] = field_template;
                template_updates_number_due_to_real_changes++;
                updated = true;
            } else {
                template_update_attempts_with_same_template_data++;
            }
        } else {
            // logger<< log4cpp::Priority::INFO<<"It's new option template
            // "<<template_id<<" for
            // host: "<<client_addres_in_string_format;
            itr->second[template_id] = field_template;
            updated                  = true;
        }
    } else {
        // We do not have any information about this Netflow agent
        template_storage_t temp_template_storage;
        temp_template_storage[template_id] = field_template;

        table_for_add[key] = temp_template_storage;
        updated            = true;
    }

    return;
}

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - record_length), data, record_length);

// Safe version of BE_COPY macro
bool be_copy_function(uint8_t* data, uint8_t* target, uint32_t target_field_length, uint32_t record_field_length) {
    if (target_field_length < record_field_length) {
        return false;
    }

    memcpy(target + (target_field_length - record_field_length), data, record_field_length);
    return true;
}

#define V9_FIELD(v9_field, store_field, flow_field) \
    case v9_field:                                  \
        BE_COPY(packet.flow_field);                 \
        break

int nf9_rec_to_flow(uint32_t record_type, uint32_t record_length, uint8_t* data, simple_packet_t& packet, netflow_meta_info_t& flow_meta) {
    /* XXX: use a table-based interpreter */
    switch (record_type) {
        V9_FIELD(NF9_IN_BYTES, OCTETS, length);
        V9_FIELD(NF9_IN_PACKETS, PACKETS, number_of_packets);
        V9_FIELD(NF9_IN_PROTOCOL, PROTO_FLAGS_TOS, protocol);
        V9_FIELD(NF9_TCP_FLAGS, PROTO_FLAGS_TOS, flags);
        V9_FIELD(NF9_L4_SRC_PORT, SRCDST_PORT, source_port);
        V9_FIELD(NF9_L4_DST_PORT, SRCDST_PORT, destination_port);

    case NF9_IPV4_SRC_ADDR:
        memcpy(&packet.src_ip, data, record_length);
        break;
    case NF9_IPV4_DST_ADDR:
        memcpy(&packet.dst_ip, data, record_length);
        break;
    case NF9_SRC_AS:
        // It could be 2 or 4 byte length
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
        }
        break;
    case NF9_IPV6_SRC_ADDR:
        // It should be 16 bytes only
        if (record_length == 16) {
            memcpy(&packet.src_ipv6, data, record_length);
            // Set protocol version to IPv6
            packet.ip_protocol_version = 6;
        }

        break;
    case NF9_IPV6_DST_ADDR:
        // It should be 16 bytes only
        if (record_length == 16) {
            memcpy(&packet.dst_ipv6, data, record_length);
            // Set protocol version to IPv6
            packet.ip_protocol_version = 6;
        }

        break;
    case NF9_DST_AS:
        // It could be 2 or 4 byte length
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
        }

        break;
    case NF9_INPUT_SNMP:
        // According to Netflow standard this field could have 2 or more bytes
        // Juniper MX uses 4 byte encoding
        // Here we support 2 or 4 byte encoding only
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
            // We do not support it
        }

        break;
    case NF9_OUTPUT_SNMP:
        // According to Netflow standard this field could have 2 or more bytes
        // Juniper MX uses 4 byte encoding
        // Here we support 2 or 4 byte encoding only
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
            // We do not support it
        }

        break;
    case NF9_FIRST_SWITCHED:
        if (record_length == 4) {
            uint32_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            packet.flow_start = flow_started;
        } else {
            // We do not support it
        }

        break;
    case NF9_LAST_SWITCHED:
        if (record_length == 4) {
            uint32_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            packet.flow_end = flow_finished;
        } else {
            // We do not support it
        }

        break;
    case NF9_FORWARDING_STATUS:
        // Documented here: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
        // Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
        // This field may carry information about fragmentation but we cannot confirm it, ASR 9000 exports most of the traffic with field 64, which means unknown
        if (record_length == 1) {
            uint8_t forwarding_status = 0;

            memcpy(&forwarding_status, data, record_length);

            // logger << log4cpp::Priority::ERROR << "Forwarding status: " << int(forwarding_status);
        } else {
            // It must be exactly one byte
        }

        break;
    case NF9_SELECTOR_TOTAL_PACKETS_OBSERVED:
        if (record_length == 8) {
            uint64_t packets_observed = 0;

            memcpy(&packets_observed, data, record_length);
            flow_meta.observed_packets = fast_ntoh(packets_observed);
        } else {
            // We do not support other length
        }

        break;
    case NF9_SELECTOR_TOTAL_PACKETS_SELECTED:
        if (record_length == 8) {
            uint64_t packets_selected = 0;

            memcpy(&packets_selected, data, record_length);
            flow_meta.selected_packets = fast_ntoh(packets_selected);
        } else {
            // We do not support other length
        }

        break;
    case NF9_DATALINK_FRAME_SIZE:
        if (record_length == 2) {
            uint16_t datalink_frame_size = 0;

            memcpy(&datalink_frame_size, data, record_length);
            flow_meta.data_link_frame_size = fast_ntoh(datalink_frame_size);
        } else {
            // We do not support other length
        }

        break;
    case NF9_LAYER2_PACKET_SECTION_DATA:
		// Netflow Lite parser logic
		break;
    }

    return 0;
}

bool nf10_rec_to_flow(uint32_t record_type, uint32_t record_length, uint8_t* data, simple_packet_t& packet) {
    /* XXX: use a table-based interpreter */
    switch (record_type) {
    case NF10_IN_BYTES:
        BE_COPY(packet.length);
        break;
    case NF10_IN_PACKETS:
        BE_COPY(packet.number_of_packets);
        break;
    case NF10_IN_PROTOCOL:
        BE_COPY(packet.protocol);
        break;
    case NF10_TCP_FLAGS:
        // Cisco NCS 55A1 encodes them as two bytes :(
        if (sizeof(packet.flags) < record_length) {
            return false;
        }

        BE_COPY(packet.flags);
        break;
    case NF10_L4_SRC_PORT:
        BE_COPY(packet.source_port);
        break;
    case NF10_L4_DST_PORT:
        BE_COPY(packet.destination_port);
        break;
    case NF10_IPV4_SRC_ADDR:
        memcpy(&packet.src_ip, data, record_length);
        break;
    case NF10_IPV4_DST_ADDR:
        memcpy(&packet.dst_ip, data, record_length);
        break;

    // According to https://www.iana.o > rg/assignments/ipfix/ipfix.xhtml ASN can be 4 byte only
    // Unfortunately, customer (Intermedia) shared pcap with ASNs encoded as 2 byte values :(
    case NF10_SRC_AS:
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
        }

        break;
    case NF10_DST_AS:
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
        }

        break;
    // According to https://www.iana.org/assignments/ipfix/ipfix.xhtml interfaces can be 4 byte only
    case NF10_INPUT_SNMP:
        if (record_length == 4) {
            uint32_t input_interface = 0;
            memcpy(&input_interface, data, record_length);

            input_interface        = fast_ntoh(input_interface);
            packet.input_interface = input_interface;
        }

        break;
    case NF10_OUTPUT_SNMP:
        if (record_length == 4) {
            uint32_t output_interface = 0;
            memcpy(&output_interface, data, record_length);

            output_interface        = fast_ntoh(output_interface);
            packet.output_interface = output_interface;
        }

        break;
    case NF10_IPV6_SRC_ADDR:
        // It should be 16 bytes only
        if (record_length == 16) {
            memcpy(&packet.src_ipv6, data, record_length);
            // Set protocol version to IPv6
            packet.ip_protocol_version = 6;
        }
        break;
    case NF10_IPV6_DST_ADDR:
        // It should be 16 bytes only
        if (record_length == 16) {
            memcpy(&packet.dst_ipv6, data, record_length);
            // Set protocol version to IPv6
            packet.ip_protocol_version = 6;
        }
        break;
    case NF10_FIRST_SWITCHED:
        // Mikrotik uses this encoding
        if (record_length == 4) {
            uint32_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            packet.flow_start = flow_started;
        } else {
            // We do not support it
        }

        break;
    case NF10_LAST_SWITCHED:
        // Mikrotik uses this encoding
        if (record_length == 4) {
            uint32_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            packet.flow_end = flow_finished;
        } else {
            // We do not support it
        }

        break;
        // Juniper uses NF10_FLOW_START_MILLISECONDS and NF10_FLOW_END_MILLISECONDS
    case NF10_FLOW_START_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            // We cast unsigned to signed and it may cause issues
            packet.flow_start = flow_started;
        }
        break;
    case NF10_FLOW_END_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            // We cast unsigned to signed and it may cause issues
            packet.flow_end = flow_finished;
        }

        break;
    case NF10_FLOW_END_REASON:
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
        }

		break;
    }

    return true;
}

// Read options data packet with known templat
bool nf10_options_flowset_to_store(uint8_t* pkt, size_t len, nf10_header_t* nf10_hdr, peer_nf9_template* flow_template, std::string client_addres_in_string_format) {
    // Skip scope fields, I really do not want to parse this informations
    pkt += flow_template->option_scope_length;

    auto template_records = flow_template->records;

    uint32_t sampling_rate = 0;
    uint32_t offset        = 0;

    for (auto elem : template_records) {
        uint8_t* data_shift = pkt + offset;

        // Time to extract sampling rate
        if (elem.record_type == NF10_SAMPLING_INTERVAL) {
            // RFC suggest that this field is 4 byte: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            if (elem.record_length > sizeof(sampling_rate)) {
                logger << log4cpp::Priority::ERROR << "Unexpectedly big size for IPFIX_SAMPLING_INTERVAL: " << elem.record_length;
                return false;
            }

            bool result = be_copy_function(data_shift, (uint8_t*)&sampling_rate, sizeof(sampling_rate), elem.record_length);

            if (!result) {
                logger << log4cpp::Priority::ERROR
                       << "Prevented attempt to read outside of allowed memory region for IPFIX_SAMPLING_INTERVAL";
                return false;
            }
        } else if (elem.record_type == NF10_SAMPLING_PACKET_INTERVAL) {
            // RFC suggest that this field is 4 byte: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            if (elem.record_length > sizeof(sampling_rate)) {
                logger << log4cpp::Priority::ERROR
                       << "Unexpectedly big size for IPFIX_SAMPLING_PACKET_INTERVAL: " << elem.record_length;
                return false;
            }

            bool result = be_copy_function(data_shift, (uint8_t*)&sampling_rate, sizeof(sampling_rate), elem.record_length);

            if (!result) {
                logger << log4cpp::Priority::ERROR << "Prevented attempt to read outside of allowed memory region for IPFIX_SAMPLING_PACKET_INTERVAL";
                return false;
            }
        }

        offset += elem.record_length;
    }

    if (sampling_rate != 0) {
        auto new_sampling_rate = fast_ntoh(sampling_rate);

        ipfix_custom_sampling_rate_received++;

        logger << log4cpp::Priority::DEBUG << "I extracted sampling rate: " << new_sampling_rate << " for "
               << client_addres_in_string_format;

        // Replace old sampling rate value
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);
        auto old_sampling_rate = ipfix_sampling_rates[client_addres_in_string_format];

        if (old_sampling_rate != new_sampling_rate) {
            ipfix_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

            ipfix_sampling_rate_changes++;

            logger << log4cpp::Priority::DEBUG << "Change IPFIX sampling rate from " << old_sampling_rate << " to "
                   << new_sampling_rate << " for " << client_addres_in_string_format;
        }
    }

    return true;
}

// We should rewrite nf9_flowset_to_store accroding to fixes here
void nf10_flowset_to_store(uint8_t* pkt, size_t len, nf10_header_t* nf10_hdr, peer_nf9_template* field_template, uint32_t client_ipv4_address, const std::string& client_addres_in_string_format) {
    uint32_t offset = 0;

    if (len < field_template->total_len) {
        logger << log4cpp::Priority::ERROR << "Total len from template bigger than packet len";
        return;
    }

    simple_packet_t packet;
    packet.source = NETFLOW;

    packet.agent_ip_address = client_ipv4_address;

    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec         = ntohl(nf10_hdr->time_sec);

    {
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);
        auto itr = ipfix_sampling_rates.find(client_addres_in_string_format);

        if (itr == ipfix_sampling_rates.end()) {
            // Use global value
            packet.sample_ratio = netflow_sampling_ratio;
        } else {
            packet.sample_ratio = itr->second;
        }
    }

    // By default, assume IPv4 traffic here
    // But code below can switch it to IPv6
    packet.ip_protocol_version = 4;

    for (std::vector<peer_nf9_record_t>::iterator iter = field_template->records.begin();
         iter != field_template->records.end(); iter++) {
        
        uint32_t record_type   = iter->record_type;
        uint32_t record_length = iter->record_length;

        nf10_rec_to_flow(record_type, record_length, pkt + offset, packet);

        offset += record_length;
    }

    netflow_all_protocols_total_flows++;

    netflow_ipfix_total_flows++;

    if (packet.ip_protocol_version == 4) {
        netflow_ipfix_total_ipv4_packets++;
    } else if (packet.ip_protocol_version == 6) {
        netflow_ipfix_total_ipv6_packets++;
    }

    double duration_float = packet.flow_end - packet.flow_start;
    // Covert milliseconds to seconds
    duration_float = duration_float / 1000;

    int64_t duration = int64_t(duration_float);

    // Increments duration counters
    increment_duration_counters_ipfix(duration);

    // logger<< log4cpp::Priority::INFO<< "Flow start: " << packet.flow_start << " end: " << packet.flow_end << " duration: " << duration;

    // logger<< log4cpp::Priority::INFO<<"src asn: " << packet.src_asn << " " << "dst asn: " << packet.dst_asn;

    // logger<< log4cpp::Priority::INFO<<"output: " << packet.output_interface << " " << " input: " << packet.input_interface;

    // decode data in network byte order to host byte order
    packet.length = fast_ntoh(packet.length);

    // It's tricky to distinguish IP length and full packet length here. Let's use same.
    packet.ip_length = packet.length;

    packet.number_of_packets = fast_ntoh(packet.number_of_packets);

    packet.protocol = fast_ntoh(packet.protocol);

    // We should convert ports to host byte order too
    packet.source_port      = fast_ntoh(packet.source_port);
    packet.destination_port = fast_ntoh(packet.destination_port);

    // Set protocol
    switch (packet.protocol) {
    case 1: {
        packet.protocol = IPPROTO_ICMP;

        packet.source_port      = 0;
        packet.destination_port = 0;
    } break;

    case 6: {
        packet.protocol = IPPROTO_TCP;
    } break;

    case 17: {
        packet.protocol = IPPROTO_UDP;
    } break;
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
}

// Read options data packet with known template
void nf9_options_flowset_to_store(uint8_t* pkt, size_t len, nf9_header_t* nf9_hdr, peer_nf9_template* flow_template, std::string client_addres_in_string_format) {
    // Skip scope fields, I really do not want to parse this informations
    pkt += flow_template->option_scope_length;
    // logger << log4cpp::Priority::ERROR << "We have following length for option_scope_length " <<
    // flow_template->option_scope_length;

    auto template_records = flow_template->records;

    uint32_t sampling_rate = 0;
    uint32_t offset        = 0;

    for (auto elem : template_records) {
        uint8_t* data_shift = pkt + offset;

        // Time to extract sampling rate
        // Cisco ASR1000
        if (elem.record_type == FLOW_SAMPLER_RANDOM_INTERVAL) {
            // Check supported length
            if (elem.record_length == FLOW_SAMPLER_RANDOM_INTERVAL_LENGTH or elem.record_length == FLOW_SAMPLER_RANDOM_INTERVAL_LENGTH_ASR1000) {
                bool result = be_copy_function(data_shift, (uint8_t*)&sampling_rate, sizeof(sampling_rate), elem.record_length);

                if (!result) {
                    logger << log4cpp::Priority::ERROR
                           << "Tool tried to read outside allowed memory region, prevented "
                              "fault: FLOW_SAMPLER_RANDOM_INTERVAL";
                }

                // logger << log4cpp::Priority::ERROR << "sampling rate: " << fast_ntoh(sampling_rate);
            } else {
                logger << log4cpp::Priority::ERROR << "Incorrect length for FLOW_SAMPLER_RANDOM_INTERVAL: " << elem.record_length;
            }
        } else if (elem.record_type == NETFLOW9_SAMPLING_INTERVAL) {
            // Juniper MX
            if (elem.record_length > sizeof(sampling_rate)) {
                logger << log4cpp::Priority::ERROR << "Unexpectedly big size for NETFLOW9_SAMPLING_INTERVAL: " << elem.record_length;
                continue;
            }

            bool result = be_copy_function(data_shift, (uint8_t*)&sampling_rate, sizeof(sampling_rate), elem.record_length);

            if (!result) {
                logger << log4cpp::Priority::ERROR << "Tool tried to read outside allowed memory region, prevented fault: NETFLOW9_SAMPLING_INTERVAL";
            }
        }

        offset += elem.record_length;
    }

    if (sampling_rate != 0) {
        auto new_sampling_rate = fast_ntoh(sampling_rate);

        netflow9_custom_sampling_rate_received++;

        // logger<< log4cpp::Priority::INFO << "I extracted sampling rate: " << new_sampling_rate
        //    << "for " << client_addres_in_string_format;

        // Replace old sampling rate value
        std::lock_guard<std::mutex> lock(netflow9_sampling_rates_mutex);
        auto old_sampling_rate = netflow9_sampling_rates[client_addres_in_string_format];

        if (old_sampling_rate != new_sampling_rate) {
            netflow9_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

            netflow9_sampling_rate_changes++;

            logger << log4cpp::Priority::DEBUG << "Change sampling rate from " << old_sampling_rate << " to "
                   << new_sampling_rate << " for " << client_addres_in_string_format;
        }
    }
}

// That's kind of histogram emulation
void increment_duration_counters_netflow_v9(int64_t duration) {
    if (duration <= 15) {
        netflow9_duration_less_15_seconds++;
    } else if (duration <= 30) {
        netflow9_duration_less_30_seconds++;
    } else if (duration <= 60) {
        netflow9_duration_less_60_seconds++;
    } else if (duration <= 90) {
        netflow9_duration_less_90_seconds++;
    } else if (duration <= 180) {
        netflow9_duration_less_180_seconds++;
    } else {
        netflow9_duration_exceed_180_seconds++;
    }

    return;
}

// That's kind of histogram emulation
void increment_duration_counters_ipfix(int64_t duration) {
    if (duration <= 15) {
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

// That's kind of histogram emulation
void increment_duration_counters_netflow_v5(int64_t duration) {
    if (duration <= 15) {
        netflow5_duration_less_15_seconds++;
    } else if (duration <= 30) {
        netflow5_duration_less_30_seconds++;
    } else if (duration <= 60) {
        netflow5_duration_less_60_seconds++;
    } else if (duration <= 90) {
        netflow5_duration_less_90_seconds++;
    } else if (duration <= 180) {
        netflow5_duration_less_180_seconds++;
    } else {
        netflow5_duration_exceed_180_seconds++;
    }

    return;
}


void nf9_flowset_to_store(uint8_t* pkt,
                          size_t len,
                          nf9_header_t* nf9_hdr,
                          std::vector<peer_nf9_record_t>& template_records,
                          std::string& client_addres_in_string_format,
                          uint32_t client_ipv4_address) {
    // Should be done according to
    // https://github.com/pavel-odintsov/fastnetmon/issues/147
    // if (template->total_len > len)
    //    return 1;

    uint32_t offset = 0;

    simple_packet_t packet;
    packet.source = NETFLOW;

    packet.agent_ip_address = client_ipv4_address;

    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec         = ntohl(nf9_hdr->time_sec);

    // By default, assume IPv4 traffic here
    // But code below can switch it to IPv6
    packet.ip_protocol_version = 4;

    {
        std::lock_guard<std::mutex> lock(netflow9_sampling_rates_mutex);
        auto itr = netflow9_sampling_rates.find(client_addres_in_string_format);

        if (itr == netflow9_sampling_rates.end()) {
            // Use global value
            packet.sample_ratio = netflow_sampling_ratio;
        } else {
            packet.sample_ratio = itr->second;
        }
    }

    // Place to keep meta information which is not needed in simple_simple_packet_t structure
    netflow_meta_info_t flow_meta;

    // We should iterate over all available template fields
    for (std::vector<peer_nf9_record_t>::iterator iter = template_records.begin(); iter != template_records.end(); iter++) {
        uint32_t record_type   = iter->record_type;
        uint32_t record_length = iter->record_length;

        int nf9_rec_to_flow_result = nf9_rec_to_flow(record_type, record_length, pkt + offset, packet, flow_meta);
        // logger<< log4cpp::Priority::INFO<<"Read data with type: "<<record_type<<"
        // and
        // length:"<<record_length;
        if (nf9_rec_to_flow_result != 0) {
            return;
        }

        offset += record_length;
    }

    // Total number of Netflow v9 flows
    netflow_v9_total_flows++;

    netflow_all_protocols_total_flows++;

    if (packet.ip_protocol_version == 4) {
        netflow_v9_total_ipv4_packets++;
    } else if (packet.ip_protocol_version == 6) {
        netflow_v9_total_ipv6_packets++;
    }

    double duration_float = packet.flow_end - packet.flow_start;
    // Covert milliseconds to seconds
    duration_float = duration_float / 1000;

    int64_t duration = int64_t(duration_float);

    // Increments duration counters
    increment_duration_counters_netflow_v9(duration);

    // logger<< log4cpp::Priority::INFO<< "Flow start: " << packet.flow_start << " end: " << packet.flow_end << " duration: " << duration;

    // decode data in network byte order to host byte order
    packet.length = fast_ntoh(packet.length);

    // It's tricky to distinguish IP length and full packet lenght here. Let's use same.
    packet.ip_length         = packet.length;
    packet.number_of_packets = fast_ntoh(packet.number_of_packets);

    packet.protocol = fast_ntoh(packet.protocol);

    // We should convert ports to host byte order too
    packet.source_port      = fast_ntoh(packet.source_port);
    packet.destination_port = fast_ntoh(packet.destination_port);

    // Set protocol
    switch (packet.protocol) {
    case 1: {
        packet.protocol = IPPROTO_ICMP;

        packet.source_port      = 0;
        packet.destination_port = 0;
    } break;

    case 6: {
        packet.protocol = IPPROTO_TCP;
    } break;

    case 17: {
        packet.protocol = IPPROTO_UDP;
    } break;
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
}

bool process_netflow_v10_data(uint8_t* pkt,
                             size_t len,
                             nf10_header_t* nf10_hdr,
                             uint32_t source_id,
                             const std::string& client_addres_in_string_format,
                             uint32_t client_ipv4_address) {

    nf10_data_flowset_header_t* dath = (nf10_data_flowset_header_t*)pkt;

    // Store packet end, it's useful for sanity checks
    uint8_t* packet_end = pkt + len;

    if (len < sizeof(*dath)) {
        logger << log4cpp::Priority::ERROR << "Short netflow v10 data flowset header. Agent: " << client_addres_in_string_format;
        return false;
    }

    uint32_t flowset_id = ntohs(dath->c.flowset_id);

    peer_nf9_template* flowset_template = peer_nf10_find_template(source_id, flowset_id, client_addres_in_string_format);

    if (flowset_template == NULL) {
        ipfix_packets_with_unknown_templates++;

        logger << log4cpp::Priority::DEBUG << "We don't have a IPFIX template for flowset_id: " << flowset_id
               << " client " << client_addres_in_string_format << " source_id: " << source_id
               << " but it's not an error if this message disappears in 5-10 "
                  "seconds. We need some "
                  "time to learn it!";

        return false;
    }

    if (flowset_template->records.empty()) {
        logger << log4cpp::Priority::ERROR << "Blank records in IPFIX template. Agent: " << client_addres_in_string_format;
        return false;
    }

    uint32_t offset       = sizeof(*dath);
    uint32_t num_flowsets = (len - offset) / flowset_template->total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logger << log4cpp::Priority::ERROR << "Invalid number of data flowset, strange number of flows: " << num_flowsets;
        return false;
    }

    if (flowset_template->type == netflow9_template_type::Data) {

        for (uint32_t i = 0; i < num_flowsets; i++) {
            // process whole flowset
            nf10_flowset_to_store(pkt + offset, flowset_template->total_len, nf10_hdr, flowset_template,
                                  client_ipv4_address, client_addres_in_string_format);

            offset += flowset_template->total_len;
        }

    } else if (flowset_template->type == netflow9_template_type::Options) {
        ipfix_options_packet_number++;

        // Check that we will not read outside of packet
        if (pkt + offset + flowset_template->total_len > packet_end) {
            logger << log4cpp::Priority::ERROR << "We tried to read data outside packet for IPFIX options. "
                   << "Agent: " << client_addres_in_string_format;
            return 1;
        }

        // Process options packet
        nf10_options_flowset_to_store(pkt + offset, flowset_template->total_len, nf10_hdr, flowset_template,
                                      client_addres_in_string_format);
    }

    return true;
}

int process_netflow_v9_data(uint8_t* pkt,
                            size_t len,
                            nf9_header_t* nf9_hdr,
                            uint32_t source_id,
                            std::string& client_addres_in_string_format,
                            uint32_t client_ipv4_address) {
    nf9_data_flowset_header_t* dath = (nf9_data_flowset_header_t*)pkt;

    // Store packet end, it's useful for sanity checks
    uint8_t* packet_end = pkt + len;

    if (len < sizeof(*dath)) {
        logger << log4cpp::Priority::INFO << "Short netflow v9 data flowset header";
        return 1;
    }

    // uint32_t is a 4 byte integer. Any reason why we convert here 16 bit flowset_id to 32 bit? ... Strange
    uint32_t flowset_id = ntohs(dath->c.flowset_id);
    // logger<< log4cpp::Priority::INFO<<"We have data with flowset_id:
    // "<<flowset_id;

    // We should find template here
    peer_nf9_template* flowset_template = peer_nf9_find_template(source_id, flowset_id, client_addres_in_string_format);

    if (flowset_template == NULL) {
        netflow9_packets_with_unknown_templates++;

        logger << log4cpp::Priority::DEBUG << "We don't have a Netflow 9 template for flowset_id: " << flowset_id
               << " client " << client_addres_in_string_format << " source_id: " << source_id
               << " but it's not an error if this message disappears in 5-10 "
                  "seconds. We need some "
                  "time to learn it!";
        return 0;
    }

    if (flowset_template->records.empty()) {
        logger << log4cpp::Priority::ERROR << "Blank records in template";
        return 1;
    }

    uint32_t offset       = sizeof(*dath);
    uint32_t num_flowsets = (len - offset) / flowset_template->total_len;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logger << log4cpp::Priority::ERROR << "Invalid number of data flowsets, strange number of flows: " << num_flowsets;
        return 1;
    }

    if (flowset_template->type == netflow9_template_type::Data) {
        for (uint32_t i = 0; i < num_flowsets; i++) {
            // process whole flowset
            nf9_flowset_to_store(pkt + offset, flowset_template->total_len, nf9_hdr, flowset_template->records,
                                 client_addres_in_string_format, client_ipv4_address);

            offset += flowset_template->total_len;
        }
    } else if (flowset_template->type == netflow9_template_type::Options) {
        // logger << log4cpp::Priority::INFO << "I have " << num_flowsets << " flowsets here";
        // logger << log4cpp::Priority::INFO << "Flowset template total length: " << flowset_template->total_len;

        netflow9_options_packet_number++;

        for (uint32_t i = 0; i < num_flowsets; i++) {
            if (pkt + offset + flowset_template->total_len > packet_end) {
                logger << log4cpp::Priority::ERROR << "We tried to read data outside packet end";
                return 1;
            }

            // logger << log4cpp::Priority::INFO << "Process flowset: " << i;
            nf9_options_flowset_to_store(pkt + offset, flowset_template->total_len, nf9_hdr, flowset_template,
                                         client_addres_in_string_format);

            offset += flowset_template->total_len;
        }
    }

    return 0;
}

bool process_netflow_packet_v10(uint8_t* packet, uint32_t len, const std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    nf10_header_t* nf10_hdr = (nf10_header_t*)packet;
    nf10_flowset_header_common_t* flowset;

    uint32_t flowset_id, flowset_len;

    if (len < sizeof(*nf10_hdr)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX header " << len << " bytes";
        return false;
    }

    /* v10 uses pkt length, not # of flows */
    uint32_t pktlen    = ntohs(nf10_hdr->c.flows);
    uint32_t source_id = ntohl(nf10_hdr->source_id);

    uint32_t offset      = sizeof(*nf10_hdr);
    uint32_t total_flows = 0;

    uint64_t flowset_number = 0;

    // Yes, it's infinite loop but we apply boundaries inside to limit it
    while (true) {
        flowset_number++;

        // We limit number of flow sets in packet and also use it for infinite loop prevention
        if (flowset_number > flowsets_per_packet_maximum_number) {
            logger << log4cpp::Priority::ERROR << "Infinite loop prevention triggered or we have so many flowsets inside IPFIX packet";
            return false;
        }

        if (offset >= len) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside of IPFIX packet agent IP: " << client_addres_in_string_format;
            return false;
        }

        flowset     = (nf10_flowset_header_common_t*)(packet + offset);
        flowset_id  = ntohs(flowset->flowset_id);
        flowset_len = ntohs(flowset->length);

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */

        if (offset + flowset_len > len) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside IPFIX packet flowset agent IP: " << client_addres_in_string_format;
            return false;
        }

        switch (flowset_id) {
        case NF10_TEMPLATE_FLOWSET_ID:
            ipfix_data_templates_number++;
            if (!process_netflow_v10_template(packet + offset, flowset_len, source_id, client_addres_in_string_format)) {
                return false;
            }
            break;
        case NF10_OPTIONS_FLOWSET_ID:
            ipfix_options_templates_number++;
            if (!process_ipfix_options_template(packet + offset, flowset_len, source_id, client_addres_in_string_format)) {
                return false;
            }
            break;
        default:
            if (flowset_id < NF10_MIN_RECORD_FLOWSET_ID) {
                logger << log4cpp::Priority::ERROR << "Received unknown IPFIX reserved flowset type " << flowset_id;
                break; // interrupts only switch!
            }

            ipfix_data_packet_number++;

            if (!process_netflow_v10_data(packet + offset, flowset_len, nf10_hdr, source_id,
                                         client_addres_in_string_format, client_ipv4_address)) {
                return false;
            }

            break;
        }

        offset += flowset_len;
        if (offset == len) {
            break;
        }
    }

    return true;
}

bool process_netflow_packet_v9(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    // logger<< log4cpp::Priority::INFO<<"We get v9 netflow packet!";

    nf9_header_t* nf9_hdr                = (nf9_header_t*)packet;
    nf9_flowset_header_common_t* flowset = nullptr;

    if (len < sizeof(*nf9_hdr)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 header";
        return false;
    }

    uint32_t flowset_count_total = ntohs(nf9_hdr->c.flows);

    // Limit reasonable number of flow sets per packet
    if (flowset_count_total > flowsets_per_packet_maximum_number) {
        logger << log4cpp::Priority::ERROR << "We have so many flowsets inside Netflow v9 packet: " << flowset_count_total
               << " Agent IP:" << client_addres_in_string_format;
        return false;
    }

    uint32_t source_id = ntohl(nf9_hdr->source_id);
    // logger<< log4cpp::Priority::INFO<<"Template source id: "<<source_id;

    uint32_t offset      = sizeof(*nf9_hdr);

    // logger<< log4cpp::Priority::INFO<< "Total flowsets " << flowset_count_total;

    for (uint32_t flowset_number = 0; flowset_number < flowset_count_total; flowset_number++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= len) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside Netflow packet agent IP:" << client_addres_in_string_format
                   << " flowset number: " << flowset_number;
            return false;
        }

        flowset = (nf9_flowset_header_common_t*)(packet + offset);

        uint32_t flowset_id  = ntohs(flowset->flowset_id);
        uint32_t flowset_len = ntohs(flowset->length);

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */

        if (offset + flowset_len > len) {
            logger << log4cpp::Priority::ERROR << "We tried to read from address outside Netflow's packet flowset agent IP: "
                   << client_addres_in_string_format << " flowset number: " << flowset_number
                   << " flowset_id: " << flowset_id << " flowset_length: " << flowset_len;
            return false;
        }

        switch (flowset_id) {
        case NF9_TEMPLATE_FLOWSET_ID:
            netflow9_data_templates_number++;
            // logger<< log4cpp::Priority::INFO<<"We read template";
            if (!process_netflow_v9_template(packet + offset, flowset_len, source_id, client_addres_in_string_format, flowset_number)) {
                return false;
            }
            break;
        case NF9_OPTIONS_FLOWSET_ID:
            netflow9_options_templates_number++;
            if (!process_netflow_v9_options_template(packet + offset, flowset_len, source_id, client_addres_in_string_format)) {
                return false;
            }
            break;
        default:
            if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
                logger << log4cpp::Priority::ERROR << "Received unknown Netflow v9 reserved flowset type " << flowset_id
                       << " agent IP: " << client_addres_in_string_format;
                break; // interrupts only switch!
            }

            netflow9_data_packet_number++;
            // logger<< log4cpp::Priority::INFO<<"We read data";

            if (process_netflow_v9_data(packet + offset, flowset_len, nf9_hdr, source_id,
                                        client_addres_in_string_format, client_ipv4_address) != 0) {
                // logger<< log4cpp::Priority::ERROR<<"Can't process function
                // process_netflow_v9_data correctly";
                netflow_broken_packets++;
                return false;
            }

            break;
        }

        // This logic will stop processing if we've reached end of flow set setction before reading all flow sets
        // It's not reliable to use alone because we may have garbadge at the end of packet. That's why we have loop over number of flowset records as main condition.
        offset += flowset_len;
        if (offset == len) {
            break;
        }
    }

    return true;
}

bool process_netflow_packet_v5(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    // logger<< log4cpp::Priority::INFO<<"We get v5 netflow packet!";

    nf5_header_t* nf5_hdr = (nf5_header_t*)packet;

    if (len < sizeof(*nf5_hdr)) {
        logger << log4cpp::Priority::ERROR << "Short netflow v5 packet " << len;
        return false;
    }

    uint32_t nflows = ntohs(nf5_hdr->c.flows);
    if (nflows == 0 || nflows > NF5_MAXFLOWS) {
        logger << log4cpp::Priority::ERROR << "Invalid number of flows in netflow " << nflows;
        return false;
    }

    uint16_t netflow5_sampling_ratio = fast_ntoh(nf5_hdr->sampling_rate);

    // In first two bits we store sampling type.
    // We are not interested in it and should zeroify it for getting correct value
    // of sampling rate
    clear_bit_value(netflow5_sampling_ratio, 15);
    clear_bit_value(netflow5_sampling_ratio, 16);

    // Sampling not enabled on device
    if (netflow5_sampling_ratio == 0) {
        netflow5_sampling_ratio = 1;
    }

    for (uint32_t i = 0; i < nflows; i++) {
        size_t offset        = NF5_PACKET_SIZE(i);
        nf5_flow_t* nf5_flow = (nf5_flow_t*)(packet + offset);

        /* Check packet bounds */
        if (offset + sizeof(nf5_flow_t) > len) {
            logger << log4cpp::Priority::ERROR << "Error! You will try to read outside the Netflow v5 packet";
            return false;
        }

        netflow_all_protocols_total_flows++;
        netflow_v5_total_flows++;

        /* Decode to host encoding */
        // TODO: move to separate function
        nf5_flow->flow_octets  = fast_ntoh(nf5_flow->flow_octets);
        nf5_flow->flow_packets = fast_ntoh(nf5_flow->flow_packets);

        // Convert to little endian
        nf5_flow->if_index_in  = fast_ntoh(nf5_flow->if_index_in);
        nf5_flow->if_index_out = fast_ntoh(nf5_flow->if_index_out);

        // convert netflow to simple packet form
        simple_packet_t current_packet;
        current_packet.source = NETFLOW;

        current_packet.agent_ip_address = client_ipv4_address;

        current_packet.src_ip     = nf5_flow->src_ip;
        current_packet.dst_ip     = nf5_flow->dest_ip;
        current_packet.ts.tv_sec  = ntohl(nf5_hdr->time_sec);
        current_packet.ts.tv_usec = ntohl(nf5_hdr->time_nanosec);
        current_packet.flags      = 0;

        // If we have ASN information it should not be zero
        current_packet.src_asn = fast_ntoh(nf5_flow->src_as);
        current_packet.dst_asn = fast_ntoh(nf5_flow->dest_as);

        // We do not need fast_ntoh here becasue we already converted these fields before
        current_packet.input_interface  = nf5_flow->if_index_in;
        current_packet.output_interface = nf5_flow->if_index_out;

        current_packet.source_port      = 0;
        current_packet.destination_port = 0;

        // TODO: we should pass data about "flow" structure of this data
        // It's pretty interesting because according to Cisco's
        // http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
        // In Netflow v5 we have "Total number of Layer 3 bytes in the packets of the flow"
        // TODO: so for full length we should use flow_octets + 14 bytes per each packet for more reliable bandwidth
        // detection
        current_packet.length            = nf5_flow->flow_octets;
        current_packet.ip_length         = nf5_flow->flow_octets;
        current_packet.number_of_packets = nf5_flow->flow_packets;

        // This interval in milliseconds, convert it to seconds
        int64_t interval_length = (fast_ntoh(nf5_flow->flow_finish) - fast_ntoh(nf5_flow->flow_start)) / 1000;

        increment_duration_counters_netflow_v5(interval_length);

        // TODO: use sampling data from packet, disable customization here
        // Wireshark dump approves this idea
        current_packet.sample_ratio = netflow5_sampling_ratio;

        current_packet.source_port      = fast_ntoh(nf5_flow->src_port);
        current_packet.destination_port = fast_ntoh(nf5_flow->dest_port);

        // We do not support IPv6 in NetFlow v5 at all
        current_packet.ip_protocol_version = 4;

        switch (nf5_flow->protocol) {
        case 1: {
            // ICMP
            current_packet.protocol = IPPROTO_ICMP;
        } break;

        case 6: {
            // TCP
            current_packet.protocol = IPPROTO_TCP;

            // TODO: flags can be in another format!
            current_packet.flags = nf5_flow->tcp_flags;
        } break;

        case 17: {
            // UDP
            current_packet.protocol = IPPROTO_UDP;
        } break;
        }

        // Call processing function for every flow in packet
        netflow_process_func_ptr(current_packet);
    }

    return true;
}

bool process_netflow_packet(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    nf_header_common_t* hdr = (nf_header_common_t*)packet;

    switch (ntohs(hdr->version)) {
    case 5:
        netflow_v5_total_packets++;
        return process_netflow_packet_v5(packet, len, client_addres_in_string_format, client_ipv4_address);
    case 9:
        netflow_v9_total_packets++;
        return process_netflow_packet_v9(packet, len, client_addres_in_string_format, client_ipv4_address);
    case 10:
        netflow_ipfix_total_packets++;
        return process_netflow_packet_v10(packet, len, client_addres_in_string_format, client_ipv4_address);
    default:
        netflow_broken_packets++;
        logger << log4cpp::Priority::ERROR << "We do not support Netflow " << ntohs(hdr->version)
               << " we received this packet from " << client_addres_in_string_format;

        return false;
    }

    return true;
}

void start_netflow_collector(std::string netflow_host, unsigned int netflow_port, bool reuse_port);

void start_netflow_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "netflow plugin started";

    netflow_process_func_ptr = func_ptr;
    // By default we listen on IPv4
    std::string netflow_host = "0.0.0.0";

    // If we have custom port use it from configuration
    if (configuration_map.count("netflow_host") != 0) {
        netflow_host = configuration_map["netflow_host"];
    }

    std::string netflow_ports_string = "";

    if (configuration_map.count("netflow_port") != 0) {
        netflow_ports_string = configuration_map["netflow_port"];
    }

    if (configuration_map.count("netflow_sampling_ratio") != 0) {
        netflow_sampling_ratio = convert_string_to_integer(configuration_map["netflow_sampling_ratio"]);

        logger << log4cpp::Priority::INFO << "Using custom sampling ratio for Netflow v9 and IPFIX: " << netflow_sampling_ratio;
    }

    std::vector<std::string> ports_for_listen;
    boost::split(ports_for_listen, netflow_ports_string, boost::is_any_of(","), boost::token_compress_on);

    std::vector<unsigned int> netflow_ports;

    for (auto port: ports_for_listen) {
        unsigned int netflow_port = convert_string_to_integer(port);

        if (netflow_port == 0) {
            logger << log4cpp::Priority::ERROR << "Cannot parse Netflow port: " << port;
            continue;
        }

        netflow_ports.push_back(netflow_port);
    }

    boost::thread_group netflow_collector_threads;

    logger << log4cpp::Priority::INFO << netflow_plugin_log_prefix << "We will listen on " << netflow_ports.size() << " ports";

    for (const auto& netflow_port : netflow_ports) {
        bool reuse_port = false;

        auto netflow_processing_thread = new boost::thread(start_netflow_collector, netflow_host, netflow_port, reuse_port);

        // Set unique name
        std::string thread_name = "netflow_" + std::to_string(netflow_port);
        set_boost_process_name(netflow_processing_thread, thread_name);

        netflow_collector_threads.add_thread(netflow_processing_thread);
    }

    netflow_collector_threads.join_all();

    logger << log4cpp::Priority::INFO << "Function start_netflow_collection was finished";
}

void start_netflow_collector(std::string netflow_host, unsigned int netflow_port, bool reuse_port) {
    logger << log4cpp::Priority::INFO << "netflow plugin will listen on " << netflow_host << ":" << netflow_port << " udp port";

    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);

    // Could be AF_INET6 or AF_INET
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    // This flag will generate wildcard IP address if we not specified certain IP
    // address for
    // binding
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    struct addrinfo* servinfo = NULL;

    const char* address_for_binding = NULL;

    if (!netflow_host.empty()) {
        address_for_binding = netflow_host.c_str();
    }

    char port_as_string[16];
    sprintf(port_as_string, "%d", netflow_port);

    int getaddrinfo_result = getaddrinfo(address_for_binding, port_as_string, &hints, &servinfo);

    if (getaddrinfo_result != 0) {
        logger << log4cpp::Priority::ERROR << "Netflow getaddrinfo function failed with code: " << getaddrinfo_result
               << " please check netflow_host";
        return;
    }

    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

    if (reuse_port) {
        int reuse_port_optval = 1;

        auto set_reuse_port_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse_port_optval, sizeof(reuse_port_optval));

        if (set_reuse_port_res != 0) {
            logger << log4cpp::Priority::ERROR << "Cannot enable reuse port mode";
            return;
        }
    }

    int bind_result = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);

    if (bind_result) {
        logger << log4cpp::Priority::ERROR << "Can't listen on port: " << netflow_port << " on host " << netflow_host
               << " errno:" << errno << " error: " << strerror(errno);
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
        // This approach provide ability to store both IPv4 and IPv6 client's
        // addresses
        struct sockaddr_storage client_address;
        // It's MUST
        memset(&client_address, 0, sizeof(struct sockaddr_storage));
        socklen_t address_len = sizeof(struct sockaddr_storage);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr*)&client_address, &address_len);

        // logger << log4cpp::Priority::ERROR << "Received " << received_bytes << " with netflow UDP server";

        if (received_bytes > 0) {
            uint32_t client_ipv4_address = 0;

            if (client_address.ss_family == AF_INET) {
                // Convert to IPv4 structure
                struct sockaddr_in* sockaddr_in_ptr = (struct sockaddr_in*)&client_address;

                client_ipv4_address = sockaddr_in_ptr->sin_addr.s_addr;
                // logger << log4cpp::Priority::ERROR << "client ip: " << convert_ip_as_uint_to_string(client_ip_address);
            } else if (client_address.ss_family == AF_INET6) {
                // We do not support them now
            } else {
                // Should not happen
            }


            // Pass host and port as numbers without any conversion
            int getnameinfo_flags = NI_NUMERICSERV | NI_NUMERICHOST;
            char host[NI_MAXHOST];
            char service[NI_MAXSERV];

            // TODO: we should check return value here
            int result = getnameinfo((struct sockaddr*)&client_address, address_len, host, NI_MAXHOST, service,
                                     NI_MAXSERV, getnameinfo_flags);

            // We sill store client's IP address as string for allowing IPv4 and IPv6
            // processing in same time
            std::string client_addres_in_string_format = std::string(host);
            // logger<< log4cpp::Priority::INFO<<"We receive packet from IP:
            // "<<client_addres_in_string_format;

            netflow_total_packets++;
            process_netflow_packet((uint8_t*)udp_buffer, received_bytes, client_addres_in_string_format, client_ipv4_address);
        } else {

            if (received_bytes == -1) {
                if (errno == EAGAIN) {
                    // We got timeout, it's OK!
                } else {
                    logger << log4cpp::Priority::ERROR << "netflow data receive failed with error number: " << errno << " "
                           << "error name: " << strerror(errno);
                }
            }
        }

        // Add interruption point for correct application shutdown
        boost::this_thread::interruption_point();
    }

    logger << log4cpp::Priority::INFO << "Netflow processing thread for " << netflow_host << ":" << netflow_port << " was finished";
    freeaddrinfo(servinfo);
}
