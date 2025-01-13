#pragma once

std::string ipfix_marked_zero_next_hop_and_zero_output_as_dropped_desc =
    "IPFIX flow was marked as dropped from interface and next hop information";
uint64_t ipfix_marked_zero_next_hop_and_zero_output_as_dropped = 0;

std::string ipfix_total_packets_desc = "Total number of IPFIX UDP packets received";
uint64_t ipfix_total_packets         = 0;

std::string ipfix_total_flows_desc = "Total number of IPFIX flows (multiple in each packet)";
uint64_t ipfix_total_flows         = 0;

std::string ipfix_total_ipv4_flows_desc = "Total number of IPFIX IPv4 flows (multiple in each packet)";
uint64_t ipfix_total_ipv4_flows         = 0;

std::string ipfix_active_flow_timeout_received_desc = "Total number of received active IPFIX flow timeouts";
uint64_t ipfix_active_flow_timeout_received         = 0;

std::string ipfix_inactive_flow_timeout_received_desc = "Total number of received inactive IPFIX flow timeouts";
uint64_t ipfix_inactive_flow_timeout_received         = 0;

std::string ipfix_total_ipv6_flows_desc = "Total number of IPFIX IPv6 flows (multiple in each packet)";
uint64_t ipfix_total_ipv6_flows         = 0;

std::string ipfix_sampling_rate_changes_desc = "How much times we changed sampling rate for same agent.  As change we "
                                               "also count when we received it for the first time";
uint64_t ipfix_sampling_rate_changes = 0;


std::string ipfix_duration_0_seconds_desc = "IPFIX flows with duration 0 seconds";
uint64_t ipfix_duration_0_seconds         = 0;

std::string ipfix_duration_less_1_seconds_desc = "IPFIX flows with duration less then 1 seconds";
uint64_t ipfix_duration_less_1_seconds         = 0;

std::string ipfix_duration_less_2_seconds_desc = "IPFIX flows with duration less then 2 seconds";
uint64_t ipfix_duration_less_2_seconds         = 0;

std::string ipfix_duration_less_3_seconds_desc = "IPFIX flows with duration less then 3 seconds";
uint64_t ipfix_duration_less_3_seconds         = 0;

std::string ipfix_duration_less_5_seconds_desc = "IPFIX flows with duration less then 5 seconds";
uint64_t ipfix_duration_less_5_seconds         = 0;

std::string ipfix_duration_less_10_seconds_desc = "IPFIX flows with duration less then 10 seconds";
uint64_t ipfix_duration_less_10_seconds         = 0;

std::string ipfix_duration_less_15_seconds_desc = "IPFIX flows with duration less then 15 seconds";
uint64_t ipfix_duration_less_15_seconds         = 0;

std::string ipfix_duration_less_30_seconds_desc = "IPFIX flows with duration less then 30 seconds";
uint64_t ipfix_duration_less_30_seconds         = 0;

std::string ipfix_duration_less_60_seconds_desc = "IPFIX flows with duration less then 60 seconds";
uint64_t ipfix_duration_less_60_seconds         = 0;

std::string ipfix_duration_less_90_seconds_desc = "IPFIX flows with duration less then 90 seconds";
uint64_t ipfix_duration_less_90_seconds         = 0;

std::string ipfix_duration_less_180_seconds_desc = "IPFIX flows with duration less then 180 seconds";
uint64_t ipfix_duration_less_180_seconds         = 0;

std::string ipfix_duration_exceed_180_seconds_desc = "IPFIX flows with duration more then 180 seconds";
uint64_t ipfix_duration_exceed_180_seconds         = 0;

std::string ipfix_forwarding_status_desc = "Number of IPFIX flows with forwarding status provided";
uint64_t ipfix_forwarding_status         = 0;

std::string ipfix_custom_sampling_rate_received_desc = "IPFIX customer sampling rates received";
uint64_t ipfix_custom_sampling_rate_received         = 0;

std::string ipfix_duration_negative_desc =
    "IPFIX packets with negative duration, it may happen when vendor does not implement protocol correctly";
uint64_t ipfix_duration_negative = 0;

std::string ipfix_data_packet_number_desc = "IPFIX data packets number";
uint64_t ipfix_data_packet_number         = 0;

std::string ipfix_data_templates_number_desc = "IPFIX data templates number";
uint64_t ipfix_data_templates_number         = 0;

std::string ipfix_options_templates_number_desc = "IPFIX options templates number";
uint64_t ipfix_options_templates_number         = 0;

std::string ipfix_options_packet_number_desc = "IPFIX options data packets number";
uint64_t ipfix_options_packet_number         = 0;

std::string ipfix_packets_with_unknown_templates_desc =
    "Number of dropped IPFIX packets due to unknown template in message";
uint64_t ipfix_packets_with_unknown_templates = 0;

// https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason
std::string ipfix_flows_end_reason_idle_timeout_desc = "IPFIX flows finished by idle timeout";
uint64_t ipfix_flows_end_reason_idle_timeout         = 0;

std::string ipfix_flows_end_reason_active_timeout_desc = "IPFIX flows finished by active timeout";
uint64_t ipfix_flows_end_reason_active_timeout         = 0;

std::string ipfix_flows_end_reason_end_of_flow_timeout_desc = "IPFIX flows finished by end of flow timeout";
uint64_t ipfix_flows_end_reason_end_of_flow_timeout         = 0;

std::string ipfix_flows_end_reason_force_end_timeout_desc = "IPFIX flows finished by force end timeout";
uint64_t ipfix_flows_end_reason_force_end_timeout         = 0;

std::string ipfix_flows_end_reason_lack_of_resource_timeout_desc = "IPFIX flows finished by lack of resources";
uint64_t ipfix_flows_end_reason_lack_of_resource_timeout         = 0;

std::string ipfix_sets_with_anomaly_padding_desc = "IPFIX sets with anomaly padding more then 7 bytes";
uint64_t ipfix_sets_with_anomaly_padding         = 0;

std::string ipfix_template_data_updates_desc = "Count times when template data actually changed for IPFIX";
uint64_t ipfix_template_data_updates         = 0;

std::string ipfix_protocol_version_adjustments_desc = "Number of IPFIX flows with re-classified protocol version";
uint64_t ipfix_protocol_version_adjustments         = 0;

std::string ipfix_too_large_field_desc = "We increment these counters when field we use to store particular type of "
                                         "IPFIX record is smaller than we actually received from device";
uint64_t ipfix_too_large_field = 0;

std::string ipfix_inline_header_parser_error_desc = "IPFIX inline header parser errors";
uint64_t ipfix_inline_header_parser_error         = 0;

std::string ipfix_inline_header_parser_success_desc = "IPFIX inline header parser success";
uint64_t ipfix_inline_header_parser_success         = 0;

std::string ipfix_inline_encoding_error_desc = "IPFIX inline encoding issues";
uint64_t ipfix_inline_encoding_error         = 0;

std::string ipfix_inline_headers_desc = "Total number of headers in IPFIX received";
uint64_t ipfix_inline_headers         = 0;

std::string ipfix_packets_with_padding_desc = "Total number of IPFIX packets with padding";
uint64_t ipfix_packets_with_padding         = 0;
