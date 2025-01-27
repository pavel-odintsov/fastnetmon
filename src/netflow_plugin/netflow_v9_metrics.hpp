#pragma once

std::string netflow_v9_total_packets_desc = "Total number of Netflow v9 UDP packets received";
uint64_t netflow_v9_total_packets         = 0;

std::string netflow_v9_total_flows_desc = "Total number of Netflow v9 flows (multiple in each packet)";
uint64_t netflow_v9_total_flows         = 0;

std::string netflow_v9_total_ipv4_flows_desc = "Total number of Netflow v9 IPv4 flows (multiple in each packet)";
uint64_t netflow_v9_total_ipv4_flows         = 0;

std::string netflow_v9_total_ipv6_flows_desc = "Total number of Netflow v9 IPv6 flows (multiple in each packet)";
uint64_t netflow_v9_total_ipv6_flows         = 0;

std::string netflow_v9_forwarding_status_desc = "Number of Netflow v9 flows with forwarding status provided";
uint64_t netflow_v9_forwarding_status         = 0;

std::string netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped_desc =
    "Netflow v9 flow was marked as dropped from interface and next hop information";
uint64_t netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped = 0;


std::string netflow_v9_active_flow_timeout_received_desc = "Total number of received active Netflow v9 flow timeouts";
uint64_t netflow_v9_active_flow_timeout_received         = 0;

std::string netflow_v9_inactive_flow_timeout_received_desc =
    "Total number of received inactive Netflow v9 flow timeouts";
uint64_t netflow_v9_inactive_flow_timeout_received = 0;

std::string netflow_v9_broken_packets_desc = "Netflow v9 packets we cannot decode";
uint64_t netflow_v9_broken_packets         = 0;


std::string netflow_v9_template_data_updates_desc = "Count times when template data actually changed for Netflow v9";
uint64_t netflow_v9_template_data_updates         = 0;

std::string netflow_v9_too_large_field_desc = "We increment these counters when field we use to store particular type "
                                              "of Netflow v9 record is smaller than we actually received from device";
uint64_t netflow_v9_too_large_field = 0;

std::string netflow_v9_lite_header_parser_error_desc = "Netflow v9 Lite header parser errors";
uint64_t netflow_v9_lite_header_parser_error         = 0;

std::string netflow_v9_lite_header_parser_success_desc = "Netflow v9 Lite header parser success";
uint64_t netflow_v9_lite_header_parser_success         = 0;

std::string netflow_v9_lite_headers_desc = "Total number of headers in Netflow v9 lite received";
uint64_t netflow_v9_lite_headers         = 0;

std::string netflow9_protocol_version_adjustments_desc =
    "Number of Netflow v9 flows with re-classified protocol version";
uint64_t netflow9_protocol_version_adjustments = 0;

std::string netflow9_packets_with_unknown_templates_desc =
    "Number of dropped Netflow v9 packets due to unknown template in message";
uint64_t netflow9_packets_with_unknown_templates = 0;

std::string netflow9_duration_0_seconds_desc = "Netflow v9 flows with duration 0 seconds";
uint64_t netflow9_duration_0_seconds         = 0;

std::string netflow9_duration_less_1_seconds_desc = "Netflow v9 flows with duration less then 1 seconds";
uint64_t netflow9_duration_less_1_seconds         = 0;

std::string netflow9_duration_less_2_seconds_desc = "Netflow v9 flows with duration less then 2 seconds";
uint64_t netflow9_duration_less_2_seconds         = 0;

std::string netflow9_duration_less_3_seconds_desc = "Netflow v9 flows with duration less then 3 seconds";
uint64_t netflow9_duration_less_3_seconds         = 0;

std::string netflow9_duration_less_5_seconds_desc = "Netflow v9 flows with duration less then 5 seconds";
uint64_t netflow9_duration_less_5_seconds         = 0;

std::string netflow9_duration_less_10_seconds_desc = "Netflow v9 flows with duration less then 10 seconds";
uint64_t netflow9_duration_less_10_seconds         = 0;

std::string netflow9_duration_less_15_seconds_desc = "Netflow v9 flows with duration less then 15 seconds";
uint64_t netflow9_duration_less_15_seconds         = 0;

std::string netflow9_duration_less_30_seconds_desc = "Netflow v9 flows with duration less then 30 seconds";
uint64_t netflow9_duration_less_30_seconds         = 0;

std::string netflow9_duration_less_60_seconds_desc = "Netflow v9 flows with duration less then 60 seconds";
uint64_t netflow9_duration_less_60_seconds         = 0;

std::string netflow9_duration_less_90_seconds_desc = "Netflow v9 flows with duration less then 90 seconds";
uint64_t netflow9_duration_less_90_seconds         = 0;

std::string netflow9_duration_less_180_seconds_desc = "Netflow v9 flows with duration less then 180 seconds";
uint64_t netflow9_duration_less_180_seconds         = 0;

std::string netflow9_duration_exceed_180_seconds_desc = "Netflow v9 flows with duration more then 180 seconds";
uint64_t netflow9_duration_exceed_180_seconds         = 0;

std::string netflow9_data_packet_number_desc = "Number of Netflow v9 data packets";
uint64_t netflow9_data_packet_number         = 0;

std::string netflow9_data_templates_number_desc = "Number of Netflow v9 data template packets";
uint64_t netflow9_data_templates_number         = 0;

std::string netflow9_options_templates_number_desc = "Number of Netflow v9 options templates packets";
uint64_t netflow9_options_templates_number         = 0;

std::string netflow9_custom_sampling_rate_received_desc =
    "Number of times we received sampling rate from Netflow v9 agent";
uint64_t netflow9_custom_sampling_rate_received = 0;

std::string netflow9_options_packet_number_desc = "Number of Netflow v9 options data packets";
uint64_t netflow9_options_packet_number         = 0;

std::string netflow9_sampling_rate_changes_desc = "How much times we changed sampling rate for same agent. As change "
                                                  "we also count when we received it for the first time";
uint64_t netflow9_sampling_rate_changes = 0;
