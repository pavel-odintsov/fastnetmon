/* netflow plugin body */

// TODO: add timestamp to netflow templates stored at disk
// TODO: do not kill disk with netflow template writes to disk

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>  // sockaddr_in6
#include <ws2tcpip.h> // getaddrinfo
#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <fstream>
#include <map>
#include <mutex>
#include <vector>

#include "../fast_library.hpp"
#include "../ipfix_fields/ipfix_rfc.hpp"

#include "../all_logcpp_libraries.hpp"

#include "../fastnetmon_plugin.hpp"

#include "netflow.hpp"

// Protocol specific things
#include "netflow_v5.hpp"
#include "netflow_v9.hpp"
#include "ipfix.hpp"

#include "netflow_template.hpp"
#include "netflow_collector.hpp"

#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>

#include <boost/archive/xml_iarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>

// For Netflow lite parsing
#include "../simple_packet_parser_ng.hpp"

#include <boost/algorithm/string.hpp>

// Get it from main programme
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

// Active timeout for IPFIX
class device_timeouts_t {
    public:
    // Both values use seconds
    std::optional<uint32_t> active_timeout   = 0;
    std::optional<uint32_t> inactive_timeout = 0;

    bool operator!=(const device_timeouts_t& rhs) const {
        return !(*this == rhs);
    }

    // We generate default == operator which compares each field in class using standard compare operators for each class
    bool operator==(const device_timeouts_t& rhs) const = default;
};

// Variable encoding may be single or two byte and we need to distinguish them explicitly
enum class variable_length_encoding_t { unknown, single_byte, two_byte };


// IPFIX per device timeouts
std::mutex ipfix_per_device_flow_timeouts_mutex;
std::map<std::string, device_timeouts_t> ipfix_per_device_flow_timeouts;

// Netflow v9 per device timeouts
std::mutex netflow_v9_per_device_flow_timeouts_mutex;
std::map<std::string, device_timeouts_t> netflow_v9_per_device_flow_timeouts;

// Per router packet counters
std::mutex netflow5_packets_per_router_mutex;
std::map<std::string, uint64_t> netflow5_packets_per_router;

std::mutex netflow9_packets_per_router_mutex;
std::map<std::string, uint64_t> netflow9_packets_per_router;

std::mutex ipfix_packets_per_router_mutex;
std::map<std::string, uint64_t> ipfix_packets_per_router;

ipfix_information_database ipfix_db_instance;

// Counters section start

std::string netflow_ipfix_total_ipv4_packets_desc = "Total number of Netflow or IPFIX UDP packets received over IPv4 protocol";
uint64_t netflow_ipfix_total_ipv4_packets         = 0;

std::string netflow_ipfix_total_ipv6_packets_desc = "Total number of Netflow or IPFIX UDP packets received over IPv6 protocol";
uint64_t netflow_ipfix_total_ipv6_packets         = 0;

std::string netflow_ipfix_total_packets_desc = "Total number of Netflow or IPFIX UDP packets received";
uint64_t netflow_ipfix_total_packets         = 0;

std::string netflow_v5_total_packets_desc = "Total number of Netflow v5 UDP packets received";
uint64_t netflow_v5_total_packets         = 0;

std::string netflow_v5_total_flows_desc = "Total number of Netflow v5 flows (multiple in each packet)";
uint64_t netflow_v5_total_flows         = 0;

std::string netflow_v9_total_packets_desc = "Total number of Netflow v5 UDP packets received";
uint64_t netflow_v9_total_packets         = 0;

std::string netflow_v9_total_flows_desc = "Total number of Netflow v9 flows (multiple in each packet)";
uint64_t netflow_v9_total_flows         = 0;

std::string netflow_v9_total_ipv4_flows_desc = "Total number of Netflow v9 IPv4 flows (multiple in each packet)";
uint64_t netflow_v9_total_ipv4_flows         = 0;

std::string netflow_v9_total_ipv6_flows_desc = "Total number of Netflow v9 IPv6 flows (multiple in each packet)";
uint64_t netflow_v9_total_ipv6_flows         = 0;

std::string netflow_v9_forwarding_status_desc = "Number of Netflow v9 flows with forwarding status provided";
uint64_t netflow_v9_forwarding_status         = 0;

std::string ipfix_marked_zero_next_hop_and_zero_output_as_dropped_desc =
    "IPFIX flow was marked as dropped from interface and next hop information";
uint64_t ipfix_marked_zero_next_hop_and_zero_output_as_dropped = 0;

std::string netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped_desc =
    "Netflow v9 flow was marked as dropped from interface and next hop information";
uint64_t netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped = 0;

std::string ipfix_total_packets_desc = "Total number of IPFIX UDP packets received";
uint64_t ipfix_total_packets         = 0;

std::string netflow_ipfix_all_protocols_total_flows_desc =
    "Total number of flows summarized for all kinds of Netflow and IPFIX";
uint64_t netflow_ipfix_all_protocols_total_flows = 0;

std::string ipfix_total_flows_desc = "Total number of IPFIX flows (multiple in each packet)";
uint64_t ipfix_total_flows         = 0;

std::string ipfix_total_ipv4_flows_desc = "Total number of IPFIX IPv4 flows (multiple in each packet)";
uint64_t ipfix_total_ipv4_flows         = 0;

std::string ipfix_flowsets_with_anomaly_padding_desc = "IPFIX flowsets with anomaly padding more then 7 bytes";
uint64_t ipfix_flowsets_with_anomaly_padding         = 0;

std::string ipfix_active_flow_timeout_received_desc = "Total number of received active IPFIX flow timeouts";
uint64_t ipfix_active_flow_timeout_received         = 0;

std::string ipfix_inactive_flow_timeout_received_desc = "Total number of received inactive IPFIX flow timeouts";
uint64_t ipfix_inactive_flow_timeout_received         = 0;

std::string netflow_v9_active_flow_timeout_received_desc = "Total number of received active Netflow v9 flow timeouts";
uint64_t netflow_v9_active_flow_timeout_received         = 0;

std::string netflow_v9_inactive_flow_timeout_received_desc =
    "Total number of received inactive Netflow v9 flow timeouts";
uint64_t netflow_v9_inactive_flow_timeout_received = 0;

std::string ipfix_total_ipv6_flows_desc = "Total number of IPFIX IPv6 flows (multiple in each packet)";
uint64_t ipfix_total_ipv6_flows         = 0;

std::string netflow_v9_broken_packets_desc = "Netflow v9 packets we cannot decode";
uint64_t netflow_v9_broken_packets         = 0;

std::string netflow_ipfix_udp_packet_drops_desc = "Number of UDP packets dropped by system on our socket";
uint64_t netflow_ipfix_udp_packet_drops         = 0;

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
uint64_t netflow9_sampling_rate_changes         = 0;

std::string netflow_ipfix_unknown_protocol_version_desc =
    "Number of packets with unknown Netflow version. In may be sign that some another protocol like sFlow is being "
    "send to Netflow or IPFIX port";
uint64_t netflow_ipfix_unknown_protocol_version = 0;

std::string ipfix_sampling_rate_changes_desc = "How much times we changed sampling rate for same agent.  As change we "
                                               "also count when we received it for the first time";
uint64_t ipfix_sampling_rate_changes         = 0;

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

std::string netflow5_duration_less_15_seconds_desc = "Netflow v5 flows with duration less then 15 seconds";
uint64_t netflow5_duration_less_15_seconds         = 0;

std::string netflow5_duration_less_30_seconds_desc = "Netflow v5 flows with duration less then 30 seconds";
uint64_t netflow5_duration_less_30_seconds         = 0;

std::string netflow5_duration_less_60_seconds_desc = "Netflow v5 flows with duration less then 60 seconds";
uint64_t netflow5_duration_less_60_seconds         = 0;

std::string netflow5_duration_less_90_seconds_desc = "Netflow v5 flows with duration less then 90 seconds";
uint64_t netflow5_duration_less_90_seconds         = 0;

std::string netflow5_duration_less_180_seconds_desc = "Netflow v5 flows with duration less then 180 seconds";
uint64_t netflow5_duration_less_180_seconds         = 0;

std::string netflow5_duration_exceed_180_seconds_desc = "Netflow v5 flows with duration more then 180 seconds";
uint64_t netflow5_duration_exceed_180_seconds         = 0;

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

std::string template_update_attempts_with_same_template_data_desc =
    "Number of templates received with same data as inside known by us";
uint64_t template_update_attempts_with_same_template_data = 0;

std::string ipfix_template_data_updates_desc = "Count times when template data actually changed for IPFIX";
uint64_t ipfix_template_data_updates         = 0;

std::string netflow_v9_template_data_updates_desc = "Count times when template data actually changed for Netflow v9";
uint64_t netflow_v9_template_data_updates         = 0;

std::string template_netflow_ipfix_disk_writes_desc =
    "Number of times when we write Netflow or ipfix templates to disk";
uint64_t template_netflow_ipfix_disk_writes = 0;


std::string netflow_ignored_long_flows_desc = "Number of flows which exceed specified limit in configuration";
uint64_t netflow_ignored_long_flows         = 0;

std::string netflow9_protocol_version_adjustments_desc =
    "Number of Netflow v9 flows with re-classified protocol version";
uint64_t netflow9_protocol_version_adjustments = 0;

std::string ipfix_protocol_version_adjustments_desc = "Number of IPFIX flows with re-classified protocol version";
uint64_t ipfix_protocol_version_adjustments         = 0;

std::string ipfix_too_large_field_desc = "We increment these counters when field we use to store particular type of "
                                         "IPFIX record is smaller than we actually received from device";
uint64_t ipfix_too_large_field         = 0;

std::string netflow_v9_too_large_field_desc = "We increment these counters when field we use to store particular type "
                                              "of Netflow v9 record is smaller than we actually received from device";
uint64_t netflow_v9_too_large_field         = 0;

std::string netflow_v9_lite_header_parser_error_desc = "Netflow v9 Lite header parser errors";
uint64_t netflow_v9_lite_header_parser_error         = 0;

std::string netflow_v9_lite_header_parser_success_desc = "Netflow v9 Lite header parser success";
uint64_t netflow_v9_lite_header_parser_success         = 0;

std::string ipfix_inline_header_parser_error_desc = "IPFIX inline header parser errors";
uint64_t ipfix_inline_header_parser_error         = 0;

std::string ipfix_inline_header_parser_success_desc = "IPFIX inline header parser success";
uint64_t ipfix_inline_header_parser_success         = 0;

std::string netflow_v9_lite_headers_desc = "Total number of headers in Netflow v9 lite received";
uint64_t netflow_v9_lite_headers         = 0;

std::string ipfix_inline_headers_desc = "Total number of headers in IPFIX received";
uint64_t ipfix_inline_headers         = 0;

std::string ipfix_inline_encoding_error_desc = "IPFIX inline encoding issues";
uint64_t  ipfix_inline_encoding_error         = 0;

std::string ipfix_packets_with_padding_desc = "Total number of IPFIX packets with padding";
uint64_t ipfix_packets_with_padding         = 0;

// END of counters section


void increment_duration_counters_ipfix(int64_t duration);

// We limit number of flowsets in packet Netflow v9 / IPFIX packets with some reasonable number to reduce possible attack's surface and reduce probability of infinite loop
uint64_t flowsets_per_packet_maximum_number = 256;

// TODO: add per source uniq templates support
process_packet_pointer netflow_process_func_ptr = NULL;

std::mutex global_netflow9_templates_mutex;
std::map<std::string, std::map<uint32_t, template_t>> global_netflow9_templates;

std::mutex global_ipfix_templates_mutex;
std::map<std::string, std::map<uint32_t, template_t>> global_ipfix_templates;

std::vector<system_counter_t> get_netflow_stats() {
    std::vector<system_counter_t> system_counter;

    // Netflow v5
    system_counter.push_back(system_counter_t("netflow_v5_total_packets", netflow_v5_total_packets,
                                              metric_type_t::counter, netflow_v5_total_packets_desc));
    system_counter.push_back(system_counter_t("netflow_v5_total_flows", netflow_v5_total_flows, metric_type_t::counter,
                                              netflow_v5_total_flows_desc));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_15_seconds", netflow5_duration_less_15_seconds,
                                              metric_type_t::counter, netflow5_duration_less_15_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_30_seconds", netflow5_duration_less_30_seconds,
                                              metric_type_t::counter, netflow5_duration_less_30_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_60_seconds", netflow5_duration_less_60_seconds,
                                              metric_type_t::counter, netflow5_duration_less_60_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_90_seconds", netflow5_duration_less_90_seconds,
                                              metric_type_t::counter, netflow5_duration_less_90_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v5_duration_less_180_seconds", netflow5_duration_less_180_seconds,
                                              metric_type_t::counter, netflow5_duration_less_180_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v5_duration_exceed_180_seconds", netflow5_duration_exceed_180_seconds,
                                              metric_type_t::counter, netflow5_duration_exceed_180_seconds_desc));

    // Netflow v9
    system_counter.push_back(system_counter_t("netflow_v9_total_packets", netflow_v9_total_packets,
                                              metric_type_t::counter, netflow_v9_total_packets_desc));
    system_counter.push_back(system_counter_t("netflow_v9_total_flows", netflow_v9_total_flows, metric_type_t::counter,
                                              netflow_v9_total_flows_desc));
    system_counter.push_back(system_counter_t("netflow_v9_total_ipv4_flows", netflow_v9_total_ipv4_flows,
                                              metric_type_t::counter, netflow_v9_total_ipv4_flows_desc));
    system_counter.push_back(system_counter_t("netflow_v9_total_ipv6_flows", netflow_v9_total_ipv6_flows,
                                              metric_type_t::counter, netflow_v9_total_ipv6_flows_desc));

    system_counter.push_back(system_counter_t("netflow_v9_duration_0_seconds", netflow9_duration_0_seconds,
                                              metric_type_t::counter, netflow9_duration_0_seconds_desc));

    system_counter.push_back(system_counter_t("netflow_v9_duration_less_1_seconds", netflow9_duration_less_1_seconds,
                                              metric_type_t::counter, netflow9_duration_less_1_seconds_desc));

    system_counter.push_back(system_counter_t("netflow_v9_duration_less_2_seconds", netflow9_duration_less_2_seconds,
                                              metric_type_t::counter, netflow9_duration_less_2_seconds_desc));

    system_counter.push_back(system_counter_t("netflow_v9_duration_less_3_seconds", netflow9_duration_less_3_seconds,
                                              metric_type_t::counter, netflow9_duration_less_3_seconds_desc));

    system_counter.push_back(system_counter_t("netflow_v9_duration_less_5_seconds", netflow9_duration_less_5_seconds,
                                              metric_type_t::counter, netflow9_duration_less_5_seconds_desc));

    system_counter.push_back(system_counter_t("netflow_v9_duration_less_10_seconds", netflow9_duration_less_10_seconds,
                                              metric_type_t::counter, netflow9_duration_less_10_seconds_desc));


    system_counter.push_back(system_counter_t("netflow_v9_duration_less_15_seconds", netflow9_duration_less_15_seconds,
                                              metric_type_t::counter, netflow9_duration_less_15_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_30_seconds", netflow9_duration_less_30_seconds,
                                              metric_type_t::counter, netflow9_duration_less_30_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_60_seconds", netflow9_duration_less_60_seconds,
                                              metric_type_t::counter, netflow9_duration_less_60_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_90_seconds", netflow9_duration_less_90_seconds,
                                              metric_type_t::counter, netflow9_duration_less_90_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v9_duration_less_180_seconds", netflow9_duration_less_180_seconds,
                                              metric_type_t::counter, netflow9_duration_less_180_seconds_desc));
    system_counter.push_back(system_counter_t("netflow_v9_duration_exceed_180_seconds", netflow9_duration_exceed_180_seconds,
                                              metric_type_t::counter, netflow9_duration_exceed_180_seconds_desc));

    system_counter.push_back(system_counter_t("netflow_v9_data_packet_number", netflow9_data_packet_number,
                                              metric_type_t::counter, netflow9_data_packet_number_desc));
    system_counter.push_back(system_counter_t("netflow_v9_data_templates_number", netflow9_data_templates_number,
                                              metric_type_t::counter, netflow9_data_templates_number_desc));
    system_counter.push_back(system_counter_t("netflow_v9_options_templates_number", netflow9_options_templates_number,
                                              metric_type_t::counter, netflow9_options_templates_number_desc));
    system_counter.push_back(system_counter_t("netflow_v9_options_packet_number", netflow9_options_packet_number,
                                              metric_type_t::counter, netflow9_options_packet_number_desc));
    system_counter.push_back(system_counter_t("netflow_v9_packets_with_unknown_templates", netflow9_packets_with_unknown_templates,
                                              metric_type_t::counter, netflow9_packets_with_unknown_templates_desc));
    system_counter.push_back(system_counter_t("netflow_v9_custom_sampling_rate_received", netflow9_custom_sampling_rate_received,
                                              metric_type_t::counter, netflow9_custom_sampling_rate_received_desc));
    system_counter.push_back(system_counter_t("netflow_v9_sampling_rate_changes", netflow9_sampling_rate_changes,
                                              metric_type_t::counter, netflow9_sampling_rate_changes_desc));
    system_counter.push_back(system_counter_t("netflow_v9_protocol_version_adjustments", netflow9_protocol_version_adjustments,
                                              metric_type_t::counter, netflow9_protocol_version_adjustments_desc));
    system_counter.push_back(system_counter_t("netflow_v9_template_updates_number_due_to_real_changes", netflow_v9_template_data_updates,
                                              metric_type_t::counter, netflow_v9_template_data_updates_desc));
    system_counter.push_back(system_counter_t("netflow_v9_too_large_field", netflow_v9_too_large_field,
                                              metric_type_t::counter, netflow_v9_too_large_field_desc));
    system_counter.push_back(system_counter_t("netflow_v9_lite_headers", netflow_v9_lite_headers,
                                              metric_type_t::counter, netflow_v9_lite_headers_desc));
    system_counter.push_back(system_counter_t("netflow_v9_forwarding_status", netflow_v9_forwarding_status,
                                              metric_type_t::counter, netflow_v9_forwarding_status_desc));

    system_counter.push_back(system_counter_t("netflow_v9_lite_header_parser_success", netflow_v9_lite_header_parser_success,
                                              metric_type_t::counter, netflow_v9_lite_header_parser_success_desc));

    system_counter.push_back(system_counter_t("netflow_v9_lite_header_parser_error", netflow_v9_lite_header_parser_error,
                                              metric_type_t::counter, netflow_v9_lite_header_parser_error_desc));
    system_counter.push_back(system_counter_t("netflow_v9_broken_packets", netflow_v9_broken_packets,
                                              metric_type_t::counter, netflow_v9_broken_packets_desc));

    system_counter.push_back(system_counter_t("netflow_v9_active_flow_timeout_received", netflow_v9_active_flow_timeout_received,
                                              metric_type_t::counter, netflow_v9_active_flow_timeout_received_desc));
    system_counter.push_back(system_counter_t("netflow_v9_inactive_flow_timeout_received", netflow_v9_inactive_flow_timeout_received,
                                              metric_type_t::counter, netflow_v9_inactive_flow_timeout_received_desc));

    system_counter.push_back(system_counter_t("netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped",
                                              netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped, metric_type_t::counter,
                                              netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped_desc));

    // IPFIX
    system_counter.push_back(system_counter_t("ipfix_total_flows", ipfix_total_flows, metric_type_t::counter, ipfix_total_flows_desc));
    system_counter.push_back(
        system_counter_t("ipfix_total_packets", ipfix_total_packets, metric_type_t::counter, ipfix_total_packets_desc));
    system_counter.push_back(system_counter_t("ipfix_total_ipv4_flows", ipfix_total_ipv4_flows, metric_type_t::counter,
                                              ipfix_total_ipv4_flows_desc));
    system_counter.push_back(system_counter_t("ipfix_total_ipv6_flows", ipfix_total_ipv6_flows, metric_type_t::counter,
                                              ipfix_total_ipv6_flows_desc));

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

    system_counter.push_back(system_counter_t("ipfix_inline_header_parser_success", ipfix_inline_header_parser_success,
                                              metric_type_t::counter, ipfix_inline_header_parser_success_desc));

    system_counter.push_back(system_counter_t("ipfix_active_flow_timeout_received", ipfix_active_flow_timeout_received,
                                              metric_type_t::counter, ipfix_active_flow_timeout_received_desc));
    system_counter.push_back(system_counter_t("ipfix_inactive_flow_timeout_received", ipfix_inactive_flow_timeout_received,
                                              metric_type_t::counter, ipfix_inactive_flow_timeout_received_desc));

    // Common

    system_counter.push_back(system_counter_t("netflow_ipfix_total_packets", netflow_ipfix_total_packets,
                                              metric_type_t::counter, netflow_ipfix_total_packets_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_total_ipv4_packets", netflow_ipfix_total_ipv4_packets,
                                              metric_type_t::counter, netflow_ipfix_total_ipv4_packets_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_total_ipv6_packets", netflow_ipfix_total_ipv6_packets,
                                              metric_type_t::counter, netflow_ipfix_total_ipv6_packets_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_all_protocols_total_flows", netflow_ipfix_all_protocols_total_flows,
                                              metric_type_t::counter, netflow_ipfix_all_protocols_total_flows_desc));
    system_counter.push_back(system_counter_t("netflow_ipfix_udp_packet_drops", netflow_ipfix_udp_packet_drops,
                                              metric_type_t::counter, netflow_ipfix_udp_packet_drops_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_unknown_protocol_version", netflow_ipfix_unknown_protocol_version,
                                              metric_type_t::counter, netflow_ipfix_unknown_protocol_version_desc));

    system_counter.push_back(system_counter_t("template_update_attempts_with_same_template_data",
                                              template_update_attempts_with_same_template_data, metric_type_t::counter,
                                              template_update_attempts_with_same_template_data_desc));

    system_counter.push_back(system_counter_t("netflow_ignored_long_flows", netflow_ignored_long_flows,
                                              metric_type_t::counter, netflow_ignored_long_flows_desc));

    system_counter.push_back(system_counter_t("template_netflow_ipfix_disk_writes", template_netflow_ipfix_disk_writes,
                                              metric_type_t::counter, template_netflow_ipfix_disk_writes_desc));

    return system_counter;
}

// Returns fancy name of protocol version
std::string get_netflow_protocol_version_as_string(const netflow_protocol_version_t& netflow_protocol_version) {
    std::string protocol_name = "unknown";

    if (netflow_protocol_version == netflow_protocol_version_t::netflow_v9) {
        protocol_name = "Netflow v9";
    } else if (netflow_protocol_version == netflow_protocol_version_t::ipfix) {
        protocol_name = "IPFIX";
    }

    return protocol_name;
}


/* Prototypes */
void add_update_peer_template(const netflow_protocol_version_t& netflow_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_addres_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template);

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

    // The IPv4 address of the next IPv4 hop.
    uint32_t ip_next_hop_ipv4 = 0;

    // We set this flag when we read it from flow. We need it to distinguish one case when we receive 0.0.0.0 from
    // device. It's impossible without explicit flag because default value is already 0
    bool ip_next_hop_ipv4_set = false;

    // The IPv4 address of the next (adjacent) BGP hop.
    uint32_t bgp_next_hop_ipv4 = 0;

    // We set this flag when we read it from flow. We need it to distinguish one case when we receive 0.0.0.0 from
    // device. It's impossible without explicit flag because default value is already 0
    bool bgp_next_hop_ipv4_set = false;

    // Next hop flag for IPv6
    in6_addr bgp_next_hop_ipv6{};

    // Same as in case of IPv4
    bool bgp_next_hop_ipv6_set = false;

    // This flag is set when we explicitly received forwarding status
    bool received_forwarding_status = false;

    // Cisco ASA uses very unusual encoding when they encode incoming and outgoing traffic in single flow
    uint64_t bytes_from_source_to_destination = 0;
    uint64_t bytes_from_destination_to_source = 0;

    uint64_t packets_from_source_to_destination = 0;
    uint64_t packets_from_destination_to_source = 0;

    // Cisco ASA flow identifier
    uint64_t flow_id = 0;

    variable_length_encoding_t variable_field_length_encoding = variable_length_encoding_t::unknown;

    // Store variable field length here to avoid repeating parsing
    uint16_t variable_field_length = 0;
};

int nf9_rec_to_flow(uint32_t record_type,
                    uint32_t record_length,
                    uint8_t* data,
                    simple_packet_t& packet,
                    std::vector<template_record_t>& template_records,
                    netflow_meta_info_t& flow_meta);

template_t* peer_find_template(std::map<std::string, std::map<uint32_t, template_t>>& table_for_lookup,
                                      std::mutex& table_for_lookup_mutex,
                                      uint32_t source_id,
                                      uint32_t template_id,
                                      std::string client_addres_in_string_format) {

    // We use source_id for distinguish multiple netflow agents with same IP
    std::string key = client_addres_in_string_format + "_" + std::to_string(source_id);

    std::lock_guard<std::mutex> lock(table_for_lookup_mutex);

    auto itr = table_for_lookup.find(key);

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

// Overrides some fields from specified nested packet
void override_packet_fields_from_nested_packet(simple_packet_t& packet, const simple_packet_t& nested_packet) {
    // Copy IP addresses
    packet.src_ip = nested_packet.src_ip;
    packet.dst_ip = nested_packet.dst_ip;

    packet.src_ipv6 = nested_packet.src_ipv6;
    packet.dst_ipv6 = nested_packet.dst_ipv6;

    packet.ip_protocol_version = nested_packet.ip_protocol_version;
    packet.ttl                 = nested_packet.ttl;

    // Ports
    packet.source_port      = nested_packet.source_port;
    packet.destination_port = nested_packet.destination_port;

    packet.protocol          = nested_packet.protocol;
    packet.length            = nested_packet.length;
    packet.ip_length         = nested_packet.ip_length;
    packet.number_of_packets = 1;
    packet.flags             = nested_packet.flags;
    packet.ip_fragmented     = nested_packet.ip_fragmented;
    packet.ip_dont_fragment  = nested_packet.ip_dont_fragment;
    packet.vlan              = nested_packet.vlan;

    // Copy Ethernet MAC addresses to main packet structure using native C++ approach to avoid touching memory with memcpy
    std::copy(std::begin(nested_packet.source_mac), std::end(nested_packet.source_mac), std::begin(packet.source_mac));

    std::copy(std::begin(nested_packet.destination_mac), std::end(nested_packet.destination_mac), std::begin(packet.destination_mac));
}

void add_update_peer_template(
                              const netflow_protocol_version_t& netflow_protocol_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_address_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template) {

    std::string key = client_address_in_string_format + "_" + std::to_string(source_id);

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Received " << get_netflow_protocol_version_as_string(netflow_protocol_version)
            << " template with id " << template_id << " from host " << client_address_in_string_format
            << " source id: " << source_id;  
    }

    // We need to put lock on it
    std::lock_guard<std::mutex> lock(table_for_add_mutex);

    auto itr = table_for_add.find(key);

    if (itr == table_for_add.end()) {
        std::map<uint32_t, template_t> temp_template_storage;
        temp_template_storage[template_id] = field_template;

        table_for_add[key] = temp_template_storage;
        updated            = true;

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "We had no "
                << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " templates for source " << key;

            logger << log4cpp::Priority::DEBUG << "Added " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " template with ID " << template_id << " for " << key; 
        }

        return;
    }

    // We have information about this agent

    // Try to find actual template id here
    if (itr->second.count(template_id) == 0) {

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "We had no information about " 
                << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " template with ID " << template_id << " for " << key;

            logger << log4cpp::Priority::DEBUG << "Added " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " template with ID " << template_id << " for " << key;
        }

        itr->second[template_id] = field_template;
        updated                  = true;

        return;
    }

    // TODO: Should I track timestamp here and drop old templates after some time?
    if (itr->second[template_id] != field_template) {
        //
        // We can see that template definition actually changed
        //
        // In case of IPFIX this is clear protocol violation:
        // https://datatracker.ietf.org/doc/html/rfc7011#section-8.1
        //

        //
        // If a Collecting Process receives a new Template Record or Options
        // Template Record for an already-allocated Template ID, and that
        // Template or Options Template is different from the already-received
        // Template or Options Template, this indicates a malfunctioning or
        // improperly implemented Exporting Process.  The continued receipt and
        // unambiguous interpretation of Data Records for this Template ID are
        // no longer possible, and the Collecting Process SHOULD log the error.
        // Further Collecting Process actions are out of scope for this
        // specification.
        //

        //
        // We cannot follow RFC recommendation for IPFIX as it will break our on disk template caching.
        // I.e. we may have template with specific list of fields in cache
        // Then after firmware upgrade vendor changes list of fields but does not change template id
        // We have to accept new one and update to be able to decode data
        //
        
        // 
        // Netflow v9 explicitly prohibits template content updates: https://www.ietf.org/rfc/rfc3954.txt
        // 
        // A newly created Template record is assigned an unused Template ID
        // from the Exporter. If the template configuration is changed, the
        // current Template ID is abandoned and SHOULD NOT be reused until the
        // NetFlow process or Exporter restarts.
        //
        // 

        // 
        // But in same time Netflow v9 RFC allows template update for collector and that's exactly what we do:
        //
        // If a Collector should receive a new definition for an already existing Template ID, it MUST discard 
        // the previous template definition and use the new one.
        //

        // On debug level we have to print templates
        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Old " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                <<" template: " << print_template(itr->second[template_id]);

            logger << log4cpp::Priority::DEBUG << "New " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                <<" template: " << print_template(field_template);
        }

        // We use ERROR level as this behavior is definitely not a common and must be carefully investigated
        logger << log4cpp::Priority::ERROR << get_netflow_protocol_version_as_string(netflow_protocol_version)
            << " template " << template_id << " was updated for " << key;

        // Warn user that something bad going on
        logger << log4cpp::Priority::ERROR << get_netflow_protocol_version_as_string(netflow_protocol_version)
            << " template update may be sign of RFC violation by vendor and if you observe this behaviour please reach support@fastnetmon.com and share information about your equipment and firmware versions"; 


        itr->second[template_id] = field_template;

        // We need to track this case as it's pretty unusual and in some cases it may be very destructive when router does it incorrectly
        updated_existing_template = true;

        updated = true;
    } else {
        template_update_attempts_with_same_template_data++;
    }

    return;
}

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - record_length), data, record_length);

// Safe version of BE_COPY macro
bool be_copy_function(const uint8_t* data, uint8_t* target, uint32_t target_field_length, uint32_t record_field_length) {
    if (target_field_length < record_field_length) {
        return false;
    }

    memcpy(target + (target_field_length - record_field_length), data, record_field_length);
    return true;
}


// Updates flow timeouts from device
void update_device_flow_timeouts(const device_timeouts_t& device_timeouts,
                                 std::mutex& structure_mutex,
                                 std::map<std::string, device_timeouts_t>& timeout_storage,
                                 const std::string& client_addres_in_string_format,
                                 const netflow_protocol_version_t& netflow_protocol_version) {

    // We did not receive any information about timeouts
    // We do not expect that devices reports only active or any inactive timeouts as it does not make any sense
    if (!device_timeouts.active_timeout.has_value() && !device_timeouts.inactive_timeout.has_value()) {
        return;
    }

    std::lock_guard<std::mutex> lock(structure_mutex);

    auto current_timeouts = timeout_storage.find(client_addres_in_string_format);

    if (current_timeouts == timeout_storage.end()) {
        timeout_storage[client_addres_in_string_format] = device_timeouts;

        logger << log4cpp::Priority::INFO
               << "Learnt new active flow timeout value: " << device_timeouts.active_timeout.value_or(0) << " seconds "
               << "and inactive flow timeout value: " << device_timeouts.inactive_timeout.value_or(0)
               << " seconds for device " << client_addres_in_string_format << " protocol " << get_netflow_protocol_version_as_string(netflow_protocol_version);

        return;
    }

    auto old_flow_timeouts = current_timeouts->second;

    // They're equal with previously received, nothing to worry about
    if (old_flow_timeouts == device_timeouts) {
        return;
    }

    // We had values previously
    logger << log4cpp::Priority::INFO << "Update old active flow timeout value "
           << current_timeouts->second.active_timeout.value_or(0) << " to " << device_timeouts.active_timeout.value_or(0)
           << " for " << client_addres_in_string_format << " protocol " << get_netflow_protocol_version_as_string(netflow_protocol_version);
    
    logger << log4cpp::Priority::INFO << "Update old inactive flow timeout value "
           << current_timeouts->second.inactive_timeout.value_or(0) << " to " << device_timeouts.inactive_timeout.value_or(0)
           << " for " << client_addres_in_string_format << " protocol " << get_netflow_protocol_version_as_string(netflow_protocol_version);

    current_timeouts->second = device_timeouts;
    return;
}


// Temporary during migration
#include "netflow_v5_collector.cpp"

#include "netflow_v9_collector.cpp"

#include "ipfix_collector.cpp"

bool process_netflow_packet(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    netflow_header_common_t* hdr = (netflow_header_common_t*)packet;

    switch (ntohs(hdr->version)) {
    case 5:
        netflow_v5_total_packets++;
        return process_netflow_packet_v5(packet, len, client_addres_in_string_format, client_ipv4_address);
    case 9:
        netflow_v9_total_packets++;
        return process_netflow_packet_v9(packet, len, client_addres_in_string_format, client_ipv4_address);
    case 10:
        netflow_ipfix_total_packets++;
        return process_ipfix_packet(packet, len, client_addres_in_string_format, client_ipv4_address);
    default:
        netflow_ipfix_unknown_protocol_version++;
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

    for (auto port : ports_for_listen) {
        unsigned int netflow_port = convert_string_to_integer(port);

        if (netflow_port == 0) {
            logger << log4cpp::Priority::ERROR << "Cannot parse Netflow port: " << port;
            continue;
        }

        netflow_ports.push_back(netflow_port);
    }

    boost::thread_group netflow_collector_threads;

    logger << log4cpp::Priority::INFO << "Netflow plugin will listen on " << netflow_ports.size() << " ports";

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
        // Windows does not support this setsockopt but they may add such logic in future.
        // Instead of disabling this logic I prefer to define missing constant to address compilation failure
#ifdef _WIN32
#define SO_REUSEPORT 15
#endif

        int reuse_port_optval = 1;

        // Windows uses char* as 4rd argument: https://learn.microsoft.com/en-gb/windows/win32/api/winsock/nf-winsock-getsockopt and we need to add explicit cast
        // Linux uses void* https://linux.die.net/man/2/setsockopt
        // So I think char* works for both platforms
        auto set_reuse_port_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (char*)&reuse_port_optval, sizeof(reuse_port_optval));

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

            netflow_ipfix_total_packets++;
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
