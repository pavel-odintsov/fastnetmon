#include "bgp_protocol_flow_spec.hpp"
#include "fastnetmon_simple_packet.hpp"

bool filter_packet_by_flowspec_rule_list(const simple_packet_t& current_packet,
                                         const std::vector<flow_spec_rule_t>& active_flow_spec_announces);
bool filter_packet_by_flowspec_rule(const simple_packet_t& current_packet, const flow_spec_rule_t& flow_announce);
