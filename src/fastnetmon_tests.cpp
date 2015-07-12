#include <gtest/gtest.h>
#include <math.h>

#include "fast_library.h"
#include "bgp_flow_spec.h"

TEST(BgpFlowSpec, protocol_check_udp) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);

    EXPECT_EQ(exabgp_rule.serialize_protocols(), "protocol [ udp ];");
}

TEST(BgpFlowSpec, protocol_check_tcp) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_TCP);

    EXPECT_EQ(exabgp_rule.serialize_protocols(), "protocol [ tcp ];");
}

TEST(BgpFlowSpec, protocol_check_icmp) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_ICMP);

    EXPECT_EQ(exabgp_rule.serialize_protocols(), "protocol [ icmp ];");
}


TEST(BgpFlowSpec, protocol_check_mix) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_TCP);

    EXPECT_EQ(exabgp_rule.serialize_protocols(), "protocol [ udp tcp ];");
}

TEST(BgpFlowSpec, packet_length)  {
    exabgp_flow_spec_rule_t exabgp_rule;

    exabgp_rule.add_packet_length(777);
    exabgp_rule.add_packet_length(1122);
    EXPECT_EQ(exabgp_rule.serialize_packet_lengths(), "packet-length [ =777 =1122 ];");
}

TEST(BgpFlowSpec, source_subnet) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.set_source_subnet( convert_subnet_from_string_to_binary_with_cidr_format("4.0.0.0/24") );

    EXPECT_EQ(exabgp_rule.serialize_source_subnet(), "source 4.0.0.0/24;");
}

TEST(BgpFlowSpec, destination_subnet) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.set_destination_subnet( convert_subnet_from_string_to_binary_with_cidr_format("77.0.0.0/24") );

    EXPECT_EQ(exabgp_rule.serialize_destination_subnet(), "destination 77.0.0.0/24;");
}

TEST(BgpFlowSpec, source_port) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_source_port(53);
    
    EXPECT_EQ(exabgp_rule.serialize_source_ports(), "source-port [ =53 ];");
}

TEST(BgpFlowSpec, destaination_port) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_destination_port(53);
        
    EXPECT_EQ(exabgp_rule.serialize_destination_ports(), "destination-port [ =53 ];");
}

TEST(BgpFlowSpec, source_ports) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_source_port(53);
    exabgp_rule.add_source_port(7777);    

    EXPECT_EQ(exabgp_rule.serialize_source_ports(), "source-port [ =53 =7777 ];");
}

TEST(BgpFlowSpec, destaination_ports) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_destination_port(53);
    exabgp_rule.add_destination_port(1900);
    
    EXPECT_EQ(exabgp_rule.serialize_destination_ports(), "destination-port [ =53 =1900 ];");
}

TEST(BgpFlowSpec, fragmentation_is_fragment) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_IS_A_FRAGMENT);
    
    EXPECT_EQ(exabgp_rule.serialize_fragmentation_flags(), "fragment [ is-fragment ];");
}

TEST(BgpFlowSpec, fragmentation_first_fragment) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_FIRST_FRAGMENT);

    EXPECT_EQ(exabgp_rule.serialize_fragmentation_flags(), "fragment [ first-fragment ];");
}

TEST(BgpFlowSpec, fragmentation_dont_fragment) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_DONT_FRAGMENT);

    EXPECT_EQ(exabgp_rule.serialize_fragmentation_flags(), "fragment [ dont-fragment ];");
}

TEST(BgpFlowSpec, fragmentation_last_fragment) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_LAST_FRAGMENT);

    EXPECT_EQ(exabgp_rule.serialize_fragmentation_flags(), "fragment [ last-fragment ];");
}

TEST(BgpFlowSpec, fragmentation_not_a_fragment) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_fragmentation_flag(FLOW_NOT_A_FRAGMENT);

    EXPECT_EQ(exabgp_rule.serialize_fragmentation_flags(), "fragment [ not-a-fragment ];");
}


TEST(BgpFlowSpec, fragmentation_fragments) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_fragmentation_flag(FLOW_NOT_A_FRAGMENT);

    EXPECT_EQ(exabgp_rule.serialize_fragmentation_flags(), "fragment [ not-a-fragment ];");
}

// exabgp_rule.add_fragmentation_flag(FLOW_SPEC_IS_A_FRAGMENT);
// exabgp_rule.add_fragmentation_flag(FLOW_SPEC_DONT_FRAGMENT);
// 

