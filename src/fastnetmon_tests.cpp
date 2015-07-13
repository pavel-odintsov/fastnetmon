#include <gtest/gtest.h>
#include <math.h>

#include "fast_library.h"
#include "bgp_flow_spec.h"

#include <fstream>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

log4cpp::Category& logger = log4cpp::Category::getRoot();

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

// tcp flags tests
TEST(BgpFlowSpec, syn) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_tcp_flag(FLOW_TCP_FLAG_SYN);

    EXPECT_EQ(exabgp_rule.serialize_tcp_flags(), "tcp-flags [ syn ];" );
}

TEST(BgpFlowSpec, rst) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_tcp_flag(FLOW_TCP_FLAG_RST);

    EXPECT_EQ(exabgp_rule.serialize_tcp_flags(), "tcp-flags [ rst ];" );
}

TEST(BgpFlowSpec, ack) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_tcp_flag(FLOW_TCP_FLAG_ACK);

    EXPECT_EQ(exabgp_rule.serialize_tcp_flags(), "tcp-flags [ ack ];" );
}

TEST(BgpFlowSpec, fin) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_tcp_flag(FLOW_TCP_FLAG_FIN);

    EXPECT_EQ(exabgp_rule.serialize_tcp_flags(), "tcp-flags [ fin ];" );
}

TEST(BgpFlowSpec, psh) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_tcp_flag(FLOW_TCP_FLAG_PSH);

    EXPECT_EQ(exabgp_rule.serialize_tcp_flags(), "tcp-flags [ push ];" );
}

TEST(BgpFlowSpec, urg) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_tcp_flag(FLOW_TCP_FLAG_URG);

    EXPECT_EQ(exabgp_rule.serialize_tcp_flags(), "tcp-flags [ urgent ];" );
}

TEST(BgpFlowSpec, serialize_match_first) {
    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);
    exabgp_rule.add_source_port(53);
    exabgp_rule.add_destination_port(80);

    exabgp_rule.add_packet_length(777);
    exabgp_rule.add_packet_length(1122);

    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_IS_A_FRAGMENT);
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_DONT_FRAGMENT);

    exabgp_rule.set_destination_subnet( convert_subnet_from_string_to_binary_with_cidr_format("127.0.0.0/24") );
    exabgp_rule.set_source_subnet( convert_subnet_from_string_to_binary_with_cidr_format("4.0.0.0/24") );
    
    // Disable indentation
    exabgp_rule.disable_indents();

    EXPECT_EQ( exabgp_rule.serialize_match(), "match {source 4.0.0.0/24;destination 127.0.0.0/24;protocol [ udp ];source-port [ =53 ];destination-port [ =80 ];packet-length [ =777 =1122 ];fragment [ is-fragment dont-fragment ];}");
}

TEST(BgpFlowSpec, serialize_then_first) {
    exabgp_flow_spec_rule_t exabgp_rule;
    
    bgp_flow_spec_action_t my_action;
    //my_action.set_type(FLOW_SPEC_ACTION_ACCEPT);
    my_action.set_type(FLOW_SPEC_ACTION_RATE_LIMIT);
    my_action.set_rate_limit(1024); 

    exabgp_rule.set_action( my_action );

    exabgp_rule.disable_indents();

    EXPECT_EQ( exabgp_rule.serialize_then(), "then {rate-limit 1024;}");
}

TEST(BgpFlowSpec, serialize_whole) {
    bgp_flow_spec_action_t my_action;
    //my_action.set_type(FLOW_SPEC_ACTION_ACCEPT);
    my_action.set_type(FLOW_SPEC_ACTION_RATE_LIMIT);
    my_action.set_rate_limit(1024); 

    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);
    exabgp_rule.add_source_port(53);
    exabgp_rule.add_destination_port(80);

    exabgp_rule.add_packet_length(777);
    exabgp_rule.add_packet_length(1122);

    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_IS_A_FRAGMENT);
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_DONT_FRAGMENT);

    exabgp_rule.set_destination_subnet( convert_subnet_from_string_to_binary_with_cidr_format("127.0.0.0/24") );
    exabgp_rule.set_source_subnet( convert_subnet_from_string_to_binary_with_cidr_format("4.0.0.0/24") );

    exabgp_rule.set_action( my_action );
    
    exabgp_rule.disable_indents();

    EXPECT_EQ( exabgp_rule.serialize(), "route {match {source 4.0.0.0/24;destination 127.0.0.0/24;protocol [ udp ];source-port [ =53 ];destination-port [ =80 ];packet-length [ =777 =1122 ];fragment [ is-fragment dont-fragment ];}then {rate-limit 1024;}}");
}

TEST(BgpFlowSpec, serialize_with_real_exabgp) {
    bgp_flow_spec_action_t my_action;
    //my_action.set_type(FLOW_SPEC_ACTION_ACCEPT);
    my_action.set_type(FLOW_SPEC_ACTION_RATE_LIMIT);
    my_action.set_rate_limit(1024); 

    exabgp_flow_spec_rule_t exabgp_rule;
    exabgp_rule.add_protocol(FLOW_SPEC_PROTOCOL_UDP);
    exabgp_rule.add_source_port(53);
    exabgp_rule.add_destination_port(80);

    exabgp_rule.add_packet_length(777);
    exabgp_rule.add_packet_length(1122);

    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_IS_A_FRAGMENT);
    exabgp_rule.add_fragmentation_flag(FLOW_SPEC_DONT_FRAGMENT);

    exabgp_rule.set_destination_subnet( convert_subnet_from_string_to_binary_with_cidr_format("127.0.0.0/24") );
    exabgp_rule.set_source_subnet( convert_subnet_from_string_to_binary_with_cidr_format("4.0.0.0/24") );

    exabgp_rule.set_action( my_action );
        
    //exabgp_rule.disable_indents();
    std::string exabgp_configuration = exabgp_rule.serialize_complete_exabgp_configuration();

    std::ofstream config_file;
    config_file.open("/tmp/exabgp_test_config.conf", std::ios::trunc);

    if (config_file.is_open()) {
        config_file << exabgp_configuration;
        config_file.close();
    }

    int system_ret_code = system("/usr/src/exabgp/sbin/exabgp --test /tmp/exabgp_test_config.conf 2>/dev/null");

    EXPECT_EQ( system_ret_code, 0 );
}


// Flow Spec actions tests

TEST(BgpFlowSpecAction, rate_limit) {
    bgp_flow_spec_action_t my_action;
    my_action.set_type(FLOW_SPEC_ACTION_RATE_LIMIT);
    my_action.set_rate_limit(1024);
    
    EXPECT_EQ( my_action.serialize(), "rate-limit 1024;");    
}

TEST(BgpFlowSpecAction, discard) {
    bgp_flow_spec_action_t my_action;
    my_action.set_type(FLOW_SPEC_ACTION_DISCARD);
    
    EXPECT_EQ( my_action.serialize(), "discard;"); 
}

TEST(BgpFlowSpecAction, accept) {
    bgp_flow_spec_action_t my_action;
    my_action.set_type(FLOW_SPEC_ACTION_ACCEPT);
    
    EXPECT_EQ( my_action.serialize(), "accept;"); 
}

TEST(BgpFlowSpecAction, default_constructor) {
    bgp_flow_spec_action_t my_action;
    
    EXPECT_EQ( my_action.serialize(), "accept;"); 
}

// Serializers tests

TEST(serialize_vector_by_string, single_element) {
    std::vector<std::string> vect;
    vect.push_back("123");

    EXPECT_EQ( serialize_vector_by_string(vect, ","), "123"); 
} 

TEST(serialize_vector_by_string, few_elements) {
    std::vector<std::string> vect;
    vect.push_back("123");
    vect.push_back("456");

    EXPECT_EQ( serialize_vector_by_string(vect, ","), "123,456"); 
}

TEST(serialize_vector_by_string_with_prefix, single_element) {
    std::vector<uint16_t> vect;
    vect.push_back(123);

    EXPECT_EQ( serialize_vector_by_string_with_prefix(vect, ",", "^"), "^123"); 
} 

TEST(serialize_vector_by_string_with_prefix, few_elements) {
    std::vector<uint16_t> vect;
    vect.push_back(123);
    vect.push_back(456);

    EXPECT_EQ( serialize_vector_by_string_with_prefix(vect, ",", "^"), "^123,^456"); 
}

