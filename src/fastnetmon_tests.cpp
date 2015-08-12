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

#include <arpa/inet.h>

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

TEST(BgpFlowSpec, serialize_signle_line) {
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
    
    EXPECT_EQ( exabgp_rule.serialize_single_line_exabgp_v4_configuration(), "flow route source 4.0.0.0/24 destination 127.0.0.0/24 protocol [ udp ] source-port [ =53 ] destination-port [ =80 ] packet-length [ =777 =1122 ] fragment [ is-fragment dont-fragment ] rate-limit 1024 ");
}

TEST(BgpFlowSpec, serialize_whole_single_line_form) {
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

    // TBD     
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

/* Patricia tests */

TEST (patricia, negative_lookup_ipv6_prefix) {
    patricia_tree_t* lookup_ipv6_tree;
    lookup_ipv6_tree = New_Patricia(128);

    make_and_lookup_ipv6(lookup_ipv6_tree, (char*)"2a03:f480::/32");

    //Destroy_Patricia(lookup_ipv6_tree, (void_fn_t)0);
   
    prefix_t prefix_for_check_address;
    
    // Convert fb.com frontend address to internal structure
    inet_pton(AF_INET6, "2a03:2880:2130:cf05:face:b00c::1", (void*)&prefix_for_check_address.add.sin6);

    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;
 
    bool found = patricia_search_best2(lookup_ipv6_tree, &prefix_for_check_address, 1) != NULL;

    EXPECT_EQ( found, false );   
}

TEST (patricia, positive_lookup_ipv6_prefix) {
    patricia_tree_t* lookup_ipv6_tree;
    lookup_ipv6_tree = New_Patricia(128);

    make_and_lookup_ipv6(lookup_ipv6_tree, (char*)"2a03:f480::/32");

    //Destroy_Patricia(lookup_ipv6_tree, (void_fn_t)0);
   
    prefix_t prefix_for_check_address;
    
    inet_pton(AF_INET6, "2a03:f480:2130:cf05:face:b00c::1", (void*)&prefix_for_check_address.add.sin6);

    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;
 
    bool found = patricia_search_best2(lookup_ipv6_tree, &prefix_for_check_address, 1) != NULL;

    EXPECT_EQ( found, true );
}

TEST (serialize_attack_description, blank_attack) {
    attack_details current_attack;
    std::string result = serialize_attack_description(current_attack);
    EXPECT_EQ( result, "Attack type: unknown\nInitial attack power: 0 packets per second\nPeak attack power: 0 packets per second\nAttack direction: other\nAttack protocol: unknown\nTotal incoming traffic: 0 mbps\nTotal outgoing traffic: 0 mbps\nTotal incoming pps: 0 packets per second\nTotal outgoing pps: 0 packets per second\nTotal incoming flows: 0 flows per second\nTotal outgoing flows: 0 flows per second\nAverage incoming traffic: 0 mbps\nAverage outgoing traffic: 0 mbps\nAverage incoming pps: 0 packets per second\nAverage outgoing pps: 0 packets per second\nAverage incoming flows: 0 flows per second\nAverage outgoing flows: 0 flows per second\nIncoming ip fragmented traffic: 0 mbps\nOutgoing ip fragmented traffic: 0 mbps\nIncoming ip fragmented pps: 0 packets per second\nOutgoing ip fragmented pps: 0 packets per second\nIncoming tcp traffic: 0 mbps\nOutgoing tcp traffic: 0 mbps\nIncoming tcp pps: 0 packets per second\nOutgoing tcp pps: 0 packets per second\nIncoming syn tcp traffic: 0 mbps\nOutgoing syn tcp traffic: 0 mbps\nIncoming syn tcp pps: 0 packets per second\nOutgoing syn tcp pps: 0 packets per second\nIncoming udp traffic: 0 mbps\nOutgoing udp traffic: 0 mbps\nIncoming udp pps: 0 packets per second\nOutgoing udp pps: 0 packets per second\nIncoming icmp traffic: 0 mbps\nOutgoing icmp traffic: 0 mbps\nIncoming icmp pps: 0 packets per second\nOutgoing icmp pps: 0 packets per second\n");
}

TEST (serialize_attack_description_to_json, blank_attack) {
    attack_details current_attack;
    json_object * jobj = serialize_attack_description_to_json(current_attack);

    EXPECT_EQ( std::string(json_object_to_json_string(jobj)), "{ \"Attack type\": \"unknown\", \"Initial attack power\": 0, \"Peak attack power\": 0, \"Attack direction\": \"other\", \"Attack protocol\": \"unknown\", \"Total incoming traffic\": 0, \"Total outgoing traffic\": 0, \"Total incoming pps\": 0, \"Total outgoing pps\": 0, \"Total incoming flows\": 0, \"Total outgoing flows\": 0, \"Average incoming traffic\": 0, \"Average outgoing traffic\": 0, \"Average incoming pps\": 0, \"Average outgoing pps\": 0, \"Average incoming flows\": 0, \"Average outgoing flows\": 0, \"Incoming ip fragmented traffic\": 0, \"Outgoing ip fragmented traffic\": 0, \"Incoming ip fragmented pps\": 0, \"Outgoing ip fragmented pps\": 0, \"Incoming tcp traffic\": 0, \"Outgoing tcp traffic\": 0, \"Incoming tcp pps\": 0, \"Outgoing tcp pps\": 0, \"Incoming syn tcp traffic\": 0, \"Outgoing syn tcp traffic\": 0, \"Incoming syn tcp pps\": 0, \"Outgoing syn tcp pps\": 0, \"Incoming udp traffic\": 0, \"Outgoing udp traffic\": 0, \"Incoming udp pps\": 0, \"Outgoing udp pps\": 0, \"Incoming icmp traffic\": 0, \"Outgoing icmp traffic\": 0, \"Incoming icmp pps\": 0, \"Outgoing icmp pps\": 0 }");
}

TEST (serialize_network_load_to_text, blank_attck_average) {
    map_element network_speed_meter;

    EXPECT_EQ( serialize_network_load_to_text(network_speed_meter, true), "Average network incoming traffic: 0 mbps\nAverage network outgoing traffic: 0 mbps\nAverage network incoming pps: 0 packets per second\nAverage network outgoing pps: 0 packets per second\n");
}

TEST (serialize_network_load_to_text, blank_attck_absolute) {
    map_element network_speed_meter;

    EXPECT_EQ( serialize_network_load_to_text(network_speed_meter, false), "Network incoming traffic: 0 mbps\nNetwork outgoing traffic: 0 mbps\nNetwork incoming pps: 0 packets per second\nNetwork outgoing pps: 0 packets per second\n");
}

TEST (serialize_network_load_to_json, blank_attack_average) {
    map_element network_speed_meter;
    json_object * jobj = serialize_network_load_to_json(network_speed_meter);

    EXPECT_EQ( std::string(json_object_to_json_string(jobj)), "{ \"incoming traffic\": 0, \"outgoing traffic\": 0, \"incoming pps\": 0, \"outgoing pps\": 0 }");
}

