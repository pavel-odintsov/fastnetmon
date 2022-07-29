#include <gtest/gtest.h>
#include <math.h>

#include "bgp_flow_spec.h"
#include "fast_library.h"

#include <fstream>

#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include <arpa/inet.h>

log4cpp::Category& logger = log4cpp::Category::getRoot();

// Flow Spec actions tests

TEST(BgpFlowSpecAction, rate_limit) {
    bgp_flow_spec_action_t my_action;
    my_action.set_type(FLOW_SPEC_ACTION_RATE_LIMIT);
    my_action.set_rate_limit(1024);

    EXPECT_EQ(my_action.serialize(), "rate-limit 1024;");
}

TEST(BgpFlowSpecAction, discard) {
    bgp_flow_spec_action_t my_action;
    my_action.set_type(FLOW_SPEC_ACTION_DISCARD);

    EXPECT_EQ(my_action.serialize(), "discard;");
}

TEST(BgpFlowSpecAction, accept) {
    bgp_flow_spec_action_t my_action;
    my_action.set_type(FLOW_SPEC_ACTION_ACCEPT);

    EXPECT_EQ(my_action.serialize(), "accept;");
}

TEST(BgpFlowSpecAction, default_constructor) {
    bgp_flow_spec_action_t my_action;

    EXPECT_EQ(my_action.serialize(), "accept;");
}

// Serializers tests

TEST(serialize_vector_by_string, single_element) {
    std::vector<std::string> vect;
    vect.push_back("123");

    EXPECT_EQ(serialize_vector_by_string(vect, ","), "123");
}

TEST(serialize_vector_by_string, few_elements) {
    std::vector<std::string> vect;
    vect.push_back("123");
    vect.push_back("456");

    EXPECT_EQ(serialize_vector_by_string(vect, ","), "123,456");
}

TEST(serialize_vector_by_string_with_prefix, single_element) {
    std::vector<uint16_t> vect;
    vect.push_back(123);

    EXPECT_EQ(serialize_vector_by_string_with_prefix(vect, ",", "^"), "^123");
}

TEST(serialize_vector_by_string_with_prefix, few_elements) {
    std::vector<uint16_t> vect;
    vect.push_back(123);
    vect.push_back(456);

    EXPECT_EQ(serialize_vector_by_string_with_prefix(vect, ",", "^"), "^123,^456");
}

/* Patricia tests */

TEST(patricia, negative_lookup_ipv6_prefix) {
    patricia_tree_t* lookup_ipv6_tree;
    lookup_ipv6_tree = New_Patricia(128);

    make_and_lookup_ipv6(lookup_ipv6_tree, (char*)"2a03:f480::/32");

    // Destroy_Patricia(lookup_ipv6_tree);

    prefix_t prefix_for_check_address;

    // Convert fb.com frontend address to internal structure
    inet_pton(AF_INET6, "2a03:2880:2130:cf05:face:b00c::1", (void*)&prefix_for_check_address.add.sin6);

    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;

    bool found = patricia_search_best2(lookup_ipv6_tree, &prefix_for_check_address, 1) != NULL;

    EXPECT_EQ(found, false);
}

TEST(patricia, positive_lookup_ipv6_prefix) {
    patricia_tree_t* lookup_ipv6_tree;
    lookup_ipv6_tree = New_Patricia(128);

    make_and_lookup_ipv6(lookup_ipv6_tree, (char*)"2a03:f480::/32");

    // Destroy_Patricia(lookup_ipv6_tree);

    prefix_t prefix_for_check_address;

    inet_pton(AF_INET6, "2a03:f480:2130:cf05:face:b00c::1", (void*)&prefix_for_check_address.add.sin6);

    prefix_for_check_address.family = AF_INET6;
    prefix_for_check_address.bitlen = 128;

    bool found = patricia_search_best2(lookup_ipv6_tree, &prefix_for_check_address, 1) != NULL;

    EXPECT_EQ(found, true);
}

TEST(serialize_attack_description, blank_attack) {
    attack_details current_attack;
    std::string result = serialize_attack_description(current_attack);
    EXPECT_EQ(result, "Attack type: unknown\nInitial attack power: 0 packets per second\nPeak attack power: 0 "
                      "packets per second\nAttack direction: other\nAttack protocol: unknown\nTotal incoming "
                      "traffic: 0 mbps\nTotal outgoing traffic: 0 mbps\nTotal incoming pps: 0 packets per "
                      "second\nTotal outgoing pps: 0 packets per second\nTotal incoming flows: 0 flows per "
                      "second\nTotal outgoing flows: 0 flows per second\nAverage incoming traffic: 0 mbps\nAverage "
                      "outgoing traffic: 0 mbps\nAverage incoming pps: 0 packets per second\nAverage outgoing pps: 0 "
                      "packets per second\nAverage incoming flows: 0 flows per second\nAverage outgoing flows: 0 "
                      "flows per second\nIncoming ip fragmented traffic: 0 mbps\nOutgoing ip fragmented traffic: 0 "
                      "mbps\nIncoming ip fragmented pps: 0 packets per second\nOutgoing ip fragmented pps: 0 packets "
                      "per second\nIncoming tcp traffic: 0 mbps\nOutgoing tcp traffic: 0 mbps\nIncoming tcp pps: 0 "
                      "packets per second\nOutgoing tcp pps: 0 packets per second\nIncoming syn tcp traffic: 0 "
                      "mbps\nOutgoing syn tcp traffic: 0 mbps\nIncoming syn tcp pps: 0 packets per second\nOutgoing "
                      "syn tcp pps: 0 packets per second\nIncoming udp traffic: 0 mbps\nOutgoing udp traffic: 0 "
                      "mbps\nIncoming udp pps: 0 packets per second\nOutgoing udp pps: 0 packets per "
                      "second\nIncoming icmp traffic: 0 mbps\nOutgoing icmp traffic: 0 mbps\nIncoming icmp pps: 0 "
                      "packets per second\nOutgoing icmp pps: 0 packets per second\n");
}

TEST(serialize_attack_description_to_json, blank_attack) {
    attack_details current_attack;
    json_object* jobj = serialize_attack_description_to_json(current_attack);

    EXPECT_EQ(std::string(json_object_to_json_string(jobj)),
              "{ \"Attack type\": \"unknown\", \"Initial attack power\": 0, \"Peak attack power\": "
              "0, \"Attack direction\": \"other\", \"Attack protocol\": \"unknown\", \"Total "
              "incoming traffic\": 0, \"Total outgoing traffic\": 0, \"Total incoming pps\": 0, "
              "\"Total outgoing pps\": 0, \"Total incoming flows\": 0, \"Total outgoing flows\": "
              "0, \"Average incoming traffic\": 0, \"Average outgoing traffic\": 0, \"Average "
              "incoming pps\": 0, \"Average outgoing pps\": 0, \"Average incoming flows\": 0, "
              "\"Average outgoing flows\": 0, \"Incoming ip fragmented traffic\": 0, \"Outgoing ip "
              "fragmented traffic\": 0, \"Incoming ip fragmented pps\": 0, \"Outgoing ip "
              "fragmented pps\": 0, \"Incoming tcp traffic\": 0, \"Outgoing tcp traffic\": 0, "
              "\"Incoming tcp pps\": 0, \"Outgoing tcp pps\": 0, \"Incoming syn tcp traffic\": 0, "
              "\"Outgoing syn tcp traffic\": 0, \"Incoming syn tcp pps\": 0, \"Outgoing syn tcp "
              "pps\": 0, \"Incoming udp traffic\": 0, \"Outgoing udp traffic\": 0, \"Incoming udp "
              "pps\": 0, \"Outgoing udp pps\": 0, \"Incoming icmp traffic\": 0, \"Outgoing icmp "
              "traffic\": 0, \"Incoming icmp pps\": 0, \"Outgoing icmp pps\": 0 }");
}

TEST(serialize_network_load_to_text, blank_attck_average) {
    map_element network_speed_meter;

    EXPECT_EQ(serialize_network_load_to_text(network_speed_meter, true),
              "Average network incoming traffic: 0 mbps\nAverage network outgoing traffic: 0 "
              "mbps\nAverage network incoming pps: 0 packets per second\nAverage network outgoing "
              "pps: 0 packets per second\n");
}

TEST(serialize_network_load_to_text, blank_attck_absolute) {
    map_element network_speed_meter;

    EXPECT_EQ(serialize_network_load_to_text(network_speed_meter, false),
              "Network incoming traffic: 0 mbps\nNetwork outgoing traffic: 0 mbps\nNetwork "
              "incoming pps: 0 packets per second\nNetwork outgoing pps: 0 packets per second\n");
}

TEST(serialize_network_load_to_json, blank_attack_average) {
    map_element network_speed_meter;
    json_object* jobj = serialize_network_load_to_json(network_speed_meter);

    EXPECT_EQ(std::string(json_object_to_json_string(jobj)),
              "{ \"incoming traffic\": 0, \"outgoing traffic\": 0, \"incoming pps\": 0, \"outgoing "
              "pps\": 0 }");
}
