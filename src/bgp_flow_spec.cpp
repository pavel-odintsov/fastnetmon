#include "bgp_flow_spec.h"

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

/*
    g++ fast_library.cpp -c -o fast_library.o
    gcc libpatricia/patricia.c -c -o patricia.o

    g++ bgp_flow_spec.cpp fast_library.o patricia.o -lboost_system -lboost_regex -llog4cpp 
*/

// For library compilation
log4cpp::Category& logger = log4cpp::Category::getRoot();

int main() {
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

    exabgp_rule.announce_is_correct();

    //std::cout << exabgp_rule.serialize();
    std::cout << exabgp_rule.serialize_complete_exabgp_configuration();

    // /usr/src/exabgp/sbin/exabgp --test flow_spec.conf 2> /dev/null ; echo $?

    /*
        Example output:

        flow {
            match {
                source 4.0.0.0/24;
                destination 127.0.0.0/24;
                protocol [ udp ];
                source-port [ =53 ];
                destination-port [ =80 ];
                packet-length [ =777 =1122 ];
                fragment [ is-fragment dont-fragment ];
            }
         then {
                rate-limit 1024;
        }
    }
    */
}

void exabgp_flow_spec_rule_ban_manage(std::string action, flow_spec_rule_t flow_spec_rule) {
// "announce flow route {\\n match {\\n source 10.0.0.1/32;\\nsource-port =" + str(i) +
// ";\\n destination 1.2.3.4/32;\\n }\\n then {\\n discard;\\n }\\n }\\n\n")
}
