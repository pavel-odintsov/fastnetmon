#ifndef BGP_FLOW_SPEC_H
#define BGP_FLOW_SPEC_H

#include <stdint.h>
#include <string>

// All possible values for BGP Flow Spec fragmentation field
enum flow_spec_fragmentation_types {
    FLOW_SPEC_DONT_FRAGMENT,
    FLOW_SPEC_IS_A_FRAGMENT,
    FLOW_SPEC_FIRST_FRAGMENT,
    FLOW_SPEC_LAST_FRAGMENT,
};

// Flow spec actions
enum bgp_flow_spec_action_types_t {
    FLOW_SPEC_ACTION_DISCARD,
    FLOW_SPEC_ACTION_ACCEPT,
    FLOW_SPEC_ACTION_RATE_LIMIT,
    // TBD
};

class bgp_flow_spec_action_t {
    public:
        bgp_flow_spec_action_types_t action_type;
        // TBD:
        // Community, rate-limit value 
};

// We do not use < and > operators at all, sorry
class flow_spec_rule_t {
    public:
        flow_spec_rule_t() { }

        std::string source;
        bool source_used;

        uint16_t source_port;
        bool source_port_used;

        std::string destination;
        bool destination_used;

        uint16_t destination_port;
        bool destination_port_used;

        uint16_t packet_length;
        bool packet_length_used;

        unsigned int protocol; 
        bool protocol_used;

        std::string tcp_flags;
        bool tcp_flags_used;

        std::string icmp_flags;
        bool icmp_flags_used;

        std::string icmp_type;
        bool icmp_type_used;

        std::string dscp; 
        bool dscp_used;

        flow_spec_fragmentation_types fragmentation;
        bool fragmentation_used;

        bgp_flow_spec_action_t action;

        bool sanity_check() {
            // check all fields for correctness! We SHOULD not announce weird flow spec
        }    
        std::string serialize() {
            // Build text representation of flow spec
        }    
};

#endif
