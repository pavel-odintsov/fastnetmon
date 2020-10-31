#include "bgp_flow_spec.h"

#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

// Enable custom casts from our own types
std::ostream& operator<<(std::ostream& os, bgp_flow_spec_protocol_t const& protocol) {
    if (protocol == FLOW_SPEC_PROTOCOL_UDP) {
        return os << "udp";
    } else if (protocol == FLOW_SPEC_PROTOCOL_TCP) {
        return os << "tcp";
    } else if (protocol == FLOW_SPEC_PROTOCOL_ICMP) {
        return os << "icmp";
    } else {
        return os;
    }
}

void exabgp_flow_spec_rule_ban_manage(std::string action, flow_spec_rule_t flow_spec_rule) {
    // "announce flow route {\\n match {\\n source 10.0.0.1/32;\\nsource-port =" + str(i) +
    // ";\\n destination 1.2.3.4/32;\\n }\\n then {\\n discard;\\n }\\n }\\n\n")
}

std::ostream& operator<<(std::ostream& os, flow_spec_tcp_flags_t const& tcp_flag) {
    if (tcp_flag == FLOW_TCP_FLAG_SYN) {
        return os << "syn";
    } else if (tcp_flag == FLOW_TCP_FLAG_ACK) {
        return os << "ack";
    } else if (tcp_flag == FLOW_TCP_FLAG_FIN) {
        return os << "fin";
    } else if (tcp_flag == FLOW_TCP_FLAG_URG) {
        return os << "urgent";
    } else if (tcp_flag == FLOW_TCP_FLAG_PSH) {
        return os << "push";
    } else if (tcp_flag == FLOW_TCP_FLAG_RST) {
        return os << "rst";
    } else {
        return os;
    }
}

std::ostream& operator<<(std::ostream& os, flow_spec_fragmentation_types_t const& fragment_flag) {
    // Nice docs here: https://github.com/Exa-Networks/exabgp/blob/71157d560096ec20084cf96cfe0f60203721e93b/lib/exabgp/protocol/ip/fragment.py

    if (fragment_flag == FLOW_SPEC_DONT_FRAGMENT) {
        return os << "dont-fragment";
    } else if (fragment_flag == FLOW_SPEC_IS_A_FRAGMENT) {
        return os << "is-fragment";
    } else if (fragment_flag == FLOW_SPEC_FIRST_FRAGMENT) {
        return os << "first-fragment";
    } else if (fragment_flag == FLOW_SPEC_LAST_FRAGMENT) {
        return os << "last-fragment";
    } else if (fragment_flag == FLOW_NOT_A_FRAGMENT) {
        return os << "not-a-fragment";
    } else {
        return os;
    }
}

