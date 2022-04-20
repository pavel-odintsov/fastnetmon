#include "bgp_protocol.hpp"

#include "log4cpp/Appender.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include "all_logcpp_libraries.h"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

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

bool read_bgp_community_from_string(std::string community_as_string, bgp_community_attribute_element_t& bgp_community_attribute_element) {
    std::vector<std::string> community_as_vector;

    split(community_as_vector, community_as_string, boost::is_any_of(":"), boost::token_compress_on);

    if (community_as_vector.size() != 2) {
        logger << log4cpp::Priority::WARN << "Could not parse community: " << community_as_string;
        return false;
    }

    int asn_as_integer = 0;

    if (!convert_string_to_positive_integer_safe(community_as_vector[0], asn_as_integer)) {
        logger << log4cpp::Priority::WARN << "Could not parse ASN from raw format: " << community_as_vector[0];
        return false;
    }

    int community_number_as_integer = 0;

    if (!convert_string_to_positive_integer_safe(community_as_vector[1], community_number_as_integer)) {
        logger << log4cpp::Priority::WARN << "Could not parse community from raw format: " << community_as_vector[0];
        return false;
    }

    if (asn_as_integer < 0 or community_number_as_integer < 0) {
        logger << log4cpp::Priority::WARN << "For some strange reasons we've got negative ASN or community numbers";
        return false;
    }

    if (asn_as_integer > UINT16_MAX) {
        logger << log4cpp::Priority::ERROR << "Your ASN value exceeds maximum allowed value " << UINT16_MAX;
        return false;
    }

    if (community_number_as_integer > UINT16_MAX) {
        logger << log4cpp::Priority::ERROR << "Your community value exceeds maximum allowed value " << UINT16_MAX;
        return false;
    }

    bgp_community_attribute_element.asn_number       = asn_as_integer;
    bgp_community_attribute_element.community_number = community_number_as_integer;

    return true;
}

// Wrapper function which just checks correctness of bgp community
bool is_bgp_community_valid(std::string community_as_string) {
    bgp_community_attribute_element_t bgp_community_attribute_element;

    return read_bgp_community_from_string(community_as_string, bgp_community_attribute_element);
}
