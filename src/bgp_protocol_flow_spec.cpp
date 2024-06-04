#include "bgp_protocol.hpp"

#include <iostream>

#include "fast_library.hpp"

// inet_ntoa
#include "network_data_structures.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <cmath>

#include "nlohmann/json.hpp"

#include "bgp_protocol_flow_spec.hpp"

// We use this encoding in FastNetMon code
void uint8t_representation_of_tcp_flags_to_flow_spec(uint8_t tcp_flags, flow_spec_tcp_flagset_t& flagset) {
    if (extract_bit_value(tcp_flags, TCP_SYN_FLAG_SHIFT)) {
        flagset.syn_flag = true;
    }

    if (extract_bit_value(tcp_flags, TCP_FIN_FLAG_SHIFT)) {
        flagset.fin_flag = true;
    }

    if (extract_bit_value(tcp_flags, TCP_RST_FLAG_SHIFT)) {
        flagset.rst_flag = true;
    }

    if (extract_bit_value(tcp_flags, TCP_PSH_FLAG_SHIFT)) {
        flagset.psh_flag = true;
    }

    if (extract_bit_value(tcp_flags, TCP_ACK_FLAG_SHIFT)) {
        flagset.ack_flag = true;
    }

    if (extract_bit_value(tcp_flags, TCP_URG_FLAG_SHIFT)) {
        flagset.urg_flag = true;
    }
}


bool read_flow_spec_fragmentation_types_from_string(const std::string& string_form, flow_spec_fragmentation_types_t& fragment_flag) {
    // Unify case for better experience with this function
    std::string string_form_lowercase = boost::algorithm::to_lower_copy(string_form);

    if (string_form_lowercase == "dont-fragment") {
        fragment_flag = flow_spec_fragmentation_types_t::FLOW_SPEC_DONT_FRAGMENT;
    } else if (string_form_lowercase == "is-fragment") {
        fragment_flag = flow_spec_fragmentation_types_t::FLOW_SPEC_IS_A_FRAGMENT;
    } else if (string_form_lowercase == "first-fragment") {
        fragment_flag = flow_spec_fragmentation_types_t::FLOW_SPEC_FIRST_FRAGMENT;
    } else if (string_form_lowercase == "last-fragment") {
        fragment_flag = flow_spec_fragmentation_types_t::FLOW_SPEC_LAST_FRAGMENT;
    } else if (string_form_lowercase == "not-a-fragment") {
        fragment_flag = flow_spec_fragmentation_types_t::FLOW_SPEC_NOT_A_FRAGMENT;
    } else {
        return false;
    }

    return true;
}

std::string flow_spec_fragmentation_flags_to_string(flow_spec_fragmentation_types_t const& fragment_flag) {
    // https://github.com/Exa-Networks/exabgp/blob/71157d560096ec20084cf96cfe0f60203721e93b/lib/exabgp/protocol/ip/fragment.py

    if (fragment_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_DONT_FRAGMENT) {
        return "dont-fragment";
    } else if (fragment_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_IS_A_FRAGMENT) {
        return "is-fragment";
    } else if (fragment_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_FIRST_FRAGMENT) {
        return "first-fragment";
    } else if (fragment_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_LAST_FRAGMENT) {
        return "last-fragment";
    } else if (fragment_flag == flow_spec_fragmentation_types_t::FLOW_SPEC_NOT_A_FRAGMENT) {
        return "not-a-fragment";
    } else {
        return "";
    }
}

bool read_flow_spec_action_type_from_string(const std::string& string_form, bgp_flow_spec_action_types_t& action_type) {
    if (string_form == "accept") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_ACCEPT;
    } else if (string_form == "discard") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD;
    } else if (string_form == "rate-limit") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT;
    } else if (string_form == "redirect") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT;
    } else if (string_form == "mark") {
        action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_MARK;
    } else {
        return false;
    }

    return true;
}

std::string serialize_action_type(const bgp_flow_spec_action_types_t& action_type) {
    if (action_type == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_ACCEPT) {
        return "accept";
    } else if (action_type == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD) {
        return "discard";
    } else if (action_type == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT) {
        return "rate-limit";
    } else if (action_type == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT) {
        return "redirect";
    } else if (action_type == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_MARK) {
        return "mark";
    } else {
        // TODO: add return code for notifying about this case
        return std::string("");
    }
}

bool read_flow_spec_tcp_flags_from_strig(const std::string& string_form, flow_spec_tcp_flagset_t& flagset) {
    // Unify case for better experience with this function
    std::string string_form_lowercase = boost::algorithm::to_lower_copy(string_form);

    std::vector<std::string> tcp_flags;

    // Split line by "|"
    boost::split(tcp_flags, string_form_lowercase, boost::is_any_of("|"), boost::token_compress_on);

    for (auto tcp_flag_string : tcp_flags) {
        if (tcp_flag_string == "syn") {
            flagset.syn_flag = true;
        } else if (tcp_flag_string == "ack") {
            flagset.ack_flag = true;
        } else if (tcp_flag_string == "fin") {
            flagset.fin_flag = true;
        } else if (tcp_flag_string == "urgent") {
            flagset.urg_flag = true;
        } else if (tcp_flag_string == "push") {
            flagset.psh_flag = true;
        } else if (tcp_flag_string == "rst") {
            flagset.rst_flag = true;
        } else {
            return false;
        }
    }

    return true;
}

std::string flow_spec_tcp_flagset_to_string(flow_spec_tcp_flagset_t const& tcp_flagset) {
    std::vector<std::string> output;

    if (tcp_flagset.syn_flag) {
        output.push_back("syn");
    }

    if (tcp_flagset.ack_flag) {
        output.push_back("ack");
    }

    if (tcp_flagset.fin_flag) {
        output.push_back("fin");
    }

    if (tcp_flagset.rst_flag) {
        output.push_back("rst");
    }

    if (tcp_flagset.urg_flag) {
        output.push_back("urgent");
    }

    if (tcp_flagset.psh_flag) {
        output.push_back("push");
    }

    return boost::algorithm::join(output, "|");
}

bool operator==(const bgp_flow_spec_action_t& lhs, const bgp_flow_spec_action_t& rhs) {
    if (lhs.get_type() != rhs.get_type()) {
        return false;
    }

    // Action types are equal
    if (lhs.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT) {
        return lhs.get_rate_limit() == rhs.get_rate_limit();
    } else {
        return true;
    }
}

bool operator!=(const bgp_flow_spec_action_t& lhs, const bgp_flow_spec_action_t& rhs) {
    return !(lhs == rhs);
}

// It does not check UUID
bool operator==(const flow_spec_rule_t& lhs, const flow_spec_rule_t& rhs) {
    // Compare source subnets

    // IPv4
    if (lhs.source_subnet_ipv4_used != rhs.source_subnet_ipv4_used) {
        return false;
    } else {
        if (lhs.source_subnet_ipv4_used) {
            // If they have values
            if (lhs.source_subnet_ipv4 != rhs.source_subnet_ipv4) {
                return false;
            }
        }
    }

    // IPv6
    if (lhs.source_subnet_ipv6_used != rhs.source_subnet_ipv6_used) {
        return false;
    } else {
        if (lhs.source_subnet_ipv6_used) {
            // If they have values
            if (lhs.source_subnet_ipv6 != rhs.source_subnet_ipv6) {
                return false;
            }
        }
    }

    // Compare destination subnets

    // IPv4
    if (lhs.destination_subnet_ipv4_used != rhs.destination_subnet_ipv4_used) {
        return false;
    } else {
        if (lhs.destination_subnet_ipv4_used) {
            if (lhs.destination_subnet_ipv4 != rhs.destination_subnet_ipv4) {
                return false;
            }
        }
    }

    // IPv6
    if (lhs.destination_subnet_ipv6_used != rhs.destination_subnet_ipv6_used) {
        return false;
    } else {
        if (lhs.destination_subnet_ipv6_used) {
            if (lhs.destination_subnet_ipv6 != rhs.destination_subnet_ipv6) {
                return false;
            }
        }
    }

    // Compare actions
    if (lhs.action != rhs.action) {
        return false;
    }

    if (lhs.source_ports != rhs.source_ports) {
        return false;
    }

    if (lhs.destination_ports != rhs.destination_ports) {
        return false;
    }

    if (lhs.packet_lengths != rhs.packet_lengths) {
        return false;
    }

    // This one is non standard compliant field and it cannot be used for BGP flow spec announces
    if (lhs.vlans != rhs.vlans) {
        return false;
    }

    // This one is non standard compliant field and it cannot be used for BGP flow spec announces
    if (lhs.ttls != rhs.ttls) {
        return false;
    }

    if (lhs.ipv4_nexthops != rhs.ipv4_nexthops) {
        return false;
    }

    if (lhs.protocols != rhs.protocols) {
        return false;
    }

    if (lhs.tcp_flags != rhs.tcp_flags) {
        return false;
    }

    if (lhs.fragmentation_flags != rhs.fragmentation_flags) {
        return false;
    }

    return true;
}

bool operator!=(const flow_spec_rule_t& lhs, const flow_spec_rule_t& rhs) {
    return !(lhs == rhs);
}

bool operator!=(const flow_spec_tcp_flagset_t& lhs, const flow_spec_tcp_flagset_t& rhs) {
    return !(lhs == rhs);
}

bool operator==(const flow_spec_tcp_flagset_t& lhs, const flow_spec_tcp_flagset_t& rhs) {
    if (lhs.syn_flag == rhs.syn_flag && lhs.ack_flag == rhs.ack_flag && lhs.rst_flag == rhs.rst_flag &&
        lhs.psh_flag == rhs.psh_flag && lhs.urg_flag == rhs.urg_flag && lhs.fin_flag == rhs.fin_flag) {
        return true;
    } else {
        return false;
    }
}

/*
{
  "source_prefix": "4.0.0.0\/24",
  "destination_prefix": "127.0.0.0\/24",
  "destination_ports": [ 80 ],
  "source_ports": [ 53, 5353 ],
  "packet_lengths": [ 777, 1122 ],
  "protocols": [ "tcp" ],
  "fragmentation_flags":[ "is-fragment", "dont-fragment" ],
  "tcp_flags": [ "syn" ],
  "action_type": "rate-limit",
  "action": { "rate": 1024 }
}
*/

bool read_flow_spec_from_json_to_native_format(const std::string& json_encoded_flow_spec, flow_spec_rule_t& flow_spec_rule, bool require_action) {
    using json = nlohmann::json;

    // We explicitly disable exceptions
    auto json_doc = json::parse(json_encoded_flow_spec, nullptr, false);

    if (json_doc.is_discarded()) {
        logger << log4cpp::Priority::ERROR << "Cannot decode Flow Spec rule from JSON: '" << json_encoded_flow_spec << "'";
        return false;
    }

    if (json_doc.contains("source_prefix")) {
        std::string source_prefix_string;

        try {
            source_prefix_string = json_doc["source_prefix"].get<std::string>();
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not parse JSON encoded source_prefix";
            return false;
        }

        if (source_prefix_string.find(":") != std::string::npos) {
            subnet_ipv6_cidr_mask_t subnet_cidr_mask;

            bool conversion_result = read_ipv6_subnet_from_string(subnet_cidr_mask, source_prefix_string);

            if (!conversion_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse JSON encoded IPv6 source_prefix";
                return false;
            }

            flow_spec_rule.set_source_subnet_ipv6(subnet_cidr_mask);
        } else {
            subnet_cidr_mask_t subnet_cidr_mask;
            bool conversion_result =
                convert_subnet_from_string_to_binary_with_cidr_format_safe(source_prefix_string, subnet_cidr_mask);

            if (!conversion_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse JSON encoded source_prefix";
                return false;
            }

            flow_spec_rule.set_source_subnet_ipv4(subnet_cidr_mask);
        }
    }

    if (json_doc.contains("destination_prefix")) {
        std::string destination_prefix_string;

        try {
            destination_prefix_string = json_doc["destination_prefix"].get<std::string>();
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not parse JSON encoded destination_prefix";
            return false;
        }

        if (destination_prefix_string.find(":") != std::string::npos) {
            subnet_ipv6_cidr_mask_t subnet_cidr_mask;

            bool conversion_result = read_ipv6_subnet_from_string(subnet_cidr_mask, destination_prefix_string);

            if (!conversion_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse JSON encoded IPv6 destination_prefix";
                return false;
            }

            flow_spec_rule.set_destination_subnet_ipv6(subnet_cidr_mask);
        } else {
            subnet_cidr_mask_t subnet_cidr_mask;
            bool conversion_result =
                convert_subnet_from_string_to_binary_with_cidr_format_safe(destination_prefix_string, subnet_cidr_mask);

            if (!conversion_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse json encoded destination_prefix";
                return false;
            }

            flow_spec_rule.set_destination_subnet_ipv4(subnet_cidr_mask);
        }
    }

    if (json_doc.contains("destination_ports")) {
        std::vector<int32_t> ports_vector_as_ints;

        try {
            ports_vector_as_ints = json_doc["destination_ports"].get<std::vector<int32_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode destination_ports " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode destination_ports";
            return false;
        }

        for (auto port : ports_vector_as_ints) {
            if (!valid_port(port)) {
                logger << log4cpp::Priority::ERROR << "Could not parse destination_ports element: bad range " << port;
                return false;
            }

            flow_spec_rule.add_destination_port(port);
        }
    }

    if (json_doc.contains("source_ports")) {
        std::vector<int32_t> ports_vector_as_ints;

        try {
            ports_vector_as_ints = json_doc["source_ports"].get<std::vector<int32_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode source_ports " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode source_ports";
            return false;
        }

        for (auto port : ports_vector_as_ints) {
            if (!valid_port(port)) {
                logger << log4cpp::Priority::ERROR << "Could not parse source_ports element: bad range " << port;
                return false;
            }

            flow_spec_rule.add_source_port(port);
        }
    }

    if (json_doc.contains("packet_lengths")) {
        std::vector<int32_t> packet_lengths_vector_as_ints;

        try {
            packet_lengths_vector_as_ints = json_doc["packet_lengths"].get<std::vector<int32_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode packet_lengths " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode packet_lengths";
            return false;
        }

        for (auto packet_length : packet_lengths_vector_as_ints) {
            if (packet_length < 0) {
                logger << log4cpp::Priority::ERROR << "Could not parse packet_lengths element, it must be positive: " << packet_length;
                return false;
            }

            // Should we drop it?
            if (packet_length > 1500) {
                logger << log4cpp::Priority::ERROR
                       << "Could not parse packet_lengths element, it must not exceed 1500: " << packet_length;
                return false;
            }

            flow_spec_rule.add_packet_length(packet_length);
        }
    }

    // TODO: this logic is not covered by tests

    if (json_doc.contains("vlans")) {
        std::vector<int32_t> vlans_vector_as_ints;

        try {
            vlans_vector_as_ints = json_doc["vlans"].get<std::vector<int32_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode vlans " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode vlans";
            return false;
        }

        for (auto vlan : vlans_vector_as_ints) {
            if (vlan < 0) {
                logger << log4cpp::Priority::ERROR << "Could not parse vlan element, bad range: " << vlan;
                return false;
            }

            flow_spec_rule.add_vlan(vlan);
        }
    }

    // TODO: this logic is not covered by tests
    if (json_doc.contains("ttls")) {
	// TODO: I'm not sure that it can handle such small unsigned well
        std::vector<uint8_t> ttls_vector_as_ints;

        try {
            ttls_vector_as_ints = json_doc["ttls"].get<std::vector<uint8_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode TTLs " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode TTLs";
            return false;
        }

        for (auto ttl : ttls_vector_as_ints) {
            flow_spec_rule.add_ttl(ttl);
        }
    }

    if (json_doc.contains("protocols")) {
        std::vector<std::string> protocols_vector_as_strings;

        try {
            protocols_vector_as_strings = json_doc["protocols"].get<std::vector<std::string>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode protocols " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode protocols";
            return false;
        }

        for (const auto& protocol_as_string : protocols_vector_as_strings) {
            ip_protocol_t protocol;

            bool result = read_protocol_from_string(protocol_as_string, protocol);

            if (!result) {
                logger << log4cpp::Priority::ERROR << "Could not parse this " << protocol_as_string << " as protocol";
                return false;
            }

            flow_spec_rule.add_protocol(protocol);
        }
    }

    // TODO: this logic is not covered by tests
    if (json_doc.contains("ipv4_nexthops")) {
        std::vector<std::string> next_hops_vector_as_strings;

        try {
            next_hops_vector_as_strings = json_doc["ipv4_nexthops"].get<std::vector<std::string>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode ipv4_nexthops " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode ipv4_nexthops";
            return false;
        }

        for (const auto& next_hop_as_string : next_hops_vector_as_strings) {
            uint32_t next_hop_ipv4 = 0;

            auto ip_parser_result = convert_ip_as_string_to_uint_safe(next_hop_as_string, next_hop_ipv4);

            if (!ip_parser_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse this " << next_hop_as_string << " as IPv4 address";
                return false;
            }

            flow_spec_rule.add_ipv4_nexthop(next_hop_ipv4);
        }
    }

    if (json_doc.contains("fragmentation_flags")) {
        std::vector<std::string> fragmentation_flags_vector_as_strings;

        try {
            fragmentation_flags_vector_as_strings = json_doc["fragmentation_flags"].get<std::vector<std::string>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode fragmentation_flags " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode fragmentation_flags";
            return false;
        }

        for (const auto& fragmentation_flag_as_string : fragmentation_flags_vector_as_strings) {
            flow_spec_fragmentation_types_t fragment_flag;

            bool result = read_flow_spec_fragmentation_types_from_string(fragmentation_flag_as_string, fragment_flag);

            if (!result) {
                logger << log4cpp::Priority::ERROR << "Could not parse this " << fragmentation_flag_as_string
                       << " as flow spec fragmentation flag";
                return false;
            }

            flow_spec_rule.add_fragmentation_flag(fragment_flag);
        }
    }


    if (json_doc.contains("tcp_flags")) {
        std::vector<std::string> tcp_flags_vector_as_strings;

        try {
            tcp_flags_vector_as_strings = json_doc["tcp_flags"].get<std::vector<std::string>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode tcp_flags " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode tcp_flags";
            return false;
        }

        for (const auto& tcp_flag_as_string : tcp_flags_vector_as_strings) {
            flow_spec_tcp_flagset_t flagset;

            bool result = read_flow_spec_tcp_flags_from_strig(tcp_flag_as_string, flagset);

            if (!result) {
                logger << log4cpp::Priority::ERROR << "Could not parse this " << tcp_flag_as_string << " as flow spec tcp option flag";
                return false;
            }

            flow_spec_rule.add_tcp_flagset(flagset);
        }
    }

    // Skip action section when we do not need it
    if (!require_action) {
        return true;
    }

    bgp_flow_spec_action_t bgp_flow_spec_action;

    if (!json_doc.contains("action_type")) {
        logger << log4cpp::Priority::ERROR << "We have no action_type in JSON and it's mandatory";
        return false;
    }

    std::string action_as_string;

    try {
        action_as_string = json_doc["action_type"].get<std::string>();
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Could not parse JSON encoded action_type";
        return false;
    }

    bgp_flow_spec_action_types_t action_type;
    bool result = read_flow_spec_action_type_from_string(action_as_string, action_type);

    if (!result) {
        logger << log4cpp::Priority::ERROR << "Could not parse action type: " << action_as_string;
        return false;
    }

    bgp_flow_spec_action.set_type(action_type);

    // And in this case we should extract rate_limit number
    if (bgp_flow_spec_action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT) {
        if (json_doc.contains("action")) {
            auto json_action_doc = json_doc["action"];

            if (!json_action_doc.contains("rate")) {
                logger << log4cpp::Priority::ERROR << "Absent rate argument for rate limit action";
                return false;
            }

            int32_t rate = 0;

            try {
                rate = json_action_doc["rate"].get<int32_t>();
            } catch (...) {
                logger << log4cpp::Priority::ERROR << "Could not parse JSON document for rate";
                return false;
            }


            if (rate < 0) {
                logger << log4cpp::Priority::ERROR << "Rate validation failed, it must be positive: " << rate;
                return false;
            }

            bgp_flow_spec_action.set_rate_limit(rate);
        } else {
            // We assume zero rate in this case
        }
    } else if (bgp_flow_spec_action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT) {
        if (!json_doc.contains("action")) {
            logger << log4cpp::Priority::ERROR << "Action need to be provided for redirect";
            return false;
        }

        auto json_action_doc = json_doc["action"];

        if (!json_action_doc.contains("redirect_target_as")) {
            logger << log4cpp::Priority::ERROR << "Absent redirect_target_as argument for redirect action";
            return false;
        }

        uint16_t redirect_target_as = 0;

        try {
            redirect_target_as = json_action_doc["redirect_target_as"].get<uint16_t>();
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not parse JSON document for redirect_target_as";
            return false;
        }

        bgp_flow_spec_action.set_redirect_as(redirect_target_as);

        uint32_t redirect_target_value = 0;
        
        try {
            redirect_target_value = json_action_doc["redirect_target_value"].get<uint32_t>();
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not parse JSON document for redirect_target_value";
            return false;
        }   
        
        bgp_flow_spec_action.set_redirect_value(redirect_target_value);
    }

    flow_spec_rule.set_action(bgp_flow_spec_action);

    return true;
}

// Encode flow spec announce into JSON representation
bool encode_flow_spec_to_json(const flow_spec_rule_t& flow_spec_rule, std::string& json_encoded_flow_spec, bool add_uuid) {
    nlohmann::json flow_json;

    bool encoding_result = encode_flow_spec_to_json_raw(flow_spec_rule, add_uuid, flow_json);

    if (!encoding_result) {
        logger << log4cpp::Priority::ERROR << "Cannot encode Flow Spec into JSON";
        return false;
    }

    std::string json_as_text = flow_json.dump();

    // Remove ugly useless escaping for flow spec destination and source subnets
    // I.e. 127.0.0.1\/32
    boost::replace_all(json_as_text, "\\", "");

    json_encoded_flow_spec = json_as_text;
    return true;
}

// Encode flow spec in JSON object representation
bool encode_flow_spec_to_json_raw(const flow_spec_rule_t& flow_spec_rule, bool add_uuid, nlohmann::json& flow_json) {
    // UUID is quite important for us, let's add it
    if (add_uuid) {
        flow_json["uuid"] = flow_spec_rule.get_announce_uuid_as_string();
    }

    if (flow_spec_rule.source_subnet_ipv4_used) {
        flow_json["source_prefix"] = convert_ipv4_subnet_to_string(flow_spec_rule.source_subnet_ipv4);
    } else if (flow_spec_rule.source_subnet_ipv6_used) {
        flow_json["source_prefix"] = convert_ipv6_subnet_to_string(flow_spec_rule.source_subnet_ipv6);
    }

    if (flow_spec_rule.destination_subnet_ipv4_used) {
        flow_json["destination_prefix"] = convert_ipv4_subnet_to_string(flow_spec_rule.destination_subnet_ipv4);
    } else if (flow_spec_rule.destination_subnet_ipv6_used) {
        flow_json["destination_prefix"] = convert_ipv6_subnet_to_string(flow_spec_rule.destination_subnet_ipv6);
    }

    if (!flow_spec_rule.destination_ports.empty()) {
        flow_json["destination_ports"] = flow_spec_rule.destination_ports;
    }

    if (!flow_spec_rule.source_ports.empty()) {
        flow_json["source_ports"] = flow_spec_rule.source_ports;
    }

    if (!flow_spec_rule.packet_lengths.empty()) {
        flow_json["packet_lengths"] = flow_spec_rule.packet_lengths;
    }

    if (!flow_spec_rule.vlans.empty()) {
        flow_json["vlans"] = flow_spec_rule.vlans;
    }

    if (!flow_spec_rule.ttls.empty()) {
        flow_json["ttls"] = flow_spec_rule.ttls;
    }

    if (!flow_spec_rule.protocols.empty()) {
        flow_json["protocols"] = nlohmann::json::array();

        for (auto protocol : flow_spec_rule.protocols) {
            std::string protocol_name = get_ip_protocol_name(protocol);

            // We use lowercase format
            boost::algorithm::to_lower(protocol_name);

            flow_json["protocols"].push_back(protocol_name);
        }
    }

    if (!flow_spec_rule.fragmentation_flags.empty()) {
        flow_json["fragmentation_flags"] = nlohmann::json::array();

        for (auto fragment_flag : flow_spec_rule.fragmentation_flags) {
            std::string fragmentation_flag_as_string = flow_spec_fragmentation_flags_to_string(fragment_flag);

            // For some reasons we cannot convert it to string
            if (fragmentation_flag_as_string == "") {
                continue;
            }

            flow_json["fragmentation_flags"].push_back(fragmentation_flag_as_string);
        }
    }

    // If we have TCP in protocols list explicitly, we add flags
    bool we_have_tcp_protocol_in_list = find(flow_spec_rule.protocols.begin(), flow_spec_rule.protocols.end(),
                                             ip_protocol_t::TCP) != flow_spec_rule.protocols.end();

    if (!flow_spec_rule.tcp_flags.empty() && we_have_tcp_protocol_in_list) {
        flow_json["tcp_flags"] = nlohmann::json::array();

        for (auto tcp_flag : flow_spec_rule.tcp_flags) {
            std::string tcp_flags_as_string = flow_spec_tcp_flagset_to_string(tcp_flag);

            // For some reasons we cannot encode it, skip iteration
            if (tcp_flags_as_string == "") {
                continue;
            }

            flow_json["tcp_flags"].push_back(tcp_flags_as_string);
        }
    }

    // Encode action structure
    flow_json["action_type"] = serialize_action_type(flow_spec_rule.action.get_type());

    // We add sub document action when arguments needed
    if (flow_spec_rule.action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT) {
        nlohmann::json action_json;
        action_json["rate"] = flow_spec_rule.action.get_rate_limit();

        flow_json["action"] = action_json;
    } else if (flow_spec_rule.action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT) {
        nlohmann::json action_json;

        action_json["redirect_target_as"] = flow_spec_rule.action.get_redirect_as();
        action_json["redirect_target_value"] = flow_spec_rule.action.get_redirect_value();

        flow_json["action"] = action_json;
    }

    return true;
}

bgp_flowspec_one_byte_byte_encoded_tcp_flags_t return_in_one_byte_encoding(const flow_spec_tcp_flagset_t& flagset) {
    bgp_flowspec_one_byte_byte_encoded_tcp_flags_t one_byte_flags{};

    if (flagset.syn_flag) {
        one_byte_flags.syn = 1;
    }

    if (flagset.fin_flag) {
        one_byte_flags.fin = 1;
    }

    if (flagset.urg_flag) {
        one_byte_flags.urg = 1;
    }

    if (flagset.ack_flag) {
        one_byte_flags.ack = 1;
    }

    if (flagset.psh_flag) {
        one_byte_flags.psh = 1;
    }

    if (flagset.rst_flag) {
        one_byte_flags.rst = 1;
    }

    return one_byte_flags;
}

flow_spec_tcp_flagset_t convert_one_byte_encoding_to_flowset(const bgp_flowspec_one_byte_byte_encoded_tcp_flags_t& one_byte_flags) {
    flow_spec_tcp_flagset_t flagset;

    if (one_byte_flags.syn == 1) {
        flagset.syn_flag = true;
    }

    if (one_byte_flags.fin == 1) {
        flagset.fin_flag = true;
    }

    if (one_byte_flags.urg == 1) {
        flagset.urg_flag = true;
    }

    if (one_byte_flags.ack == 1) {
        flagset.ack_flag = true;
    }


    if (one_byte_flags.psh == 1) {
        flagset.psh_flag = true;
    }

    if (one_byte_flags.rst == 1) {
        flagset.rst_flag = true;
    }

    return flagset;
}

// Is it range valid for port?
bool valid_port(int32_t port) {
    return port >= 0 && port <= 65535;
}
