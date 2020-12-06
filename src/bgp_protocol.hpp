#pragma once

#include <stdint.h>
#include <string>
#include <vector>

#include "fast_library.h"
#include "fastnetmon_types.h"

// Helper for serialization by comma
template <typename T>
std::string serialize_vector_by_string(const std::vector<T> vect, std::string delimiter) {
    std::ostringstream output_buffer;

    std::copy(vect.begin(), vect.end() - 1, std::ostream_iterator<T>(output_buffer, delimiter.c_str()));
    output_buffer << vect.back();

    return output_buffer.str();
}

template <typename T>
std::string
serialize_vector_by_string_with_prefix(const std::vector<T> vect, std::string delimiter, std::string prefix) {
    std::vector<std::string> elements_with_prefix;

    for (typename std::vector<T>::const_iterator itr = vect.begin(); itr != vect.end(); ++itr) {
        elements_with_prefix.push_back(prefix + convert_int_to_string(*itr));
    }

    return serialize_vector_by_string<std::string>(elements_with_prefix, delimiter);
}

// All possible values for BGP Flow Spec fragmentation field
enum flow_spec_fragmentation_types_t {
    FLOW_SPEC_DONT_FRAGMENT,
    FLOW_SPEC_IS_A_FRAGMENT,
    FLOW_SPEC_FIRST_FRAGMENT,
    FLOW_SPEC_LAST_FRAGMENT,
    FLOW_NOT_A_FRAGMENT,
};

// TCP flags for Flow Spec
enum flow_spec_tcp_flags_t {
    FLOW_TCP_FLAG_SYN,
    FLOW_TCP_FLAG_FIN,
    FLOW_TCP_FLAG_URG,
    FLOW_TCP_FLAG_ACK,
    FLOW_TCP_FLAG_PSH,
    FLOW_TCP_FLAG_RST,
};

// Flow spec actions
enum bgp_flow_spec_action_types_t {
    FLOW_SPEC_ACTION_DISCARD,
    FLOW_SPEC_ACTION_ACCEPT,
    FLOW_SPEC_ACTION_RATE_LIMIT,
    // TBD
};

enum bgp_flow_spec_protocol_t {
    FLOW_SPEC_PROTOCOL_UDP,
    FLOW_SPEC_PROTOCOL_TCP,
    FLOW_SPEC_PROTOCOL_ICMP,
};

// Class for storing old style BGP communities which support only 16 bit ASN numbers
class __attribute__((__packed__)) bgp_community_attribute_element_t {
    public:
    uint16_t asn_number       = 0;
    uint16_t community_number = 0;

    void host_byte_order_to_network_byte_order() {
        asn_number       = htons(asn_number);
        community_number = htons(community_number);
    }
};

bool read_bgp_community_from_string(std::string community_as_string, bgp_community_attribute_element_t& bgp_community_attribute_element);

static_assert(sizeof(bgp_community_attribute_element_t) == 4, "Broken size of bgp_community_attribute_element_t");


// Enable custom casts from our own types
std::ostream& operator<<(std::ostream& os, bgp_flow_spec_protocol_t const& protocol);

std::ostream& operator<<(std::ostream& os, flow_spec_fragmentation_types_t const& fragment_flag);

std::ostream& operator<<(std::ostream& os, flow_spec_tcp_flags_t const& tcp_flag);

class bgp_flow_spec_action_t {
    public:
    bgp_flow_spec_action_t() {
        this->action_type = FLOW_SPEC_ACTION_ACCEPT;
        this->rate_limit = 9600;

        sentence_separator = ";";
    }

    void set_type(bgp_flow_spec_action_types_t action_type) {
        this->action_type = action_type;
    }

    void set_rate_limit(unsigned int rate_limit) {
        this->rate_limit = rate_limit;
    }

    void set_sentence_separator(std::string sentence_separator) {
        this->sentence_separator = sentence_separator;
    }

    std::string serialize() {
        if (this->action_type == FLOW_SPEC_ACTION_ACCEPT) {
            return "accept" + sentence_separator;
        } else if (this->action_type == FLOW_SPEC_ACTION_DISCARD) {
            return "discard" + sentence_separator;
        } else if (this->action_type == FLOW_SPEC_ACTION_RATE_LIMIT) {
            return "rate-limit " + convert_int_to_string(this->rate_limit) + sentence_separator;
        } else {
            return "accept" + sentence_separator;
        }
    }

    private:
    bgp_flow_spec_action_types_t action_type;
    unsigned int rate_limit;
    std::string sentence_separator;
    // TBD

    // Community, rate-limit value
};

// We do not use < and > operators at all, sorry
class flow_spec_rule_t {
    public:
    flow_spec_rule_t() {
        // We should explidictly initialize it!
        source_subnet_used = false;
        destination_subnet_used = false;
    }

    bool announce_is_correct() {
        if (source_subnet_used || destination_subnet_used) {
            return true;
        } else {
            return false;
        }
    }

    void set_source_subnet(subnet_cidr_mask_t source_subnet) {
        this->source_subnet = source_subnet;
        this->source_subnet_used = true;
    }

    void set_destination_subnet(subnet_cidr_mask_t destination_subnet) {
        this->destination_subnet = destination_subnet;
        this->destination_subnet_used = true;
    }

    void add_source_port(uint16_t source_port) {
        this->source_ports.push_back(source_port);
    }

    void add_destination_port(uint16_t destination_port) {
        this->destination_ports.push_back(destination_port);
    }

    void add_packet_length(uint16_t packet_length) {
        this->packet_lengths.push_back(packet_length);
    }

    void add_protocol(bgp_flow_spec_protocol_t protocol) {
        this->protocols.push_back(protocol);
    }

    /*
    std::string icmp_flags;
    bool icmp_flags_used;

    std::string icmp_type;
    bool icmp_type_used;

    std::string dscp;
    bool dscp_used;
    */

    void add_fragmentation_flag(flow_spec_fragmentation_types_t flag) {
        this->fragmentation_flags.push_back(flag);
    }

    void add_tcp_flag(flow_spec_tcp_flags_t flag) {
        this->tcp_flags.push_back(flag);
    }

    void set_action(bgp_flow_spec_action_t action) {
        this->action = action;
    }

    protected:
    // Only IPv4 supported
    subnet_cidr_mask_t source_subnet;
    bool source_subnet_used;

    subnet_cidr_mask_t destination_subnet;
    bool destination_subnet_used;

    std::vector<uint16_t> source_ports;
    std::vector<uint16_t> destination_ports;
    std::vector<uint16_t> packet_lengths;
    std::vector<bgp_flow_spec_protocol_t> protocols;
    std::vector<flow_spec_fragmentation_types_t> fragmentation_flags;
    std::vector<flow_spec_tcp_flags_t> tcp_flags;

    bgp_flow_spec_action_t action;
};

class exabgp_flow_spec_rule_t : public flow_spec_rule_t {
    public:
    exabgp_flow_spec_rule_t() {
        four_spaces = "    ";
        sentence_separator = ";";

        this->enabled_indents = true;
        this->enble_block_headers = true;
    }

    void disable_indents() {
        enabled_indents = false;
    }

    std::string serialize_source_ports() {
        std::ostringstream output_buffer;

        output_buffer << "source-port [ "
                      << serialize_vector_by_string_with_prefix<uint16_t>(this->source_ports, " ", "=")
                      << " ]" << sentence_separator;

        return output_buffer.str();
    }

    std::string serialize_destination_ports() {
        std::ostringstream output_buffer;

        output_buffer << "destination-port [ "
                      << serialize_vector_by_string_with_prefix<uint16_t>(this->destination_ports, " ", "=")
                      << " ]" << sentence_separator;

        return output_buffer.str();
    }

    std::string serialize_packet_lengths() {
        std::ostringstream output_buffer;

        output_buffer << "packet-length [ "
                      << serialize_vector_by_string_with_prefix<uint16_t>(this->packet_lengths, " ", "=")
                      << " ]" << sentence_separator;

        return output_buffer.str();
    }


    std::string serialize_protocols() {
        std::ostringstream output_buffer;

        output_buffer << "protocol [ " << serialize_vector_by_string(this->protocols, " ") << " ]"
                      << sentence_separator;

        return output_buffer.str();
    }
    std::string serialize_fragmentation_flags() {
        std::ostringstream output_buffer;

        output_buffer << "fragment [ " << serialize_vector_by_string(this->fragmentation_flags, " ")
                      << " ]" << sentence_separator;

        return output_buffer.str();
    }

    std::string serialize_tcp_flags() {
        std::ostringstream output_buffer;

        output_buffer << "tcp-flags [ " << serialize_vector_by_string(this->tcp_flags, " ") << " ]"
                      << sentence_separator;

        return output_buffer.str();
    }

    std::string serialize_source_subnet() {
        return "source " + convert_subnet_to_string(this->source_subnet) + sentence_separator;
    }

    std::string serialize_destination_subnet() {
        return "destination " + convert_subnet_to_string(this->destination_subnet) + sentence_separator;
    }

    // More details regarding format: https://github.com/Exa-Networks/exabgp/blob/master/qa/conf/api-flow.run
    // https://plus.google.com/+ThomasMangin/posts/bL6w16BXcJ4
    // This format is INCOMPATIBLE with ExaBGP v3, please be careful!
    std::string serialize_single_line_exabgp_v4_configuration() {
        this->enabled_indents = false;
        this->enble_block_headers = false;
        sentence_separator = " ";

        return "flow route " + this->serialize_match() + this->serialize_then();

        sentence_separator = ";";
        this->enabled_indents = true;
        this->enble_block_headers = true;
    }

    std::string serialize_complete_exabgp_configuration() {
        std::ostringstream buffer;

        buffer << "neighbor 127.0.0.1 {"
               << "\n"
               << four_spaces << "router-id 1.2.3.4;"
               << "\n"
               << four_spaces << "local-address 127.0.0.1;"
               << "\n"
               << four_spaces << "local-as 1;"
               << "\n"
               << four_spaces << "peer-as 1;"
               << "\n"
               << four_spaces << "group-updates false;"
               << "\n\n";

        buffer << four_spaces << "family {"
               << "\n"
               << four_spaces << four_spaces << "ipv4 flow;"
               << "\n"
               << four_spaces << four_spaces << "ipv6 flow;"
               << "\n"
               << four_spaces << "}"
               << "\n";

        buffer << "flow {"
               << "\n";
        buffer << this->serialize();
        buffer << "}"
               << "\n";

        buffer << "}"
               << "\n";

        return buffer.str();
    }

    std::string serialize() {
        std::ostringstream buffer;

        buffer << "route {";

        if (enabled_indents) {
            buffer << "\n";
        }

        buffer << this->serialize_match();
        buffer << this->serialize_then();

        if (enabled_indents) {
            buffer << "\n";
        }

        buffer << "}";

        if (enabled_indents) {
            buffer << "\n";
        }

        return buffer.str();
    }

    std::string serialize_match() {
        std::ostringstream buffer;

        if (enabled_indents) {
            buffer << four_spaces;
        }

        if (enble_block_headers) {
            buffer << "match {";
        }

        if (enabled_indents) {
            buffer << "\n";
        }

        // Match block
        if (this->source_subnet_used) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << serialize_source_subnet();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        if (this->destination_subnet_used) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << serialize_destination_subnet();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        if (!this->protocols.empty()) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << this->serialize_protocols();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        // If we have TCP in protocols list explicitly, we add flags
        if (find(this->protocols.begin(), this->protocols.end(), FLOW_SPEC_PROTOCOL_TCP) !=
            this->protocols.end()) {

            if (!this->tcp_flags.empty()) {
                if (enabled_indents) {
                    buffer << four_spaces << four_spaces;
                }

                buffer << this->serialize_tcp_flags();

                if (enabled_indents) {
                    buffer << "\n";
                }
            }
        }

        if (!this->source_ports.empty()) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << this->serialize_source_ports();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        if (!this->destination_ports.empty()) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << this->serialize_destination_ports();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        if (!this->packet_lengths.empty()) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << this->serialize_packet_lengths();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        if (!this->fragmentation_flags.empty()) {
            if (enabled_indents) {
                buffer << four_spaces << four_spaces;
            }

            buffer << this->serialize_fragmentation_flags();

            if (enabled_indents) {
                buffer << "\n";
            }
        }

        // Match block end
        if (enabled_indents) {
            buffer << four_spaces;
        }

        if (enble_block_headers) {
            buffer << "}";
        }

        return buffer.str();
    }

    std::string serialize_then() {
        std::ostringstream buffer;

        if (enabled_indents) {
            buffer << "\n" << four_spaces;
        }

        if (enble_block_headers) {
            buffer << "then {";
        }

        if (enabled_indents) {
            buffer << "\n";
            buffer << four_spaces << four_spaces;
        }

        // Set same sentence separator as in main class
        this->action.set_sentence_separator(this->sentence_separator);

        buffer << this->action.serialize();

        if (enabled_indents) {
            buffer << "\n";
            buffer << four_spaces;
        }

        if (enble_block_headers) {
            buffer << "}";
        }

        return buffer.str();
    }

    private:
    std::string four_spaces;
    bool enabled_indents;
    bool enble_block_headers;
    std::string sentence_separator;
};

void exabgp_flow_spec_rule_ban_manage(std::string action, flow_spec_rule_t flow_spec_rule);

bool read_bgp_community_from_string(std::string community_as_string, bgp_community_attribute_element_t& bgp_community_attribute_element);
bool is_bgp_community_valid(std::string community_as_string);
