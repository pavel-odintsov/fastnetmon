#ifndef BGP_FLOW_SPEC_H
#define BGP_FLOW_SPEC_H

#include <stdint.h>
#include <string>
#include <vector>

#include "fastnetmon_types.h"
#include "fast_library.h"

// Helper for serialization by comma
template <typename T> 
std::string serialize_vector_by_string(const std::vector<T> vect, std::string delimiter) {
    std::ostringstream output_buffer;

    std::copy(vect.begin(), vect.end() - 1, std::ostream_iterator<T>(output_buffer, delimiter.c_str()));
    output_buffer << vect.back();

    return output_buffer.str();
}   

template <typename T>
std::string serialize_vector_by_string_with_prefix(const std::vector<T> vect, std::string delimiter, std::string prefix) {
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

// Enable custom casts from our own types
std::ostream &operator<<(std::ostream &os, bgp_flow_spec_protocol_t const &protocol) {
    if (protocol == FLOW_SPEC_PROTOCOL_UDP) { 
        return os << "udp";
    } else if (protocol == FLOW_SPEC_PROTOCOL_TCP) {
        return os << "tcp";
    } else if (protocol == FLOW_SPEC_PROTOCOL_ICMP) {
        return os << "icmp";
    }
}

std::ostream &operator<<(std::ostream &os, flow_spec_fragmentation_types_t const &fragment_flag) {
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
    }
}

class bgp_flow_spec_action_t {
    public:
        bgp_flow_spec_action_t() {
           this->action_type = FLOW_SPEC_ACTION_ACCEPT; 
           this->rate_limit = 9600;
        }

        void set_type(bgp_flow_spec_action_types_t action_type) {
            this->action_type = action_type;
        }

        void set_rate_limit(unsigned int rate_limit) {
            this->rate_limit = rate_limit;
        } 

        std::string serialize() {
            if (this->action_type == FLOW_SPEC_ACTION_ACCEPT) {
                return "accept;";
            } else if (this->action_type == FLOW_SPEC_ACTION_DISCARD) {
                return "discard;";
            } else if (this->action_type == FLOW_SPEC_ACTION_RATE_LIMIT) {
                return "rate-limit " + convert_int_to_string(this->rate_limit) + ";"; 
            }
        } 
    private:
        bgp_flow_spec_action_types_t action_type;
        unsigned int rate_limit;
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

        void set_source_subnet(subnet_t source_subnet) {
            this->source_subnet = source_subnet;
            this->source_subnet_used = true;
        }

        std::string serialize_source_subnet() {
            return convert_subnet_to_string(this->source_subnet);
        }

        std::string serialize_destination_subnet() {
            return convert_subnet_to_string(this->destination_subnet);
        }

        void set_destination_subnet(subnet_t destination_subnet) {
            this->destination_subnet = destination_subnet;
            this->destination_subnet_used = true;
        }

        void add_source_port(uint16_t source_port) {
            this->source_ports.push_back(source_port);
        }


        std::string serialize_source_ports() {
            std::ostringstream output_buffer;
            
            output_buffer << "source-port [ " << serialize_vector_by_string_with_prefix<uint16_t>(this->source_ports, ",", "=") << " ];";

            return output_buffer.str();
        }

        void add_destination_port(uint16_t destination_port) {
            this->destination_ports.push_back(destination_port);
        }

        std::string serialize_destination_ports() {
            std::ostringstream output_buffer;

            output_buffer << "destination-port [ " << serialize_vector_by_string_with_prefix<uint16_t>(this->destination_ports, " ", "=") << " ];";

            return output_buffer.str();
        }

        std::string serialize_packet_lengths() {
            std::ostringstream output_buffer;

            output_buffer << "packet-length [ " <<  serialize_vector_by_string_with_prefix<uint16_t>(this->packet_lengths, " ", "=")  << " ];";

            return output_buffer.str();
        } 

        void add_packet_length(uint16_t packet_length) {
            this->packet_lengths.push_back(packet_length);
        }

        void add_protocol(bgp_flow_spec_protocol_t protocol) {
            this->protocols.push_back(protocol);
        }

        std::string serialize_protocol() {
            std::ostringstream output_buffer;

            output_buffer << "protocol [ " <<  serialize_vector_by_string(this->protocols, " ")  << " ];";

            return output_buffer.str();
        }

        std::string serialize_fragmentation_flags() {
            std::ostringstream output_buffer;

            output_buffer << "fragment [ " <<  serialize_vector_by_string(this->fragmentation_flags, " ")  << " ];";

            return output_buffer.str();
        }

        /*
        std::string tcp_flags;
        bool tcp_flags_used;

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

        void set_action(bgp_flow_spec_action_t action) {
            this->action = action; 
        }
    protected:
        // Only IPv4 supported
        subnet_t source_subnet;
        bool source_subnet_used;

        subnet_t destination_subnet;
        bool destination_subnet_used;

        std::vector<uint16_t> source_ports;
        std::vector<uint16_t> destination_ports;
        std::vector<uint16_t> packet_lengths;
        std::vector<bgp_flow_spec_protocol_t> protocols;
        std::vector<flow_spec_fragmentation_types_t> fragmentation_flags;

        bgp_flow_spec_action_t action;

        bool sanity_check() {
            // check all fields for correctness! We SHOULD not announce weird flow spec
        }    
};

class exabgp_flow_spec_rule_t : public flow_spec_rule_t {
    public:
        std::string serialize() {
            std::ostringstream buffer;

            std::string four_spaces = "    ";
            buffer << "flow {\n" << four_spaces << "match {\n";

            // Match block
            if (this->source_subnet_used) {
                buffer <<  four_spaces << four_spaces << "source " << serialize_source_subnet() << ";\n";
            }

            if (this->destination_subnet_used) {
                buffer <<  four_spaces << four_spaces << "destination " << serialize_destination_subnet() << ";\n";
            }

            if (!this->protocols.empty()) {
                buffer <<  four_spaces << four_spaces << this->serialize_protocol() << "\n";
            }


            if (!this->source_ports.empty()) {
                buffer <<  four_spaces << four_spaces << this->serialize_source_ports() << "\n";
            }

            if (!this->destination_ports.empty()) {
                buffer <<  four_spaces << four_spaces << this->serialize_destination_ports() << "\n";
            }

            if (!this->packet_lengths.empty()) {
                buffer <<  four_spaces << four_spaces << this->serialize_packet_lengths() << "\n";
            }

            if (!this->fragmentation_flags.empty()) {
                buffer << four_spaces << four_spaces << this->serialize_fragmentation_flags() << "\n"; 
            }

            // Match block end

            buffer << four_spaces << "}";

            buffer << "\n" << four_spaces << "then {\n";

            buffer <<  four_spaces << four_spaces << this->action.serialize() << "\n"; 

            buffer << four_spaces << "}";
            buffer << "\n}\n"; 

            return buffer.str();
        }     
};

#endif
