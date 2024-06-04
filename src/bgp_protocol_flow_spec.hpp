#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "dynamic_binary_buffer.hpp"
#include "fast_library.hpp"
#include "fastnetmon_networks.hpp"

#include <boost/serialization/nvp.hpp>

#include "iana_ip_protocols.hpp"

#include "bgp_protocol.hpp"

class bgp_flow_spec_action_t;


// This structure stores TCP flags in very human friendly way
// It could store multiple enabled flags in same time
class flow_spec_tcp_flagset_t {
    public:
    bool syn_flag = false;
    bool ack_flag = false;
    bool fin_flag = false;
    bool psh_flag = false;
    bool rst_flag = false;
    bool urg_flag = false;

    // Do we have least one flag enabled?
    bool we_have_least_one_flag_enabled() const {
        return syn_flag || fin_flag || urg_flag || ack_flag || psh_flag || rst_flag;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "syn: " << syn_flag << " "
               << "ack: " << ack_flag << " "
               << "fin: " << fin_flag << " "
               << "psh: " << psh_flag << " "
               << "rst: " << rst_flag << " "
               << "urg: " << urg_flag;

        return buffer.str();
    }

    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(syn_flag);
        ar& BOOST_SERIALIZATION_NVP(ack_flag);
        ar& BOOST_SERIALIZATION_NVP(fin_flag);
        ar& BOOST_SERIALIZATION_NVP(psh_flag);
        ar& BOOST_SERIALIZATION_NVP(rst_flag);
        ar& BOOST_SERIALIZATION_NVP(urg_flag);
    }
};

bool operator==(const flow_spec_tcp_flagset_t& lhs, const flow_spec_tcp_flagset_t& rhs);
bool operator!=(const flow_spec_tcp_flagset_t& lhs, const flow_spec_tcp_flagset_t& rhs);

// All possible values for BGP Flow Spec fragmentation field
enum class flow_spec_fragmentation_types_t {
    FLOW_SPEC_DONT_FRAGMENT,
    FLOW_SPEC_IS_A_FRAGMENT,
    FLOW_SPEC_FIRST_FRAGMENT,
    FLOW_SPEC_LAST_FRAGMENT,
    // Well, this entity does not exist in RFC at all. It was addition from ExaBGP
    FLOW_SPEC_NOT_A_FRAGMENT,
};

// Flow spec actions
enum class bgp_flow_spec_action_types_t {
    FLOW_SPEC_ACTION_DISCARD,
    FLOW_SPEC_ACTION_ACCEPT,
    FLOW_SPEC_ACTION_RATE_LIMIT,
    FLOW_SPEC_ACTION_REDIRECT,
    FLOW_SPEC_ACTION_MARK
};



bool read_flow_spec_action_type_from_string(const std::string& string_form, bgp_flow_spec_action_types_t& action_type);
std::string serialize_action_type(const bgp_flow_spec_action_types_t& action_type);

class bgp_flow_spec_action_t {
    public:
    void set_type(bgp_flow_spec_action_types_t action_type) {
        this->action_type = action_type;
    }

    bgp_flow_spec_action_types_t get_type() const {
        return this->action_type;
    }

    void set_rate_limit(unsigned int rate_limit) {
        this->rate_limit = rate_limit;
    }

    unsigned int get_rate_limit() const {
        return this->rate_limit;
    }

    uint16_t get_redirect_as() const {
        return redirect_as;
    }

    uint32_t get_redirect_value() const {
        return redirect_value;
    }

    void set_redirect_as(uint16_t value) {
        redirect_as = value;
    }
    
    void set_redirect_value(uint32_t value) {
        redirect_value = value;
    }


    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(action_type);
        ar& BOOST_SERIALIZATION_NVP(rate_limit);
        ar& BOOST_SERIALIZATION_NVP(redirect_as);
        ar& BOOST_SERIALIZATION_NVP(redirect_value);
    }

    private:
    bgp_flow_spec_action_types_t action_type = bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_ACCEPT;
    unsigned int rate_limit                  = 0;

    // Values for redirect
    uint16_t redirect_as = 0;
    uint32_t redirect_value = 0;
};

bool operator==(const bgp_flow_spec_action_t& lhs, const bgp_flow_spec_action_t& rhs);
bool operator!=(const bgp_flow_spec_action_t& lhs, const bgp_flow_spec_action_t& rhs);

// We do not use < and > operators at all, sorry
class flow_spec_rule_t {
    public:
    // This operation is very heavy, it may crash in case of entropy shortage and it actually happened to our customer
    // And we must not do them in constructors as it causes lots of side effects and slows down all things
    bool generate_uuid() {
        boost::uuids::random_generator gen;

        try {
            announce_uuid = gen();
        } catch (...) {
            return false;
        }

        return true;
    }

    void set_source_subnet_ipv4(const subnet_cidr_mask_t& source_subnet) {
        this->source_subnet_ipv4      = source_subnet;
        this->source_subnet_ipv4_used = true;
    }

    void set_source_subnet_ipv6(const subnet_ipv6_cidr_mask_t& source_subnet) {
        this->source_subnet_ipv6      = source_subnet;
        this->source_subnet_ipv6_used = true;
    }

    void set_destination_subnet_ipv4(const subnet_cidr_mask_t& destination_subnet) {
        this->destination_subnet_ipv4      = destination_subnet;
        this->destination_subnet_ipv4_used = true;
    }

    void set_destination_subnet_ipv6(const subnet_ipv6_cidr_mask_t& destination_subnet) {
        this->destination_subnet_ipv6      = destination_subnet;
        this->destination_subnet_ipv6_used = true;
    }

    void set_agent_subnet(subnet_cidr_mask_t subnet_param) {
        this->agent_subnet      = subnet_param;
        this->agent_subnet_used = true;
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

    void add_vlan(uint16_t vlan) {
        this->vlans.push_back(vlan);
    }

    void add_ipv4_nexthop(uint32_t ip) {
        this->ipv4_nexthops.push_back(ip);
    }

    void add_protocol(ip_protocol_t protocol) {
        this->protocols.push_back(protocol);
    }

    void add_ttl(uint8_t ttl) {
	 this->ttls.push_back(ttl);
    }

    void add_fragmentation_flag(flow_spec_fragmentation_types_t flag) {
        this->fragmentation_flags.push_back(flag);
    }

    void add_tcp_flagset(flow_spec_tcp_flagset_t flag) {
        this->tcp_flags.push_back(flag);
    }

    void set_action(bgp_flow_spec_action_t action) {
        this->action = action;
    }

    bgp_flow_spec_action_t get_action() const {
        return this->action;
    }

    std::string get_announce_uuid_as_string() const {
        return boost::uuids::to_string(announce_uuid);
    }

    template <class Archive> void serialize(Archive& ar, [[maybe_unused]] const unsigned int version) {
        ar& BOOST_SERIALIZATION_NVP(source_subnet_ipv4);
        ar& BOOST_SERIALIZATION_NVP(source_subnet_ipv4_used);

        ar& BOOST_SERIALIZATION_NVP(source_subnet_ipv6);
        ar& BOOST_SERIALIZATION_NVP(source_subnet_ipv6_used);

        ar& BOOST_SERIALIZATION_NVP(destination_subnet_ipv4);
        ar& BOOST_SERIALIZATION_NVP(destination_subnet_ipv4_used);

        ar& BOOST_SERIALIZATION_NVP(destination_subnet_ipv6);
        ar& BOOST_SERIALIZATION_NVP(destination_subnet_ipv6_used);

        ar& BOOST_SERIALIZATION_NVP(agent_subnet);
        ar& BOOST_SERIALIZATION_NVP(agent_subnet_used);

        ar& BOOST_SERIALIZATION_NVP(source_ports);
        ar& BOOST_SERIALIZATION_NVP(destination_ports);
        ar& BOOST_SERIALIZATION_NVP(packet_lengths);
        ar& BOOST_SERIALIZATION_NVP(vlans);
	ar& BOOST_SERIALIZATION_NVP(ttls);
        ar& BOOST_SERIALIZATION_NVP(ipv4_nexthops);

        ar& BOOST_SERIALIZATION_NVP(protocols);
        ar& BOOST_SERIALIZATION_NVP(fragmentation_flags);

        ar& BOOST_SERIALIZATION_NVP(tcp_flags);
        ar& BOOST_SERIALIZATION_NVP(set_match_bit_for_tcp_flags);
        ar& BOOST_SERIALIZATION_NVP(set_match_bit_for_fragmentation_flags);

        ar& BOOST_SERIALIZATION_NVP(action);
        ar& BOOST_SERIALIZATION_NVP(announce_uuid);
    }

    // Source prefix
    subnet_cidr_mask_t source_subnet_ipv4;
    bool source_subnet_ipv4_used = false;

    subnet_ipv6_cidr_mask_t source_subnet_ipv6;
    bool source_subnet_ipv6_used = false;

    // Destination prefix
    subnet_cidr_mask_t destination_subnet_ipv4;
    bool destination_subnet_ipv4_used = false;

    subnet_ipv6_cidr_mask_t destination_subnet_ipv6;
    bool destination_subnet_ipv6_used = false;

    // Agent subnet
    subnet_cidr_mask_t agent_subnet;
    bool agent_subnet_used = false;

    std::vector<uint16_t> source_ports;
    std::vector<uint16_t> destination_ports;

    // It's total IP packet length (excluding Layer 2 but including IP header)
    // https://datatracker.ietf.org/doc/html/rfc5575#section-4
    std::vector<uint16_t> packet_lengths;

    // This one is an non standard extension for our own purposes
    std::vector<uint16_t> vlans;

    // This one is an non standard extension for our own purposes
    std::vector<uint8_t> ttls;

    // IPv4 next hops for https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect-ip-01
    std::vector<uint32_t> ipv4_nexthops ;

    std::vector<ip_protocol_t> protocols;
    std::vector<flow_spec_fragmentation_types_t> fragmentation_flags;

    std::vector<flow_spec_tcp_flagset_t> tcp_flags;

    // By default we do not use match bit for TCP flags when encode them to Flow Spec NLRI
    // But in some cases it could be really useful
    bool set_match_bit_for_tcp_flags = false;

    // By default we do not use match bit for fragmentation flags when encode them to Flow Spec NLRI
    // But in some cases (Huawei) it could be useful
    bool set_match_bit_for_fragmentation_flags = false;

    bgp_flow_spec_action_t action;
    boost::uuids::uuid announce_uuid{};
};

bool operator==(const flow_spec_rule_t& lhs, const flow_spec_rule_t& rhs);
bool operator!=(const flow_spec_rule_t& lhs, const flow_spec_rule_t& rhs);

bool read_flow_spec_from_json_to_native_format(const std::string& json_encoded_flow_spec, flow_spec_rule_t& flow_spec_rule, bool require_action);
bool encode_flow_spec_to_json(const flow_spec_rule_t& flow_spec_rule, std::string& json_encoded_flow_spec, bool add_uuid);
bool decode_native_flow_spec_announce_from_binary_encoded_atributes(std::vector<dynamic_binary_buffer_t> binary_attributes,
                                                                    flow_spec_rule_t& flow_spec_rule);

bool encode_bgp_flow_spec_action_as_extended_attribute(const bgp_flow_spec_action_t& bgp_flow_spec_action,
                                                       dynamic_binary_buffer_t& extended_attributes_as_binary_array);

// It's format of redirect target. So called route target community. Official spec RFC5575 is pretty vague about it: 
// https://datatracker.ietf.org/doc/html/rfc4360#section-4
// But new BGP Flow Spec clarifies it as https://datatracker.ietf.org/doc/html/rfc8955#name-rt-redirect-rt-redirect-sub
class __attribute__((__packed__)) redirect_2_octet_as_4_octet_value_t {
    // We must not access these fields directly as it requires explicit byte order conversion
    private:
    uint16_t as = 0;
    uint32_t value = 0;

public:
    uint16_t get_as_host_byte_order() const {
        return fast_ntoh(as);
    }

    uint32_t get_value_host_byte_order() const {
        return fast_ntoh(value);
    }
 
   std::string print() const {
        std::stringstream buffer;

        buffer << "as: " << get_as_host_byte_order() << " "
               << "value: " << get_value_host_byte_order() << " ";

        return buffer.str();
    }

};

static_assert(sizeof(redirect_2_octet_as_4_octet_value_t) == 6,
              "Bad size for redirect_2_octet_as_4_octet_value_t");

// More details at https://tools.ietf.org/html/rfc5575 page 6
class __attribute__((__packed__)) bgp_flow_spec_operator_byte_t {
    public:
    uint8_t equal : 1 = 0, greater_than : 1 = 0, less_than : 1 = 0, reserved : 1 = 0, bit_shift_len : 2 = 0,
                    and_bit : 1 = 0, end_of_list : 1 = 0;

    void set_equal_bit() {
        equal = 1;
    }

    void set_greater_than_bit() {
        greater_than = 1;
    }

    void set_less_than_bit() {
        less_than = 1;
    }

    void set_and_bit() {
        and_bit = 1;
    }

    void set_end_of_list_bit() {
        end_of_list = 1;
    }

    bool set_length_in_bytes(uint32_t byte_length) {
        // We could set only for numbers which are pow of 2
        if (byte_length == 1) {
            bit_shift_len = 0;
        } else if (byte_length == 2) {
            bit_shift_len = 1;
        } else if (byte_length == 4) {
            bit_shift_len = 2;
        } else {
            logger << log4cpp::Priority::ERROR << "Could not calculate log2 for " << byte_length;
            return false;
        }

        return true;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "end of list: " << uint32_t(end_of_list) << " "
               << "and_bit: " << uint32_t(and_bit) << " "
               << "bit_shift_len: " << uint32_t(bit_shift_len) << " "
               << "reserved: " << uint32_t(reserved) << " "
               << "less_than: " << uint32_t(less_than) << " "
               << "greater_than: " << uint32_t(greater_than) << " "
               << "equal: " << uint32_t(equal);

        return buffer.str();
    }

    // Real value evaluated as 1 << bit_shift_len
    uint32_t get_value_length() {
        return 1 << bit_shift_len;
    }
};

// Here we store multiple enumerable values for flow spec protocol (ports,
// protocols and other)
class flow_spec_enumerable_lement {
    public:
    uint8_t one_byte_value  = 0;
    uint16_t two_byte_value = 0;

    // Could be only 1 or 2 bytes
    uint32_t value_length = 0;
    bgp_flow_spec_operator_byte_t operator_byte{};
};

typedef std::vector<flow_spec_enumerable_lement> multiple_flow_spec_enumerable_items_t;

bool read_one_or_more_values_encoded_with_operator_byte(uint8_t* start,
                                                        uint8_t* global_end,
                                                        uint32_t& readed_bytes,
                                                        multiple_flow_spec_enumerable_items_t& multiple_flow_spec_enumerable_items);
std::string get_flow_spec_type_name_by_number(uint8_t flow_spec_type);
std::string get_bgp_attribute_name_by_number(uint8_t bgp_attribute_type);
bool flow_spec_decode_nlri_value(uint8_t* data_ptr, uint32_t data_length, flow_spec_rule_t& flow_spec_rule);

class __attribute__((__packed__)) bgp_flow_spec_fragmentation_entity_t {
    public:
    uint8_t dont_fragment : 1 = 0, is_fragment : 1 = 0, first_fragment : 1 = 0, last_fragment : 1 = 0, reserved : 4 = 0;

    std::string print() const {
        std::stringstream buffer;

        buffer << "reserved: " << uint32_t(reserved) << " "
               << "last_fragment: " << uint32_t(last_fragment) << " "
               << "first_fragment: " << uint32_t(first_fragment) << " "
               << "is_fragment: " << uint32_t(is_fragment) << " "
               << "dont_fragment: " << uint32_t(dont_fragment);

        return buffer.str();
    }
};

static_assert(sizeof(bgp_flow_spec_fragmentation_entity_t) == 1, "Broken size for bgp_flow_spec_fragmentation_entity_t");

// More details at https://tools.ietf.org/html/rfc5575#page-9
// We use this version of operator byte for TCP flags and for fragmentation flags
class __attribute__((__packed__)) bgp_flow_spec_bitmask_operator_byte_t {
    public:
    uint8_t match_bit : 1 = 0, not_bit : 1 = 0, reserved2 : 1 = 0, reserved1 : 1 = 0, bit_shift_len : 2 = 0,
                        and_bit : 1 = 0, end_of_list : 1 = 0;

    bgp_flow_spec_bitmask_operator_byte_t() {
        memset(this, 0, sizeof(*this));
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "end of list: " << uint32_t(end_of_list) << " "
               << "and_bit: " << uint32_t(and_bit) << " "
               << "bit_shift_len: " << uint32_t(bit_shift_len) << " "
               << "reserved1: " << uint32_t(reserved1) << " "
               << "reserved2: " << uint32_t(reserved2) << " "
               << "not_bit: " << uint32_t(not_bit) << " "
               << "match_bit: " << uint32_t(match_bit);

        return buffer.str();
    }

    void set_not_bit() {
        not_bit = 1;
    }

    void set_and_bit() {
        and_bit = 1;
    }

    void set_match_bit() {
        match_bit = 1;
    }

    void set_end_of_list_bit() {
        end_of_list = 1;
    }

    bool set_length_in_bytes(uint32_t byte_length) {
        // We could set only for numbers which are pow of 2
        if (byte_length == 1) {
            bit_shift_len = 0;
        } else if (byte_length == 2) {
            bit_shift_len = 1;
        } else if (byte_length == 4) {
            bit_shift_len = 2;
        } else {
            logger << log4cpp::Priority::WARN << "Could not calculate log2 for " << byte_length;
            return false;
        }

        return true;
    }

    // Real value evaluated as 1 << bit_shift_len
    uint32_t get_value_length() {
        return 1 << bit_shift_len;
    }
};

// We have two ways to encode TCP flags - one byte and two byte

// This is extracted some piece of code from: tcp_header_t /
// network_data_structures
class __attribute__((__packed__)) bgp_flowspec_two_byte_encoded_tcp_flags_t {
    public:
    uint16_t fin : 1 = 0, syn : 1 = 0, rst : 1 = 0, psh : 1 = 0, ack : 1 = 0, urg : 1 = 0, ece : 1 = 0, cwr : 1 = 0,
                   ns : 1 = 0, reserved : 3 = 0, data_offset : 4 = 0;
};

static_assert(sizeof(bgp_flowspec_two_byte_encoded_tcp_flags_t) == 2, "Bad size for bgp_flowspec_two_byte_encoded_tcp_flags_t");

class __attribute__((__packed__)) bgp_flowspec_one_byte_byte_encoded_tcp_flags_t {
    public:
    // Just drop 8 bytes from bgp_flowspec_two_byte_encoded_tcp_flags
    uint8_t fin : 1 = 0, syn : 1 = 0, rst : 1 = 0, psh : 1 = 0, ack : 1 = 0, urg : 1 = 0, ece : 1 = 0, cwr : 1 = 0;

    std::string print() const {
        std::stringstream buffer;

        buffer << "cwr: " << uint32_t(cwr) << " "
               << "ece: " << uint32_t(ece) << " "
               << "urg: " << uint32_t(urg) << " "
               << "ack: " << uint32_t(ack) << " "
               << "psh: " << uint32_t(psh) << " "
               << "rst: " << uint32_t(rst) << " "
               << "syn: " << uint32_t(syn) << " "
               << "fin: " << uint32_t(fin);

        return buffer.str();
    }
};

static_assert(sizeof(bgp_flowspec_one_byte_byte_encoded_tcp_flags_t) == 1, "Bad size for ");

// BGP flow spec entity numbers
enum FLOW_SPEC_ENTITY_TYPES : uint8_t {
    FLOW_SPEC_ENTITY_DESTINATION_PREFIX = 1,
    FLOW_SPEC_ENTITY_SOURCE_PREFIX      = 2,
    FLOW_SPEC_ENTITY_IP_PROTOCOL        = 3,
    FLOW_SPEC_ENTITY_PORT               = 4,
    FLOW_SPEC_ENTITY_DESTINATION_PORT   = 5,
    FLOW_SPEC_ENTITY_SOURCE_PORT        = 6,
    FLOW_SPEC_ENTITY_ICMP_TYPE          = 7,
    FLOW_SPEC_ENTITY_ICMP_CODE          = 8,
    FLOW_SPEC_ENTITY_TCP_FLAGS          = 9,
    FLOW_SPEC_ENTITY_PACKET_LENGTH      = 10,
    FLOW_SPEC_ENTITY_DSCP               = 11,
    FLOW_SPEC_ENTITY_FRAGMENT           = 12,
};

/*
    Here we have custom NLRI encoding
   (https://tools.ietf.org/html/rfc4760#section-5.1.3):
    +---------------------------------------------------------+
    | Address Family Identifier (2 octets)                    |
    +---------------------------------------------------------+
    | Subsequent Address Family Identifier (1 octet)          |
    +---------------------------------------------------------+
    | Length of Next Hop Network Address (1 octet)            |
    +---------------------------------------------------------+
    | Network Address of Next Hop (variable)                  |
    +---------------------------------------------------------+
    | Reserved (1 octet)                                      |
    +---------------------------------------------------------+
    | Network Layer Reachability Information (variable)       |
    +---------------------------------------------------------+
*/
class __attribute__((__packed__)) bgp_mp_ext_flow_spec_header_t {
    public:
    uint16_t afi_identifier = AFI_IP;
    uint8_t safi_identifier = SAFI_FLOW_SPEC_UNICAST;
    // For BGP Flow spec we are using blank next hop because it's useless for us
    // now
    uint8_t length_of_next_hop = 0;
    // Here we have blank next hop. Or haven't ... :)
    uint8_t reserved = 0;
    // Here we have NLRI information

    void network_to_host_byte_order() {
        afi_identifier = ntohs(afi_identifier);
    }

    void host_byte_order_to_network_byte_order() {
        afi_identifier = htons(afi_identifier);
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "afi_identifier: " << uint32_t(afi_identifier) << " "
               << "safi_identifier: " << uint32_t(safi_identifier) << " "
               << "length_of_next_hop: " << uint32_t(length_of_next_hop) << " "
               << "reserved: " << uint32_t(reserved);

        return buffer.str();
    }
};

class __attribute__((__packed__)) bgp_extended_community_element_flow_spec_rate_t {
    public:
    uint8_t type_hight = EXTENDED_COMMUNITY_TRANSITIVE_EXPEREMENTAL;
    uint8_t type_low   = FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_TRAFFIC_RATE;

    // This bytes are meaningless and should not processed at all by receiver side
    uint8_t value[2] = { 0, 0 };
    float rate_limit = 0;

    void host_byte_order_to_network_byte_order() {
        // Have you ever do little endian to big endian conversion for float? We do!
        float rate_limit_copy = rate_limit;

        logger << log4cpp::Priority::DEBUG << "Original rate: " << rate_limit;

        // We do not use pointer to field structure here because it may cause alignment issues and gcc yells on it:
        // warning: taking address of packed member of ... may result in an unaligned pointer value [-Waddress-of-packed-member]
        uint32_t* integer_pointer = (uint32_t*)&rate_limit_copy;

        logger << log4cpp::Priority::DEBUG << "Integer part of rate: " << *integer_pointer;

        *integer_pointer = htonl(*integer_pointer);

        // Overwrite original value
        this->rate_limit = rate_limit_copy;

        logger << log4cpp::Priority::DEBUG << "Network byte order encoded rate limit: " << rate_limit;
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "type hight: " << uint32_t(type_hight) << " "
               << "type low: " << uint32_t(type_low) << " "
               << "value raw: " << print_binary_string_as_hex_with_leading_0x(value, sizeof(value));

        return buffer.str();
    }
};

static_assert(sizeof(bgp_extended_community_element_flow_spec_rate_t) == 8,
              "Bad size for bgp_extended_community_element_flow_spec_rate_t");

class __attribute__((__packed__)) bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value_t_t {
    public:
    uint8_t type_hight = EXTENDED_COMMUNITY_TRANSITIVE_EXPEREMENTAL;
    uint8_t type_low   = FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_REDIRECT_AS_TWO_BYTE;

    // 6 octet value
    uint16_t redirect_as = 0;
    uint32_t redirect_value = 0;

    void set_redirect_as(uint16_t value) {
        redirect_as = fast_hton(value);
    }

    void set_redirect_value(uint32_t value) {
        redirect_value = fast_hton(value);
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "type hight: " << uint32_t(type_hight) << " "
               << "type low: " << uint32_t(type_low) << " "
               << "redirect_as: " << redirect_as << " "
               << "redirect_value: " << redirect_value;

        return buffer.str();
    }
};

static_assert(sizeof(bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value_t_t) == 8,
              "Bad size for bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value_t_t");

// This structure encodes Flow Spec next hop IPv4
class __attribute__((__packed__)) bgp_extended_community_element_flow_spec_ipv4_next_hop_t {
    public:
    uint8_t type_hight = EXTENDED_COMMUNITY_TRANSITIVE_IPV4_ADDRESS_SPECIFIC;
    uint8_t type_low   = BGP_IPV4_EXTENDED_COMMUNITY_SUBTYPE_FLOW_SPEC_REDIRECT_IPv4;

    // Actual value of IPv4 next hop
    uint32_t next_hop_ipv4 = 0;

    // In this field we can set mirror flag to make packet copies
    uint16_t local_administrator = 0;

    void host_byte_order_to_network_byte_order() {
    }

    std::string print() const {
        std::stringstream buffer;

        buffer << "type hight: " << uint32_t(type_hight) << " "
               << "type low: " << uint32_t(type_low) << " "
               << "nexthop: " << next_hop_ipv4 << " "
               << "local administrator: " << local_administrator;

        return buffer.str();
    }
};


static_assert(sizeof(bgp_extended_community_element_flow_spec_ipv4_next_hop_t) == 8,
              "Bad size for bgp_extended_community_element_flow_spec_ipv4_next_hop_t");

static_assert(sizeof(bgp_flow_spec_bitmask_operator_byte_t) == 1, "Bad size for bgp_flow_spec_bitmask_operator_byte_t");
static_assert(sizeof(bgp_flow_spec_operator_byte_t) == 1, "Bad size for bgp_flow_spec_operator_byte_t");

bool read_flow_spec_tcp_flags_from_strig(const std::string& string_form, flow_spec_tcp_flagset_t& tcp_flagset);
bool read_flow_spec_fragmentation_types_from_string(const std::string& string_form, flow_spec_fragmentation_types_t& fragment_flag);
bool valid_port(int32_t port);
bool encode_flow_spec_to_json_raw(const flow_spec_rule_t& flow_spec_rule, bool add_uuid, nlohmann::json& flow_json);
std::string flow_spec_fragmentation_flags_to_string(flow_spec_fragmentation_types_t const& fragment_flag);
std::string flow_spec_tcp_flagset_to_string(flow_spec_tcp_flagset_t const& tcp_flagset);
