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

#include "all_logcpp_libraries.hpp"

// Get log4cpp logger from main programme
extern log4cpp::Category& logger;

class bgp_attribute_origin;
class bgp_attribute_next_hop_ipv4;
class IPv4UnicastAnnounce;
class IPv6UnicastAnnounce;

bool decode_bgp_subnet_encoding_ipv4_raw(uint8_t* value, subnet_cidr_mask_t& extracted_prefix);
bool decode_bgp_subnet_encoding_ipv4(int len, uint8_t* value, subnet_cidr_mask_t& extracted_prefix, uint32_t& parsed_nlri_length);
uint32_t how_much_bytes_we_need_for_storing_certain_subnet_mask(uint8_t prefix_bit_length);
std::string get_bgp_attribute_name_by_number(uint8_t bgp_attribute_type);

enum BGP_PROTOCOL_MESSAGE_TYPES_UNTYPED : uint8_t {
    BGP_PROTOCOL_MESSAGE_OPEN         = 1,
    BGP_PROTOCOL_MESSAGE_UPDATE       = 2,
    BGP_PROTOCOL_MESSAGE_NOTIFICATION = 3,
    BGP_PROTOCOL_MESSAGE_KEEPALIVE    = 4,
};

// More details here https://tools.ietf.org/html/rfc4271#page-12
class __attribute__((__packed__)) bgp_message_header_t {
    public:
    uint8_t marker[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint16_t length    = 0;
    uint8_t type       = 0;

    void host_byte_order_to_network_byte_order() {
        length = htons(length);
    }
};

static_assert(sizeof(bgp_message_header_t) == 19, "Broken size for bgp_message_header_t");

// TODO: move to 
//
// https://www.ietf.org/rfc/rfc4271.txt pages 15 and 16
// https://github.com/osrg/gobgp/blob/d6148c75a30d87c3f8c1d0f68725127e4c5f3a65/packet/bgp.go#L3012
struct __attribute__((__packed__)) bgp_attribute_flags {
    uint8_t : 4, extended_length_bit : 1 = 0, partial_bit : 1 = 0, transitive_bit : 1 = 0, optional_bit : 1 = 0;

    bgp_attribute_flags(uint8_t flag_as_integer) {
        memcpy(this, &flag_as_integer, sizeof(flag_as_integer));
    }

    bgp_attribute_flags() {
        memset(this, 0, sizeof(*this));
    }

    void set_optional_bit(bool bit_value) {
        optional_bit = (int)bit_value;
    }

    void set_transitive_bit(bool bit_value) {
        transitive_bit = (int)bit_value;
    }

    void set_partial_bit(bool bit_value) {
        partial_bit = (int)bit_value;
    }

    void set_extended_length_bit(bool bit_value) {
        extended_length_bit = (int)bit_value;
    }

    bool get_optional_bit() {
        return optional_bit == 1 ? true : false;
    }

    bool get_transitive_bit() {
        return transitive_bit == 1 ? true : false;
    }

    bool get_partial_bit() {
        return partial_bit == 1 ? true : false;
    }

    bool get_extended_length_bit() {
        return extended_length_bit == 1 ? true : false;
    }

    std::string print() const {
        std::stringstream buf;

        buf << "optional: " << int(optional_bit) << " transitive: " << int(transitive_bit)
            << " partial_bit: " << int(partial_bit) << " extended_length_bit: " << int(extended_length_bit);

        return buf.str();
    }
};

class bgp_attibute_common_header_t {
    public:
    uint8_t attribute_flags         = 0;
    uint8_t attribute_type          = 0;
    uint32_t length_of_length_field = 0;
    uint32_t attribute_value_length = 0;
    uint32_t attribute_body_shift   = 0;
    // Just const value
    uint32_t attribute_flag_and_type_length = 2;

    std::string print() const {
        std::stringstream buffer;

        buffer << "attribute_flags: " << uint32_t(attribute_flags)
               << " "
               // << "attribute_pretty_flags: " <<
               // bgp_attribute_flags(attribute_flags).print() << " "
               << "attribute_type: " << uint32_t(attribute_type) << " "
               << "attribute_name: " << get_bgp_attribute_name_by_number(attribute_type) << " "
               << "length_of_length_field: " << length_of_length_field << " "
               << "attribute_value_length: " << attribute_value_length;

        return buffer.str();
    }

    // More user friendly form
    bool parse_raw_bgp_attribute_binary_buffer(dynamic_binary_buffer_t dynamic_binary_buffer) {
        return parse_raw_bgp_attribute((uint8_t*)dynamic_binary_buffer.get_pointer(), dynamic_binary_buffer.get_used_size());
    }

    bool parse_raw_bgp_attribute(uint8_t* value, size_t len) {
        if (len < attribute_flag_and_type_length or value == NULL) {
            logger << log4cpp::Priority::WARN << "Too short attribute. We need least two bytes here but get " << len << " bytes";
            return false;
        }

        // https://www.ietf.org/rfc/rfc4271.txt page 15
        attribute_flags = value[0];
        attribute_type  = value[1];

        bgp_attribute_flags attr_flags(attribute_flags);
        // attr_flags.print();

        length_of_length_field = 1;

        if (attr_flags.extended_length_bit == 1) {
            // When we have extended_length_bit we have two bytes for length
            // information
            // TODO: add support for this type of attributes
            // logger << log4cpp::Priority::WARN << "We haven't support for extended
            // length attributes.
            // Sorry!" <<
            // std::endl;
            length_of_length_field = 2;
        }

        if (len < attribute_flag_and_type_length + length_of_length_field) {
            logger << log4cpp::Priority::WARN << "Too short attribute because we need least "
                   << attribute_flag_and_type_length + length_of_length_field << " bytes";
            return false;
        }

        attribute_value_length = value[2];

        // logger << log4cpp::Priority::WARN << "Attribute type: " <<
        // int(attribute_type)         ;
        // logger << log4cpp::Priority::WARN << "Raw attribute length: " << len ;
        // logger << log4cpp::Priority::WARN << "Attribute internal length: " <<
        // int(attribute_value_length)
        //         ;

        uint32_t total_attribute_length = attribute_flag_and_type_length + length_of_length_field + attribute_value_length;

        // logger << log4cpp::Priority::WARN << "attribute_flag_and_type_length: "
        // <<
        // attribute_flag_and_type_length <<
        // std::endl
        //    << "length_of_length_field: " << length_of_length_field
        //    << "attribute_value_length: " << attribute_value_length         ;

        if (len < total_attribute_length) {
            logger << log4cpp::Priority::WARN << "Atrribute value length: " << total_attribute_length
                   << " length exceed whole packet length " << len;

            return false;
        }

        // Store shift to attribute payload
        attribute_body_shift = attribute_flag_and_type_length + length_of_length_field;

        return true;
    }
};

bool decode_nlri_ipv4(int len, uint8_t* value, subnet_cidr_mask_t& extracted_prefix);
bool decode_attribute(int len, char* value, IPv4UnicastAnnounce& unicast_ipv4_announce);
bool encode_bgp_subnet_encoding(const subnet_cidr_mask_t& prefix, dynamic_binary_buffer_t& buffer_result);
std::string get_origin_name_by_value(uint8_t origin_value);

const unsigned int AFI_IP                 = 1;
const unsigned int AFI_IP6                = 2;

const unsigned int SAFI_UNICAST           = 1;
const unsigned int SAFI_FLOW_SPEC_UNICAST = 133;

const unsigned int ipv4_unicast_route_family   = AFI_IP << 16 | SAFI_UNICAST;
const unsigned int ipv4_flow_spec_route_family = AFI_IP << 16 | SAFI_FLOW_SPEC_UNICAST;

const unsigned int ipv6_unicast_route_family   = AFI_IP6 << 16 | SAFI_UNICAST;
const unsigned int ipv6_flow_spec_route_family = AFI_IP6 << 16 | SAFI_FLOW_SPEC_UNICAST;

// http://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml
// https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#transitive
enum EXTENDED_COMMUNITY_TYPES_HIGHT_UNTYPED : uint8_t {
    // Transitive IPv4-Address-Specific Extended Community (Sub-Types are defined in the "Transitive IPv4-Address-Specific Extended Community Sub-Types" registry)
    EXTENDED_COMMUNITY_TRANSITIVE_IPV4_ADDRESS_SPECIFIC = 1, // 0x01

    // We are encoding attributes for BGP flow spec this way
    // Generic Transitive Experimental Use Extended Community
    EXTENDED_COMMUNITY_TRANSITIVE_EXPEREMENTAL = 128, // 0x80
};

// Subtypes for EXTENDED_COMMUNITY_TRANSITIVE_EXPEREMENTAL
// http://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml
// https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#transitive
enum EXTENDED_COMMUNITY_TYPES_LOW_FOR_COMMUNITY_TRANSITIVE_EXPEREMENTAL : uint8_t {
    FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_TRAFFIC_RATE         = 6,
    FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_TRAFFIC_ACTION       = 7,
    FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_REDIRECT_AS_TWO_BYTE = 8,
    FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_TRAFFIC_REMARKING    = 9,
};

enum BGP_ATTRIBUTES_TYPES : uint8_t {
    // https://www.ietf.org/rfc/rfc4271.txt from page 17
    BGP_ATTRIBUTE_ORIGIN           = 1,
    BGP_ATTRIBUTE_AS_PATH          = 2,
    BGP_ATTRIBUTE_NEXT_HOP         = 3,
    BGP_ATTRIBUTE_MULTI_EXIT_DISC  = 4,
    BGP_ATTRIBUTE_LOCAL_PREF       = 5,
    BGP_ATTRIBUTE_ATOMIC_AGGREGATE = 6,
    BGP_ATTRIBUTE_AGGREGATOR       = 7,
    // https://tools.ietf.org/html/rfc1997 from page 1
    BGP_ATTRIBUTE_COMMUNITY = 8,
    // https://tools.ietf.org/html/rfc4760 from page 2
    BGP_ATTRIBUTE_MP_REACH_NLRI = 14,
    // https://tools.ietf.org/html/rfc4360 from page 1
    BGP_ATTRIBUTE_EXTENDED_COMMUNITY = 16,
};

// https://www.ietf.org/rfc/rfc4271.txt from page 17
enum BGP_ORIGIN_TYPES : uint8_t { BGP_ORIGIN_IGP = 0, BGP_ORIGIN_EGP = 1, BGP_ORIGIN_INCOMPLETE = 2 };

// https://www.iana.org/assignments/bgp-extended-communities/bgp-extended-communities.xhtml#trans-ipv4
enum BGP_IPV4_EXTENDED_COMMUNITY_SUBTYPES_TRANSITIVE : uint8_t {
    BGP_IPV4_EXTENDED_COMMUNITY_SUBTYPE_FLOW_SPEC_REDIRECT_IPv4 = 0x0c,
};

// It's short MP reach NLRI header. We use it in case when we have non zero length for length_of_next_hop
// I use it only to decode/encode IPv6 annnounces
class __attribute__((__packed__)) bgp_mp_reach_short_header_t {
    public:
    uint16_t afi_identifier = AFI_IP6;
    uint8_t safi_identifier = SAFI_UNICAST;
    // According to https://www.ietf.org/rfc/rfc2545.txt we should set it to 16 for global IP addresses
    uint8_t length_of_next_hop = 16;

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
               << "length_of_next_hop: " << uint32_t(length_of_next_hop);

        return buffer.str();
    }
};

class __attribute__((__packed__)) bgp_attribute_community_t {
    public:
    bgp_attribute_community_t() {
        attribute_type = BGP_ATTRIBUTE_COMMUNITY;

        // Set attribute flags
        attribute_flags.set_transitive_bit(true);
        attribute_flags.set_partial_bit(false);
        attribute_flags.set_optional_bit(true);
        attribute_flags.set_extended_length_bit(false);
    }

    bgp_attribute_flags attribute_flags;
    uint8_t attribute_type = 0;

    // This variable store total size in bytes of all community elements (each
    // element should has
    // size 4 bytes)
    uint8_t attribute_length = 0;

    // Here we have multiple elements of type: bgp_community_attribute_element_t
};

// This is new extended communities:
// More details: https://tools.ietf.org/html/rfc4360
class __attribute__((__packed__)) bgp_extended_community_attribute_t {
    public:
    bgp_extended_community_attribute_t() {
        // Set attribute flags
        attribute_flags.set_transitive_bit(true);
        attribute_flags.set_partial_bit(false);
        attribute_flags.set_optional_bit(true);
        attribute_flags.set_extended_length_bit(false);
    }

    bgp_attribute_flags attribute_flags;
    uint8_t attribute_type = BGP_ATTRIBUTE_EXTENDED_COMMUNITY;

    // This variable store total size in bytes of all community elements. Each
    // community element has
    // size 8 bytes
    uint8_t attribute_length = 0;
    // Here we have multiple elements of type: bgp_extended_community_element_t
};

// BGP extended community attribute
class __attribute__((__packed__)) bgp_extended_community_element_t {
    public:
    uint8_t type_hight = 0;
    uint8_t type_low   = 0;

    // This data depends on implementation and values in type_* variables
    uint8_t value[6] = { 0, 0, 0, 0, 0, 0 };

    std::string print() const {
        std::stringstream buffer;

        buffer << "type hight: " << uint32_t(type_hight) << " "
               << "type low: " << uint32_t(type_low) << " "
               << "value raw: " << print_binary_string_as_hex_with_leading_0x(value, sizeof(value));

        return buffer.str();
    }
};

static_assert(sizeof(bgp_extended_community_element_t) == 8, "Bad size for bgp_extended_community_element_t");

// This is class for storing old style BGP communities which support only 16
// bit AS numbers
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

// With this attribute we are encoding different things (flow spec for example)
class __attribute__((__packed__)) bgp_attribute_multiprotocol_extensions_t {
    public:
    bgp_attribute_multiprotocol_extensions_t() {
        attribute_flags.set_transitive_bit(false);
        attribute_flags.set_optional_bit(true);

        attribute_flags.set_partial_bit(false);
        attribute_flags.set_extended_length_bit(false);
    }

    std::string print() const {
        std::stringstream buf;

        buf << attribute_flags.print() << "attribute type: " << int(attribute_type)
            << " attribute_length: " << int(attribute_length);

        return buf.str();
    }

    bgp_attribute_flags attribute_flags;
    uint8_t attribute_type   = BGP_ATTRIBUTE_MP_REACH_NLRI;
    uint8_t attribute_length = 0;
    // value has very complex format and we are encoding it with external code
};

class __attribute__((__packed__)) bgp_attribute_origin {
    public:
    bgp_attribute_origin() {
        // Set attribute flags
        attribute_flags.set_transitive_bit(true);

        attribute_flags.set_partial_bit(false);
        attribute_flags.set_optional_bit(false);
        attribute_flags.set_extended_length_bit(false);
    }

    std::string print() const {
        std::stringstream buf;

        buf << attribute_flags.print() << "attribute type: " << int(attribute_type)
            << " attribute_length: " << int(attribute_length) << " attribute_value: " << attribute_value;

        return buf.str();
    }

    bgp_attribute_flags attribute_flags;
    uint8_t attribute_type   = BGP_ATTRIBUTE_ORIGIN;
    uint8_t attribute_length = 1;
    uint8_t attribute_value  = (uint8_t)BGP_ORIGIN_INCOMPLETE;
};

class __attribute__((__packed__)) bgp_attribute_next_hop_ipv4 {
    public:
    bgp_attribute_next_hop_ipv4() {
        // Set attribute flags
        attribute_flags.set_transitive_bit(true);

        attribute_flags.set_partial_bit(false);
        attribute_flags.set_optional_bit(false);
        attribute_flags.set_extended_length_bit(false);
    }

    bgp_attribute_next_hop_ipv4(uint32_t next_hop) : bgp_attribute_next_hop_ipv4() {
        attribute_value = next_hop;
    }

    bgp_attribute_flags attribute_flags;
    uint8_t attribute_type   = BGP_ATTRIBUTE_NEXT_HOP;
    uint8_t attribute_length = 4;
    uint32_t attribute_value = 0;

    std::string print() const {
        std::stringstream buf;

        buf << attribute_flags.print() << "attribute type: " << int(attribute_type)
            << " attribute_length: " << int(attribute_length) << " attribute_value: " << attribute_value;

        return buf.str();
    }
};


class IPv4UnicastAnnounce {
    public:
    void set_withdraw(bool withdraw) {
        this->is_withdraw = withdraw;
    }

    bool get_withdraw() {
        return this->is_withdraw;
    }

    void set_next_hop(uint32_t next_hop) {
        this->next_hop = next_hop;
    }

    void set_prefix(subnet_cidr_mask_t prefix) {
        this->prefix = prefix;
    }

    void set_origin(BGP_ORIGIN_TYPES origin) {
        this->origin = origin;
    }

    uint32_t get_next_hop() {
        return next_hop;
    }

    subnet_cidr_mask_t get_prefix() {
        return this->prefix;
    }
    BGP_ORIGIN_TYPES get_origin() {
        return this->origin;
    }

    // Returns prefix in text form
    std::string get_prefix_in_cidr_form() {
        return convert_ip_as_uint_to_string(prefix.subnet_address) + "/" + std::to_string(prefix.cidr_prefix_length);
    }

    bool generate_nlri(dynamic_binary_buffer_t& buffer_result) const {
        return encode_bgp_subnet_encoding(this->prefix, buffer_result);
    }

    std::vector<dynamic_binary_buffer_t> get_attributes() const {
        /*
         *   The sender of an UPDATE message SHOULD order path attributes within
         *   the UPDATE message in ascending order of attribute type.  The
         *   receiver of an UPDATE message MUST be prepared to handle path
         *   attributes within UPDATE messages that are out of order.
         */

        bgp_attribute_origin origin_attr;

        // logger << log4cpp::Priority::WARN << "origin_attr: "          <<
        // origin_attr.print() <<
        // std::endl;

        bgp_attribute_next_hop_ipv4 next_hop_attr(next_hop);

        // logger << log4cpp::Priority::WARN << "next_hop_attr: "          <<
        // next_hop_attr.print() <<
        // std::endl;

        dynamic_binary_buffer_t origin_as_binary_array;
        origin_as_binary_array.set_maximum_buffer_size_in_bytes(sizeof(origin_attr));
        origin_as_binary_array.append_data_as_object_ptr(&origin_attr);

        dynamic_binary_buffer_t next_hop_as_binary_array;
        next_hop_as_binary_array.set_maximum_buffer_size_in_bytes(sizeof(next_hop_attr));
        next_hop_as_binary_array.append_data_as_object_ptr(&next_hop_attr);

        // TODO: remove ugly code with custom build of each vector
        if (community_list.empty()) {
            // Vector should be ordered in ascending order of attribute types
            return std::vector<dynamic_binary_buffer_t>{ origin_as_binary_array, next_hop_as_binary_array };
        } else {
            // We have communities
            bgp_attribute_community_t bgp_attribute_community;

            // Each record has this of 4 bytes
            bgp_attribute_community.attribute_length = community_list.size() * sizeof(bgp_community_attribute_element_t);
            uint32_t community_attribute_full_length = sizeof(bgp_attribute_community_t) + bgp_attribute_community.attribute_length;

            dynamic_binary_buffer_t communities_list_as_binary_array;
            communities_list_as_binary_array.set_maximum_buffer_size_in_bytes(community_attribute_full_length);

            communities_list_as_binary_array.append_data_as_object_ptr(&bgp_attribute_community);

            for (auto bgp_community_element : community_list) {
                // Encode they in network byte order
                bgp_community_element.host_byte_order_to_network_byte_order();

                communities_list_as_binary_array.append_data_as_object_ptr(&bgp_community_element);
            }

            return std::vector<dynamic_binary_buffer_t>{ origin_as_binary_array, next_hop_as_binary_array,
                                                         communities_list_as_binary_array };
        }
    }

    std::string print() const {
        std::stringstream buf;

        buf << "Prefix: " << convert_ip_as_uint_to_string(prefix.subnet_address) << "/" << prefix.cidr_prefix_length << " "
            << "Origin: " << get_origin_name_by_value(origin) << " "
            << "Next hop: " << convert_ip_as_uint_to_string(next_hop) + "/32";
        // TODO: print pretty communities!!!

        return buf.str();
    }

    // Add multiple communities in single step
    bool add_multiple_communities(std::vector<bgp_community_attribute_element_t> bgp_communities) {
        for (auto bgp_community : bgp_communities) {
            community_list.push_back(bgp_community);
        }

        return true;
    }

    bool add_community(bgp_community_attribute_element_t bgp_community) {
        community_list.push_back(bgp_community);

        return true;
    }

    private:
    uint32_t next_hop = 0;
    subnet_cidr_mask_t prefix;
    BGP_ORIGIN_TYPES origin = BGP_ORIGIN_INCOMPLETE;
    bool is_withdraw        = false;
    std::vector<bgp_community_attribute_element_t> community_list;
};

class IPv6UnicastAnnounce {
    public:
    void set_withdraw(bool withdraw) {
        this->is_withdraw = withdraw;
    }

    bool get_withdraw() {
        return this->is_withdraw;
    }

    void set_next_hop(subnet_ipv6_cidr_mask_t next_hop) {
        this->next_hop = next_hop;
    }

    void set_prefix(subnet_ipv6_cidr_mask_t prefix) {
        this->prefix = prefix;
    }

    void set_origin(BGP_ORIGIN_TYPES origin) {
        this->origin = origin;
    }

    subnet_ipv6_cidr_mask_t get_next_hop() const {
        return next_hop;
    }

    subnet_ipv6_cidr_mask_t get_prefix() const {
        return this->prefix;
    }

    BGP_ORIGIN_TYPES get_origin() const {
        return this->origin;
    }

    std::string print() const {
        std::stringstream buf;

        buf << "Prefix: " << convert_ipv6_subnet_to_string(prefix) << " "
            << "Origin: " << get_origin_name_by_value(origin) << " "
            << "Next hop: " << convert_ipv6_subnet_to_string(next_hop);

        return buf.str();
    }

    // Returns prefix in text form
    std::string get_prefix_in_cidr_form() const {
        return convert_ipv6_subnet_to_string(prefix);
    }

    // Add multiple communities in single step
    bool add_multiple_communities(std::vector<bgp_community_attribute_element_t> bgp_communities) {
        for (auto bgp_community : bgp_communities) {
            community_list.push_back(bgp_community);
        }

        return true;
    }

    bool add_community(bgp_community_attribute_element_t bgp_community) {
        community_list.push_back(bgp_community);

        return true;
    }

    std::vector<bgp_community_attribute_element_t> get_communities() const {
        return community_list;
    }

    private:
    subnet_ipv6_cidr_mask_t next_hop{};
    subnet_ipv6_cidr_mask_t prefix{};
    BGP_ORIGIN_TYPES origin = BGP_ORIGIN_INCOMPLETE;
    bool is_withdraw        = false;
    std::vector<bgp_community_attribute_element_t> community_list;
};

static_assert(sizeof(bgp_attribute_flags) == 1, "broken size for bgp_attribute_flags");
static_assert(sizeof(bgp_attribute_origin) == 4, "Bad size for bgp_attribute_origin");
static_assert(sizeof(bgp_attribute_next_hop_ipv4) == 7, "Bad size for bgp_attribute_next_hop_ipv4");

bool is_bgp_community_valid(std::string community_as_string);
bool decode_ipv6_announce_from_binary_encoded_atributes(std::vector<dynamic_binary_buffer_t> binary_attributes,
                                                        IPv6UnicastAnnounce& ipv6_announce);
bool decode_mp_reach_ipv6(int len, uint8_t* value, bgp_attibute_common_header_t bgp_attibute_common_header, IPv6UnicastAnnounce& ipv6_announce);
bool encode_ipv6_announces_into_bgp_mp_reach_attribute_internal(const IPv6UnicastAnnounce& ipv6_announce,
                                                                dynamic_binary_buffer_t& bgp_mp_reach_ipv6_attribute);

bool encode_ipv6_announces_into_bgp_mp_reach_attribute(const IPv6UnicastAnnounce& ipv6_announce,

                                                       dynamic_binary_buffer_t& bgp_mp_reach_ipv6_attribute);
bool encode_ipv6_prefix(const subnet_ipv6_cidr_mask_t& prefix, dynamic_binary_buffer_t& dynamic_buffer);

