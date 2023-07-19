#include "bgp_protocol.hpp"

#include <iostream>

#include "fast_library.hpp"

#include "network_data_structures.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif 

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <cmath>

#include "nlohmann/json.hpp"

uint32_t convert_cidr_to_binary_netmask_local_function_copy(unsigned int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF;
    binary_netmask          = binary_netmask << (32 - cidr);
    // htonl from host byte order to network
    // ntohl from network byte order to host

    // We need network byte order at output
    return htonl(binary_netmask);
}

bool decode_nlri_ipv4(int len, uint8_t* value, subnet_cidr_mask_t& extracted_prefix) {
    uint32_t not_used_number_of_scanned_bytes = 0;

    return decode_bgp_subnet_encoding_ipv4(len, value, extracted_prefix, not_used_number_of_scanned_bytes);
}

// https://www.ietf.org/rfc/rfc4271.txt
/*

    a) Length:
        The Length field indicates the length in bits of the IP
        address prefix.  A length of zero indicates a prefix that
        matches all IP addresses (with prefix, itself, of zero
        octets).

    b) Prefix:

        The Prefix field contains an IP address prefix, followed by
        the minimum number of trailing bits needed to make the end
        of the field fall on an octet boundary.  Note that the value
        of trailing bits is irrelevant.

*/
// https://github.com/Exa-Networks/exabgp/blob/master/lib/exabgp/bgp/message/update/nlri/cidr.py#L81
// https://github.com/osrg/gobgp/blob/d6148c75a30d87c3f8c1d0f68725127e4c5f3a65/packet/bgp.go#L700
bool decode_bgp_subnet_encoding_ipv4(int len, uint8_t* value, subnet_cidr_mask_t& extracted_prefix, uint32_t& parsed_nlri_length) {
    // We have NLRI only for IPv4 announces! IPv6 and Flow Spec do not use it!

    if (len == 0 or value == NULL) {
        logger << log4cpp::Priority::WARN << "NLRI content is blank for this announce";
        return false;
    }

    uint8_t prefix_bit_length = value[0];

    // logger << log4cpp::Priority::WARN << "We extracted prefix length: " <<
    // int(prefix_bit_length) <<
    // std::endl;

    // Rounds x upward
    uint32_t prefix_byte_length = how_much_bytes_we_need_for_storing_certain_subnet_mask(prefix_bit_length);

    // 1 means 1 byte size for prefix_bit_length itself
    uint32_t full_nlri_length = prefix_byte_length + 1;

    if (len < full_nlri_length) {
        logger << log4cpp::Priority::WARN << "Not enough data size! We need least " << prefix_byte_length << " bytes of data";
        return false;
    }

    // We need number of scanned bytes for next parses
    parsed_nlri_length = full_nlri_length;

    return decode_bgp_subnet_encoding_ipv4_raw(value, extracted_prefix);
}

// Same as decode_bgp_subnet_encoding but do not check array bounds at all
// We need to ensure about enough length of data array before calling of this
// code!
bool decode_bgp_subnet_encoding_ipv4_raw(uint8_t* value, subnet_cidr_mask_t& extracted_prefix) {
    if (value == NULL) {
        logger << log4cpp::Priority::WARN << "Zero value unexpected for decode_bgp_subnet_encoding_ipv4_raw";
        return false;
    }

    uint8_t prefix_bit_length   = value[0];
    uint32_t prefix_byte_length = how_much_bytes_we_need_for_storing_certain_subnet_mask(prefix_bit_length);

    // 1 means 1 byte size for prefix_bit_length itself
    // uint32_t full_nlri_length = prefix_byte_length + 1;

    uint32_t prefix_ipv4 = 0;
    memcpy(&prefix_ipv4, value + 1, prefix_byte_length);

    // Then we should set to zero all non important bits in address because they
    // could store weird
    // information
    uint32_t subnet_address_netmask_binary = convert_cidr_to_binary_netmask_local_function_copy(prefix_bit_length);

    // Remove useless bits with this approach
    prefix_ipv4 = prefix_ipv4 & subnet_address_netmask_binary;

    // logger << log4cpp::Priority::WARN << "Extracted prefix: " <<
    // convert_ip_as_uint_to_string(prefix_ipv4) << "/" <<
    // int(prefix_bit_length)         ;
    extracted_prefix.subnet_address     = prefix_ipv4;
    extracted_prefix.cidr_prefix_length = prefix_bit_length;

    return true;
}

bool decode_ipv6_announce_from_binary_encoded_atributes(std::vector<dynamic_binary_buffer_t> binary_attributes,
                                                        IPv6UnicastAnnounce& ipv6_announce) {
    for (auto binary_attribute : binary_attributes) {
        bgp_attibute_common_header_t bgp_attibute_common_header;

        bool bgp_attrinute_read_result = bgp_attibute_common_header.parse_raw_bgp_attribute_binary_buffer(binary_attribute);

        if (!bgp_attrinute_read_result) {
            logger << log4cpp::Priority::WARN << "Could not read BGP attribute to common structure";
            return false;
        }

        // bgp_attribute_common_header.print() ;

        if (bgp_attibute_common_header.attribute_type == BGP_ATTRIBUTE_MP_REACH_NLRI) {
            bool ipv6_decode_result =
                decode_mp_reach_ipv6(binary_attribute.get_used_size(), (uint8_t*)binary_attribute.get_pointer(),
                                     bgp_attibute_common_header, ipv6_announce);

            if (!ipv6_decode_result) {
                logger << log4cpp::Priority::ERROR << "Can't decode IPv6 announce";
                return false;
            }
        }
    }

    return true;
}

// Decodes MP Reach NLRI attribute and populates IPv6 specific fields
bool decode_mp_reach_ipv6(int len, uint8_t* value, bgp_attibute_common_header_t bgp_attibute_common_header, IPv6UnicastAnnounce& ipv6_announce) {
    // TODO: we should add sanity checks to avoid reads after attribute's memory block

    uint8_t* mp_reach_attribute_shift = (uint8_t*)value + bgp_attibute_common_header.attribute_body_shift;

    // Read first part of MP Reach NLRI header
    bgp_mp_reach_short_header_t* bgp_mp_ext_header = (bgp_mp_reach_short_header_t*)mp_reach_attribute_shift;
    bgp_mp_ext_header->network_to_host_byte_order();

    // logger << log4cpp::Priority::INFO << bgp_mp_ext_header->print();

    if (not(bgp_mp_ext_header->afi_identifier == AFI_IP6 and bgp_mp_ext_header->safi_identifier == SAFI_UNICAST)) {
        logger << log4cpp::Priority::WARN << "We have got unexpected afi or safi numbers from IPv6 MP Reach NLRI";
        return false;
    }

    subnet_ipv6_cidr_mask_t next_hop_ipv6;

    // We support only 16 byte (/128) next hops
    next_hop_ipv6.cidr_prefix_length = 128; //-V1048

    if (bgp_mp_ext_header->length_of_next_hop != 16) {
        logger << log4cpp::Priority::WARN << "We support only 16 byte next hop for IPv6 MP Reach NLRI";
        return false;
    }

    memcpy(&next_hop_ipv6.subnet_address, mp_reach_attribute_shift + sizeof(bgp_mp_reach_short_header_t),
           bgp_mp_ext_header->length_of_next_hop);

    ipv6_announce.set_next_hop(next_hop_ipv6);

    // logger << log4cpp::Priority::INFO << "IPv6 next hop is: "<< convert_ipv6_subnet_to_string(next_hop_ipv6);

    // Strip single byte reserved field
    uint8_t* prefix_length = mp_reach_attribute_shift + sizeof(bgp_mp_reach_short_header_t) +
                             bgp_mp_ext_header->length_of_next_hop + sizeof(uint8_t);

    // We should cast it to int for proper print
    // logger << log4cpp::Priority::INFO << "NLRI length: " << int(*prefix_length);
    uint32_t number_of_bytes_required_for_prefix = how_much_bytes_we_need_for_storing_certain_subnet_mask(*prefix_length);

    // logger << log4cpp::Priority::INFO << "We need " << number_of_bytes_required_for_prefix << " bytes for this prefix";

    subnet_ipv6_cidr_mask_t prefix_ipv6;
    prefix_ipv6.cidr_prefix_length = *prefix_length;

    // Strip single byte for prefix_length and read network address
    memcpy(&prefix_ipv6.subnet_address, prefix_length + sizeof(uint8_t), number_of_bytes_required_for_prefix);

    ipv6_announce.set_prefix(prefix_ipv6);

    // logger << log4cpp::Priority::INFO << "Prefix is: " << convert_ipv6_subnet_to_string(prefix_ipv6);

    return true;
}

// https://github.com/osrg/gobgp/blob/d6148c75a30d87c3f8c1d0f68725127e4c5f3a65/packet/bgp.go#L5940
bool decode_attribute(int len, char* value, IPv4UnicastAnnounce& unicast_ipv4_announce) {
    bgp_attibute_common_header_t bgp_attibute_common_header;

    bool bgp_attrinute_read_result = bgp_attibute_common_header.parse_raw_bgp_attribute((uint8_t*)value, len);

    if (!bgp_attrinute_read_result) {
        logger << log4cpp::Priority::WARN << "Could not read BGP attribute to common structure";
        return false;
    }

    switch (bgp_attibute_common_header.attribute_type) {
    case BGP_ATTRIBUTE_ORIGIN: {
        if (bgp_attibute_common_header.attribute_value_length != 1) {
            logger << log4cpp::Priority::WARN
                   << "Broken size for BGP_ATTRIBUTE_ORIGIN: " << bgp_attibute_common_header.attribute_value_length;
            return false;
        }

        uint8_t origin_value = 0;
        memcpy(&origin_value,
               value + bgp_attibute_common_header.attribute_flag_and_type_length + bgp_attibute_common_header.length_of_length_field,
               sizeof(origin_value));
        // logger << log4cpp::Priority::WARN << "BGP_ATTRIBUTE_ORIGIN: " <<
        // get_origin_name_by_value(origin_value) <<
        // std::endl;

        unicast_ipv4_announce.set_origin((BGP_ORIGIN_TYPES)origin_value);
    }

    break;

    case BGP_ATTRIBUTE_AS_PATH: {
        logger << log4cpp::Priority::DEBUG << "Got BGP_ATTRIBUTE_AS_PATH but I do not have code for parsing it";
    }

    break;

    case BGP_ATTRIBUTE_NEXT_HOP: {
        if (bgp_attibute_common_header.attribute_value_length == 4) {
            uint32_t nexthop_value = 0;

            memcpy(&nexthop_value,
                   value + bgp_attibute_common_header.attribute_flag_and_type_length + bgp_attibute_common_header.length_of_length_field,
                   sizeof(nexthop_value));

            // logger << log4cpp::Priority::WARN << "BGP_ATTRIBUTE_NEXT_HOP value is: " << convert_ip_as_uint_to_string(nexthop_value);

            unicast_ipv4_announce.set_next_hop(nexthop_value);
        } else if (bgp_attibute_common_header.attribute_value_length == 16) {
            logger << log4cpp::Priority::WARN << "BGP_ATTRIBUTE_NEXT_HOP is not supported yet for IPv6";
        } else {
            logger << log4cpp::Priority::ERROR << "Wrong next hop length: " << bgp_attibute_common_header.attribute_value_length;
            return false;
        }
    }

    break;

    case BGP_ATTRIBUTE_MULTI_EXIT_DISC: {
        logger << log4cpp::Priority::DEBUG << "Got BGP_ATTRIBUTE_MULTI_EXIT_DISC but I do not have code for parsing it";
    }

    break;

    case BGP_ATTRIBUTE_LOCAL_PREF: {
        logger << log4cpp::Priority::DEBUG << "Got BGP_ATTRIBUTE_LOCAL_PREF but I do not have code for parsing it";
    }

    break;

    case BGP_ATTRIBUTE_COMMUNITY: {
        logger << log4cpp::Priority::DEBUG << "Got BGP_ATTRIBUTE_COMMUNITY but I do not have code for parsing it";
    }

    break;

    case BGP_ATTRIBUTE_MP_REACH_NLRI: {
        logger << log4cpp::Priority::WARN << "BGP_ATTRIBUTE_MP_REACH_NLRI with length "
               << bgp_attibute_common_header.attribute_value_length;

        // TODO: I call this code only for testing purposes
        // IPv6UnicastAnnounce ipv6_announce;
        // decode_mp_reach_ipv6(len, value, bgp_attibute_common_header, ipv6_announce);
        // logger << log4cpp::Priority::WARN << ipv6_announce.print();
    }

    break;

    case BGP_ATTRIBUTE_EXTENDED_COMMUNITY: {
        logger << log4cpp::Priority::DEBUG
               << "BGP_ATTRIBUTE_EXTENDED_COMMUNITY with length: " << bgp_attibute_common_header.attribute_value_length;
    }

    break;

    default: {
        logger << log4cpp::Priority::DEBUG << "Unknown attribute: " << int(bgp_attibute_common_header.attribute_type);
    }

    break;
    }

    return true;
}

// Prepare MP Reach IPv6 attribute for IPv6 traffic
// This function creates only internal payload without attribute headers
bool encode_ipv6_announces_into_bgp_mp_reach_attribute_internal(const IPv6UnicastAnnounce& ipv6_announce,
                                                                dynamic_binary_buffer_t& bgp_mp_reach_ipv6_attribute) {
    // Create internal content of IPv6 MP Reach NLRI
    bgp_mp_reach_ipv6_attribute.set_maximum_buffer_size_in_bytes(2048);

    /*
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

    // Create short header
    bgp_mp_reach_short_header_t bgp_mp_reach_short_header;

    bgp_mp_reach_short_header.afi_identifier     = AFI_IP6; //-V1048
    bgp_mp_reach_short_header.safi_identifier    = SAFI_UNICAST; //-V1048
    
    // Add next hop field
    bgp_mp_reach_short_header.length_of_next_hop = 16; //-V1048

    bgp_mp_reach_short_header.host_byte_order_to_network_byte_order();

    // Add next hop field
    bgp_mp_reach_ipv6_attribute.append_data_as_object_ptr(&bgp_mp_reach_short_header);

    auto next_hop = ipv6_announce.get_next_hop();
    logger << log4cpp::Priority::DEBUG << "Append next hop " << convert_ipv6_subnet_to_string(next_hop) << " with length of "
        << sizeof(next_hop.subnet_address) << " bytes";

    bgp_mp_reach_ipv6_attribute.append_data_as_pointer(&next_hop.subnet_address, sizeof(next_hop.subnet_address));

    // Append reserved byte
    uint8_t reserved_byte = 0;
    bgp_mp_reach_ipv6_attribute.append_byte(reserved_byte);

    // Get prefix for announce
    auto prefix = ipv6_announce.get_prefix();

    logger << log4cpp::Priority::DEBUG << "Extracted prefix " << convert_ipv6_subnet_to_string(prefix);
    
    if (!encode_ipv6_prefix(prefix, bgp_mp_reach_ipv6_attribute)) {
        logger << log4cpp::Priority::ERROR << "Cannot encode IPv6 prefix";
        return false;
    }

    return true;
}

// Encodes IPv6 in BGP encoding format:
// Prefix length followed by prefix itself
// NB! You have to initialise dynamic_buffer before calling it
bool encode_ipv6_prefix(const subnet_ipv6_cidr_mask_t& prefix, dynamic_binary_buffer_t& dynamic_buffer) {
    // Add prefix length
    uint8_t prefix_length = uint8_t(prefix.cidr_prefix_length);

    logger << log4cpp::Priority::DEBUG << "Prefix length: " << uint32_t(prefix_length);

    if (!dynamic_buffer.append_byte(prefix_length)) {
        logger << log4cpp::Priority::ERROR << "Cannot add prefix length";
        return false;
    }

    uint32_t prefix_byte_length = how_much_bytes_we_need_for_storing_certain_subnet_mask(prefix_length);

    logger << log4cpp::Priority::DEBUG << "We need " << int(prefix_byte_length) << " bytes to encode IPv6 prefix " << convert_ipv6_subnet_to_string(prefix);

    // We should copy only first meaningful bytes
    if (!dynamic_buffer.append_data_as_pointer(&prefix.subnet_address, prefix_byte_length)) {
        logger << log4cpp::Priority::ERROR << "Cannot add prefix itself";
        return false;
    }

    return true;
}

bool encode_ipv6_announces_into_bgp_mp_reach_attribute(const IPv6UnicastAnnounce& ipv6_announce,
                                                       dynamic_binary_buffer_t& bgp_mp_reach_ipv6_attribute) {
    dynamic_binary_buffer_t mp_nlri_binary_buffer;
    bool mp_nlri_encode_result = encode_ipv6_announces_into_bgp_mp_reach_attribute_internal(ipv6_announce, mp_nlri_binary_buffer);

    if (!mp_nlri_encode_result) {
        logger << log4cpp::Priority::ERROR << "Can't create inner MP Reach attribute for IPv6";
        return false;
    }

    // uint8_t nlri_length = mp_nlri_binary_buffer.get_used_size();

    // logger << log4cpp::Priority::INFO << "Crafter mp reach with size: " << int(nlri_length);

    // Create attribute header
    bgp_attribute_multiprotocol_extensions_t bgp_attribute_multiprotocol_extensions;
    bgp_attribute_multiprotocol_extensions.attribute_length = mp_nlri_binary_buffer.get_used_size();

    bgp_mp_reach_ipv6_attribute.set_maximum_buffer_size_in_bytes(2048);

    bgp_mp_reach_ipv6_attribute.append_data_as_object_ptr(&bgp_attribute_multiprotocol_extensions);
    bgp_mp_reach_ipv6_attribute.append_dynamic_buffer(mp_nlri_binary_buffer);

    if (bgp_mp_reach_ipv6_attribute.is_failed()) {
        logger << log4cpp::Priority::WARN << "We have issues with binary buffer in IPv6 NLRI generation code";
        return false;
    }

    return true;
}

// TODO: add sanity checks
// If you want to improve this code with eliminating memory copy
// Please read this https://en.wikipedia.org/wiki/Return_value_optimization
bool encode_bgp_subnet_encoding(const subnet_cidr_mask_t& prefix, dynamic_binary_buffer_t& dynamic_binary_buffer) {
    uint32_t subnet_address    = prefix.subnet_address;
    uint32_t prefix_bit_length = prefix.cidr_prefix_length;

    // Rounds x upward
    uint32_t prefix_byte_length = ceil(float(prefix_bit_length) / 8);

    // We need 1 byte for prefix length in bits and X bytes for prefix itself
    uint32_t full_nlri_length = 1 + prefix_byte_length;

    // logger << log4cpp::Priority::WARN << "We will allocate " <<
    // full_nlri_length << " bytes in buffer"
    //         ;

    bool allocation_result = dynamic_binary_buffer.set_maximum_buffer_size_in_bytes(full_nlri_length);

    if (!allocation_result) {
        logger << log4cpp::Priority::WARN << "Allocation error";
        return false;
    }

    dynamic_binary_buffer.append_byte(uint8_t(prefix_bit_length));

    // Then we should set to zero all non important bits in address because they
    // could store weird
    // information

    uint32_t subnet_address_netmask_binary = convert_cidr_to_binary_netmask_local_function_copy(prefix_bit_length);

    // Zeroify useless bits
    subnet_address = subnet_address & subnet_address_netmask_binary;

    dynamic_binary_buffer.append_data_as_pointer(&subnet_address, prefix_byte_length);

    return true;
}

std::string get_origin_name_by_value(uint8_t origin_value) {
    switch (origin_value) {
    case BGP_ORIGIN_IGP:
        return "BGP_ORIGIN_IGP";
        break;
    case BGP_ORIGIN_EGP:
        return "BGP_ORIGIN_EGP";
        break;
    case BGP_ORIGIN_INCOMPLETE:
        return "BGP_ORIGIN_INCOMPLETE";
        break;
    default:
        return "Unknown";
        break;
    }
}

std::string get_bgp_attribute_name_by_number(uint8_t bgp_attribute_type) {
    switch (bgp_attribute_type) {
    case BGP_ATTRIBUTE_ORIGIN:
        return "BGP_ATTRIBUTE_ORIGIN";
        break;
    case BGP_ATTRIBUTE_AS_PATH:
        return "BGP_ATTRIBUTE_AS_PATH";
        break;
    case BGP_ATTRIBUTE_NEXT_HOP:
        return "BGP_ATTRIBUTE_NEXT_HOP";
        break;
    case BGP_ATTRIBUTE_MULTI_EXIT_DISC:
        return "BGP_ATTRIBUTE_MULTI_EXIT_DISC";
        break;
    case BGP_ATTRIBUTE_LOCAL_PREF:
        return "BGP_ATTRIBUTE_LOCAL_PREF";
        break;
    case BGP_ATTRIBUTE_ATOMIC_AGGREGATE:
        return "BGP_ATTRIBUTE_ATOMIC_AGGREGATE";
        break;
    case BGP_ATTRIBUTE_AGGREGATOR:
        return "BGP_ATTRIBUTE_AGGREGATOR";
        break;
    case BGP_ATTRIBUTE_COMMUNITY:
        return "BGP_ATTRIBUTE_COMMUNITY";
        break;
    case BGP_ATTRIBUTE_MP_REACH_NLRI:
        return "BGP_ATTRIBUTE_MP_REACH_NLRI";
        break;
    case BGP_ATTRIBUTE_EXTENDED_COMMUNITY:
        return "BGP_ATTRIBUTE_EXTENDED_COMMUNITY";
        break;
    default:
        return "UNKNOWN";
        break;
    }
}

// This function calculates number of bytes required for store some certain
// network
// This is very useful if you are working with BGP encoded subnets
uint32_t how_much_bytes_we_need_for_storing_certain_subnet_mask(uint8_t prefix_bit_length) {
    return ceil(float(prefix_bit_length) / 8);
}

// Wrapper function which just checks correctness of bgp community
bool is_bgp_community_valid(std::string community_as_string) {
    bgp_community_attribute_element_t bgp_community_attribute_element;

    return read_bgp_community_from_string(community_as_string, bgp_community_attribute_element);
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
