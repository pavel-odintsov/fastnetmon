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

// By default use default MTU
uint64_t reject_flow_spec_validation_if_slow_spec_length_exceeds_this_number = 1500;

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

bool decode_native_flow_spec_announce_from_binary_encoded_atributes(std::vector<dynamic_binary_buffer_t> binary_attributes,
                                                                    flow_spec_rule_t& flow_spec_rule) {
    for (auto binary_attribute : binary_attributes) {
        bgp_attibute_common_header_t bgp_attibute_common_header;

        bool bgp_attrinute_read_result = bgp_attibute_common_header.parse_raw_bgp_attribute_binary_buffer(binary_attribute);

        if (!bgp_attrinute_read_result) {
            logger << log4cpp::Priority::WARN << "Could not read BGP attribute to common structure";
            return false;
        }

        // bgp_attibute_common_header.print() ;

        if (bgp_attibute_common_header.attribute_type == BGP_ATTRIBUTE_EXTENDED_COMMUNITY) {
            // logger << log4cpp::Priority::WARN << "Got BGP_ATTRIBUTE_EXTENDED_COMMUNITIES with length " <<
            // gobgp_lib_path->path_attributes[i]->len ;
            // TODO: TBD
            // logger << log4cpp::Priority::WARN << bgp_attibute_common_header.print() ;

            uint32_t number_of_extened_community_elements =
                bgp_attibute_common_header.attribute_value_length / sizeof(bgp_extended_community_element_t);

            if (bgp_attibute_common_header.attribute_value_length % sizeof(bgp_extended_community_element_t) != 0) {
                logger << log4cpp::Priority::WARN << "attribute_value_length should be multiplied by "
                       << sizeof(bgp_extended_community_element_t) << " bytes";
                return false;
            }

            // logger << log4cpp::Priority::WARN << "We have: " << number_of_extened_community_elements << "
            // extended community elements" ;

            if (number_of_extened_community_elements != 1) {
                logger << log4cpp::Priority::WARN
                       << "We do not support multiple or zero extended communities "
                          "for flow spec announes";
                return false;
            }

            uint8_t* attribute_shift = (uint8_t*)binary_attribute.get_pointer() + bgp_attibute_common_header.attribute_body_shift;

            // TODO: we could read only first community element
            bgp_extended_community_element_t* bgp_extended_community_element = (bgp_extended_community_element_t*)attribute_shift;

            // logger << log4cpp::Priority::WARN << bgp_extended_community_element->print() ;

            // This type for BGP flow spec actions
            if (bgp_extended_community_element->type_hight == EXTENDED_COMMUNITY_TRANSITIVE_EXPEREMENTAL) {

                if (bgp_extended_community_element->type_low == FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_TRAFFIC_RATE) {
                    // logger << log4cpp::Priority::WARN << "Found flow spec action value!!!" ;

                    // Two bytes in value store identification. It's not useful for us and
                    // we could drop it
                    // Next 4 bytes has float value encoded as IEEE.754.1985. So we could
                    // use float (4 bytes too) to interpret it
                    uint32_t* rate_as_integer = (uint32_t*)(bgp_extended_community_element->value + 2);

                    // Yes, really, float number encoded as big endian and we should decode
                    // it
                    *rate_as_integer = ntohl(*rate_as_integer);

                    float* rate_as_float_ptr = (float*)rate_as_integer;

                    if (*rate_as_float_ptr < 0) {
                        logger << log4cpp::Priority::WARN << "Rate could not be negative";
                        return false;
                    }

                    bgp_flow_spec_action_t bgp_flow_spec_action;

                    if (int(*rate_as_float_ptr) == 0) {
                        bgp_flow_spec_action.set_type(bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD);
                    } else {
                        bgp_flow_spec_action.set_type(bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT);
                        bgp_flow_spec_action.set_rate_limit(int(*rate_as_float_ptr));
                    }

                    flow_spec_rule.set_action(bgp_flow_spec_action);
                    // logger << log4cpp::Priority::WARN << "Rate: " << *rate_as_float_ptr ;
                } else if (bgp_extended_community_element->type_low == FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_REDIRECT_AS_TWO_BYTE) {
                    const redirect_2_octet_as_4_octet_value_t* redirect_2_octet_as_4_octet_value =
                        (const redirect_2_octet_as_4_octet_value_t*)bgp_extended_community_element->value;

                    bgp_flow_spec_action_t bgp_flow_spec_action;
                    bgp_flow_spec_action.set_type(bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT);

                    bgp_flow_spec_action.set_redirect_as(redirect_2_octet_as_4_octet_value->get_as_host_byte_order());
                    bgp_flow_spec_action.set_redirect_value(redirect_2_octet_as_4_octet_value->get_value_host_byte_order());

                    flow_spec_rule.set_action(bgp_flow_spec_action);

                    logger << log4cpp::Priority::DEBUG
                           << "BGP Flow Spec redirect field: " << redirect_2_octet_as_4_octet_value->print();
                } else if (bgp_extended_community_element->type_low == FLOW_SPEC_EXTENDED_COMMUNITY_SUBTYPE_TRAFFIC_REMARKING) {
                    logger << log4cpp::Priority::WARN
                           << "BGP Flow Spec traffic marking is not supported: " << bgp_extended_community_element->print();
                }
            }
        } else if (bgp_attibute_common_header.attribute_type == BGP_ATTRIBUTE_MP_REACH_NLRI) {
            // logger << log4cpp::Priority::WARN << "Will process BGP_ATTRIBUTE_MP_REACH_NLRI in details" <<
            // std::endl;

            // logger << log4cpp::Priority::WARN << "Whole MP reach NLRI in hex: " <<
            // print_binary_string_as_hex_without_leading_0x(
            //        (uint8_t*)gobgp_lib_path->path_attributes[i]->value,
            //        gobgp_lib_path->path_attributes[i]->len) ;

            uint8_t* flow_spec_attribute_shift =
                (uint8_t*)binary_attribute.get_pointer() + bgp_attibute_common_header.attribute_body_shift;

            bgp_mp_ext_flow_spec_header_t* bgp_mp_ext_flow_spec_header = (bgp_mp_ext_flow_spec_header_t*)flow_spec_attribute_shift;
            bgp_mp_ext_flow_spec_header->network_to_host_byte_order();

            if (not(bgp_mp_ext_flow_spec_header->afi_identifier == AFI_IP and
                    bgp_mp_ext_flow_spec_header->safi_identifier == SAFI_FLOW_SPEC_UNICAST)) {
                logger << log4cpp::Priority::WARN
                       << "We have got unexpected AFI or SAFI numbers from BGP Flow "
                          "Spec MP header";
                return false;
            }

            uint8_t* flow_spec_types_shift = (uint8_t*)binary_attribute.get_pointer() + bgp_attibute_common_header.attribute_body_shift +
                                             sizeof(bgp_mp_ext_flow_spec_header_t);

            // logger << log4cpp::Priority::WARN << bgp_mp_ext_flow_spec_header->print() ;

            uint16_t nlri_value_length           = 0;
            uint16_t nlri_length_of_length_field = 1;

            // 240 is 0xf0
            if (flow_spec_types_shift[0] < 240) {
                nlri_value_length           = flow_spec_types_shift[0];
                nlri_length_of_length_field = 1;
            } else {
                nlri_length_of_length_field = 2;
                logger << log4cpp::Priority::WARN << "We do not support for 2 byte NLRI length encoding yet";
                return false;
            }

            // TODO: add sanity checks for length
            // logger << log4cpp::Priority::WARN << "We have " <<
            // uint32_t(gobgp_lib_path->path_attributes[i]->len) << " byte length
            // attrinute" ;
            // logger << log4cpp::Priority::WARN << "We have NLRI header length: " <<
            // uint32_t(sizeof(bgp_mp_ext_flow_spec_header_t)) ;
            // logger << log4cpp::Priority::WARN << "We have " << uint32_t(nlri_value_length) << " byte length
            // NLRI" ;

            bool flowspec_decode_result =
                flow_spec_decode_nlri_value((uint8_t*)(flow_spec_types_shift + nlri_length_of_length_field),
                                            nlri_value_length, flow_spec_rule);

            if (!flowspec_decode_result) {
                logger << log4cpp::Priority::WARN << "Could not parse Flow Spec payload";
                return false;
            }
        }
    }

    return true;
}

// Build BGP attributes for BGP flow spec announce
std::vector<dynamic_binary_buffer_t> build_attributes_for_flowspec_announce(flow_spec_rule_t flow_spec_rule) {
    // Prepare origin
    bgp_attribute_origin origin_attr;

    dynamic_binary_buffer_t origin_as_binary_array;
    origin_as_binary_array.set_maximum_buffer_size_in_bytes(sizeof(origin_attr));
    origin_as_binary_array.append_data_as_object_ptr(&origin_attr);

    dynamic_binary_buffer_t bgp_mp_ext_flow_spec_header_as_binary_array;
    bool encode_bgp_flow_spec_as_mp_attr_result =
        encode_bgp_flow_spec_elements_into_bgp_mp_attribute(flow_spec_rule, bgp_mp_ext_flow_spec_header_as_binary_array, true);

    if (!encode_bgp_flow_spec_as_mp_attr_result) {
        logger << log4cpp::Priority::WARN << "Could not encode flow spec announce as mp attribute";
        return std::vector<dynamic_binary_buffer_t>{};
    }

    // Prepare extended community
    bgp_flow_spec_action_t bgp_flow_spec_action = flow_spec_rule.get_action();

    if (bgp_flow_spec_action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_ACCEPT) {
        logger << log4cpp::Priority::DEBUG << "this flow spec rule has action set to accept, skip rate limit section";
        // According to RFC: The default action for a traffic filtering flow specification is to
        // accept IP traffic that matches that particular rule.
        // And we do not need any additional communities in this case to encode action

        // Here we can add next hop for IPv4 when it set
        if (flow_spec_rule.ipv4_nexthops.size() > 0) {
            logger << log4cpp::Priority::DEBUG << "We have got nexthop IPv4 value for flowspec, let's add it";

            dynamic_binary_buffer_t extended_attributes_flow_spec_ipv4_as_binary_array;

            if (flow_spec_rule.ipv4_nexthops.size() > 1) {
                logger << log4cpp::Priority::WARN << "We support only single IPv4 next hop for flow spec";
            }

            // We pick up only first next hop
            bool next_hop_encode_result =
                encode_bgp_flow_spec_next_hop_as_extended_attribute(flow_spec_rule.ipv4_nexthops[0],
                                                                    extended_attributes_flow_spec_ipv4_as_binary_array);

            if (!next_hop_encode_result) {
                logger << log4cpp::Priority::WARN << "Cannot encode IPv4 next hop for flow spec";
                return std::vector<dynamic_binary_buffer_t>{};
            }

            return std::vector<dynamic_binary_buffer_t>{ origin_as_binary_array, bgp_mp_ext_flow_spec_header_as_binary_array,
                                                         extended_attributes_flow_spec_ipv4_as_binary_array };
        }

        return std::vector<dynamic_binary_buffer_t>{ origin_as_binary_array, bgp_mp_ext_flow_spec_header_as_binary_array };
    }

    logger << log4cpp::Priority::DEBUG << "Encode rate for flow spec";
    dynamic_binary_buffer_t extended_attributes_as_binary_array;

    bool action_encode_result =
        encode_bgp_flow_spec_action_as_extended_attribute(bgp_flow_spec_action, extended_attributes_as_binary_array);

    if (!action_encode_result) {
        logger << log4cpp::Priority::WARN << "Could not encode flow spec action";

        // Return blank array
        return std::vector<dynamic_binary_buffer_t>{};
    }

    logger << log4cpp::Priority::DEBUG << "Successfully encoded flow spec action";

    return std::vector<dynamic_binary_buffer_t>{ origin_as_binary_array, bgp_mp_ext_flow_spec_header_as_binary_array,
                                                 extended_attributes_as_binary_array };
}

// Encode flow spec elements into MP NLRI
bool encode_bgp_flow_spec_elements_as_mp_nlri(const flow_spec_rule_t& flow_spec_rule, dynamic_binary_buffer_t& mp_nlri_flow_spec) {
    mp_nlri_flow_spec.set_maximum_buffer_size_in_bytes(2048);

    // Encode IPv4 destination prefix
    if (flow_spec_rule.destination_subnet_ipv4_used) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute destination prefix";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_DESTINATION_PREFIX);

        dynamic_binary_buffer_t encoded_destination_prefix_as_binary_array;
        bool dest_encode_result =
            encode_bgp_subnet_encoding(flow_spec_rule.destination_subnet_ipv4, encoded_destination_prefix_as_binary_array);

        if (!dest_encode_result) {
            logger << log4cpp::Priority::WARN << "Could not encode FLOW_SPEC_ENTITY_DESTINATION_PREFIX";
            return false;
        }

        logger << log4cpp::Priority::DEBUG << "Encoded destination subnet as "
               << encoded_destination_prefix_as_binary_array.get_used_size() << " bytes array";

        mp_nlri_flow_spec.append_dynamic_buffer(encoded_destination_prefix_as_binary_array);
    }

    // Encode source IPv4 prefix
    if (flow_spec_rule.source_subnet_ipv4_used) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute source prefix";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_SOURCE_PREFIX);

        dynamic_binary_buffer_t encoded_source_prefix_as_binary_array;
        bool src_encode_result =
            encode_bgp_subnet_encoding(flow_spec_rule.source_subnet_ipv4, encoded_source_prefix_as_binary_array);

        if (!src_encode_result) {
            logger << log4cpp::Priority::WARN << "Could not encode FLOW_SPEC_ENTITY_SOURCE_PREFIX";
            return false;
        }

        logger << log4cpp::Priority::DEBUG << "Encoded source subnet as "
               << encoded_source_prefix_as_binary_array.get_used_size() << " bytes array";

        mp_nlri_flow_spec.append_dynamic_buffer(encoded_source_prefix_as_binary_array);
    }

    if (flow_spec_rule.protocols.size() > 0) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute protocols";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_IP_PROTOCOL);

        for (auto itr = flow_spec_rule.protocols.begin(); itr != flow_spec_rule.protocols.end(); ++itr) {
            bgp_flow_spec_operator_byte_t bgp_flow_spec_operator_byte;
            bgp_flow_spec_operator_byte.set_length_in_bytes(1);

            // We support only equal operations
            bgp_flow_spec_operator_byte.set_equal_bit();

            // It's it's last element set end bit
            if (std::distance(itr, flow_spec_rule.protocols.end()) == 1) {
                bgp_flow_spec_operator_byte.set_end_of_list_bit();
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_operator_byte);

            // Cast strictly typed protocol type into underlying number
            uint8_t protocol_number = static_cast<std::underlying_type<ip_protocol_t>::type>(*itr);

            mp_nlri_flow_spec.append_byte(protocol_number);
        }
    }

    if (flow_spec_rule.destination_ports.size() > 0) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute desination ports";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_DESTINATION_PORT);

        for (auto itr = flow_spec_rule.destination_ports.begin(); itr != flow_spec_rule.destination_ports.end(); ++itr) {
            bgp_flow_spec_operator_byte_t bgp_flow_spec_operator_byte;

            // In destination_ports we encode porn number with two bytes
            // I have not reasons to reduce amount of data here
            bgp_flow_spec_operator_byte.set_length_in_bytes(sizeof(*itr));

            // We support only equal operations
            bgp_flow_spec_operator_byte.set_equal_bit();

            // It's it's last element set end bit
            if (std::distance(itr, flow_spec_rule.destination_ports.end()) == 1) {
                bgp_flow_spec_operator_byte.set_end_of_list_bit();
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_operator_byte);
            uint16_t destination_port = *itr;
            destination_port          = htons(destination_port);

            mp_nlri_flow_spec.append_data_as_object_ptr(&destination_port);
        }
    }

    if (flow_spec_rule.source_ports.size() > 0) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute source ports";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_SOURCE_PORT);

        for (auto itr = flow_spec_rule.source_ports.begin(); itr != flow_spec_rule.source_ports.end(); ++itr) {
            bgp_flow_spec_operator_byte_t bgp_flow_spec_operator_byte;

            // In source_ports we encode porn number with two bytes
            // I have not reasons to reduce amount of data here
            bgp_flow_spec_operator_byte.set_length_in_bytes(sizeof(*itr));

            // We support only equal operations
            bgp_flow_spec_operator_byte.set_equal_bit();

            // It's it's last element set end bit
            if (std::distance(itr, flow_spec_rule.source_ports.end()) == 1) {
                bgp_flow_spec_operator_byte.set_end_of_list_bit();
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_operator_byte);
            uint16_t source_port = *itr;
            source_port          = htons(source_port);

            mp_nlri_flow_spec.append_data_as_object_ptr(&source_port);
        }
    }

    if (flow_spec_rule.tcp_flags.size() > 0) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute TCP flags";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_TCP_FLAGS);

        for (auto itr = flow_spec_rule.tcp_flags.begin(); itr != flow_spec_rule.tcp_flags.end(); ++itr) {
            bgp_flow_spec_bitmask_operator_byte_t bgp_flow_spec_operator_byte_tcp_flags;
            bgp_flow_spec_operator_byte_tcp_flags.set_length_in_bytes(sizeof(bgp_flowspec_one_byte_byte_encoded_tcp_flags_t));

            if (std::distance(itr, flow_spec_rule.tcp_flags.end()) == 1) {
                bgp_flow_spec_operator_byte_tcp_flags.set_end_of_list_bit();
            }

            // Set match bit if we asked to do it
            if (flow_spec_rule.set_match_bit_for_tcp_flags) {
                bgp_flow_spec_operator_byte_tcp_flags.set_match_bit();
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_operator_byte_tcp_flags);

            if (!itr->we_have_least_one_flag_enabled()) {
                logger << log4cpp::Priority::WARN << "For some reasons we have tcp flags attribute without flags";
                return false;
            }

            bgp_flowspec_one_byte_byte_encoded_tcp_flags_t bgp_flowspec_one_byte_byte_encoded_tcp_flags =
                return_in_one_byte_encoding(*itr);

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flowspec_one_byte_byte_encoded_tcp_flags);
        }
    }

    if (flow_spec_rule.packet_lengths.size() > 0) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute packet lengths";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_PACKET_LENGTH);

        for (auto itr = flow_spec_rule.packet_lengths.begin(); itr != flow_spec_rule.packet_lengths.end(); ++itr) {
            bgp_flow_spec_operator_byte_t bgp_flow_spec_operator_byte;

            // In packet_lengths we encode porn number with two bytes
            // I have not reasons to reduce amount of data here
            bgp_flow_spec_operator_byte.set_length_in_bytes(sizeof(*itr));

            // We support only equal operations
            bgp_flow_spec_operator_byte.set_equal_bit();

            // It's it's last element set end bit
            if (std::distance(itr, flow_spec_rule.packet_lengths.end()) == 1) {
                bgp_flow_spec_operator_byte.set_end_of_list_bit();
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_operator_byte);
            uint16_t packet_length = *itr;
            packet_length          = htons(packet_length);
            mp_nlri_flow_spec.append_data_as_object_ptr(&packet_length);
        }
    }

    if (flow_spec_rule.fragmentation_flags.size() > 0) {
        logger << log4cpp::Priority::DEBUG << "Encode flow spec attribute fragmentation flags";

        mp_nlri_flow_spec.append_byte(FLOW_SPEC_ENTITY_FRAGMENT);

        for (auto itr = flow_spec_rule.fragmentation_flags.begin(); itr != flow_spec_rule.fragmentation_flags.end(); ++itr) {
            bgp_flow_spec_fragmentation_entity_t bgp_flow_spec_fragmentation_entity{};

            bgp_flow_spec_bitmask_operator_byte_t bgp_flow_spec_operator_byte;
            bgp_flow_spec_operator_byte.set_length_in_bytes(sizeof(bgp_flow_spec_fragmentation_entity_t));

            if (std::distance(itr, flow_spec_rule.fragmentation_flags.end()) == 1) {
                bgp_flow_spec_operator_byte.set_end_of_list_bit();
            }

            // Set match bit if we asked to do it
            if (flow_spec_rule.set_match_bit_for_fragmentation_flags) {
                bgp_flow_spec_operator_byte.set_match_bit();
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_operator_byte);

            if (*itr == flow_spec_fragmentation_types_t::FLOW_SPEC_DONT_FRAGMENT) {
                bgp_flow_spec_fragmentation_entity.dont_fragment = 1;
            } else if (*itr == flow_spec_fragmentation_types_t::FLOW_SPEC_IS_A_FRAGMENT) {
                bgp_flow_spec_fragmentation_entity.is_fragment = 1;
            } else if (*itr == flow_spec_fragmentation_types_t::FLOW_SPEC_FIRST_FRAGMENT) {
                bgp_flow_spec_fragmentation_entity.first_fragment = 1;
            } else if (*itr == flow_spec_fragmentation_types_t::FLOW_SPEC_LAST_FRAGMENT) {
                bgp_flow_spec_fragmentation_entity.last_fragment = 1;
            } else if (*itr == flow_spec_fragmentation_types_t::FLOW_SPEC_NOT_A_FRAGMENT) {
                // Structure without any flags enabled
            } else {
                logger << log4cpp::Priority::WARN << "Very strange packet without fragmentation options";
                return false;
            }

            mp_nlri_flow_spec.append_data_as_object_ptr(&bgp_flow_spec_fragmentation_entity);
        }
    }

    if (mp_nlri_flow_spec.is_failed()) {
        logger << log4cpp::Priority::WARN << "Internal issues with mp_nlri_flow_spec binary buffer";
        return false;
    }

    return true;
}

// Prepare BGP MP attribute for flow spec
bool encode_bgp_flow_spec_elements_into_bgp_mp_attribute(const flow_spec_rule_t& flow_spec_rule,
                                                         dynamic_binary_buffer_t& bgp_mp_ext_flow_spec_header_as_binary_array,
                                                         bool add_preamble) {
    dynamic_binary_buffer_t mp_nlri_binary_buffer;
    bool mp_nlri_encode_result = encode_bgp_flow_spec_elements_as_mp_nlri(flow_spec_rule, mp_nlri_binary_buffer);

    if (!mp_nlri_encode_result) {
        logger << log4cpp::Priority::WARN << "call of encode_bgp_flow_spec_elements_as_mp_nlri failed";
        return false;
    }

    uint8_t nlri_length = mp_nlri_binary_buffer.get_used_size();

    if (nlri_length >= 240) {
        logger << log4cpp::Priority::WARN << "We should encode length in two bytes";
        return false;
    }

    logger << log4cpp::Priority::DEBUG << "Encoded flow spec elements as MP Reach NLRI with size: " << int(nlri_length);

    bgp_attribute_multiprotocol_extensions_t bgp_attribute_multiprotocol_extensions;
    bgp_attribute_multiprotocol_extensions.attribute_length =
        sizeof(bgp_mp_ext_flow_spec_header_t) + sizeof(nlri_length) + mp_nlri_binary_buffer.get_used_size();

    logger << log4cpp::Priority::DEBUG
           << "BGP MP reach attribute length: " << int(bgp_attribute_multiprotocol_extensions.attribute_length);
    // Prepare flow spec MP Extenstion attribute
    bgp_mp_ext_flow_spec_header_as_binary_array.set_maximum_buffer_size_in_bytes(2048);

    bgp_mp_ext_flow_spec_header_t bgp_mp_ext_flow_spec_header;
    bgp_mp_ext_flow_spec_header.host_byte_order_to_network_byte_order();

    // For one very special GoBGP specific encoding we need capability to strip these fields
    if (add_preamble) {
        bgp_mp_ext_flow_spec_header_as_binary_array.append_data_as_object_ptr(&bgp_attribute_multiprotocol_extensions);
        bgp_mp_ext_flow_spec_header_as_binary_array.append_data_as_object_ptr(&bgp_mp_ext_flow_spec_header);
    }

    bgp_mp_ext_flow_spec_header_as_binary_array.append_data_as_object_ptr(&nlri_length);
    bgp_mp_ext_flow_spec_header_as_binary_array.append_dynamic_buffer(mp_nlri_binary_buffer);

    if (bgp_mp_ext_flow_spec_header_as_binary_array.is_failed()) {
        logger << log4cpp::Priority::WARN << "We have issues with binary buffer in flow spec crafter code";
        return false;
    }

    return true;
}

bool encode_bgp_flow_spec_action_as_extended_attribute(const bgp_flow_spec_action_t& bgp_flow_spec_action,
                                                       dynamic_binary_buffer_t& extended_attributes_as_binary_array) {

    // Allocate buffer
    // We use two kind of structures here:
    // bgp_extended_community_element_flow_spec_rate_t and bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value_t_t
    // As they have same size we use size from one of them
    extended_attributes_as_binary_array.set_maximum_buffer_size_in_bytes(
        sizeof(bgp_extended_community_attribute_t) + 1 * sizeof(bgp_extended_community_element_flow_spec_rate_t));

    bgp_extended_community_attribute_t bgp_extended_community_attribute;
    bgp_extended_community_attribute.attribute_length = sizeof(bgp_extended_community_element_t);

    if (bgp_flow_spec_action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD) {
        bgp_extended_community_element_flow_spec_rate_t bgp_extended_community_element_flow_spec_rate;

        logger << log4cpp::Priority::DEBUG << "We encode flow spec discard action as zero rate";
        bgp_extended_community_element_flow_spec_rate.rate_limit = 0;

        bgp_extended_community_element_flow_spec_rate.host_byte_order_to_network_byte_order();

        extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_attribute);
        extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_element_flow_spec_rate);

    } else if (bgp_flow_spec_action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT) {
        bgp_extended_community_element_flow_spec_rate_t bgp_extended_community_element_flow_spec_rate;

        logger << log4cpp::Priority::DEBUG << "Encode rate limit value " << bgp_flow_spec_action.get_rate_limit();
        bgp_extended_community_element_flow_spec_rate.rate_limit = bgp_flow_spec_action.get_rate_limit();

        bgp_extended_community_element_flow_spec_rate.host_byte_order_to_network_byte_order();

        extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_attribute);
        extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_element_flow_spec_rate);
    } else if (bgp_flow_spec_action.get_type() == bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT) {
        bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value_t_t bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value;

        bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value.set_redirect_as(
            bgp_flow_spec_action.get_redirect_as());
        bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value.set_redirect_value(
            bgp_flow_spec_action.get_redirect_value());

        extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_attribute);
        extended_attributes_as_binary_array.append_data_as_object_ptr(
            &bgp_extended_community_element_flow_spec_redirect_2_octet_as_4_octet_value);
    } else {
        logger << log4cpp::Priority::WARN << "We support only discard, rate limit, redirect actions";
        return false;
    }

    return true;
}

bool encode_bgp_flow_spec_next_hop_as_extended_attribute(uint32_t next_hop_ipv4,
                                                         dynamic_binary_buffer_t& extended_attributes_as_binary_array) {

    // Allocate buffer
    extended_attributes_as_binary_array.set_maximum_buffer_size_in_bytes(
        sizeof(bgp_extended_community_attribute_t) + sizeof(bgp_extended_community_element_flow_spec_ipv4_next_hop_t));

    bgp_extended_community_attribute_t bgp_extended_community_attribute;
    bgp_extended_community_attribute.attribute_length = sizeof(bgp_extended_community_element_t);

    // Set next hop value for structure
    bgp_extended_community_element_flow_spec_ipv4_next_hop_t bgp_extended_community_element_flow_spec_next_hop_ipv4;
    bgp_extended_community_element_flow_spec_next_hop_ipv4.next_hop_ipv4 = next_hop_ipv4;

    // Well, it does nothing but we can do it anyway for consistency
    bgp_extended_community_element_flow_spec_next_hop_ipv4.host_byte_order_to_network_byte_order();

    extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_attribute);
    extended_attributes_as_binary_array.append_data_as_object_ptr(&bgp_extended_community_element_flow_spec_next_hop_ipv4);

    return true;
}

std::string get_flow_spec_type_name_by_number(uint8_t flow_spec_type) {
    switch (flow_spec_type) {
    case FLOW_SPEC_ENTITY_DESTINATION_PREFIX:
        return "FLOW_SPEC_ENTITY_DESTINATION_PREFIX";
        break;
    case FLOW_SPEC_ENTITY_SOURCE_PREFIX:
        return "FLOW_SPEC_ENTITY_SOURCE_PREFIX";
        break;
    case FLOW_SPEC_ENTITY_IP_PROTOCOL:
        return "FLOW_SPEC_ENTITY_IP_PROTOCOL";
        break;
    case FLOW_SPEC_ENTITY_PORT:
        return "FLOW_SPEC_ENTITY_PORT";
        break;
    case FLOW_SPEC_ENTITY_DESTINATION_PORT:
        return "FLOW_SPEC_ENTITY_DESTINATION_PORT";
        break;
    case FLOW_SPEC_ENTITY_SOURCE_PORT:
        return "FLOW_SPEC_ENTITY_SOURCE_PORT";
        break;
    case FLOW_SPEC_ENTITY_ICMP_TYPE:
        return "FLOW_SPEC_ENTITY_ICMP_TYPE";
        break;
    case FLOW_SPEC_ENTITY_ICMP_CODE:
        return "FLOW_SPEC_ENTITY_ICMP_CODE";
        break;
    case FLOW_SPEC_ENTITY_TCP_FLAGS:
        return "FLOW_SPEC_ENTITY_TCP_FLAGS";
        break;
    case FLOW_SPEC_ENTITY_PACKET_LENGTH:
        return "FLOW_SPEC_ENTITY_PACKET_LENGTH";
        break;
    case FLOW_SPEC_ENTITY_DSCP:
        return "FLOW_SPEC_ENTITY_DSCP";
        break;
    case FLOW_SPEC_ENTITY_FRAGMENT:
        return "FLOW_SPEC_ENTITY_FRAGMENT";
        break;
    default:
        return "UNKNOWN";
        break;
    }
}

bool flow_spec_decode_nlri_value(uint8_t* data_ptr, uint32_t data_length, flow_spec_rule_t& flow_spec_rule) {
    // We make copy because we will change this value so often
    uint8_t* local_data_ptr = data_ptr;
    uint8_t* packet_end     = data_ptr + data_length;

    /* Flow specification components must follow strict type ordering.
     * A given component type may or may not be present in the specification, but
     * if present,
     * it MUST precede any component of higher numeric type value.
     * Source: https://tools.ietf.org/html/rfc5575
     */

    // logger << log4cpp::Priority::WARN << "Hex dump of NLRI value:"         ;
    // logger << log4cpp::Priority::WARN <<
    // print_binary_string_as_hex_with_leading_0x(data_ptr,
    // data_length);
    // logger << log4cpp::Priority::WARN         ;

    // We could use zero here because we haven't zero type for BGP Flow Spec
    // elements
    uint8_t last_processed_type = 0;

    while (local_data_ptr < packet_end) {
        if (*local_data_ptr < last_processed_type) {
            logger << log4cpp::Priority::WARN
                   << "RFC violation detected. Implementation sent BGP flow spec "
                      "elements in incorrect order";
        }

        last_processed_type = *local_data_ptr;

        // logger << log4cpp::Priority::WARN << "Process type: " <<
        // get_flow_spec_type_name_by_number(last_processed_type)
        //         ;

        // Decode IPv4 prefixes
        if (*local_data_ptr == FLOW_SPEC_ENTITY_DESTINATION_PREFIX or *local_data_ptr == FLOW_SPEC_ENTITY_SOURCE_PREFIX) {
            // Well, we've found BGP encoded subnet. Let's parse it!

            if (*local_data_ptr == FLOW_SPEC_ENTITY_DESTINATION_PREFIX && flow_spec_rule.destination_subnet_ipv4_used) {
                logger << log4cpp::Priority::WARN << "For some strange reasons we got two second destination prefix";
                return false;
            }

            if (*local_data_ptr == FLOW_SPEC_ENTITY_SOURCE_PREFIX && flow_spec_rule.source_subnet_ipv4_used) {
                logger << log4cpp::Priority::WARN
                       << "For some strange reasons we got second source prefix. "
                          "Only one allowed";
                return false;
            }

            // We need least two bytes here (type + prefix length)
            if (packet_end - local_data_ptr < 2) {
                logger << log4cpp::Priority::WARN << "Too short packet. We need more data for bgp encoded subnet";
                return false;
            }

            uint8_t prefix_bit_length   = *(local_data_ptr + 1);
            uint32_t prefix_byte_length = how_much_bytes_we_need_for_storing_certain_subnet_mask(prefix_bit_length);

            uint32_t full_size_of_bgp_encoded_subnet = 2 + prefix_byte_length;

            if (packet_end - local_data_ptr < full_size_of_bgp_encoded_subnet) {
                logger << log4cpp::Priority::WARN << "We haven't enough data for this prefix with length " << prefix_bit_length;
                return false;
            }

            subnet_cidr_mask_t extracted_prefix;

            bool decode_nlri_result = decode_bgp_subnet_encoding_ipv4_raw(local_data_ptr + 1, extracted_prefix);

            if (!decode_nlri_result) {
                logger << log4cpp::Priority::WARN << "Could not decode FLOW_SPEC_ENTITY_DESTINATION_PREFIX";
                return false;
            }

            if (*local_data_ptr == FLOW_SPEC_ENTITY_DESTINATION_PREFIX) {
                flow_spec_rule.set_destination_subnet_ipv4(extracted_prefix);
            }

            if (*local_data_ptr == FLOW_SPEC_ENTITY_SOURCE_PREFIX) {
                flow_spec_rule.set_source_subnet_ipv4(extracted_prefix);
            }

            // Reduce packet length
            // 1 means length of type
            local_data_ptr += full_size_of_bgp_encoded_subnet;
        } else if (*local_data_ptr == FLOW_SPEC_ENTITY_PORT or *local_data_ptr == FLOW_SPEC_ENTITY_DESTINATION_PORT or
                   *local_data_ptr == FLOW_SPEC_ENTITY_SOURCE_PORT or *local_data_ptr == FLOW_SPEC_ENTITY_IP_PROTOCOL or
                   *local_data_ptr == FLOW_SPEC_ENTITY_PACKET_LENGTH or *local_data_ptr == FLOW_SPEC_ENTITY_FRAGMENT or
                   *local_data_ptr == FLOW_SPEC_ENTITY_TCP_FLAGS) {
            uint8_t current_type = *local_data_ptr;

            // Skip type field
            local_data_ptr++;

            // Different type of port's
            if (current_type == FLOW_SPEC_ENTITY_PORT) {
                logger << log4cpp::Priority::WARN << "We do not support common ports";
                return false;
            }

            uint32_t scanned_bytes = 0;
            multiple_flow_spec_enumerable_items_t scanned_items;
            bool result = read_one_or_more_values_encoded_with_operator_byte(local_data_ptr, packet_end, scanned_bytes, scanned_items);

            // This one is considered non fatal, we try to do our best in parsing it
            if (!result) {
                logger << log4cpp::Priority::WARN << "read_one_or_more_values_encoded_with_operator_byte returned error but we may have some values parsed before issue happened";
            }

            for (auto extracted_item : scanned_items) {
                if (current_type == FLOW_SPEC_ENTITY_TCP_FLAGS) {
                    if (extracted_item.value_length != 1) {
                        logger << log4cpp::Priority::WARN << "We do not support two byte encoded tcp fields";
                        return false;
                    }

                    // logger << log4cpp::Priority::WARN << "We have " <<
                    // extracted_item.value_length << " byte
                    // encoded tcp
                    // option field"         ;

                    bgp_flowspec_one_byte_byte_encoded_tcp_flags_t* bgp_flowspec_one_byte_byte_encoded_tcp_flags =
                        (bgp_flowspec_one_byte_byte_encoded_tcp_flags_t*)&extracted_item.one_byte_value;

                    // logger << log4cpp::Priority::WARN << bgp_flowspec_one_byte_byte_encoded_tcp_flags->print();

                    auto flagset = convert_one_byte_encoding_to_flowset(*bgp_flowspec_one_byte_byte_encoded_tcp_flags);

                    if (flagset.we_have_least_one_flag_enabled()) {
                        flow_spec_rule.add_tcp_flagset(flagset);
                    }
                } else if (current_type == FLOW_SPEC_ENTITY_FRAGMENT) {
                    if (extracted_item.value_length != 1) {
                        logger << log4cpp::Priority::WARN << "We could not encode fragmentation with two bytes";
                        return false;
                    }

                    bgp_flow_spec_fragmentation_entity_t* bgp_flow_spec_fragmentation_entity =
                        (bgp_flow_spec_fragmentation_entity_t*)&extracted_item.one_byte_value;

                    // logger << log4cpp::Priority::WARN << "Fragmentation header: " <<
                    // bgp_flow_spec_fragmentation_entity->print()         ;

                    if (bgp_flow_spec_fragmentation_entity->last_fragment == 1) {
                        flow_spec_rule.add_fragmentation_flag(flow_spec_fragmentation_types_t::FLOW_SPEC_LAST_FRAGMENT);
                    }

                    if (bgp_flow_spec_fragmentation_entity->first_fragment == 1) {
                        flow_spec_rule.add_fragmentation_flag(flow_spec_fragmentation_types_t::FLOW_SPEC_FIRST_FRAGMENT);
                    }

                    if (bgp_flow_spec_fragmentation_entity->is_fragment == 1) {
                        flow_spec_rule.add_fragmentation_flag(flow_spec_fragmentation_types_t::FLOW_SPEC_IS_A_FRAGMENT);
                    }

                    if (bgp_flow_spec_fragmentation_entity->dont_fragment == 1) {
                        flow_spec_rule.add_fragmentation_flag(flow_spec_fragmentation_types_t::FLOW_SPEC_DONT_FRAGMENT);
                    }

                    // What we should do with flag FLOW_SPEC_NOT_A_FRAGMENT from bgp_flow_spec
                    // class?
                    // Very interesting because we haven't something like this in protocol
                    // :)
                    // In ExaBGP Thomas Mangin interpret this case as "not a fragment"
                    // So when we haven't any other flags enabled we interpret it as "not
                    // a
                    // fragment"
                    if (bgp_flow_spec_fragmentation_entity->last_fragment == 0 &&
                        bgp_flow_spec_fragmentation_entity->first_fragment == 0 &&
                        bgp_flow_spec_fragmentation_entity->is_fragment == 0 &&
                        bgp_flow_spec_fragmentation_entity->dont_fragment == 0) {

                        flow_spec_rule.add_fragmentation_flag(flow_spec_fragmentation_types_t::FLOW_SPEC_NOT_A_FRAGMENT);
                    }
                }

                if (current_type == FLOW_SPEC_ENTITY_SOURCE_PORT) {
                    flow_spec_rule.add_source_port(extracted_item.two_byte_value);
                }

                if (current_type == FLOW_SPEC_ENTITY_DESTINATION_PORT) {
                    flow_spec_rule.add_destination_port(extracted_item.two_byte_value);
                }

                if (current_type == FLOW_SPEC_ENTITY_PACKET_LENGTH) {
                    flow_spec_rule.add_packet_length(extracted_item.two_byte_value);
                }

                if (current_type == FLOW_SPEC_ENTITY_IP_PROTOCOL) {
                    // Do sanity checks for protocol number
                    if (extracted_item.two_byte_value > 255) {
                        logger << log4cpp::Priority::ERROR << "Protocol number value " << extracted_item.two_byte_value
                               << " exceeds maximum 255";
                        return false;
                    }

                    ip_protocol_t protocol = get_ip_protocol_enum_type_from_integer(uint8_t(extracted_item.two_byte_value));
                    flow_spec_rule.add_protocol(protocol);
                }
            }

            local_data_ptr += scanned_bytes;
        } else {
            logger << log4cpp::Priority::WARN << "We could not handle flow spec element type "
                   << uint32_t(*local_data_ptr) << " pretty type: " << get_flow_spec_type_name_by_number(*local_data_ptr);
            return false;
        }
    }

    if (local_data_ptr != packet_end) {
        logger << log4cpp::Priority::WARN << "For some strange reasons we haven't parsed whole packet";
    }

    return true;
}

bool read_one_or_more_values_encoded_with_operator_byte(uint8_t* start,
                                                        uint8_t* packet_end,
                                                        uint32_t& readed_bytes,
                                                        multiple_flow_spec_enumerable_items_t& multiple_flow_spec_enumerable_items) {
    // TODO: pretty danegrous idea to do infinite loop and we are using 100
    // iterations here for
    // worst case
    uint8_t* local_data_ptr = start;

    for (int i = 0; i < 100; i++) {
        if (packet_end - local_data_ptr < sizeof(bgp_flow_spec_operator_byte_t)) {
            logger << log4cpp::Priority::WARN << "Too short data for FLOW_SPEC_ENTITY_IP_PROTOCOL";
            return false;
        }

        bgp_flow_spec_operator_byte_t* bgp_flow_spec_operator_byte = (bgp_flow_spec_operator_byte_t*)local_data_ptr;
        // logger << log4cpp::Priority::WARN << "Byte operator: " <<
        // bgp_flow_spec_operator_byte->print() <<
        // std::endl;

        // We do not support almost all custom fields
        if (bgp_flow_spec_operator_byte->less_than == 1 or bgp_flow_spec_operator_byte->greater_than == 1) {
            logger << log4cpp::Priority::WARN << "We do not support greater than or lower than in flow spec";
            return false;
        }

        if (bgp_flow_spec_operator_byte->and_bit == 1) {
            logger << log4cpp::Priority::WARN << "We do not support and opertations in flow spec";
            return false;
        }

        if (bgp_flow_spec_operator_byte->get_value_length() != 2 && bgp_flow_spec_operator_byte->get_value_length() != 1) {
            logger << log4cpp::Priority::WARN << "We could encode data only with 1 or 2 bytes. ";
            return false;
        }

        if (packet_end - local_data_ptr < sizeof(bgp_flow_spec_operator_byte_t) + bgp_flow_spec_operator_byte->get_value_length()) {
            logger << log4cpp::Priority::WARN << "Not enough data for bgp_flow_spec_operator_byte_t";
            return false;
        }

        flow_spec_enumerable_lement element;

        if (bgp_flow_spec_operator_byte->get_value_length() == 1) {
            element.one_byte_value = *((uint8_t*)(local_data_ptr + sizeof(bgp_flow_spec_operator_byte_t)));

            // We will sue two byte version as common accessor
            element.two_byte_value = element.one_byte_value;
            element.value_length   = 1;
            element.operator_byte  = *bgp_flow_spec_operator_byte;

            multiple_flow_spec_enumerable_items.push_back(element);
        } else if (bgp_flow_spec_operator_byte->get_value_length() == 2) {
            element.two_byte_value = *((uint16_t*)(local_data_ptr + sizeof(bgp_flow_spec_operator_byte_t)));

            // TODO: not sure about it? We really need it?
            element.two_byte_value = ntohs(element.two_byte_value);
            element.operator_byte  = *bgp_flow_spec_operator_byte;

            multiple_flow_spec_enumerable_items.push_back(element);
        } else {
            logger << log4cpp::Priority::WARN << "Unexpected length for flow spec enumerable value: "
                   << uint32_t(bgp_flow_spec_operator_byte->get_value_length());
            return false;
        }

        // Shift pointer to next element
        local_data_ptr += sizeof(bgp_flow_spec_operator_byte_t) + bgp_flow_spec_operator_byte->get_value_length();

        // If this was last lement in list just stop this loop
        if (bgp_flow_spec_operator_byte->end_of_list == 1) {
            break;
        }
    }

    // Return number of scanned bytes
    readed_bytes = local_data_ptr - start;

    return true;
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

    if (lhs.agent_addresses != rhs.agent_addresses) {
        return false;
    }

    if (lhs.source_asns != rhs.source_asns) {
        return false;
    }

    if (lhs.destination_asns != rhs.destination_asns) {
        return false;
    }

    if (lhs.input_interfaces != rhs.input_interfaces) {
        return false;
    }

    if (lhs.output_interfaces != rhs.output_interfaces) {
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

    if (json_doc.contains("source_asns")) {
        std::vector<int64_t> asns_as_ints;

        // JSON library will allow negative values even if we ask uint32_t as type
        // That's why we use int64_t and then implement range checking
        try {
            asns_as_ints = json_doc["source_asns"].get<std::vector<int64_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode source_asns " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode source_asns";
            return false;
        }

        for (auto asn : asns_as_ints) {
            if (asn < 0) {
                logger << log4cpp::Priority::ERROR << "Could not parse ASN, it cannot be negative: " << asn;
                return false;
            }

            if (asn > std::numeric_limits<std::uint32_t>::max()) {
                logger << log4cpp::Priority::ERROR
                       << "Could not parse ASN, it cannot be bigger then: " << std::numeric_limits<std::uint32_t>::max();
                return false;
            }

            flow_spec_rule.add_source_asn((uint32_t)asn);
        }
    }

    if (json_doc.contains("destination_asns")) {
        std::vector<int64_t> asns_as_ints;

        // JSON library will allow negative values even if we ask uint32_t as type
        // That's why we use int64_t and then implement range checking
        try {
            asns_as_ints = json_doc["destination_asns"].get<std::vector<int64_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode destination_asns " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode destination_asns";
            return false;
        }

        for (auto asn : asns_as_ints) {
            if (asn < 0) {
                logger << log4cpp::Priority::ERROR << "Could not parse ASN, it cannot be negative: " << asn;
                return false;
            }

            if (asn > std::numeric_limits<std::uint32_t>::max()) {
                logger << log4cpp::Priority::ERROR
                       << "Could not parse ASN, it cannot be bigger then: " << std::numeric_limits<std::uint32_t>::max();
                return false;
            }

            flow_spec_rule.add_destination_asn(asn);
        }
    }

    if (json_doc.contains("input_interfaces")) {
        std::vector<int64_t> interfaces_as_ints;

        // JSON library will allow negative values even if we ask uint32_t as type
        // That's why we use int64_t and then implement range checking
        try {
            interfaces_as_ints = json_doc["input_interfaces"].get<std::vector<int64_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode source_asns " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode intput_interfaces";
            return false;
        }

        for (auto interface : interfaces_as_ints) {
            if (interface < 0) {
                logger << log4cpp::Priority::ERROR << "Could not parse interface, it cannot be negative: " << interface;
                return false;
            }

            if (interface > std::numeric_limits<std::uint32_t>::max()) {
                logger << log4cpp::Priority::ERROR
                       << "Could not parse interface, it cannot be bigger then: " << std::numeric_limits<std::uint32_t>::max();
                return false;
            }

            flow_spec_rule.add_input_interface((uint32_t)interface);
        }
    }

    if (json_doc.contains("output_interfaces")) {
        std::vector<int64_t> interfaces_as_ints;

        // JSON library will allow negative values even if we ask uint32_t as type
        // That's why we use int64_t and then implement range checking
        try {
            interfaces_as_ints = json_doc["output_interfaces"].get<std::vector<int64_t>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode source_asns " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode intput_interfaces";
            return false;
        }

        for (auto interface : interfaces_as_ints) {
            if (interface < 0) {
                logger << log4cpp::Priority::ERROR << "Could not parse interface, it cannot be negative: " << interface;
                return false;
            }

            if (interface > std::numeric_limits<std::uint32_t>::max()) {
                logger << log4cpp::Priority::ERROR
                       << "Could not parse interface, it cannot be bigger then: " << std::numeric_limits<std::uint32_t>::max();
                return false;
            }

            flow_spec_rule.add_output_interface((uint32_t)interface);
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

    if (json_doc.contains("agent_addresses")) {
        std::vector<std::string> agent_addresses_vector_as_strings;

        try {
            agent_addresses_vector_as_strings = json_doc["agent_addresses"].get<std::vector<std::string>>();
        } catch (nlohmann::json::exception& e) {
            logger << log4cpp::Priority::ERROR << "Could not decode agent_addresses " << e.what();
            return false;
        } catch (...) {
            logger << log4cpp::Priority::ERROR << "Could not decode agent_addresses";
            return false;
        }

        for (const auto& agent_address_as_string : agent_addresses_vector_as_strings) {
            uint32_t ipv4_agent_address = 0;

            auto ip_parser_result = convert_ip_as_string_to_uint_safe(agent_address_as_string, ipv4_agent_address);

            if (!ip_parser_result) {
                logger << log4cpp::Priority::ERROR << "Could not parse this " << agent_address_as_string << " as IPv4 address";
                return false;
            }

            flow_spec_rule.add_agent_address(ipv4_agent_address);
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

    if (!flow_spec_rule.source_asns.empty()) {
        flow_json["source_asns"] = flow_spec_rule.source_asns;
    }

    if (!flow_spec_rule.destination_asns.empty()) {
        flow_json["destination_asns"] = flow_spec_rule.destination_asns;
    }

    if (!flow_spec_rule.input_interfaces.empty()) {
        flow_json["input_interfaces"] = flow_spec_rule.input_interfaces;
    }

    if (!flow_spec_rule.output_interfaces.empty()) {
        flow_json["output_interfaces"] = flow_spec_rule.output_interfaces;
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

    if (!flow_spec_rule.ipv4_nexthops.empty()) {
        flow_json["ipv4_nexthops"] = nlohmann::json::array();

        for (auto ipv4_next_hop : flow_spec_rule.ipv4_nexthops) {
            flow_json["ipv4_nexthops"].push_back(convert_ip_as_uint_to_string(ipv4_next_hop));
        }
    }

    if (!flow_spec_rule.agent_addresses.empty()) {
        flow_json["agent_addresses"] = nlohmann::json::array();

        for (auto agent_address_ipv4 : flow_spec_rule.agent_addresses) {
            flow_json["agent_addresses"].push_back(convert_ip_as_uint_to_string(agent_address_ipv4));
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

        action_json["redirect_target_as"]    = flow_spec_rule.action.get_redirect_as();
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

// This function checks that source or destination fields of flow spec rule belong to specified patricia tree
// As side effect function returns IP address of our host related to flow spec rule
// TODO: this function does not support IPv6 at all
bool validate_flow_spec_to_belong_to_patricia(const flow_spec_rule_t& flow_spec_rule,
                                              const lookup_tree_32bit_t& lookup_tree_ipv4,
                                              const lookup_tree_128bit_t& lookup_tree_ipv6,
                                              uint32_t& client_ip) {
    if (!(flow_spec_rule.source_subnet_ipv4_used || flow_spec_rule.destination_subnet_ipv4_used ||
          flow_spec_rule.source_subnet_ipv6_used || flow_spec_rule.destination_subnet_ipv6_used)) {
        logger << log4cpp::Priority::ERROR << "Both source and destination fields for for both IPv4 and flow spec are empty";
        return false;
    }

    // Check prefix lengths for source prefix
    if (flow_spec_rule.source_subnet_ipv4_used && flow_spec_rule.source_subnet_ipv4.cidr_prefix_length != 32) {
        logger << log4cpp::Priority::ERROR << "We allow only /32 announces for destination IPv4 prefixes";
        return false;
    }

    if (flow_spec_rule.source_subnet_ipv6_used && flow_spec_rule.source_subnet_ipv6.cidr_prefix_length != 128) {
        logger << log4cpp::Priority::ERROR << "We allow only /128 announces for destination IPv6 prefixes";
        return false;
    }

    // Check prefix lengths for destination prefix
    if (flow_spec_rule.destination_subnet_ipv4_used && flow_spec_rule.destination_subnet_ipv4.cidr_prefix_length != 32) {
        logger << log4cpp::Priority::ERROR << "We allow only /32 announces for destination IPv4 prefixes";
        return false;
    }

    if (flow_spec_rule.destination_subnet_ipv6_used && flow_spec_rule.destination_subnet_ipv6.cidr_prefix_length != 128) {
        logger << log4cpp::Priority::ERROR << "We allow only /128 announces for destination IPv6 prefixes";
        return false;
    }

    // TODO: we do not have Patricia lookup logic in place and we just disable it
    if (flow_spec_rule.destination_subnet_ipv6_used || flow_spec_rule.source_subnet_ipv6_used) {
        logger << log4cpp::Priority::ERROR << "Validation in IPv6 mode is not supported yet";
        return false;
    }

    if (flow_spec_rule.destination_subnet_ipv4_used && flow_spec_rule.source_subnet_ipv4_used) {
        // We have both networks specified

        // Lookup destination network
        bool we_found_destination_subnet = lookup_tree_ipv4.lookup_network(flow_spec_rule.destination_subnet_ipv4);

        // Lookup source network
        bool we_found_source_subnet = lookup_tree_ipv4.lookup_network(flow_spec_rule.source_subnet_ipv4);

        if (!we_found_destination_subnet && !we_found_source_subnet) {
            logger << log4cpp::Priority::ERROR << "Both source and destination addresses do not belong to your ranges";
            return false;
        }

        if (we_found_destination_subnet) {
            client_ip = flow_spec_rule.destination_subnet_ipv4.subnet_address;
        }

        if (we_found_source_subnet) {
            client_ip = flow_spec_rule.source_subnet_ipv4.subnet_address;
        }

        return true;
    } else if (flow_spec_rule.destination_subnet_ipv4_used) {
        // We have only destination network
        bool we_found_this_subnet = lookup_tree_ipv4.lookup_network(flow_spec_rule.destination_subnet_ipv4);

        if (!we_found_this_subnet) {
            logger << log4cpp::Priority::ERROR << "Could not find destination subnet in our networks list";
            return false;
        }

        client_ip = flow_spec_rule.destination_subnet_ipv4.subnet_address;

        return true;
    } else if (flow_spec_rule.source_subnet_ipv4_used) {
        // We have only source network
        bool we_found_this_subnet = lookup_tree_ipv4.lookup_network(flow_spec_rule.source_subnet_ipv4);

        if (!we_found_this_subnet) {
            logger << log4cpp::Priority::ERROR << "Could not find source subnet in our networks list";
            return false;
        }

        client_ip = flow_spec_rule.source_subnet_ipv4.subnet_address;

        return true;
    }

    return true;
}

// This function checks that source or destination fields of flow spec rule belong to specified IP address
bool validate_flow_spec_ipv4(const flow_spec_rule_t& flow_spec_rule, uint32_t client_ip_as_integer) {
    if (!(flow_spec_rule.source_subnet_ipv4_used || flow_spec_rule.destination_subnet_ipv4_used)) {
        logger << log4cpp::Priority::ERROR << "both source and destination fields for flow spec are empty";
        return false;
    }

    // // Prevent packets which exceeds 1500 (default MTU)
    for (auto packet_length : flow_spec_rule.packet_lengths) {
        if (packet_length > reject_flow_spec_validation_if_slow_spec_length_exceeds_this_number) {
            logger << log4cpp::Priority::ERROR << "Flow spec's length field " << packet_length << " exceeds maximum allowed value "
                   << reject_flow_spec_validation_if_slow_spec_length_exceeds_this_number;
            return false;
        }
    }

    // At this step we have least one (src or dst) field
    // TODO: we could not check src/dst fields wider than /32 at this moment! Add this feature!
    subnet_cidr_mask_t client_subnet(client_ip_as_integer, 32);

    if (flow_spec_rule.source_subnet_ipv4_used && client_subnet == flow_spec_rule.source_subnet_ipv4) {
        return true;
    }

    if (flow_spec_rule.destination_subnet_ipv4_used && client_subnet == flow_spec_rule.destination_subnet_ipv4) {
        return true;
    }

    logger << log4cpp::Priority::ERROR << "flow spec validation failed because src or dst subnets in flow spec does not match customer IP";
    return false;
}

// Is it range valid for port?
bool valid_port(int32_t port) {
    return port >= 0 && port <= 65535;
}
