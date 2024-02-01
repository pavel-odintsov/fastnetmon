// That's not a module as we do refactoring right now in small steps
// TODO: place make it proper module

void update_ipfix_sampling_rate(uint32_t sampling_rate, const std::string& client_addres_in_string_format);

// https://tools.ietf.org/html/rfc5101#page-18
bool process_ipfix_options_template(const uint8_t* pkt, size_t flowset_length, uint32_t source_id, const std::string& client_addres_in_string_format) {
    const ipfix_options_header_common_t* options_template_header = (ipfix_options_header_common_t*)pkt;

    if (flowset_length < sizeof(ipfix_options_header_common_t)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX options template header " << flowset_length << " bytes. "
               << "Agent IP: " << client_addres_in_string_format;
        return false;
    }

    uint16_t flowset_id = fast_ntoh(options_template_header->flowset_id);

    // Yes, we have flow set length in options_template_header->length but we've read it on previous step and we can use it from argument of this function instead

    if (flowset_id != IPFIX_OPTIONS_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR << "For options template we expect " << IPFIX_OPTIONS_FLOWSET_ID
               << "flowset_id but got "
                  "another id: "
               << flowset_id << "Agent IP: " << client_addres_in_string_format;

        return false;
    }

    // logger << log4cpp::Priority::INFO << "flowset_id " << flowset_id << " flowset_length: " << flowset_length;

    const ipfix_options_header_t* options_nested_header =
        (const ipfix_options_header_t*)(pkt + sizeof(ipfix_options_header_common_t));

    // Check that we have enough space in packet to read ipfix_options_header_t
    if (flowset_length < sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t)) {
        logger << log4cpp::Priority::ERROR << "Could not read specific header for IPFIX options template."
               << "Agent IP: " << client_addres_in_string_format;
        return false;
    }

    // logger << log4cpp::Priority::INFO << "raw undecoded data template_id: " << options_nested_header->template_id <<
    // " field_count: " << options_nested_header->field_count
    //    << " scope_field_count: " << options_nested_header->scope_field_count;

    // Get all fields from options_nested_header
    uint16_t template_id       = fast_ntoh(options_nested_header->template_id);
    uint16_t field_count       = fast_ntoh(options_nested_header->field_count);
    uint16_t scope_field_count = fast_ntoh(options_nested_header->scope_field_count);

    // According to RFC scope_field_count must not be zero but I'll assume that some vendors may fail to implement it
    // https://tools.ietf.org/html/rfc7011#page-24

    // logger << log4cpp::Priority::INFO << "Options template id: " << template_id << " field_count: " << field_count
    //       << " scope_field_count: " << scope_field_count;

    if (template_id <= 255) {
        logger << log4cpp::Priority::ERROR << "Template ID for IPFIX options template should be bigger than 255, got "
               << template_id << " Agent IP: " << client_addres_in_string_format;
        return false;
    }

    logger << log4cpp::Priority::DEBUG << "Options template id: " << template_id << " field_count: " << field_count
           << " scope_field_count: " << scope_field_count;


    // According to RFC field_count includes scope_field_count
    // https://tools.ietf.org/html/rfc7011#page-24 "Number of all fields in this Options Template Record, including the Scope Fields."

    if (scope_field_count > field_count) {
        logger << log4cpp::Priority::ERROR << "Number of scope fields " << scope_field_count
               << " cannot exceed number of all fields: " << field_count << " Agent IP: " << client_addres_in_string_format;
        return false;
    }

    // Calculate number of all normal fields
    uint16_t normal_field_count = field_count - scope_field_count;

    // Shift our temporary pointer to place where scope section begins
    const uint8_t* current_pointer_in_packet =
        (const uint8_t*)(pkt + sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t));

    uint32_t scopes_total_size = 0;

    uint32_t scopes_payload_total_size = 0;

    // Then we have scope fields in packet, I'm not going to process them, I'll just skip them
    for (int scope_index = 0; scope_index < scope_field_count; scope_index++) {
        const ipfix_template_flowset_record_t* current_scopes_record =
            (const ipfix_template_flowset_record_t*)(current_pointer_in_packet);

        // Check that our attempt to read ipfix_template_flowset_record_t will not exceed packet length
        if (flowset_length < sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t) +
                                 sizeof(ipfix_template_flowset_record_t)) {
            logger << log4cpp::Priority::ERROR << "Attempt to read IPFIX flowset_record outside of packet. "
                   << "Agent IP: " << client_addres_in_string_format;
            return false;
        }

        uint16_t scope_field_size = fast_ntoh(current_scopes_record->length);
        uint16_t scope_field_type = fast_ntoh(current_scopes_record->type);

        logger << log4cpp::Priority::DEBUG << "Reading scope section with size " << scope_field_size << " and type: " << scope_field_type;

        // Increment scopes size
        scopes_total_size += sizeof(ipfix_template_flowset_record_t);

        // Increment payload size
        scopes_payload_total_size += scope_field_size;

        // Shift pointer to the end of current scope field
        current_pointer_in_packet = (const uint8_t*)(current_pointer_in_packet + sizeof(ipfix_template_flowset_record_t));
    }

    // We've reached normal fields section
    uint32_t normal_fields_total_size = 0;

    std::vector<template_record_t> template_records_map;

    uint32_t normal_fields_payload_total_size = 0;

    // Try to read all normal fields
    for (int field_index = 0; field_index < normal_field_count; field_index++) {
        const ipfix_template_flowset_record_t* current_normal_record =
            (const ipfix_template_flowset_record_t*)(current_pointer_in_packet);

        // Check that our attempt to read ipfix_template_flowset_record_t will not exceed packet length
        if (flowset_length < sizeof(ipfix_options_header_common_t) + sizeof(ipfix_options_header_t) +
                                 scopes_total_size + sizeof(ipfix_template_flowset_record_t)) {
            logger << log4cpp::Priority::ERROR << "Attempt to read IPFIX flowset_record outside of packet for normal field. "
                   << "Agent IP: " << client_addres_in_string_format;
            return false;
        }

        uint16_t normal_field_size = fast_ntoh(current_normal_record->length);
        uint16_t normal_field_type = fast_ntoh(current_normal_record->type);

        template_record_t current_record;
        current_record.record_type   = normal_field_type;
        current_record.record_length = normal_field_size;

        template_records_map.push_back(current_record);

        logger << log4cpp::Priority::DEBUG << "Reading IPFIX options field with size " << normal_field_size
               << " and type: " << normal_field_type;

        // Increment total field size
        normal_fields_total_size += sizeof(ipfix_template_flowset_record_t);

        // Increment total payload size
        normal_fields_payload_total_size += normal_field_size;

        // Shift pointer to the end of current normal field
        current_pointer_in_packet = (const uint8_t*)(current_pointer_in_packet + sizeof(ipfix_template_flowset_record_t));
    }

    template_t field_template{};

    field_template.template_id = template_id;
    field_template.records     = template_records_map;

    // I do not think that we use it in our logic but I think it's reasonable to set it to number of normal fields
    field_template.num_records = normal_field_count;

    field_template.total_length = normal_fields_payload_total_size + scopes_payload_total_size;
    field_template.type         = netflow_template_type_t::Options;

    field_template.option_scope_length = scopes_payload_total_size;

    // We need to know when we received it
    field_template.timestamp = current_inaccurate_time;

    // logger << log4cpp::Priority::INFO << "Read options template:" << print_template(field_template);

    // Add/update template
    bool updated                   = false;
    bool updated_existing_template = false;

    add_update_peer_template(netflow_protocol_version_t::ipfix, global_ipfix_templates, global_ipfix_templates_mutex, source_id,
                             template_id, client_addres_in_string_format, field_template, updated, updated_existing_template);

    // This code is not perfect from locks perspective as we read global_ipfix_templates without any locks below

    // NB! Please be careful with changing name of variable as it's part of serialisation protocol

    if (updated_existing_template) {
        ipfix_template_data_updates++;
    }

    return true;
}

bool process_ipfix_template(const uint8_t* pkt, size_t flowset_length, uint32_t source_id, const std::string& client_addres_in_string_format) {
    const ipfix_flowset_header_common_t* template_header = (const ipfix_flowset_header_common_t*)pkt;

    if (flowset_length < sizeof(*template_header)) {
        logger << log4cpp::Priority::ERROR << "Short IPFIX flowset template header " << flowset_length
               << " bytes. Agent IP: " << client_addres_in_string_format;
        return false;
    }

    if (ntohs(template_header->flowset_id) != IPFIX_TEMPLATE_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_ipfix_template expects only "
                  "IPFIX_TEMPLATE_FLOWSET_ID but "
                  "got another id: "
               << ntohs(template_header->flowset_id) << " Agent IP: " << client_addres_in_string_format;

        return false;
    }

    // These fields use quite complicated encoding and we need to identify them first
    bool ipfix_variable_length_elements_used = false;

    for (uint32_t offset = sizeof(*template_header); offset < flowset_length;) {
        const ipfix_template_flowset_header_t* tmplh = (const ipfix_template_flowset_header_t*)(pkt + offset);

        uint32_t template_id  = ntohs(tmplh->template_id);
        uint32_t record_count = ntohs(tmplh->record_count);

        offset += sizeof(*tmplh);

        std::vector<template_record_t> template_records_map;
        uint32_t total_template_data_size = 0;

        for (uint32_t i = 0; i < record_count; i++) {
            if (offset >= flowset_length) {
                logger << log4cpp::Priority::ERROR << "Short IPFIX flowset template. Agent IP: " << client_addres_in_string_format;
                return false;
            }

            const ipfix_template_flowset_record_t* tmplr = (const ipfix_template_flowset_record_t*)(pkt + offset);

            uint32_t record_type   = ntohs(tmplr->type);
            uint32_t record_length = ntohs(tmplr->length);

            template_record_t current_record;
            current_record.record_type   = record_type;
            current_record.record_length = record_length;

            // it's special size which actually means that variable length encoding was used for this field
            // https://datatracker.ietf.org/doc/html/rfc7011#page-37
            if (record_length == 65535) {
                ipfix_variable_length_elements_used = true;
            }

            template_records_map.push_back(current_record);

            offset += sizeof(*tmplr);

            if (record_type & IPFIX_ENTERPRISE) {
                offset += sizeof(uint32_t); /* XXX -- ? */
            }

            total_template_data_size += record_length;
        }

        // We use same struct as Netflow v9 because Netflow v9 and IPFIX use similar fields
        template_t field_template;

        field_template.template_id                         = template_id;
        field_template.num_records                         = record_count;
        field_template.total_length                        = total_template_data_size;
        field_template.records                             = template_records_map;
        field_template.type                                = netflow_template_type_t::Data;
        field_template.ipfix_variable_length_elements_used = ipfix_variable_length_elements_used;

        // We need to know when we received it
        field_template.timestamp = current_inaccurate_time;

        bool updated                   = false;
        bool updated_existing_template = false;

        add_update_peer_template(netflow_protocol_version_t::ipfix, global_ipfix_templates,
                                 global_ipfix_templates_mutex, source_id, template_id, client_addres_in_string_format,
                                 field_template, updated, updated_existing_template);


        if (updated_existing_template) {
            ipfix_template_data_updates++;
        }
    }

    return true;
}

bool ipfix_record_to_flow(uint32_t record_type, uint32_t record_length, const uint8_t* data, simple_packet_t& packet, netflow_meta_info_t& flow_meta) {
    switch (record_type) {
    case IPFIX_IN_BYTES:
        if (record_length > sizeof(packet.length)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IN_BYTES: " << record_length;
            }
        } else {
            BE_COPY(packet.length);

            // decode data in network byte order to host byte order
            packet.length = fast_ntoh(packet.length);

            // IPFIX carries only information about number of octets including IP headers and IP payload
            // which is exactly what we need for ip_length field
            packet.ip_length = packet.length;
        }

        break;
    case IPFIX_IN_PACKETS:
        if (record_length > sizeof(packet.number_of_packets)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IN_PACKETS: " << record_length;
            }

        } else {
            BE_COPY(packet.number_of_packets);

            packet.number_of_packets = fast_ntoh(packet.number_of_packets);
        }

        break;
    case IPFIX_IN_PROTOCOL:
        if (record_length > sizeof(packet.protocol)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IN_PROTOCOL: " << record_length;
            }

        } else {
            BE_COPY(packet.protocol);

            packet.protocol = fast_ntoh(packet.protocol);
        }

        break;
    case IPFIX_TCP_FLAGS:
        if (record_length == 1) {
            BE_COPY(packet.flags);
        } else if (record_length == 2) {
            // If exported as a single octet with reduced-size encoding, this Information Element covers the low-order
            // octet of this field (i.e, bits 0x80 to 0x01), omitting the ECN Nonce Sum and the three Future Use bits.
            // https://www.iana.org/assignments/ipfix/ipfix.xhtml
            // So we just copy second byte which carries same information as when it encoded with 1 byte
            memcpy(&packet.flags, data + 1, 1);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_TCP_FLAGS: " << record_length;
            }
        }

        break;
    case IPFIX_L4_SRC_PORT:
        if (record_length > sizeof(packet.source_port)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_L4_SRC_PORT: " << record_length;
            }

        } else {
            BE_COPY(packet.source_port);

            // We should convert port to host byte order
            packet.source_port = fast_ntoh(packet.source_port);
        }

        break;
    case IPFIX_L4_DST_PORT:
        if (record_length > sizeof(packet.destination_port)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_L4_DST_PORT: " << record_length;
            }

        } else {
            BE_COPY(packet.destination_port);

            // We should convert port to host byte order
            packet.destination_port = fast_ntoh(packet.destination_port);
        }

        break;
    case IPFIX_IPV4_SRC_ADDR:
        if (record_length > sizeof(packet.src_ip)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV4_SRC_ADDR: " << record_length;
            }

        } else {
            memcpy(&packet.src_ip, data, record_length);
        }

        break;
    case IPFIX_IPV4_DST_ADDR:
        if (record_length > sizeof(packet.dst_ip)) {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV4_DST_ADDR: " << record_length;
            }

        } else {
            memcpy(&packet.dst_ip, data, record_length);
        }

        break;
    // There is a similar field IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS but with slightly different meaning
    case IPFIX_IPV4_NEXT_HOP:
        if (record_length == 4) {
            uint32_t ip_next_hop_ipv4 = 0;
            memcpy(&ip_next_hop_ipv4, data, record_length);

            flow_meta.ip_next_hop_ipv4_set = true;
            flow_meta.ip_next_hop_ipv4     = ip_next_hop_ipv4;

            // std::cout << "IP next hop: " << convert_ip_as_uint_to_string(ip_next_hop_ipv4) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV4_NEXT_HOP: " << record_length;
            }
        }

        break;
    // There is a similar field IPFIX_IPV4_NEXT_HOP but with slightly different meaning
    case IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS:
        // Juniper MX uses this field
        if (record_length == 4) {
            uint32_t bgp_next_hop_ipv4 = 0;
            memcpy(&bgp_next_hop_ipv4, data, record_length);

            flow_meta.bgp_next_hop_ipv4_set = true;
            flow_meta.bgp_next_hop_ipv4     = bgp_next_hop_ipv4;

            // std::cout << "BGP next hop: " << convert_ip_as_uint_to_string(bgp_next_hop_ipv4) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS: " << record_length;
            }
        }

        break;
    case IPFIX_IPV6_NEXT_HOP:
        // Juniper MX uses this field
        if (record_length == 16) {
            in6_addr bgp_next_hop_ipv6{};
            memcpy(&bgp_next_hop_ipv6, data, record_length);

            flow_meta.bgp_next_hop_ipv6_set = true;
            flow_meta.bgp_next_hop_ipv6     = bgp_next_hop_ipv6;

            // std::cout << "bgp next hop: " << print_ipv6_address(ipv6_next_hop) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV6_NEXT_HOP: " << record_length;
            }
        }


        break;
    // According to https://www.iana.org/assignments/ipfix/ipfix.xhtml ASN can be 4 byte only
    // Unfortunately, customer (Intermedia) shared pcap with ASNs encoded as 2 byte values :(
    case IPFIX_SRC_AS:
        if (record_length == 4) {
            uint32_t src_asn = 0;
            memcpy(&src_asn, data, record_length);

            src_asn        = fast_ntoh(src_asn);
            packet.src_asn = src_asn;
        } else if (record_length == 2) {
            uint16_t src_asn = 0;
            memcpy(&src_asn, data, record_length);

            src_asn        = fast_ntoh(src_asn);
            packet.src_asn = src_asn;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_SRC_AS: " << record_length;
            }
        }

        break;
    case IPFIX_DST_AS:
        if (record_length == 4) {
            uint32_t dst_asn = 0;
            memcpy(&dst_asn, data, record_length);

            dst_asn        = fast_ntoh(dst_asn);
            packet.dst_asn = dst_asn;
        } else if (record_length == 2) {
            uint16_t dst_asn = 0;
            memcpy(&dst_asn, data, record_length);

            dst_asn        = fast_ntoh(dst_asn);
            packet.dst_asn = dst_asn;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_DST_AS: " << record_length;
            }
        }

        break;
    case IPFIX_SOURCE_MAC_ADDRESS:
        if (record_length == 6) {
            // Copy it directly to packet structure
            memcpy(&packet.source_mac, data, record_length);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for IPFIX_SOURCE_MAC_ADDRESS";
            }
        }
        break;
    case IPFIX_DESTINATION_MAC_ADDRESS:
        if (record_length == 6) {
            // Copy it directly to packet structure
            memcpy(&packet.destination_mac, data, record_length);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for IPFIX_DESTINATION_MAC_ADDRESS";
            }
        }
        break;
    // According to https://www.iana.org/assignments/ipfix/ipfix.xhtml interfaces can be 4 byte only
    case IPFIX_INPUT_SNMP:
        if (record_length == 4) {
            uint32_t input_interface = 0;
            memcpy(&input_interface, data, record_length);

            input_interface        = fast_ntoh(input_interface);
            packet.input_interface = input_interface;
        } else if (record_length == 2) {
            uint16_t input_interface = 0;
            memcpy(&input_interface, data, record_length);

            input_interface        = fast_ntoh(input_interface);
            packet.input_interface = input_interface;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_INPUT_SNMP: " << record_length;
            }
        }

        break;
    case IPFIX_OUTPUT_SNMP:
        if (record_length == 4) {
            uint32_t output_interface = 0;
            memcpy(&output_interface, data, record_length);

            output_interface        = fast_ntoh(output_interface);
            packet.output_interface = output_interface;
        } else if (record_length == 2) {
            uint16_t output_interface = 0;
            memcpy(&output_interface, data, record_length);

            output_interface        = fast_ntoh(output_interface);
            packet.output_interface = output_interface;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_OUTPUT_SNMP: " << record_length;
            }
        }

        break;
    case IPFIX_IPV6_SRC_ADDR:
        // It should be 16 bytes only
        if (record_length == 16) {
            memcpy(&packet.src_ipv6, data, record_length);
            // Set protocol version to IPv6
            packet.ip_protocol_version = 6;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV6_SRC_ADDR: " << record_length;
            }
        }

        break;
    case IPFIX_IPV6_DST_ADDR:
        // It should be 16 bytes only
        if (record_length == 16) {
            memcpy(&packet.dst_ipv6, data, record_length);
            // Set protocol version to IPv6
            packet.ip_protocol_version = 6;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_IPV6_DST_ADDR: " << record_length;
            }
        }
        break;
    case IPFIX_FIRST_SWITCHED:
        // Mikrotik uses this encoding
        if (record_length == 4) {
            uint32_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            packet.flow_start = flow_started;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FIRST_SWITCHED: " << record_length;
            }
        }

        break;
    case IPFIX_LAST_SWITCHED:
        // Mikrotik uses this encoding
        if (record_length == 4) {
            uint32_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            packet.flow_end = flow_finished;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_LAST_SWITCHED: " << record_length;
            }
        }

        break;
        // Juniper uses IPFIX_FLOW_START_MILLISECONDS and IPFIX_FLOW_END_MILLISECONDS
    case IPFIX_FLOW_START_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            // We cast unsigned to signed and it may cause issues
            packet.flow_start = flow_started;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_START_MILLISECONDS: " << record_length;
            }
        }

        break;
    case IPFIX_FLOW_END_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            // We cast unsigned to signed and it may cause issues
            packet.flow_end = flow_finished;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_END_MILLISECONDS: " << record_length;
            }
        }

        break;
        // Netgate TNSR uses IPFIX_FLOW_START_NANOSECONDS and IPFIX_FLOW_END_NANOSECONDS
    case IPFIX_FLOW_START_NANOSECONDS:
        if (record_length == 8) {
            uint64_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            // We cast unsigned to signed and it may cause issues
            packet.flow_start = flow_started;

            // Convert to milliseconds
            packet.flow_start = packet.flow_start / 1000000;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_START_NANOSECONDS: " << record_length;
            }
        }

        break;
    case IPFIX_FLOW_END_NANOSECONDS:
        if (record_length == 8) {
            uint64_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            // We cast unsigned to signed and it may cause issues
            packet.flow_end = flow_finished;

            // Convert to milliseconds
            packet.flow_end = packet.flow_end / 1000000;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_END_NANOSECONDS: " << record_length;
            }
        }

        break;

    case IPFIX_FORWARDING_STATUS:
        // TODO: we did using theoretical information and did not test it at all
        // Documented here: https://www.iana.org/assignments/ipfix/ipfix.xhtml#forwarding-status
        // Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
        if (record_length == 1) {
            uint8_t forwarding_status = 0;

            memcpy(&forwarding_status, data, record_length);

            const netflow9_forwarding_status_t* forwarding_status_structure = (const netflow9_forwarding_status_t*)&forwarding_status;

            // Decode numbers into forwarding statuses
            packet.forwarding_status             = forwarding_status_from_integer(forwarding_status_structure->status);
            flow_meta.received_forwarding_status = true;

            ipfix_forwarding_status++;

            // logger << log4cpp::Priority::DEBUG << "Forwarding status: " << int(forwarding_status_structure->status) << " reason code: " << int(forwarding_status_structure->reason_code);
        } else {
            // It must be exactly one byte
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FORWARDING_STATUS: " << record_length;
            }
        }

        break;
    case IPFIX_DATALINK_FRAME_SIZE:
        if (record_length == 2) {
            uint16_t datalink_frame_size = 0;

            memcpy(&datalink_frame_size, data, record_length);
            flow_meta.data_link_frame_size = fast_ntoh(datalink_frame_size);
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_DATALINK_FRAME_SIZE: " << record_length;
            }
        }

        break;
    case IPFIX_DATALINK_FRAME_SECTION:
        // Element 315: https://www.iana.org/assignments/ipfix/ipfix.xhtml

        // It's packet header as is in variable length encoding
        if (true) {
            ipfix_inline_headers++;

            // This packet is ended using IPFIX variable length encoding and it may have two possible ways of length encoding
            // https://datatracker.ietf.org/doc/html/rfc7011#section-7
            if (flow_meta.variable_field_length_encoding == variable_length_encoding_t::single_byte || flow_meta.variable_field_length_encoding == variable_length_encoding_t::two_byte) {

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Packet header length: " << flow_meta.variable_field_length;
                }

                if (flow_meta.variable_field_length != 0) {
                    bool read_packet_length_from_ip_header = true;

                    bool extract_tunnel_traffic = false;

                    const uint8_t* payload_shift = nullptr;

                    if (flow_meta.variable_field_length_encoding == variable_length_encoding_t::single_byte) {
                        payload_shift = data + sizeof(uint8_t);
                    } else if (flow_meta.variable_field_length_encoding == variable_length_encoding_t::two_byte) {
                        payload_shift = data + sizeof(uint8_t) + sizeof(uint16_t);
                    }

                    auto result =
                        parse_raw_packet_to_simple_packet_full_ng(payload_shift, flow_meta.variable_field_length,
                                                                    flow_meta.variable_field_length, flow_meta.nested_packet,
                                                                  extract_tunnel_traffic, read_packet_length_from_ip_header);

                    if (result != network_data_stuctures::parser_code_t::success) {
                        // Cannot decode data
                        ipfix_inline_header_parser_error++;

                        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                            logger << log4cpp::Priority::DEBUG << "Cannot parse packet header with error: " << network_data_stuctures::parser_code_to_string(result);
                        }

                    } else {
                        // Successfully decoded data
                        ipfix_inline_header_parser_success++;

                        flow_meta.nested_packet_parsed = true;
                        // logger << log4cpp::Priority::DEBUG << "IPFIX inline extracted packet: " << print_simple_packet(flow_meta.nested_packet);
                    }
                } else {
                    ipfix_inline_encoding_error++;

                    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                        logger << log4cpp::Priority::DEBUG << "Zero length variable fields are not supported";
                    }
                }
            } else {
                ipfix_inline_encoding_error++;
                
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unknown variable field encoding type";
                }
            }
        }

        break;
    case IPFIX_FLOW_DIRECTION:
        // It should be 1 byte value
        if (record_length == 1) {
            uint8_t flow_direction = 0;
            memcpy(&flow_direction, data, record_length);

            // According to RFC only two values possible: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            // 0x00: ingress flow
            // 0x01: egress flow
            // Juniper MX uses 255 to report unknown direction
            // std::cout << "Flow direction: " << int(flow_direction) << std::endl;
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_DIRECTION: " << record_length;
            }
        }

        break;

    case IPFIX_FLOW_END_REASON:
        // It should be 1 byte value
        if (record_length == 1) {
            uint8_t flow_end_reason = 0;

            memcpy(&flow_end_reason, data, record_length);

            // https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason
            if (flow_end_reason == 1) {
                ipfix_flows_end_reason_idle_timeout++;
            } else if (flow_end_reason == 2) {
                ipfix_flows_end_reason_active_timeout++;
            } else if (flow_end_reason == 3) {
                ipfix_flows_end_reason_end_of_flow_timeout++;
            } else if (flow_end_reason == 4) {
                ipfix_flows_end_reason_force_end_timeout++;
            } else if (flow_end_reason == 5) {
                ipfix_flows_end_reason_lack_of_resource_timeout++;
            }
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FLOW_END_REASON: " << record_length;
            }
        }

        break;
    case IPFIX_FRAGMENT_IDENTIFICATION:
        //
        // Specification: https://www.rfc-editor.org/rfc/rfc5102.html#section-5.4.23
        //
        // IPFIX uses 32 bit values to accommodate following cases:
        //  - 16 bit IPv4 identification field https://www.rfc-editor.org/rfc/rfc791
        //  - 32 bit IPv6 identification field https://en.wikipedia.org/wiki/IPv6_packet#Fragment
        //
        // Juniper uses it on J MX platforms but they do not have much information about it:
        // https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/inline-sampling-overview.html
        // I asked https://t.me/dgubin about it
        //
        // I did review of dump from J MX and I can confirm that values for IPv4 do not exceed maximum value for uint16_t (65535)
        // 
        // J MX is doing something fun with this field. I got dump in hands and in this dump of 42421 packets only 2337 have non zero value of this field.
        // Clearly they violate RFC and do not populate this field unconditionally as RFC dictates.
        //
        // I see cases like this which is very likely non first fragment of fragmented series of packets as we do not have ports:
        // Identification: 20203 ipv4:0 > ipv4:0 protocol: udp frag: 0  packets: 1 size: 352 bytes ip size: 352 bytes ttl: 0 sample ratio: 1
        // 
        // And I see packets like this which may be first packet in fragmented series of packets as we do indeed have ports here and packet length is high: 
        // Identification: 2710 ipv4:53 > ipv4:45134 protocol: udp frag: 0  packets: 1 size: 1476 bytes ip size: 1476 bytes ttl: 0 sample ratio: 1
        //
        // And majority of packets looks this way:
        // Identification: 0 ipv4:80 > ipv4:50179 protocol: tcp flags: ack frag: 0  packets: 1 size: 40 bytes ip size: 40 bytes ttl: 0 sample ratio: 1
        //
        // We clearly can distinguish first fragmented packet and non first fragmented packet
        //
        // TODO: this logic must be enabled via flag only as this is non RFC compliant behavior and we need to have confirmation from J
        //
        // We have this guide from J: https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/topics/concept/services-ipfix-flow-aggregation-ipv6-extended-attributes.html but it's written in exceptionally weird way and raises more questions then answers
        //

        // It's exactly 4 bytes
        if (record_length == 4) {
            uint32_t fragment_identification = 0;

            memcpy(&fragment_identification, data, record_length);

            fragment_identification = fast_ntoh(fragment_identification);

            // logger << log4cpp::Priority::INFO << "Fragment identification: " << fragment_identification; 
        } else {
            ipfix_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_FRAGMENT_IDENTIFICATION: " << record_length;
            }
        }

        break;
    }

    return true;
}

// Read options data packet with known template
bool ipfix_options_flowset_to_store(const uint8_t* pkt,
                                    const ipfix_header_t* ipfix_header,
                                    const template_t* flow_template,
                                    const std::string& client_addres_in_string_format) {
    // Skip scope fields, I really do not want to parse this information
    pkt += flow_template->option_scope_length;

    uint32_t sampling_rate = 0;

    // Field shift in memory
    uint32_t offset = 0;

    // Sampling algorithm for exotic sampling types
    uint16_t sampling_selector_algorithm = 0;

    // We use these fields to work with systematic count-based Sampling Selector on Nokia
    uint32_t sampling_packet_space    = 0;
    uint32_t sampling_packet_interval = 0;

    device_timeouts_t device_timeouts{};

    for (const auto& elem : flow_template->records) {
        const uint8_t* data_shift = pkt + offset;

        // Time to extract sampling rate
        if (elem.record_type == IPFIX_SAMPLING_INTERVAL) {
            // RFC suggest that this field is 4 byte: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            if (elem.record_length == 4) {
                uint32_t current_sampling_rate = 0;
                memcpy(&current_sampling_rate, data_shift, elem.record_length);

                // TODO: we do not convert value to little endian as sampling update function expects big endian / network byte order

                sampling_rate = current_sampling_rate;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "4 byte encoded IPFIX_SAMPLING_INTERVAL sampling rate: " << sampling_rate
                           << " from " << client_addres_in_string_format;
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpectedly big size for IPFIX_SAMPLING_INTERVAL: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }
        } else if (elem.record_type == IPFIX_SAMPLING_PACKET_INTERVAL) {
            // RFC suggest that this field is 4 byte: https://www.iana.org/assignments/ipfix/ipfix.xhtml
            if (elem.record_length == 4) {
                uint32_t current_sampling_packet_interval = 0;

                memcpy(&current_sampling_packet_interval, data_shift, elem.record_length);

                current_sampling_packet_interval = fast_ntoh(current_sampling_packet_interval);

                // Well, we need this information to deal with systematic count-based Sampling Selector on Nokia
                sampling_packet_interval = current_sampling_packet_interval;

                // And we need this value to use as regular sampling rate on Cisco NSC
                // We need to return it to big endian again we sampling logic in IPFIX uses big endian / network byte order
                sampling_rate = fast_hton(sampling_packet_interval);
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "Unexpectedly big size for IPFIX_SAMPLING_PACKET_INTERVAL: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }
        } else if (elem.record_type == IPFIX_SAMPLING_PACKET_SPACE) {
            // RFC requires this field to be 4 byte long
            if (elem.record_length == 4) {
                memcpy(&sampling_packet_space, data_shift, elem.record_length);

                sampling_packet_space = fast_ntoh(sampling_packet_space);
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpected size for IPFIX_SAMPLING_PACKET_SPACE: " << elem.record_length;
                }

                ipfix_too_large_field++;

                // We're OK to continue process, we should not stop it
            }

        } else if (elem.record_type == IPFIX_SAMPLING_SELECTOR_ALGORITHM) {
            // RFC requires this field to be 2 byte long
            // You can find all possible values for it here: https://www.iana.org/assignments/psamp-parameters/psamp-parameters.xhtml
            if (elem.record_length == 2) {
                memcpy(&sampling_selector_algorithm, data_shift, elem.record_length);

                sampling_selector_algorithm = fast_ntoh(sampling_selector_algorithm);

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Decoded sampling selector algorithm " << sampling_selector_algorithm;
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "Unexpected size for IPFIX_SAMPLING_SELECTOR_ALGORITM: " << elem.record_length;
                }

                ipfix_too_large_field++;

                // We're OK to continue process, we should not stop it
            }

        } else if (elem.record_type == IPFIX_ACTIVE_TIMEOUT) {
            uint16_t active_timeout = 0;

            // J MX204 with JunOS 19 encodes it with 2 bytes as RFC requires
            if (elem.record_length == 2) {
                memcpy(&active_timeout, data_shift, elem.record_length);
                active_timeout = fast_ntoh(active_timeout);

                ipfix_active_flow_timeout_received++;
                device_timeouts.active_timeout = active_timeout;
                
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got active timeout: " << active_timeout << " seconds";
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpected size for IPFIX_ACTIVE_TIMEOUT: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }

        } else if (elem.record_type == IPFIX_INACTIVE_TIMEOUT) {
            uint16_t inactive_timeout = 0;

            // J MX204 with JunOS 19 encodes it with 2 bytes as RFC requires
            if (elem.record_length == 2) {
                memcpy(&inactive_timeout, data_shift, elem.record_length);
                inactive_timeout = fast_ntoh(inactive_timeout);

                ipfix_inactive_flow_timeout_received++;
                device_timeouts.inactive_timeout = inactive_timeout;
                
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got inactive timeout: " << inactive_timeout << " seconds";
                }
            } else {
                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Unexpected size for IPFIX_INACTIVE_TIMEOUT: " << elem.record_length;
                }

                ipfix_too_large_field++;
            }
        }

        offset += elem.record_length;
    }

    // Additional logic to deal with systematic count-based Sampling Selector on Nokia Nokia 7750 SR
    // https://www.rfc-editor.org/rfc/rfc5476.html#section-6.5.2.1
    // We check that sampler selected non zero number of packets as additional sanity check that we deal with this
    // specific type of sampler and to avoid division by zero
    if (sampling_selector_algorithm == IPFIX_SAMPLER_TYPE_SYSTEMATIC_COUNT_BASED_SAMPLING && sampling_packet_interval != 0) {
        // We have seen following cases from Nokia:
        // Packet space: 999 packet interval 1
        // Packet space: 9999 packet interval 1
        //
        // Packet interval is the number of packets selected from whole packet space
        //

        //
        // We never seen packet interval which is not set to 1 but I prefer to cover this case too
        // For values of  packet interval after 1 we need to divide whole amount of observed packets
        // (sampling_packet_space + sampling_packet_interval) by number of selected packets
        //
        uint32_t systematic_count_based_sampling_rate =
            uint32_t(double(sampling_packet_space + sampling_packet_interval) / double(sampling_packet_interval));

        // Update sampling rate
        sampling_rate = fast_hton(systematic_count_based_sampling_rate);

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Packet space: " << sampling_packet_space << " packet interval "
                   << sampling_packet_interval << " sampling " << systematic_count_based_sampling_rate;
        }
    }

    update_ipfix_sampling_rate(sampling_rate, client_addres_in_string_format);

    // Update flow timeouts in our store
    update_device_flow_timeouts(device_timeouts, ipfix_per_device_flow_timeouts_mutex, ipfix_per_device_flow_timeouts,
                                client_addres_in_string_format, netflow_protocol_version_t::ipfix);

    return true;
}


// This function reads flow set using passed template
// In case of irrecoverable errors it returns false
bool ipfix_flowset_to_store(const uint8_t* pkt,
                            const ipfix_header_t* ipfix_header,
                            ssize_t flowset_maximum_length,
                            const template_t* field_template,
                            uint32_t client_ipv4_address,
                            const std::string& client_addres_in_string_format) {
    simple_packet_t packet;
    packet.source       = NETFLOW;
    packet.arrival_time = current_inaccurate_time;

    packet.agent_ip_address = client_ipv4_address;

    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec         = ntohl(ipfix_header->time_sec);

    {
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);
        auto itr = ipfix_sampling_rates.find(client_addres_in_string_format);

        if (itr == ipfix_sampling_rates.end()) {
            // Use global value
            packet.sample_ratio = netflow_sampling_ratio;
        } else {
            packet.sample_ratio = itr->second;
        }
    }

    // By default, assume IPv4 traffic here
    // But code below can switch it to IPv6
    packet.ip_protocol_version = 4; //-V1048

    // Place to keep meta information which is not needed in simple_simple_packet_t structure
    netflow_meta_info_t flow_meta;

    uint32_t offset = 0;

    for (auto iter = field_template->records.begin(); iter != field_template->records.end(); iter++) {
        uint32_t record_type   = iter->record_type;
        uint32_t record_length = iter->record_length;

        // logger << log4cpp::Priority::DEBUG << "Reading record with type " << record_type << " and length " << record_length;

        if (record_length == 65535) {
            // OK, we're facing variable length field and it's damn complex
            // It's not a perfect approach but I'm going to read field length right here as we need it for boundary checks

            // We need to have at least one byte to read data
            if (offset + sizeof(uint8_t) > flowset_maximum_length) {
                logger << log4cpp::Priority::ERROR << "Attempt to read data after end of flowset for variable field length";
                return false;
            }

            const uint8_t* field_length_ptr = (const uint8_t*)(pkt + offset);

            if (*field_length_ptr == 0) {
                logger << log4cpp::Priority::ERROR << "Zero length variable fields are not supported";
                ipfix_inline_encoding_error++;
                return false;
            }

            if (*field_length_ptr == 255) {
                // 255 is special and it means that packet length is encoded in two following bytes
                // Juniper PTX routers use this encoding even in case when packet length does not exceed 255 bytes

                // RFC reference https://datatracker.ietf.org/doc/html/rfc7011#page-37
                // In this case, the first octet of the
                // Length field MUST be 255, and the length is carried in the second and
                // third octets, as shown in Figure S.

                // Read 2 byte length by skipping placeholder byte with 255
                const uint16_t* two_byte_field_length_ptr = (const uint16_t*)(pkt + offset + sizeof(uint8_t));

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Two byte variable length encoding detected. Retrieved packet length: "
                        << fast_ntoh(*two_byte_field_length_ptr);
                }

                // Pass variable payload length 
                flow_meta.variable_field_length = fast_ntoh(*two_byte_field_length_ptr);

                // Override field length with length extracted from two bytes + length of placeholder byte itself
                record_length = flow_meta.variable_field_length + sizeof(uint8_t) + sizeof(uint16_t);;

                // Pass variable payload length
                flow_meta.variable_field_length = fast_ntoh(*two_byte_field_length_ptr);

                // Specify length encoding type as it's required for payload retrieval process
                flow_meta.variable_field_length_encoding = variable_length_encoding_t::two_byte;
            } else {
                // Pass variable payload length
                flow_meta.variable_field_length = *field_length_ptr;

                // Override field length with length extracted from leading byte
                record_length = flow_meta.variable_field_length + sizeof(uint8_t);

                // Specify length encoding type as it's required for payload retrieval process
                flow_meta.variable_field_length_encoding = variable_length_encoding_t::single_byte;
            }
        }

        // We do not need this check when we have only fixed length fields in template
        // but this function is versatile and must handle all cases.
        if (offset + record_length > flowset_maximum_length) {
            logger << log4cpp::Priority::ERROR << "Attempt to read data after end of flowset. Offset: " << offset
                << " record length: " << record_length << " flowset_maximum_length: " << flowset_maximum_length;
            return false;
        }

        bool ipfix_record_to_flow_result = ipfix_record_to_flow(record_type, record_length, pkt + offset, packet, flow_meta);

        // In case of serious errors we stop loop completely
        if (!ipfix_record_to_flow_result) {
            return false;
        }

        offset += record_length;
    }

    // If we were able to decode nested packet then it means that it was Netflow Lite and we can overwrite information in packet
    if (flow_meta.nested_packet_parsed) {
        // Override most of the fields from nested packet as we need to use them instead
        override_packet_fields_from_nested_packet(packet, flow_meta.nested_packet);
    }


    if (false) {
        //
        // For Juniper routers we need fancy logic to mark packets as dropped as it does not use RFC compliant IPFIX field for it
        //

        //
        // The only reliable information we have from Juniper documentation is about Netflow v9
        // https://apps.juniper.net/feature-explorer/feature-info.html?fKey=7679&fn=Enhancements%20to%20inline%20flow%20monitoring
        // and we have no idea how it behaves in IPFIX mode.
        //
        // I think previously we had Juniper routers which set output interface to zero and both bgp_next_hop_ipv4 and
        // ip_next_hop_ipv4 to zero values to report dropped and we checked only bgp_next_hop_ipv4 to identify dropped
        // traffic. It worked well enough until we got flows explained below where bgp_next_hop_ipv4 is not 0.0.0.0 but
        // ip_next_hop_ipv4 and output interface were set to zeroes.
        //
        // In May 2023 got dumps in Google drive "MX10003 and MX 480 dropped traffic" which confirms that Juniper MX
        // 10003 / MX480 with JUNOS 20.4R3-S4.8 encode it using zero output interface and zero ip_next_hop_ipv4. In same
        // time these dumps have bgp_next_hop_ipv4 set to real non zero value of next router. To address this issue we
        // added alternative section to check for zeroe
        //
        // I posted question on LinkedIN: https://www.linkedin.com/feed/update/urn:li:activity:7062447441895141376/
        //

        // We will apply it only if we have no forwarding_status in packet
        if (!flow_meta.received_forwarding_status) {
            // We need to confirm that TWO rules are TRUE:
            // - Output interface is 0
            // - Next hop for IPv4 is set and set to 0 OR next hop for IPv6 set and set to zero
            if (packet.output_interface == 0 &&
                ((flow_meta.bgp_next_hop_ipv4_set && flow_meta.bgp_next_hop_ipv4 == 0) ||
                 (flow_meta.ip_next_hop_ipv4_set && flow_meta.ip_next_hop_ipv4 == 0) ||
                 (is_zero_ipv6_address(flow_meta.bgp_next_hop_ipv6) && flow_meta.bgp_next_hop_ipv6_set))) {

                packet.forwarding_status = forwarding_status_t::dropped;
                ipfix_marked_zero_next_hop_and_zero_output_as_dropped++;
            }
        }
    }

    // std::cout << "bgp next hop: " << convert_ip_as_uint_to_string(flow_meta.bgp_next_hop_ipv4) << " set " << flow_meta.bgp_next_hop_ipv4_set
    //    << " " << print_ipv6_address(flow_meta.bgp_next_hop_ipv6) << " set " << flow_meta.bgp_next_hop_ipv6_set  << " output interface: " << packet.output_interface <<  std::endl;

    netflow_ipfix_all_protocols_total_flows++;

    ipfix_total_flows++;

    // We may have cases like this from previous step:
    // :0000:443 > :0000:61444 protocol: tcp flags: psh,ack frag: 0  packets: 1 size: 205 bytes ip size: 205 bytes ttl:
    // 0 sample ratio: 1000 It happens when router sends IPv4 and zero IPv6 fields in same packet
    if (packet.ip_protocol_version == 6 && is_zero_ipv6_address(packet.src_ipv6) &&
        is_zero_ipv6_address(packet.dst_ipv6) && packet.src_ip != 0 && packet.dst_ip != 0) {

        ipfix_protocol_version_adjustments++;
        packet.ip_protocol_version = 4;
    }

    if (packet.ip_protocol_version == 4) {
        ipfix_total_ipv4_flows++;
    } else if (packet.ip_protocol_version == 6) {
        ipfix_total_ipv6_flows++;
    }

    double duration_float = packet.flow_end - packet.flow_start;

    // Well, it does happen with Juniper QFX
    if (duration_float < 0) {
        ipfix_duration_negative++;

        // I see no reasons to track duration of such cases because they're definitely broken
    } else {
        // Covert milliseconds to seconds
        duration_float = duration_float / 1000;

        int64_t duration = int64_t(duration_float);

        // Increments duration counters
        increment_duration_counters_ipfix(duration);

        // logger<< log4cpp::Priority::INFO<< "Flow start: " << packet.flow_start << " end: " << packet.flow_end << " duration: " << duration;

        // This logic also does not make any sense with negative duration of flows
    }

    // logger<< log4cpp::Priority::INFO<<"src asn: " << packet.src_asn << " " << "dst asn: " << packet.dst_asn;

    // logger<< log4cpp::Priority::INFO<<"output: " << packet.output_interface << " " << " input: " << packet.input_interface;


    // Logical sources of this logic are unknown but I'm sure we had reasons to do so
    if (packet.protocol == IPPROTO_ICMP) {
        // Explicitly set ports to zeros even if device sent something in these fields
        packet.source_port      = 0;
        packet.destination_port = 0;
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
    return true;
}

// That's kind of histogram emulation
void increment_duration_counters_ipfix(int64_t duration) {
    if (duration == 0) {
        ipfix_duration_0_seconds++;
    } else if (duration <= 1) {
        ipfix_duration_less_1_seconds++;
    } else if (duration <= 2) {
        ipfix_duration_less_2_seconds++;
    } else if (duration <= 3) {
        ipfix_duration_less_3_seconds++;
    } else if (duration <= 5) {
        ipfix_duration_less_5_seconds++;
    } else if (duration <= 10) {
        ipfix_duration_less_10_seconds++;
    } else if (duration <= 15) {
        ipfix_duration_less_15_seconds++;
    } else if (duration <= 30) {
        ipfix_duration_less_30_seconds++;
    } else if (duration <= 60) {
        ipfix_duration_less_60_seconds++;
    } else if (duration <= 90) {
        ipfix_duration_less_90_seconds++;
    } else if (duration <= 180) {
        ipfix_duration_less_180_seconds++;
    } else {
        ipfix_duration_exceed_180_seconds++;
    }

    return;
}

bool process_ipfix_data(const uint8_t* pkt,
                        size_t flowset_length,
                        const ipfix_header_t* ipfix_header,
                        uint32_t source_id,
                        const std::string& client_addres_in_string_format,
                        uint32_t client_ipv4_address) {

    const ipfix_data_flowset_header_t* flowset_header = (const ipfix_data_flowset_header_t*)pkt;

    if (flowset_length < sizeof(ipfix_data_flowset_header_t)) {
        logger << log4cpp::Priority::ERROR << "Too short IPFIX flowset with not enough space for flowset header: " << flowset_length
               << " Agent: " << client_addres_in_string_format;
        return false;
    }

    // Store packet end, it's useful for sanity checks
    const uint8_t* flowset_end = pkt + flowset_length;

    uint32_t flowset_id = ntohs(flowset_header->header.flowset_id);

    const template_t* field_template = peer_find_template(global_ipfix_templates, global_ipfix_templates_mutex,
                                                          source_id, flowset_id, client_addres_in_string_format);

    if (field_template == NULL) {
        ipfix_packets_with_unknown_templates++;

        logger << log4cpp::Priority::DEBUG << "We don't have a IPFIX template for flowset_id: " << flowset_id
               << " client " << client_addres_in_string_format << " source_id: " << source_id
               << " but it's not an error if this message disappears in some time "
                  "seconds. We need some time to learn them";

        return false;
    }

    if (field_template->records.empty()) {
        logger << log4cpp::Priority::ERROR << "There are no records in IPFIX template. Agent: " << client_addres_in_string_format;
        return false;
    }

    uint32_t offset = sizeof(ipfix_data_flowset_header_t);

    if (field_template->type == netflow_template_type_t::Data) {

        if (field_template->ipfix_variable_length_elements_used) {
            // Get clean flowsets length to use it as limit for our parser
            ssize_t current_flowset_length_no_header = flowset_length - sizeof(ipfix_data_flowset_header_t);

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "IPFIX variable field element was used";
            }

            // TODO: This implementation is rather limited as we read only single flowset here
            // In many cases we use this stuff for IPFIX Inline monitoring and it uses just single flowset but it may change in future
            // TODO: Juniper PTX uses multiple flowsets per packet
            ipfix_flowset_to_store(pkt + sizeof(ipfix_data_flowset_header_t), ipfix_header, current_flowset_length_no_header,
                                   field_template, client_ipv4_address, client_addres_in_string_format);
        } else {

            // This logic is pretty reliable but it works only if we do not have variable sized fields in template
            // In that case it's completely not applicable
            // But I prefer to keep it as it's very predictable and works fix for fields fields
            // Templates with only fixed fields are 99% of our installations and variable fields are very rare

            uint32_t number_flowsets = (flowset_length - offset) / field_template->total_length;

            // We need to calculate padding value
            // IPFIX RFC explains it following way:
            // https://datatracker.ietf.org/doc/html/rfc7011?ref=pavel.network#section-3.3.1
            uint32_t flowset_padding = (flowset_length - offset) % field_template->total_length;

            // Very likely data will be aligned by 4 byte boundaries and will have padding 1, 2, 3 bytes
            // To be on safe side we assume that padding may be up to 7 bytes to achieve 8 byte boundaries
            // All other values may be sign of some kind of issues. For example, it may be template conflicts
            // https://pavel.network/its-just-wrong-to-update-ipfix-templates/
            if (flowset_padding > 7) {
                ipfix_flowsets_with_anomaly_padding++;
            }

            if (number_flowsets > 0x4000) {
                logger << log4cpp::Priority::ERROR << "Very high number of IPFIX data flowsets " << number_flowsets
                       << " Agent: " << client_addres_in_string_format
                       << " flowset template length: " << field_template->total_length;

                return false;
            }

            if (number_flowsets == 0) {
                logger << log4cpp::Priority::ERROR << "Unexpected zero number of flowsets "
                       << " agent: " << client_addres_in_string_format
                       << " flowset template length: " << field_template->total_length << " flowset length "
                       << flowset_length << " source_id " << source_id << " flowset_id: " << flowset_id;

                return false;
            }

            for (uint32_t i = 0; i < number_flowsets; i++) {
                // We apply constraint that maximum potential length of flow set cannot exceed length of all fields in
                // template In this case we have no fields with variable length which may affect it and we're safe
                ipfix_flowset_to_store(pkt + offset, ipfix_header, field_template->total_length, field_template,
                                       client_ipv4_address, client_addres_in_string_format);

                offset += field_template->total_length;
            }
        }

    } else if (field_template->type == netflow_template_type_t::Options) {
        ipfix_options_packet_number++;

        // Check that we will not read outside of packet
        if (pkt + offset + field_template->total_length > flowset_end) {
            logger << log4cpp::Priority::ERROR << "We tried to read data outside packet for IPFIX options. "
                   << "Agent: " << client_addres_in_string_format;
            return false;
        }

        // Process options packet
        ipfix_options_flowset_to_store(pkt + offset, ipfix_header, field_template, client_addres_in_string_format);
    }

    return true;
}

// Process IPFIX packet
bool process_ipfix_packet(const uint8_t* packet,
                          uint32_t udp_packet_length,
                          const std::string& client_addres_in_string_format,
                          uint32_t client_ipv4_address) {
    const ipfix_header_t* ipfix_header = (const ipfix_header_t*)packet;

    if (udp_packet_length < sizeof(ipfix_header_t)) {
        logger << log4cpp::Priority::ERROR << "Packet is too short to accomodate IPFIX header " << udp_packet_length
               << " bytes which requires at least " << sizeof(ipfix_header_t) << " bytes";
        return false;
    }

    // In compare with Netflow v9 IPFIX uses packet length instead of explicitly specified number of flows
    // https://datatracker.ietf.org/doc/html/rfc7011#section-3.1
    // Total length of the IPFIX Message, measured in octets, including Message Header and Set(s).
    uint32_t ipfix_packet_length = fast_ntoh(ipfix_header->header.length);

    if (udp_packet_length == ipfix_packet_length) {
        // Under normal circumstances udp_packet_length must be equal to ipfix_packet_length
    } else {
        // If they're different we need to do more careful checks

        if (udp_packet_length > ipfix_packet_length) {
            // Theoretically it may happen if we have some padding on the end of packet
            logger << log4cpp::Priority::DEBUG << "udp_packet_length exceeds ipfix_packet_length, suspect padding";
            ipfix_packets_with_padding++;
        }

        // And this case we cannot tolerate
        if (udp_packet_length < ipfix_packet_length) {
            logger << log4cpp::Priority::DEBUG << "UDP packet it shorter (" << udp_packet_length << ")"
                   << " then IPFIX data (" << ipfix_packet_length << "). Assume data corruption";
            return false;
        }
    }

    uint32_t source_id = ntohl(ipfix_header->source_id);

    uint32_t offset         = sizeof(*ipfix_header);
    uint64_t flowset_number = 0;

    // Yes, it's infinite loop but we apply boundaries inside to limit it
    while (true) {
        flowset_number++;

        // We limit number of flow sets in packet and also use it for infinite loop prevention
        if (flowset_number > flowsets_per_packet_maximum_number) {
            logger << log4cpp::Priority::ERROR << "Infinite loop prevention triggered or we have so many flowsets inside IPFIX packet";
            return false;
        }

        if (offset >= ipfix_packet_length) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside of IPFIX packet agent IP: " << client_addres_in_string_format;
            return false;
        }

        const ipfix_flowset_header_common_t* flowset = (const ipfix_flowset_header_common_t*)(packet + offset);

        uint32_t flowset_id     = ntohs(flowset->flowset_id);
        uint32_t flowset_length = ntohs(flowset->length);

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */

        if (offset + flowset_length > ipfix_packet_length) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside IPFIX packet flowset agent IP: " << client_addres_in_string_format;
            return false;
        }

        switch (flowset_id) {
        case IPFIX_TEMPLATE_FLOWSET_ID:
            ipfix_data_templates_number++;
            if (!process_ipfix_template(packet + offset, flowset_length, source_id, client_addres_in_string_format)) {
                return false;
            }
            break;
        case IPFIX_OPTIONS_FLOWSET_ID:
            ipfix_options_templates_number++;

            if (!process_ipfix_options_template(packet + offset, flowset_length, source_id, client_addres_in_string_format)) {
                return false;
            }

            break;
        default:
            if (flowset_id < IPFIX_MIN_RECORD_FLOWSET_ID) {
                logger << log4cpp::Priority::ERROR << "Received unknown IPFIX reserved flowset type " << flowset_id;
                break; // interrupts only switch!
            }

            ipfix_data_packet_number++;

            if (!process_ipfix_data(packet + offset, flowset_length, ipfix_header, source_id,
                                    client_addres_in_string_format, client_ipv4_address)) {
                return false;
            }

            break;
        }

        offset += flowset_length;
        if (offset == ipfix_packet_length) {
            break;
        }
    }

    return true;
}

void update_ipfix_sampling_rate(uint32_t sampling_rate, const std::string& client_addres_in_string_format) {
    if (sampling_rate == 0) {
        return;
    }

    // NB! Incoming sampling rate is big endian / network byte order
    auto new_sampling_rate = fast_ntoh(sampling_rate);

    ipfix_custom_sampling_rate_received++;

    logger << log4cpp::Priority::DEBUG << "I extracted sampling rate: " << new_sampling_rate << " for " << client_addres_in_string_format;

    {
        // Replace old sampling rate value
        std::lock_guard<std::mutex> lock(ipfix_sampling_rates_mutex);

        auto known_sampling_rate = ipfix_sampling_rates.find(client_addres_in_string_format);

        if (known_sampling_rate == ipfix_sampling_rates.end()) {
            // We had no sampling rates before
            ipfix_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

            ipfix_sampling_rate_changes++;

            logger << log4cpp::Priority::INFO << "Learnt new IPFIX sampling rate " << new_sampling_rate << " for "
                   << client_addres_in_string_format;
        } else {
            auto old_sampling_rate = known_sampling_rate->second;

            if (old_sampling_rate != new_sampling_rate) {
                ipfix_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

                ipfix_sampling_rate_changes++;

                logger << log4cpp::Priority::INFO << "Detected IPFIX sampling rate change from " << old_sampling_rate
                       << " to " << new_sampling_rate << " for " << client_addres_in_string_format;
            }
        }
    }
}

