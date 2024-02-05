// That's not a module as we do refactoring right now in small steps
// TODO: place make it proper module

void update_netflow_v9_sampling_rate(uint32_t new_sampling_rate, const std::string& client_addres_in_string_format);

// This function reads all available options templates
// http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
bool process_netflow_v9_options_template(const uint8_t* pkt, size_t flowset_length, uint32_t source_id, const std::string& client_addres_in_string_format) {
    const netflow9_options_header_common_t* options_template_header = (const netflow9_options_header_common_t*)pkt;

    if (flowset_length < sizeof(*options_template_header)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 options template header " << flowset_length
               << " bytes agent IP: " << client_addres_in_string_format;
        return false;
    }

    if (ntohs(options_template_header->flowset_id) != NETFLOW9_OPTIONS_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_netflow_v9_options_template "
                  "expects only NETFLOW9_OPTIONS_FLOWSET_ID but got "
                  "another id: "
               << ntohs(options_template_header->flowset_id) << " agent IP: " << client_addres_in_string_format;
        return false;
    }

    const netflow9_options_header_t* options_nested_header =
        (const netflow9_options_header_t*)(pkt + sizeof(*options_template_header));


    if (flowset_length < sizeof(*options_template_header) + sizeof(*options_nested_header)) {
        logger << log4cpp::Priority::ERROR << "Could not read specific header for Netflow v9 options template. "
               << " Agent IP: " << client_addres_in_string_format;
        return false;
    }

    uint16_t template_id = fast_ntoh(options_nested_header->template_id);

    if (flowset_length < sizeof(*options_template_header) + sizeof(*options_nested_header) +
                             fast_ntoh(options_nested_header->option_scope_length)) {
        logger << log4cpp::Priority::ERROR << "Could not read specific header for Netflow v9 options template: need more space for scope"
               << " agent IP: " << client_addres_in_string_format;
        return false;
    }

    // I'm going to skip scope processing right now
    const uint8_t* zone_address = pkt + sizeof(*options_template_header) + sizeof(*options_nested_header);

    uint32_t scopes_offset     = 0;
    uint32_t scopes_total_size = 0;

    // Here I should read all available scopes and calculate total size!
    for (; scopes_offset < fast_ntoh(options_nested_header->option_scope_length);) {
        netflow9_template_flowset_record_t* tmplr = (netflow9_template_flowset_record_t*)(zone_address + scopes_offset);

        scopes_total_size += fast_ntoh(tmplr->length);
        scopes_offset += sizeof(*tmplr);
    }

    const uint8_t* zone_address_without_skopes = zone_address + fast_ntoh(options_nested_header->option_scope_length);

    uint32_t offset         = 0;
    uint32_t records_number = 0;

    std::vector<template_record_t> template_records_map;
    uint32_t total_size = 0;

    for (; offset < fast_ntoh(options_nested_header->option_length);) {
        records_number++;
        const netflow9_template_flowset_record_t* tmplr =
            (const netflow9_template_flowset_record_t*)(zone_address_without_skopes + offset);

        uint32_t record_type   = fast_ntoh(tmplr->type);
        uint32_t record_length = fast_ntoh(tmplr->length);

        template_record_t current_record;
        current_record.record_type   = record_type;
        current_record.record_length = record_length;

        template_records_map.push_back(current_record);

        // logger << log4cpp::Priority::ERROR << "Got type " << record_type << " with length " << record_length;
        offset += sizeof(*tmplr);
        total_size += record_length;
    }

    template_t field_template{};

    field_template.template_id         = template_id;
    field_template.records             = template_records_map;
    field_template.num_records         = records_number;
    field_template.total_length        = total_size + scopes_total_size;
    field_template.type                = netflow_template_type_t::Options;
    field_template.option_scope_length = scopes_total_size;

    // We need to know when we received it
    field_template.timestamp = current_inaccurate_time;

    // logger << log4cpp::Priority::INFO << "Read options template:" << print_template(field_template);

    // Add/update template
    bool updated                   = false;
    bool updated_existing_template = false;

    add_update_peer_template(netflow_protocol_version_t::netflow_v9, global_netflow9_templates,
                             global_netflow9_templates_mutex, source_id, template_id, client_addres_in_string_format,
                             field_template, updated, updated_existing_template);

    // This code is not perfect from locks perspective as we read global_netflow9_templates without any locks below

    // NB! Please be careful with changing name of variable as it's part of serialisation protocol

    if (updated_existing_template) {
        netflow_v9_template_data_updates++;
    }

    return true;
}

bool process_netflow_v9_template(const uint8_t* pkt,
                                 size_t flowset_length,
                                 uint32_t source_id,
                                 const std::string& client_addres_in_string_format,
                                 uint64_t flowset_number) {
    const netflow9_flowset_header_common_t* template_header = (const netflow9_flowset_header_common_t*)pkt;

    if (flowset_length < sizeof(*template_header)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 flowset template header " << flowset_length
               << " bytes agent IP: " << client_addres_in_string_format << " flowset number: " << flowset_number;
        return false;
    }

    if (fast_ntoh(template_header->flowset_id) != NETFLOW9_TEMPLATE_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_netflow_v9_template expects only "
                  "NETFLOW9_TEMPLATE_FLOWSET_ID but "
                  "got another id: "
               << ntohs(template_header->flowset_id) << " agent IP: " << client_addres_in_string_format;
        return false;
    }

    for (uint32_t offset = sizeof(*template_header); offset < flowset_length;) {
        const netflow9_template_flowset_header_t* netflow9_template_flowset_header =
            (const netflow9_template_flowset_header_t*)(pkt + offset);

        uint32_t template_id  = ntohs(netflow9_template_flowset_header->template_id);
        uint32_t fields_count = ntohs(netflow9_template_flowset_header->fields_count);

        offset += sizeof(*netflow9_template_flowset_header);

        // logger<< log4cpp::Priority::INFO<<"Template template_id
        // is:"<<template_id;

        uint32_t total_size = 0;

        std::vector<template_record_t> template_records_map;

        for (uint32_t i = 0; i < fields_count; i++) {
            if (offset >= flowset_length) {
                logger << log4cpp::Priority::ERROR << "Short Netflow v9 flowset template. "
                       << " agent IP: " << client_addres_in_string_format << " flowset number: " << flowset_number;
                return false;
            }

            const netflow9_template_flowset_record_t* template_record_ptr =
                (const netflow9_template_flowset_record_t*)(pkt + offset);

            uint32_t record_type   = ntohs(template_record_ptr->type);
            uint32_t record_length = ntohs(template_record_ptr->length);

            template_record_t current_record;
            current_record.record_type   = record_type;
            current_record.record_length = record_length;

            template_records_map.push_back(current_record);

            // logger<< log4cpp::Priority::INFO<<"Learn new template type:
            // "<<ntohs(tmplr->type)<<"
            // length:"<<ntohs(tmplr->length);

            offset += sizeof(*template_record_ptr);
            total_size += record_length;

            // TODO: introduce netflow9_check_rec_len
        }

        template_t field_template{};

        field_template.template_id  = template_id;
        field_template.num_records  = fields_count;
        field_template.total_length = total_size;
        field_template.records      = template_records_map;
        field_template.type         = netflow_template_type_t::Data;

        // We need to know when we received it
        field_template.timestamp = current_inaccurate_time;

        // Add/update template
        bool updated                   = false;
        bool updated_existing_template = false;

        add_update_peer_template(netflow_protocol_version_t::netflow_v9, global_netflow9_templates,
                                 global_netflow9_templates_mutex, source_id, template_id,
                                 client_addres_in_string_format, field_template, updated, updated_existing_template);

        if (updated_existing_template) {
            netflow_v9_template_data_updates++;
        }
    }

    // for (auto elem: global_netflow9_templates) {
    //    logger << log4cpp::Priority::INFO  << "Template ident: " << elem.first << " content: " <<
    //    print_template(elem.second);
    //}

    return true;
}

bool netflow9_record_to_flow(uint32_t record_type,
                             uint32_t record_length,
                             const uint8_t* data,
                             simple_packet_t& packet,
                             netflow_meta_info_t& flow_meta,
                             const std::string& client_addres_in_string_format) {
    // Some devices such as Mikrotik may pass sampling rate in data section
    uint32_t sampling_rate = 0;

    switch (record_type) {
    case NETFLOW9_IN_BYTES:
        if (record_length > sizeof(packet.length)) {
            netflow_v9_too_large_field++;

            // getPriority just returns private field and does not involve any locking / heavy operations
            // We do this check to avoid overhead related with << processing
            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IN_BYTES";
            }
        } else {
            BE_COPY(packet.length);

            // Decode data in network byte order to host byte order
            packet.length = fast_ntoh(packet.length);

            // Netflow carries only information about number of octets including IP headers and IP payload
            // which is exactly what we need for ip_length field
            packet.ip_length = packet.length;
        }

        break;
    case NETFLOW9_IN_PACKETS:
        if (record_length > sizeof(packet.number_of_packets)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IN_PACKETS";
            }
        } else {
            BE_COPY(packet.number_of_packets);

            // We need to decode it to host byte order
            packet.number_of_packets = fast_ntoh(packet.number_of_packets);
        }

        break;
    case NETFLOW9_IN_PROTOCOL:
        if (record_length > sizeof(packet.protocol)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IN_PROTOCOL";
            }
        } else {
            BE_COPY(packet.protocol);

            packet.protocol = fast_ntoh(packet.protocol);
        }

        break;
    case NETFLOW9_TCP_FLAGS:
        if (record_length > sizeof(packet.flags)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_TCP_FLAGS";
            }
        } else {
            BE_COPY(packet.flags);
        }

        break;
    case NETFLOW9_L4_SRC_PORT:
        if (record_length > sizeof(packet.source_port)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_L4_SRC_PORT";
            }
        } else {
            BE_COPY(packet.source_port);

            // We should convert port to host byte order
            packet.source_port = fast_ntoh(packet.source_port);
        }

        break;
    case NETFLOW9_L4_DST_PORT:
        if (record_length > sizeof(packet.destination_port)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_L4_DST_PORT";
            }
        } else {
            BE_COPY(packet.destination_port);

            // We should convert port to host byte order
            packet.destination_port = fast_ntoh(packet.destination_port);
        }

        break;
    case NETFLOW9_IPV4_SRC_ADDR:
        if (record_length > sizeof(packet.src_ip)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IPV4_SRC_ADDR";
            }
        } else {
            memcpy(&packet.src_ip, data, record_length);
        }

        break;
    case NETFLOW9_IPV4_DST_ADDR:
        if (record_length > sizeof(packet.dst_ip)) {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IPV4_DST_ADDR";
            }
        } else {
            memcpy(&packet.dst_ip, data, record_length);
        }

        break;
    case NETFLOW9_SRC_AS:
        // It could be 2 or 4 byte length
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
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_SRC_AS";
            }
        }

        break;
    case NETFLOW9_IPV6_SRC_ADDR:
            // It should be 16 bytes only
            if (record_length == 16) {
                memcpy(&packet.src_ipv6, data, record_length);
                // Set protocol version to IPv6
                packet.ip_protocol_version = 6;
            } else {
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IPV6_SRC_ADDR";
                }
            }

        break;
    case NETFLOW9_IPV6_DST_ADDR:
            // It should be 16 bytes only
            if (record_length == 16) {
                memcpy(&packet.dst_ipv6, data, record_length);
                // Set protocol version to IPv6
                packet.ip_protocol_version = 6;
            } else {
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IPV6_DST_ADDR";
                }
            }

        break;
    case NETFLOW9_DST_AS:
        // It could be 2 or 4 byte length
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
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_DST_AS";
            }
        }

        break;
    case NETFLOW9_INPUT_SNMP:
        // According to Netflow standard this field could have 2 or more bytes
        // Juniper MX uses 4 byte encoding
        // Here we support 2 or 4 byte encoding only
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
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_INPUT_SNMP";
            }
        }

        break;
    case NETFLOW9_OUTPUT_SNMP:
        // According to Netflow standard this field could have 2 or more bytes
        // Juniper MX uses 4 byte encoding
        // Here we support 2 or 4 byte encoding only
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
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_OUTPUT_SNMP";
            }
        }

        break;
    case NETFLOW9_FIRST_SWITCHED:
        if (record_length == 4) {
            uint32_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            packet.flow_start = flow_started;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_FIRST_SWITCHED";
            }
        }

        break;
    case NETFLOW9_LAST_SWITCHED:
        if (record_length == 4) {
            uint32_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            packet.flow_end = flow_finished;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_LAST_SWITCHED";
            }
        }

        break;
    case NETFLOW9_START_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_started = 0;

            memcpy(&flow_started, data, record_length);
            flow_started = fast_ntoh(flow_started);

            // We cast unsigned to signed and it may cause issues
            packet.flow_start = flow_started;
        } else {
            netflow_v9_too_large_field++;
        }

        break;
    case NETFLOW9_END_MILLISECONDS:
        if (record_length == 8) {
            uint64_t flow_finished = 0;

            memcpy(&flow_finished, data, record_length);
            flow_finished = fast_ntoh(flow_finished);

            // We cast unsigned to signed and it may cause issues
            packet.flow_end = flow_finished;
        } else {
            netflow_v9_too_large_field++;
        }

        break;
    case NETFLOW9_FORWARDING_STATUS:
        // Documented here: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
        // Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code.
        // This field may carry information about fragmentation but we cannot confirm it, ASR 9000 exports most of the traffic with field 64, which means unknown
        if (record_length == 1) {
            uint8_t forwarding_status = 0;

            memcpy(&forwarding_status, data, record_length);

            const netflow9_forwarding_status_t* forwarding_status_structure = (const netflow9_forwarding_status_t*)&forwarding_status;

            // Decode numbers into forwarding statuses
            packet.forwarding_status             = forwarding_status_from_integer(forwarding_status_structure->status);
            flow_meta.received_forwarding_status = true;

            netflow_v9_forwarding_status++;

            // logger << log4cpp::Priority::DEBUG << "Forwarding status: " << int(forwarding_status_structure->status) << " reason code: " << int(forwarding_status_structure->reason_code);
        } else {
            // It must be exactly one byte
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_FORWARDING_STATUS";
            }
        }

        break;
    case NETFLOW9_SELECTOR_TOTAL_PACKETS_OBSERVED:
        if (record_length == 8) {
            uint64_t packets_observed = 0;

            memcpy(&packets_observed, data, record_length);
            flow_meta.observed_packets = fast_ntoh(packets_observed);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_SELECTOR_TOTAL_PACKETS_OBSERVED";
            }
        }

        break;
    case NETFLOW9_SELECTOR_TOTAL_PACKETS_SELECTED:
        if (record_length == 8) {
            uint64_t packets_selected = 0;

            memcpy(&packets_selected, data, record_length);
            flow_meta.selected_packets = fast_ntoh(packets_selected);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_SELECTOR_TOTAL_PACKETS_SELECTED";
            }
        }

        break;
    case NETFLOW9_DATALINK_FRAME_SIZE:
        if (record_length == 2) {
            uint16_t datalink_frame_size = 0;

            memcpy(&datalink_frame_size, data, record_length);
            flow_meta.data_link_frame_size = fast_ntoh(datalink_frame_size);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_DATALINK_FRAME_SIZE";
            }
        }

        break;
    case NETFLOW9_LAYER2_PACKET_SECTION_SIZE:
        if (record_length == 2) { 
            uint16_t datalink_frame_size = 0; 

            memcpy(&datalink_frame_size, data, record_length);
            flow_meta.data_link_frame_size = fast_ntoh(datalink_frame_size);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_LAYER2_PACKET_SECTION_SIZE";
            }
        }

        break;
    case NETFLOW9_LAYER2_PACKET_SECTION_DATA:
        if (true) {
            netflow_v9_lite_headers++;

            bool read_packet_length_from_ip_header = true;

            // It's our safe fallback
            uint64_t full_packet_length = record_length;

            // Device must provide this information on previous iteration, let's try to get it in case if we've got it:
            if (flow_meta.data_link_frame_size != 0) {
                full_packet_length = flow_meta.data_link_frame_size;
            }

            bool extract_tunnel_traffic = false;

            auto result = parse_raw_packet_to_simple_packet_full_ng((u_char*)(data), full_packet_length, record_length,
                                                                    flow_meta.nested_packet, extract_tunnel_traffic,
                                                                    read_packet_length_from_ip_header);

            if (result != network_data_stuctures::parser_code_t::success) {
                // Cannot decode data
                netflow_v9_lite_header_parser_error++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Cannot parse packet header with error: " << network_data_stuctures::parser_code_to_string(result); 
                }
            } else {
                netflow_v9_lite_header_parser_success++;
                // Successfully decoded data
                flow_meta.nested_packet_parsed = true;
            }
        }

        break;
    // There is a similar field NETFLOW9_BGP_NEXT_HOP_IPV4_ADDRESS but with slightly different meaning
    // https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    case NETFLOW9_IPV4_NEXT_HOP:
        // Juniper MX uses this field
        // Juniper uses this specific field (type 15) to report dropped traffic:
        // https://apps.juniper.net/feature-explorer/feature-info.html?fKey=7679&fn=Enhancements%20to%20inline%20flow%20monitoring
        if (record_length == 4) {
            uint32_t ip_next_hop_ipv4 = 0;
            memcpy(&ip_next_hop_ipv4, data, record_length);

            flow_meta.ip_next_hop_ipv4_set = true;
            flow_meta.ip_next_hop_ipv4     = ip_next_hop_ipv4;

            // std::cout << "Netflow v9 IP next hop: " << convert_ip_as_uint_to_string(bgp_next_hop_ipv4) << std::endl;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_IPV4_NEXT_HOP";
            }
        }

        break;

    // There is a similar field NETFLOW9_BGP_NEXT_HOP_IPV4_ADDRESS but with slightly different meaning
    // https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    case NETFLOW9_BGP_NEXT_HOP_IPV4_ADDRESS:

        if (record_length == 4) {
            uint32_t bgp_next_hop_ipv4 = 0;
            memcpy(&bgp_next_hop_ipv4, data, record_length);

            flow_meta.bgp_next_hop_ipv4_set = true;
            flow_meta.bgp_next_hop_ipv4     = bgp_next_hop_ipv4;

            // std::cout << "Netflow v9 BGP next hop: " << convert_ip_as_uint_to_string(bgp_next_hop_ipv4) << std::endl;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_BGP_NEXT_HOP_IPV4_ADDRESS";
            }
        }

        break;
    case NETFLOW9_FLOW_SAMPLER_ID:
        // NB! This field for options and data templates field may use different field length
        if (record_length == 1) {
            uint8_t sampler_id = 0;

            memcpy(&sampler_id, data, record_length);

            // logger << log4cpp::Priority::DEBUG << "Got sampler id from data template: " << int(sampler_id);
        } else if (record_length == 2) {
            uint16_t sampler_id = 0;

            memcpy(&sampler_id, data, record_length);

            sampler_id = fast_ntoh(sampler_id);

            // logger << log4cpp::Priority::DEBUG << "Got sampler id from data template: " << int(sampler_id);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_FLOW_SAMPLER_ID data";
            }
        }
        break;
    case NETFLOW9_FLOW_ID:
        if (record_length == 4) {
            uint32_t flow_id = 0;

            memcpy(&flow_id, data, record_length);
            flow_id = fast_ntoh(flow_id);

            flow_meta.flow_id = flow_id;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_FLOW_ID";
            }
        }

        break;
    case NETFLOW9_BYTES_FROM_SOURCE_TO_DESTINATION:
        if (record_length == 4) {
            uint32_t bytes_counter = 0;

            memcpy(&bytes_counter, data, record_length);
            bytes_counter = fast_ntoh(bytes_counter);

            flow_meta.bytes_from_source_to_destination = bytes_counter;
        } else if (record_length == 8) {
            uint64_t bytes_counter = 0;

            memcpy(&bytes_counter, data, record_length);
            bytes_counter = fast_ntoh(bytes_counter);

            flow_meta.bytes_from_source_to_destination = bytes_counter;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_BYTES_FROM_SOURCE_TO_DESTINATION";
            }
        }

        break;
    case NETFLOW9_BYTES_FROM_DESTINATION_TO_SOURCE:
        if (record_length == 2) {
            uint16_t bytes_counter = 0;

            memcpy(&bytes_counter, data, record_length);
            bytes_counter = fast_ntoh(bytes_counter);

            flow_meta.bytes_from_destination_to_source = bytes_counter;
        } else if (record_length == 4) {
            uint32_t bytes_counter = 0;

            memcpy(&bytes_counter, data, record_length);
            bytes_counter = fast_ntoh(bytes_counter);

            flow_meta.bytes_from_destination_to_source = bytes_counter;
        } else if (record_length == 8) {
            uint64_t bytes_counter = 0;

            memcpy(&bytes_counter, data, record_length);
            bytes_counter = fast_ntoh(bytes_counter);

            flow_meta.bytes_from_destination_to_source = bytes_counter;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_BYTES_FROM_DESTINATION_TO_SOURCE";
            }
        }

        break;
    case NETFLOW9_PACKETS_FROM_SOURCE_TO_DESTINATION:
        if (record_length == 4) {
            uint32_t packets_counter = 0;

            memcpy(&packets_counter, data, record_length);
            packets_counter = fast_ntoh(packets_counter);

            flow_meta.packets_from_source_to_destination = packets_counter;
        } else if (record_length == 8) {
            uint64_t packets_counter = 0;

            memcpy(&packets_counter, data, record_length);
            packets_counter = fast_ntoh(packets_counter);

            flow_meta.packets_from_source_to_destination = packets_counter;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_PACKETS_FROM_SOURCE_TO_DESTINATION";
            }
        }

        break;
    case NETFLOW9_PACKETS_FROM_DESTINATION_TO_SOURCE:
        if (record_length == 4) {
            uint32_t packets_counter = 0;

            memcpy(&packets_counter, data, record_length);
            packets_counter = fast_ntoh(packets_counter);

            flow_meta.packets_from_destination_to_source = packets_counter;
        } else if (record_length == 8) {
            uint64_t packets_counter = 0;

            memcpy(&packets_counter, data, record_length);
            packets_counter = fast_ntoh(packets_counter);

            flow_meta.packets_from_destination_to_source = packets_counter;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_PACKETS_FROM_DESTINATION_TO_SOURCE";
            }
        }

        break;
    case NETFLOW9_SOURCE_MAC_ADDRESS:
        if (record_length == 6) {
            // Copy it directly to packet structure
            memcpy(&packet.source_mac, data, record_length);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_SOURCE_MAC_ADDRESS";
            }
        }
        break;
    case NETFLOW9_DESTINATION_MAC_ADDRESS:
        if (record_length == 6) {
            // Copy it directly to packet structure
            memcpy(&packet.destination_mac, data, record_length);
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_DESTINATION_MAC_ADDRESS";
            }
        }
        break;
    case NETFLOW9_SAMPLING_INTERVAL:
        // Well, this record type is expected to be only in options templates but Mikrotik in RouterOS v6.49.6 has
        // another opinion and we have dump which clearly confirms that they send this data in data templates

        if (record_length == 4) {
            uint32_t current_sampling_rate = 0;

            memcpy(&current_sampling_rate, data, record_length);

            current_sampling_rate = fast_ntoh(current_sampling_rate);

            // Pass it to global variable
            sampling_rate = current_sampling_rate;

            // As we have it in data section it may overflow logs but that's best we can do and I think we need to have such information
            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Got sampling date from data packet: " << current_sampling_rate;
            }

            //
            // That's where Mikrotik quirks start
            // From Mikrotik routers with no sampling configured we receive 0 in this field which is not perfect but reasonable enough.
            //
            // Another issue that we receive values like: 16777216 which is just 1 wrongly encoded in host byte order in their data
            // Should I mention that in this case router had following setup: packet-sampling=yes sampling-interval=2222 sampling-space=1111
            // And I have no idea what is the source of "1" as sampling rate
            // It's so broken that we agreed to suspend implementation until they fix it
            //
            // Fortunately in ROS7.10 it works just fine
            //
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_SAMPLING_INTERVAL in data packet";
            }
        }

        break;
    }

    // We keep this logic under the fence flag because RouterOS v6 sampling implementation is exceptionally broken and
    // enabling it by default will not make any good
    if (false) {
        // TODO: another issue with this logic that we will run it for each flow in packet which may cause additional
        // overhead during processing It's not significant and we will keep it that way for now
        update_netflow_v9_sampling_rate(sampling_rate, client_addres_in_string_format);
    }

    return true;
}

// Read options data packet with known template
void netflow9_options_flowset_to_store(const uint8_t* pkt,
                                       const netflow9_header_t* netflow9_header,
                                       const template_t* flow_template,
                                       const std::string& client_addres_in_string_format) {
    // Skip scope fields, I really do not want to parse this informations
    pkt += flow_template->option_scope_length;
    // logger << log4cpp::Priority::ERROR << "We have following length for option_scope_length " <<
    // flow_template->option_scope_length;

    uint32_t sampling_rate = 0;
    uint32_t offset        = 0;

    // We may have some fun things encoded here
    // Cisco ASR9000 encodes mapping between interfaces IDs and interface names here
    // It uses pairs of two types: type 10 (input SNMP) and type 83 (interface description)
    interface_id_to_name_t interface_id_to_name;

    device_timeouts_t device_timeouts{};

    for (const auto& elem : flow_template->records) {
        const uint8_t* data_shift = pkt + offset;

        // Time to extract sampling rate
        // Cisco ASR1000
        if (elem.record_type == NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL) {
            // According to spec it should be 4 bytes: http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
            // but in real world we saw 2 byte encoding for Cisco ASR1000
            if (elem.record_length == 2) {
                uint16_t current_sampling_rate = 0;
                memcpy(&current_sampling_rate, data_shift, elem.record_length);

                // Convert 2 byte representation to little endian byte order
                current_sampling_rate = fast_ntoh(current_sampling_rate);

                sampling_rate = current_sampling_rate;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "2 byte encoded NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL sampling rate: " << sampling_rate
                           << " from " << client_addres_in_string_format;
                }
            } else if (elem.record_length == 4) {
                uint32_t current_sampling_rate = 0;
                memcpy(&current_sampling_rate, data_shift, elem.record_length);

                // Convert 4 byte representation to little endian byte order
                current_sampling_rate = fast_ntoh(current_sampling_rate);

                sampling_rate = current_sampling_rate;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "4 byte encoded NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL sampling rate: " << sampling_rate
                           << " from " << client_addres_in_string_format;
                }
            } else {
                netflow_v9_too_large_field++;
                logger << log4cpp::Priority::ERROR
                       << "Incorrect length for NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL: " << elem.record_length;
            }
        } else if (elem.record_type == NETFLOW9_SAMPLING_INTERVAL) {
            // Juniper MX uses this type to encode sampling rate

            if (elem.record_length == 2) {
                uint16_t current_sampling_rate = 0;
                memcpy(&current_sampling_rate, data_shift, elem.record_length);

                // Convert 2 byte representation to little endian byte order
                current_sampling_rate = fast_ntoh(current_sampling_rate);

                sampling_rate = current_sampling_rate;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "2 byte encoded NETFLOW9_SAMPLING_INTERVAL sampling rate: " << sampling_rate
                           << " from " << client_addres_in_string_format;
                }
            } else if (elem.record_length == 4) {
                uint32_t current_sampling_rate = 0;
                memcpy(&current_sampling_rate, data_shift, elem.record_length);

                // Convert 4 byte representation to little endian byte order
                current_sampling_rate = fast_ntoh(current_sampling_rate);

                sampling_rate = current_sampling_rate;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "4 byte encoded NETFLOW9_SAMPLING_INTERVAL sampling rate: " << sampling_rate
                           << " from " << client_addres_in_string_format;
                }
            } else {
                netflow_v9_too_large_field++;
                logger << log4cpp::Priority::ERROR << "Incorrect length for NETFLOW9_SAMPLING_INTERVAL: " << elem.record_length;
            }
        } else if (elem.record_type == NETFLOW9_INTERFACE_DESCRIPTION) {
            if (elem.record_length > 128) {
                // Apply reasonable constraints on maximum interface description field
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_INTERFACE_DESCRIPTION";
                }
            } else {
                // Find actual length of name ignoring zero characters
                // In Cisco's encoding all empty symbols are zero bytes
                size_t interface_name_length = strlen((const char*)data_shift);

                // It's not clear how strings which have same string length as field itself (i.e. X non zero chars in X
                // length field) will be encoded I assume in that case router may skip zero byte?

                if (interface_name_length <= elem.record_length) {
                    // Copy data to string using string length calculated previously
                    interface_id_to_name.interface_description = std::string((const char*)data_shift, interface_name_length);
                } else {
                    // It may mean that we have no null byte which terminates string
                    netflow_v9_too_large_field++;

                    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                        logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_INTERFACE_DESCRIPTION";
                    }
                }
            }
        } else if (elem.record_type == NETFLOW9_INPUT_SNMP) {
            // https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html claims that it may be 2 or more bytes
            if (elem.record_length == 4) {
                uint32_t input_interface = 0;
                memcpy(&input_interface, data_shift, elem.record_length);

                input_interface                   = fast_ntoh(input_interface);
                interface_id_to_name.interface_id = input_interface;
            } else if (elem.record_length == 2) {
                uint16_t input_interface = 0;
                memcpy(&input_interface, data_shift, elem.record_length);

                input_interface                   = fast_ntoh(input_interface);
                interface_id_to_name.interface_id = input_interface;
            } else {
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_INPUT_SNMP";
                }
            }
        } else if (elem.record_type == NETFLOW9_ACTIVE_TIMEOUT) {
            uint16_t active_timeout = 0;

            // According to Cisco's specification it should be 2 bytes: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
            if (elem.record_length == 2) {
                memcpy(&active_timeout, data_shift, elem.record_length);
                active_timeout = fast_ntoh(active_timeout);

                netflow_v9_active_flow_timeout_received++;
                device_timeouts.active_timeout = active_timeout;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got active timeout: " << active_timeout << " seconds";
                }
            } else {
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_ACTIVE_TIMEOUT";
                }
            }

        } else if (elem.record_type == NETFLOW9_INACTIVE_TIMEOUT) {
            uint16_t inactive_timeout = 0;

            // According to Cisco's specification it should be 2 bytes: https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
            if (elem.record_length == 2) {
                memcpy(&inactive_timeout, data_shift, elem.record_length);
                inactive_timeout = fast_ntoh(inactive_timeout);

                netflow_v9_inactive_flow_timeout_received++;
                device_timeouts.inactive_timeout = inactive_timeout;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got inactive timeout: " << inactive_timeout << " seconds";
                }
            } else {
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_INACTIVE_TIMEOUT";
                }
            }
        } else if (elem.record_type == NETFLOW9_FLOW_SAMPLER_ID) {
            if (elem.record_length == 4) {
                uint32_t sampler_id = 0;

                memcpy(&sampler_id, data_shift, elem.record_length);

                sampler_id = fast_ntoh(sampler_id);

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG << "Got sampler id from options template: " << int(sampler_id);
                }
            } else if (elem.record_length == 2) {
                uint16_t sampler_id = 0;

                memcpy(&sampler_id, data_shift, elem.record_length);

                sampler_id = fast_ntoh(sampler_id);

                logger << log4cpp::Priority::DEBUG << "Got sampler id from options template: " << int(sampler_id);
            } else {
                netflow_v9_too_large_field++;

                if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                    logger << log4cpp::Priority::DEBUG
                           << "Too large field for NETFLOW9_FLOW_SAMPLER_ID options: " << elem.record_length;
                }
            }
        }

        offset += elem.record_length;
    }

    // We print only non zero numbers to distinguish cases when we did not receive anything
    if (logger.getPriority() == log4cpp::Priority::DEBUG && interface_id_to_name.interface_id != 0) {
        logger << log4cpp::Priority::DEBUG << "Interface number: " << interface_id_to_name.interface_id << " on "
               << client_addres_in_string_format << " name: '" << interface_id_to_name.interface_description << "'";
    }


    update_netflow_v9_sampling_rate(sampling_rate, client_addres_in_string_format);

    // Update flow timeouts in our store
    update_device_flow_timeouts(device_timeouts, netflow_v9_per_device_flow_timeouts_mutex, netflow_v9_per_device_flow_timeouts,
                                client_addres_in_string_format, netflow_protocol_version_t::netflow_v9);
}

// Incoming sampling rate uses little endian
void update_netflow_v9_sampling_rate(uint32_t new_sampling_rate, const std::string& client_addres_in_string_format) {
    if (new_sampling_rate == 0) {
        return;
    }

    netflow9_custom_sampling_rate_received++;

    // logger<< log4cpp::Priority::INFO << "I extracted sampling rate: " << new_sampling_rate
    //    << "for " << client_address_in_string_format;

    {
        std::lock_guard<std::mutex> lock(netflow9_sampling_rates_mutex);

        auto known_sampling_rate = netflow9_sampling_rates.find(client_addres_in_string_format);

        if (known_sampling_rate == netflow9_sampling_rates.end()) {
            // We had no sampling rates before
            netflow9_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

            netflow9_sampling_rate_changes++;

            logger << log4cpp::Priority::INFO << "Learnt new Netflow v9 sampling rate " << new_sampling_rate << " for "
                   << client_addres_in_string_format;

        } else {
            auto old_sampling_rate = known_sampling_rate->second;

            if (old_sampling_rate != new_sampling_rate) {
                netflow9_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

                netflow9_sampling_rate_changes++;

                logger << log4cpp::Priority::INFO << "Detected sampling rate change from " << old_sampling_rate
                       << " to " << new_sampling_rate << " for " << client_addres_in_string_format;

            }
        }
    }
}

// That's kind of histogram emulation
void increment_duration_counters_netflow_v9(int64_t duration) {
    if (duration == 0) {
        netflow9_duration_0_seconds++;
    } else if (duration <= 1) {
        netflow9_duration_less_1_seconds++;
    } else if (duration <= 2) {
        netflow9_duration_less_2_seconds++;
    } else if (duration <= 3) {
        netflow9_duration_less_3_seconds++;
    } else if (duration <= 5) {
        netflow9_duration_less_5_seconds++;
    } else if (duration <= 10) {
        netflow9_duration_less_10_seconds++;
    } else if (duration <= 15) {
        netflow9_duration_less_15_seconds++;
    } else if (duration <= 30) {
        netflow9_duration_less_30_seconds++;
    } else if (duration <= 60) {
        netflow9_duration_less_60_seconds++;
    } else if (duration <= 90) {
        netflow9_duration_less_90_seconds++;
    } else if (duration <= 180) {
        netflow9_duration_less_180_seconds++;
    } else {
        netflow9_duration_exceed_180_seconds++;
    }

    return;
}

void netflow9_flowset_to_store(const uint8_t* pkt,
                               const netflow9_header_t* netflow9_header,
                               const std::vector<template_record_t>& template_records,
                               const std::string& client_addres_in_string_format,
                               uint32_t client_ipv4_address) {
    // Should be done according to
    // https://github.com/pavel-odintsov/fastnetmon/issues/147
    // if (template->total_length > len)
    //    return 1;

    simple_packet_t packet;
    packet.source       = NETFLOW;
    packet.arrival_time = current_inaccurate_time;

    packet.agent_ip_address = client_ipv4_address;

    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec         = ntohl(netflow9_header->time_sec);

    // By default, assume IPv4 traffic here
    // But code below can switch it to IPv6
    packet.ip_protocol_version = 4; //-V1048

    {
        std::lock_guard<std::mutex> lock(netflow9_sampling_rates_mutex);
        auto itr = netflow9_sampling_rates.find(client_addres_in_string_format);

        if (itr == netflow9_sampling_rates.end()) {
            // Use global value
            packet.sample_ratio = netflow_sampling_ratio;
        } else {
            packet.sample_ratio = itr->second;
        }
    }

    // Place to keep meta information which is not needed in simple_simple_packet_t structure
    netflow_meta_info_t flow_meta;

    uint32_t offset = 0;

    // We should iterate over all available template fields
    for (auto iter = template_records.begin(); iter != template_records.end(); iter++) {
        uint32_t record_type   = iter->record_type;
        uint32_t record_length = iter->record_length;

        bool netflow9_record_to_flow_result = netflow9_record_to_flow(record_type, record_length, pkt + offset, packet,
                                                                      flow_meta, client_addres_in_string_format);
        // logger<< log4cpp::Priority::INFO<<"Read data with type: "<<record_type<<"
        // and
        // length:"<<record_length;
        if (!netflow9_record_to_flow_result) {
            return;
        }

        offset += record_length;
    }

    // logger<< log4cpp::Priority::INFO << "bytes_from_source_to_destination:" << flow_meta.bytes_from_source_to_destination;
    // logger<< log4cpp::Priority::INFO << "bytes_from_destination_to_source:" << flow_meta.bytes_from_destination_to_source;

    // logger<< log4cpp::Priority::INFO << "packets_from_source_to_destination:" << flow_meta.packets_from_source_to_destination;
    // logger<< log4cpp::Priority::INFO << "packets_from_destination_to_source:" << flow_meta.packets_from_destination_to_source;

    // logger<< log4cpp::Priority::INFO << "flow_id:" << flow_meta.flow_id;

    // logger<< log4cpp::Priority::INFO << "Data link frame size: " << flow_meta.data_link_frame_size;

    // Use packet length from Netflow Lite data
    // if (packet.length == 0) {
    //    packet.length = flow_meta.data_link_frame_size;
    //}

    // If we were able to decode nested packet then it means that it was Netflow Lite and we can overwrite information in packet
    if (flow_meta.nested_packet_parsed) {
        // Override most of the fields from nested packet as we need to use them instead
        override_packet_fields_from_nested_packet(packet, flow_meta.nested_packet);

        // Try to calculate sampling rate
        if (flow_meta.selected_packets != 0) {
            packet.sample_ratio = uint32_t(double(flow_meta.observed_packets) / double(flow_meta.selected_packets));
        }
    }

    if (false) {
        // For Juniper routers we need fancy logic to mark packets as dropped:
        // https://apps.juniper.net/feature-explorer/feature-info.html?fKey=7679&fn=Enhancements%20to%20inline%20flow%20monitoring

        // We will apply it only if we have no forwarding_status in packet
        if (!flow_meta.received_forwarding_status) {
            // We need to confirm that TWO rules are TRUE:
            // - Output interface is 0
            // - Next hop for IPv4 is set and set to 0 OR next hop for IPv6 set and set to zero
            if (packet.output_interface == 0 &&
                ((flow_meta.ip_next_hop_ipv4_set && flow_meta.ip_next_hop_ipv4 == 0) ||
                 (is_zero_ipv6_address(flow_meta.bgp_next_hop_ipv6) && flow_meta.bgp_next_hop_ipv6_set))) {

                packet.forwarding_status = forwarding_status_t::dropped;
                netflow_v9_marked_zero_next_hop_and_zero_output_as_dropped++;
            }
        }
    }


    // Total number of Netflow v9 flows
    netflow_v9_total_flows++;

    netflow_ipfix_all_protocols_total_flows++;

    // We may have cases like this from previous step:
    // :0000:443 > :0000:61444 protocol: tcp flags: psh,ack frag: 0  packets: 1 size: 205 bytes ip size: 205 bytes ttl:
    // 0 sample ratio: 1000 It happens when router sends IPv4 and zero IPv6 fields in same packet
    if (packet.ip_protocol_version == 6 && is_zero_ipv6_address(packet.src_ipv6) &&
        is_zero_ipv6_address(packet.dst_ipv6) && packet.src_ip != 0 && packet.dst_ip != 0) {

        netflow9_protocol_version_adjustments++;
        packet.ip_protocol_version = 4;
    }


    if (packet.ip_protocol_version == 4) {
        netflow_v9_total_ipv4_flows++;
    } else if (packet.ip_protocol_version == 6) {
        netflow_v9_total_ipv6_flows++;
    }

    double duration_float = packet.flow_end - packet.flow_start;
    // Covert milliseconds to seconds
    duration_float = duration_float / 1000;

    int64_t duration = int64_t(duration_float);

    // Increments duration counters
    increment_duration_counters_netflow_v9(duration);

    // logger<< log4cpp::Priority::INFO<< "Flow start: " << packet.flow_start << " end: " << packet.flow_end << " duration: " << duration;

    // Logical sources of this logic are unknown but I'm sure we had reasons to do so
    if (packet.protocol == IPPROTO_ICMP) {
        // Explicitly set ports to zeros even if device sent something in these fields
        packet.source_port      = 0;
        packet.destination_port = 0;
    }

    // Logic to handle Cisco ASA Netflow v9. We can identify it by zero values for both packet.length and
    // packet.number_of_packets fields and presence of meta_info.flow_id
    if (packet.length == 0 && packet.number_of_packets == 0 && flow_meta.flow_id != 0) {
        // Very likely we're having deal with Cisco ASA
        // ASA uses bi-directional flows and we need to generate two simple packets for each single one from Cisco

        //
        // Original flow example:
        // bytes_from_source_to_destination:1687
        // bytes_from_destination_to_source:2221
        // packets_from_source_to_destination:12
        // packets_from_destination_to_source:15
        //
        // Examples of two flows generated by this logic:
        // 71.105.61.155:55819 > 198.252.166.164:443 protocol: tcp flags: - frag: 0  packets: 12 size: 1687 bytes ip
        // size: 1687 bytes ttl: 0 sample ratio: 1 198.252.166.164:443 > 71.105.61.155:55819 protocol: tcp flags: -
        // frag: 0  packets: 15 size: 2221 bytes ip size: 2221 bytes ttl: 0 sample ratio: 1
        //

        packet.length    = flow_meta.bytes_from_source_to_destination;
        packet.ip_length = packet.length;

        packet.number_of_packets = flow_meta.packets_from_source_to_destination;

        // As ASA's flows are bi-directional we need to create another flow for opposite direction
        // Create it using original packet before passing it to traffic core for processing as traffic core may alter it
        simple_packet_t reverse_packet = packet;

        // Send first packet for processing
        netflow_process_func_ptr(packet);

        // Use another set of length and packet counters
        reverse_packet.length    = flow_meta.bytes_from_destination_to_source;
        reverse_packet.ip_length = reverse_packet.length;

        reverse_packet.number_of_packets = flow_meta.packets_from_destination_to_source;

        // Swap IPv4 IPs
        std::swap(reverse_packet.src_ip, reverse_packet.dst_ip);

        // Swap IPv6 IPs
        std::swap(reverse_packet.src_ipv6, reverse_packet.dst_ipv6);

        // Swap ports
        std::swap(reverse_packet.source_port, reverse_packet.destination_port);

        // Swap interfaces
        std::swap(reverse_packet.input_interface, reverse_packet.output_interface);

        // Swap ASNs
        std::swap(reverse_packet.src_asn, reverse_packet.dst_asn);

        // Swap countries
        std::swap(reverse_packet.src_country, reverse_packet.dst_country);

        // Send it for processing
        netflow_process_func_ptr(reverse_packet);

        // Stop processing here as this logic is very special and I do not think that we have dropped support for ASA
        return;
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
}

bool process_netflow_v9_data(const uint8_t* pkt,
                             size_t flowset_length,
                             const netflow9_header_t* netflow9_header,
                             uint32_t source_id,
                             const std::string& client_addres_in_string_format,
                             uint32_t client_ipv4_address) {
    const netflow9_data_flowset_header_t* dath = (const netflow9_data_flowset_header_t*)pkt;

    // Store packet end, it's useful for sanity checks
    const uint8_t* packet_end = pkt + flowset_length;

    if (flowset_length < sizeof(*dath)) {
        logger << log4cpp::Priority::INFO << "Short Netflow v9 data flowset header";
        return false;
    }

    // uint32_t is a 4 byte integer. Any reason why we convert here 16 bit flowset_id to 32 bit? ... Strange
    uint32_t flowset_id = ntohs(dath->header.flowset_id);
    // logger<< log4cpp::Priority::INFO<<"We have data with flowset_id:
    // "<<flowset_id;

    // We should find template here
    const template_t* field_template = peer_find_template(global_netflow9_templates, global_netflow9_templates_mutex,
                                                          source_id, flowset_id, client_addres_in_string_format);

    if (field_template == NULL) {
        netflow9_packets_with_unknown_templates++;

        logger << log4cpp::Priority::DEBUG << "We don't have a Netflow 9 template for flowset_id: " << flowset_id
               << " client " << client_addres_in_string_format << " source_id: " << source_id
               << " but it's not an error if this message disappears in 5-10 "
                  "seconds. We need some "
                  "time to learn it!";
        return true;
    }

    if (field_template->records.empty()) {
        logger << log4cpp::Priority::ERROR << "Blank records in template";
        return false;
    }

    uint32_t offset       = sizeof(*dath);
    uint32_t num_flowsets = (flowset_length - offset) / field_template->total_length;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logger << log4cpp::Priority::ERROR << "Invalid number of data flowsets, strange number of flows: " << num_flowsets;
        return false;
    }

    if (field_template->type == netflow_template_type_t::Data) {
        for (uint32_t i = 0; i < num_flowsets; i++) {
            // process whole flowset
            netflow9_flowset_to_store(pkt + offset, netflow9_header, field_template->records,
                                      client_addres_in_string_format, client_ipv4_address);

            offset += field_template->total_length;
        }
    } else if (field_template->type == netflow_template_type_t::Options) {
        // logger << log4cpp::Priority::INFO << "I have " << num_flowsets << " flowsets here";
        // logger << log4cpp::Priority::INFO << "Flowset template total length: " << field_template->total_length;

        netflow9_options_packet_number++;

        for (uint32_t i = 0; i < num_flowsets; i++) {
            if (pkt + offset + field_template->total_length > packet_end) {
                logger << log4cpp::Priority::ERROR << "We tried to read data outside packet end";
                return false;
            }

            // logger << log4cpp::Priority::INFO << "Process flowset: " << i;
            netflow9_options_flowset_to_store(pkt + offset, netflow9_header, field_template, client_addres_in_string_format);

            offset += field_template->total_length;
        }
    }

    return true;
}


bool process_netflow_packet_v9(const uint8_t* packet,
                               uint32_t packet_length,
                               const std::string& client_addres_in_string_format,
                               uint32_t client_ipv4_address) {
    // logger<< log4cpp::Priority::INFO<<"We got Netflow  v9 packet!";

    const netflow9_header_t* netflow9_header = (const netflow9_header_t*)packet;

    if (packet_length < sizeof(*netflow9_header)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 header. "
               << " Agent IP:" << client_addres_in_string_format;
        return false;
    }

    // Number of flow sets in packet, each flow set may carry multiple flows
    uint32_t flowset_count_total = ntohs(netflow9_header->header.flowset_number);

    // Limit reasonable number of flow sets per packet
    if (flowset_count_total > flowsets_per_packet_maximum_number) {
        logger << log4cpp::Priority::ERROR << "We have so many flowsets inside Netflow v9 packet: " << flowset_count_total
               << " Agent IP:" << client_addres_in_string_format;

        return false;
    }

    uint32_t source_id = ntohl(netflow9_header->source_id);
    uint32_t offset    = sizeof(*netflow9_header);

    // logger<< log4cpp::Priority::INFO<<"Template source id: "<<source_id;
    // logger<< log4cpp::Priority::INFO<< "Total flowsets " << flowset_count_total;

    for (uint32_t flowset_number = 0; flowset_number < flowset_count_total; flowset_number++) {
        // Make sure we don't run off the end of the flow
        if (offset >= packet_length) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside Netflow packet agent IP:" << client_addres_in_string_format
                   << " flowset number: " << flowset_number;
            return false;
        }

        const netflow9_flowset_header_common_t* flowset = (const netflow9_flowset_header_common_t*)(packet + offset);

        uint32_t flowset_id     = ntohs(flowset->flowset_id);
        uint32_t flowset_length = ntohs(flowset->length);

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */

        if (offset + flowset_length > packet_length) {
            logger << log4cpp::Priority::ERROR << "We tried to read from address outside Netflow's packet flowset agent IP: "
                   << client_addres_in_string_format << " flowset number: " << flowset_number
                   << " flowset_id: " << flowset_id << " flowset_length: " << flowset_length;
            return false;
        }

        switch (flowset_id) {
        case NETFLOW9_TEMPLATE_FLOWSET_ID:
            netflow9_data_templates_number++;
            // logger<< log4cpp::Priority::INFO<<"We read template";
            if (!process_netflow_v9_template(packet + offset, flowset_length, source_id, client_addres_in_string_format, flowset_number)) {
                return false;
            }
            break;
        case NETFLOW9_OPTIONS_FLOWSET_ID:
            netflow9_options_templates_number++;
            if (!process_netflow_v9_options_template(packet + offset, flowset_length, source_id, client_addres_in_string_format)) {
                return false;
            }
            break;
        default:
            if (flowset_id < NETFLOW9_MIN_RECORD_FLOWSET_ID) {
                logger << log4cpp::Priority::ERROR << "Received unknown Netflow v9 reserved flowset type " << flowset_id
                       << " agent IP: " << client_addres_in_string_format;
                break; // interrupts only switch!
            }

            netflow9_data_packet_number++;
            // logger<< log4cpp::Priority::INFO<<"We read data";

            if (!process_netflow_v9_data(packet + offset, flowset_length, netflow9_header, source_id,
                                         client_addres_in_string_format, client_ipv4_address) != 0) {
                // logger<< log4cpp::Priority::ERROR<<"Can't process function
                // process_netflow_v9_data correctly";
                netflow_v9_broken_packets++;
                return false;
            }

            break;
        }

        // This logic will stop processing if we've reached end of flow set section before reading all flow sets
        // It's not reliable to use alone because we may have garbage at the end of packet. That's why we have loop over number of flowset records as main condition.
        offset += flowset_length;

        if (offset == packet_length) {
            break;
        }
    }

    return true;
}
