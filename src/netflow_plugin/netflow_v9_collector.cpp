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

    field_template.template_id  = template_id;
    field_template.records      = template_records_map;
    field_template.num_records  = records_number;
    field_template.total_length = total_size + scopes_total_size;
    field_template.type         = netflow_template_type_t::Options;
    field_template.option_scope_length = scopes_total_size;

    // We need to know when we received it
    field_template.timestamp = current_inaccurate_time;

    // logger << log4cpp::Priority::INFO << "Read options template:" << print_template(field_template);

    // Add/update template
    bool updated                   = false;
    bool updated_existing_template = false;

    add_update_peer_template(netflow_protocol_version_t::netflow_v9, global_netflow9_templates, source_id, template_id, client_addres_in_string_format,
                             field_template, updated, updated_existing_template);

    if (updated_existing_template) {
        netflow_v9_template_data_updates++;
    }

    return true;
}

bool process_netflow_v9_template(uint8_t* pkt, size_t len, uint32_t source_id, const std::string& client_addres_in_string_format, uint64_t flowset_number) {
    netflow9_flowset_header_common_t* template_header = (netflow9_flowset_header_common_t*)pkt;
    template_t field_template;

    if (len < sizeof(*template_header)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 flowset template header " << len
               << " bytes agent IP: " << client_addres_in_string_format;
        return false;
    }

    if (fast_ntoh(template_header->flowset_id) != NETFLOW9_TEMPLATE_FLOWSET_ID) {
        logger << log4cpp::Priority::ERROR
               << "Function process_netflow_v9_template expects only "
                  "NETFLOW9_TEMPLATE_FLOWSET_ID but "
                  "got another id: "
               << ntohs(template_header->flowset_id);
        return false;
    }

    for (uint32_t offset = sizeof(*template_header); offset < len;) {
        netflow9_template_flowset_header_t* tmplh = (netflow9_template_flowset_header_t*)(pkt + offset);

        uint32_t template_id = ntohs(tmplh->template_id);
        uint32_t count       = ntohs(tmplh->fields_count);
        offset += sizeof(*tmplh);

        // logger<< log4cpp::Priority::INFO<<"Template template_id
        // is:"<<template_id;

        uint32_t total_size = 0;

        std::vector<template_record_t> template_records_map;
        for (uint32_t i = 0; i < count; i++) {
            if (offset >= len) {
                logger << log4cpp::Priority::ERROR << "Short Netflow v9 flowset template";
                return false;
            }

            netflow9_template_flowset_record_t* tmplr = (netflow9_template_flowset_record_t*)(pkt + offset);

            uint32_t record_type   = ntohs(tmplr->type);
            uint32_t record_length = ntohs(tmplr->length);

            template_record_t current_record;
            current_record.record_type   = record_type;
            current_record.record_length = record_length;

            template_records_map.push_back(current_record);

            // logger<< log4cpp::Priority::INFO<<"Learn new template type:
            // "<<ntohs(tmplr->type)<<"
            // length:"<<ntohs(tmplr->length);

            offset += sizeof(*tmplr);
            total_size += record_length;

            // TODO: introduce nf9_check_rec_len
        }

        field_template.template_id = template_id;
        field_template.num_records = count;
        field_template.total_length   = total_size;
        field_template.records     = template_records_map;
        field_template.type        = netflow_template_type_t::Data;

        // Add/update template
        bool updated = false;
        bool updated_existing_template = false;

        add_update_peer_template(netflow_protocol_version_t::netflow_v9, global_netflow9_templates, source_id, template_id, client_addres_in_string_format,
                                 field_template, updated, updated_existing_template);
    }

    // for (auto elem: global_netflow9_templates) {
    //    logger << log4cpp::Priority::INFO  << "Template ident: " << elem.first << " content: " <<
    //    print_template_t(elem.second);
    //}

    return true;
}


/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - record_length), data, record_length);

// Safe version of BE_COPY macro
bool be_copy_function(uint8_t* data, uint8_t* target, uint32_t target_field_length, uint32_t record_field_length) {
    if (target_field_length < record_field_length) {
        return false;
    }

    memcpy(target + (target_field_length - record_field_length), data, record_field_length);
    return true;
}


bool netflow9_record_to_flow(uint32_t record_type, uint32_t record_length, const uint8_t* data, simple_packet_t& packet, netflow_meta_info_t& flow_meta, const std::string& client_addres_in_string_format) {
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
    case NETFLOW9_LAYER2_PACKET_SECTION_DATA:
        // We create block here as gcc does not want to compile without it with error: error: jump to case label
        // https://stackoverflow.com/questions/5685471/error-jump-to-case-label-in-switch-statement
        {
            netflow_v9_lite_headers++;

            bool read_packet_length_from_ip_header = true;

            // It's our safe fallback
            uint64_t full_packet_length = record_length;

            // Device must provide this information on previous iteration, let's try to get it in case if we've got it:
            if (flow_meta.data_link_frame_size != 0) {
                full_packet_length = flow_meta.data_link_frame_size;
            }

            bool extract_tunnel_traffic = false;

            auto result =
                parse_raw_packet_to_simple_packet_full_ng((u_char*)(data), full_packet_length, record_length,
                                                       flow_meta.nested_packet, extract_tunnel_traffic, read_packet_length_from_ip_header);

            if (result != network_data_stuctures::parser_code_t::success) {
                // Cannot decode data
                netflow_v9_lite_header_parser_error++;
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
            bytes_counter        = fast_ntoh(bytes_counter);
            
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
        // Well, this record type is expected to be only in options templates but Mikrotik in RouterOS v6.49.6 has another opinion
        // and we have dump which clearly confirms that they send this data in data templates

        if (record_length == 4) {
            uint32_t current_sampling_rate = 0;

            memcpy(&current_sampling_rate, data, record_length);

            // NB! Our sampling rate update logic uses endian-less conversion directly in update_netflow_v9_sampling_rate / update_ipfix_sampling_rate 
            // and we should not convert this value to little endian here

            // We do convert it to little endian only for pretty printing
            // logger << log4cpp::Priority::INFO << "Got sampling date from data packet: " << fast_ntoh(current_sampling_rate);
            
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

            // Pass it to global variable
            sampling_rate = current_sampling_rate;
        } else {
            netflow_v9_too_large_field++;

            if (logger.getPriority() == log4cpp::Priority::DEBUG) {
                logger << log4cpp::Priority::DEBUG << "Too large field for NETFLOW9_SAMPLING_INTERVAL in data packet";
            }
        }

        break;
    }

    return true;
}

// Read options data packet with known template
void netflow9_options_flowset_to_store(uint8_t* pkt, size_t len, netflow9_header_t* nf9_hdr, template_t* flow_template, std::string client_addres_in_string_format) {
    // Skip scope fields, I really do not want to parse this informations
    pkt += flow_template->option_scope_length;
    // logger << log4cpp::Priority::ERROR << "We have following length for option_scope_length " <<
    // flow_template->option_scope_length;

    auto template_records = flow_template->records;

    uint32_t sampling_rate = 0;
    uint32_t offset        = 0;

    for (auto elem : template_records) {
        uint8_t* data_shift = pkt + offset;

        // Time to extract sampling rate
        // Cisco ASR1000
        if (elem.record_type == NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL) {
            // Check supported length
            if (elem.record_length == NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL_LENGTH or
                elem.record_length == NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL_LENGTH_ASR1000) {
                bool result = be_copy_function(data_shift, (uint8_t*)&sampling_rate, sizeof(sampling_rate), elem.record_length);

                if (!result) {
                    logger << log4cpp::Priority::ERROR
                           << "Tool tried to read outside allowed memory region, prevented "
                              "fault: FLOW_SAMPLER_RANDOM_INTERVAL";
                }

                // logger << log4cpp::Priority::ERROR << "sampling rate: " << fast_ntoh(sampling_rate);
            } else {
                logger << log4cpp::Priority::ERROR << "Incorrect length for FLOW_SAMPLER_RANDOM_INTERVAL: " << elem.record_length;
            }
        } else if (elem.record_type == NETFLOW9_SAMPLING_INTERVAL) {
            // Juniper MX
            if (elem.record_length > sizeof(sampling_rate)) {
                logger << log4cpp::Priority::ERROR << "Unexpectedly big size for NETFLOW9_SAMPLING_INTERVAL: " << elem.record_length;
                continue;
            }

            bool result = be_copy_function(data_shift, (uint8_t*)&sampling_rate, sizeof(sampling_rate), elem.record_length);

            if (!result) {
                logger << log4cpp::Priority::ERROR << "Tool tried to read outside allowed memory region, prevented fault: NETFLOW9_SAMPLING_INTERVAL";
            }
        }

        offset += elem.record_length;
    }

    if (sampling_rate != 0) {
        auto new_sampling_rate = fast_ntoh(sampling_rate);

        netflow9_custom_sampling_rate_received++;

        // logger<< log4cpp::Priority::INFO << "I extracted sampling rate: " << new_sampling_rate
        //    << "for " << client_addres_in_string_format;

        // Replace old sampling rate value
        std::lock_guard<std::mutex> lock(netflow9_sampling_rates_mutex);
        auto old_sampling_rate = netflow9_sampling_rates[client_addres_in_string_format];

        if (old_sampling_rate != new_sampling_rate) {
            netflow9_sampling_rates[client_addres_in_string_format] = new_sampling_rate;

            netflow9_sampling_rate_changes++;

            logger << log4cpp::Priority::DEBUG << "Change sampling rate from " << old_sampling_rate << " to "
                   << new_sampling_rate << " for " << client_addres_in_string_format;
        }
    }
}

// Gap

// That's kind of histogram emulation
void increment_duration_counters_netflow_v9(int64_t duration) {
    if (duration <= 15) {
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


void netflow9_flowset_to_store(uint8_t* pkt,
                          size_t len,
                          netflow9_header_t* nf9_hdr,
                          std::vector<template_record_t>& template_records,
                          std::string& client_addres_in_string_format,
                          uint32_t client_ipv4_address) {
    // Should be done according to
    // https://github.com/pavel-odintsov/fastnetmon/issues/147
    // if (template->total_len > len)
    //    return 1;

    uint32_t offset = 0;

    simple_packet_t packet;
    packet.source = NETFLOW;

    packet.agent_ip_address = client_ipv4_address;

    // We use shifted values and should process only zeroed values
    // because we are working with little and big endian data in same time
    packet.number_of_packets = 0;
    packet.ts.tv_sec         = ntohl(nf9_hdr->time_sec);

    // By default, assume IPv4 traffic here
    // But code below can switch it to IPv6
    packet.ip_protocol_version = 4;

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

    // We should iterate over all available template fields
    for (std::vector<template_record_t>::iterator iter = template_records.begin(); iter != template_records.end(); iter++) {
        uint32_t record_type   = iter->record_type;
        uint32_t record_length = iter->record_length;

        bool netflow9_rec_to_flow_result = netflow9_record_to_flow(record_type, record_length, pkt + offset, packet, flow_meta, client_addres_in_string_format);
        // logger<< log4cpp::Priority::INFO<<"Read data with type: "<<record_type<<"
        // and
        // length:"<<record_length;
        if (!netflow9_rec_to_flow_result) {
            return;
        }

        offset += record_length;
    }

    bool netflow_lite_flow = false;

    // If we were able to decode nested packet then it means that it was Netflow Lite and we can overwrite information in packet
    if (flow_meta.nested_packet_parsed) {
        // Copy IP addresses
        packet.src_ip = flow_meta.nested_packet.src_ip;
        packet.dst_ip = flow_meta.nested_packet.dst_ip;

        packet.src_ipv6 = flow_meta.nested_packet.src_ipv6;
        packet.dst_ipv6 = flow_meta.nested_packet.dst_ipv6;

        packet.ip_protocol_version = flow_meta.nested_packet.ip_protocol_version;
        packet.ttl                 = flow_meta.nested_packet.ttl;

        // Ports
        packet.source_port      = flow_meta.nested_packet.source_port;
        packet.destination_port = flow_meta.nested_packet.destination_port;

        packet.protocol          = flow_meta.nested_packet.protocol;
        packet.length            = flow_meta.nested_packet.length;
        packet.ip_length         = flow_meta.nested_packet.ip_length;
        packet.number_of_packets = 1;
        packet.flags             = flow_meta.nested_packet.flags;
        packet.ip_fragmented     = flow_meta.nested_packet.ip_fragmented;
        packet.ip_dont_fragment  = flow_meta.nested_packet.ip_dont_fragment;
        packet.vlan              = flow_meta.nested_packet.vlan;

        // Try to calculate sampling rate
        if (flow_meta.selected_packets != 0) {
            packet.sample_ratio = uint32_t(double(flow_meta.observed_packets) / double(flow_meta.selected_packets));
        }

        // We need to set it to disable logic which populates and decodes data below
        netflow_lite_flow = true;
    }


    // Total number of Netflow v9 flows
    netflow_v9_total_flows++;

    netflow_ipfix_all_protocols_total_flows++;

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

    if (!netflow_lite_flow) {
        // logger<< log4cpp::Priority::INFO<< "Flow start: " << packet.flow_start << " end: " << packet.flow_end << " duration: " << duration;

        // decode data in network byte order to host byte order
        packet.length = fast_ntoh(packet.length);

        // It's tricky to distinguish IP length and full packet lenght here. Let's use same.
        packet.ip_length         = packet.length;
        packet.number_of_packets = fast_ntoh(packet.number_of_packets);

        packet.protocol = fast_ntoh(packet.protocol);

        // We should convert ports to host byte order too
        packet.source_port      = fast_ntoh(packet.source_port);
        packet.destination_port = fast_ntoh(packet.destination_port);

        // Set protocol
        switch (packet.protocol) {
        case 1: {
            packet.protocol = IPPROTO_ICMP;

            packet.source_port      = 0;
            packet.destination_port = 0;
        } break;

        case 6: {
            packet.protocol = IPPROTO_TCP;
        } break;

        case 17: {
            packet.protocol = IPPROTO_UDP;
        } break;
        }
    }

    // pass data to FastNetMon
    netflow_process_func_ptr(packet);
}


int process_netflow_v9_data(uint8_t* pkt,
                            size_t len,
                            netflow9_header_t* nf9_hdr,
                            uint32_t source_id,
                            std::string& client_addres_in_string_format,
                            uint32_t client_ipv4_address) {
    netflow9_data_flowset_header_t* dath = (netflow9_data_flowset_header_t*)pkt;

    // Store packet end, it's useful for sanity checks
    uint8_t* packet_end = pkt + len;

    if (len < sizeof(*dath)) {
        logger << log4cpp::Priority::INFO << "Short netflow v9 data flowset header";
        return 1;
    }

    // uint32_t is a 4 byte integer. Any reason why we convert here 16 bit flowset_id to 32 bit? ... Strange
    uint32_t flowset_id = ntohs(dath->header.flowset_id);
    // logger<< log4cpp::Priority::INFO<<"We have data with flowset_id:
    // "<<flowset_id;

    // We should find template here
    template_t* flowset_template = peer_nf9_find_template(source_id, flowset_id, client_addres_in_string_format);

    if (flowset_template == NULL) {
        netflow9_packets_with_unknown_templates++;

        logger << log4cpp::Priority::DEBUG << "We don't have a Netflow 9 template for flowset_id: " << flowset_id
               << " client " << client_addres_in_string_format << " source_id: " << source_id
               << " but it's not an error if this message disappears in 5-10 "
                  "seconds. We need some "
                  "time to learn it!";
        return 0;
    }

    if (flowset_template->records.empty()) {
        logger << log4cpp::Priority::ERROR << "Blank records in template";
        return 1;
    }

    uint32_t offset       = sizeof(*dath);
    uint32_t num_flowsets = (len - offset) / flowset_template->total_length;

    if (num_flowsets == 0 || num_flowsets > 0x4000) {
        logger << log4cpp::Priority::ERROR << "Invalid number of data flowsets, strange number of flows: " << num_flowsets;
        return 1;
    }

    if (flowset_template->type == netflow_template_type_t::Data) {
        for (uint32_t i = 0; i < num_flowsets; i++) {
            // process whole flowset
            netflow9_flowset_to_store(pkt + offset, flowset_template->total_length, nf9_hdr, flowset_template->records,
                                 client_addres_in_string_format, client_ipv4_address);

            offset += flowset_template->total_length;
        }
    } else if (flowset_template->type == netflow_template_type_t::Options) {
        // logger << log4cpp::Priority::INFO << "I have " << num_flowsets << " flowsets here";
        // logger << log4cpp::Priority::INFO << "Flowset template total length: " << flowset_template->total_length;

        netflow9_options_packet_number++;

        for (uint32_t i = 0; i < num_flowsets; i++) {
            if (pkt + offset + flowset_template->total_length > packet_end) {
                logger << log4cpp::Priority::ERROR << "We tried to read data outside packet end";
                return 1;
            }

            // logger << log4cpp::Priority::INFO << "Process flowset: " << i;
            netflow9_options_flowset_to_store(pkt + offset, flowset_template->total_length, nf9_hdr, flowset_template,
                                         client_addres_in_string_format);

            offset += flowset_template->total_length;
        }
    }

    return 0;
}


bool process_netflow_packet_v9(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    // logger<< log4cpp::Priority::INFO<<"We get v9 netflow packet!";

    netflow9_header_t* nf9_hdr                = (netflow9_header_t*)packet;
    netflow9_flowset_header_common_t* flowset = nullptr;

    if (len < sizeof(*nf9_hdr)) {
        logger << log4cpp::Priority::ERROR << "Short Netflow v9 header";
        return false;
    }

    uint32_t flowset_count_total = ntohs(nf9_hdr->header.flowset_number);

    // Limit reasonable number of flow sets per packet
    if (flowset_count_total > flowsets_per_packet_maximum_number) {
        logger << log4cpp::Priority::ERROR << "We have so many flowsets inside Netflow v9 packet: " << flowset_count_total
               << " Agent IP:" << client_addres_in_string_format;
        return false;
    }

    uint32_t source_id = ntohl(nf9_hdr->source_id);
    // logger<< log4cpp::Priority::INFO<<"Template source id: "<<source_id;

    uint32_t offset = sizeof(*nf9_hdr);

    // logger<< log4cpp::Priority::INFO<< "Total flowsets " << flowset_count_total;

    for (uint32_t flowset_number = 0; flowset_number < flowset_count_total; flowset_number++) {
        /* Make sure we don't run off the end of the flow */
        if (offset >= len) {
            logger << log4cpp::Priority::ERROR
                   << "We tried to read from address outside Netflow packet agent IP:" << client_addres_in_string_format
                   << " flowset number: " << flowset_number;
            return false;
        }

        flowset = (netflow9_flowset_header_common_t*)(packet + offset);

        uint32_t flowset_id  = ntohs(flowset->flowset_id);
        uint32_t flowset_len = ntohs(flowset->length);

        /*
         * Yes, this is a near duplicate of the short packet check
         * above, but this one validates the flowset length from in
         * the packet before we pass it to the flowset-specific
         * handlers below.
         */

        if (offset + flowset_len > len) {
            logger << log4cpp::Priority::ERROR << "We tried to read from address outside Netflow's packet flowset agent IP: "
                   << client_addres_in_string_format << " flowset number: " << flowset_number
                   << " flowset_id: " << flowset_id << " flowset_length: " << flowset_len;
            return false;
        }

        switch (flowset_id) {
        case NETFLOW9_TEMPLATE_FLOWSET_ID:
            netflow9_data_templates_number++;
            // logger<< log4cpp::Priority::INFO<<"We read template";
            if (!process_netflow_v9_template(packet + offset, flowset_len, source_id, client_addres_in_string_format, flowset_number)) {
                return false;
            }
            break;
        case NETFLOW9_OPTIONS_FLOWSET_ID:
            netflow9_options_templates_number++;
            if (!process_netflow_v9_options_template(packet + offset, flowset_len, source_id, client_addres_in_string_format)) {
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

            if (process_netflow_v9_data(packet + offset, flowset_len, nf9_hdr, source_id,
                                        client_addres_in_string_format, client_ipv4_address) != 0) {
                // logger<< log4cpp::Priority::ERROR<<"Can't process function
                // process_netflow_v9_data correctly";
                netflow_v9_broken_packets++;
                return false;
            }

            break;
        }

        // This logic will stop processing if we've reached end of flow set setction before reading all flow sets
        // It's not reliable to use alone because we may have garbadge at the end of packet. That's why we have loop over number of flowset records as main condition.
        offset += flowset_len;
        if (offset == len) {
            break;
        }
    }

    return true;
}

