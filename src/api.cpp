#include "api.hpp"

#include "fastnetmon_types.hpp"

#include "fastnetmon_logic.hpp"

#include "attack_details.hpp"

#include "ban_list.hpp"

::grpc::Status FastnetmonApiServiceImpl::GetBanlist(::grpc::ServerContext* context,
                                            const ::fastnetmoninternal::BanListRequest* request,
                                            ::grpc::ServerWriter<::fastnetmoninternal::BanListReply>* writer) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;


    logger << log4cpp::Priority::INFO << "API we asked for banlist";

    // IPv4
    std::map<uint32_t, banlist_item_t> ban_list_ipv4_copy;

    // Get whole ban list content atomically
    ban_list_ipv4.get_whole_banlist(ban_list_ipv4_copy);

    for (auto itr : ban_list_ipv4_copy) {
        fastnetmoninternal::BanListReply reply;

        reply.set_ip_address(convert_ip_as_uint_to_string(itr.first) + "/32");
        
        writer->Write(reply);
    }

    // IPv6
    std::map<subnet_ipv6_cidr_mask_t, banlist_item_t> ban_list_ipv6_copy;

    // Get whole ban list content atomically
    ban_list_ipv6.get_whole_banlist(ban_list_ipv6_copy);


    for (auto itr : ban_list_ipv6_copy) {
        fastnetmoninternal::BanListReply reply;
        reply.set_ip_address(print_ipv6_cidr_subnet(itr.first));
        writer->Write(reply);
    }

    return grpc::Status::OK;
}

::grpc::Status FastnetmonApiServiceImpl::ExecuteBan(ServerContext* context,
                                            const fastnetmoninternal::ExecuteBanRequest* request,
                                            fastnetmoninternal::ExecuteBanReply* reply) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;
    extern patricia_tree_t *lookup_tree_ipv4;
    extern patricia_tree_t *lookup_tree_ipv6;


    logger << log4cpp::Priority::INFO << "API we asked for ban for IP: " << request->ip_address();

    if (!validate_ipv6_or_ipv4_host(request->ip_address())) {
        logger << log4cpp::Priority::ERROR << "You specified malformed IP address";
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Malformed IP address");
    }

    // At this step IP should be valid IPv4 or IPv6 address
    bool ipv6 = false;

    if (request->ip_address().find(":") != std::string::npos) {
        ipv6 = true;
    }

    bool ipv4 = !ipv6;

    uint32_t client_ip = 0;

    subnet_ipv6_cidr_mask_t ipv6_address;
    ipv6_address.cidr_prefix_length = 128;

    attack_details_t current_attack;
    current_attack.ipv6 = ipv6;

    // We trigger this action manually
    current_attack.attack_detection_source = attack_detection_source_t::Manual;

    boost::circular_buffer<simple_packet_t> empty_simple_packets_buffer;

    // Empty raw buffer
    boost::circular_buffer<fixed_size_packet_storage_t> empty_raw_packets_buffer;

    std::string flow_attack_details = "manually triggered attack";

    if (ipv4) {
        bool parse_res = convert_ip_as_string_to_uint_safe(request->ip_address(), client_ip);

        if (!parse_res) {
            logger << log4cpp::Priority::ERROR << "Can't parse IPv4 address: " << request->ip_address();
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Can't parse IPv4 address");
        }

        subnet_cidr_mask_t subnet;

        bool lookup_result =
            lookup_ip_in_integer_form_inpatricia_and_return_subnet_if_found(lookup_tree_ipv4, client_ip, subnet);

        if (!lookup_result) {
            logger << log4cpp::Priority::ERROR << "IP address " << request->ip_address() << " does not belong to our networks.";
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "This IP does not belong to our subnets");
        }

        ban_list_ipv4.add_to_blackhole(client_ip, current_attack);
    } else {
        bool parsed_ipv6 = read_ipv6_host_from_string(request->ip_address(), ipv6_address.subnet_address);

        if (!parsed_ipv6) {
            logger << log4cpp::Priority::ERROR << "Can't parse IPv6 address: " << request->ip_address();
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Can't parse IPv6 address");
        }

        bool in_our_networks_list = ip_belongs_to_patricia_tree_ipv6(lookup_tree_ipv6, ipv6_address.subnet_address);

        if (!in_our_networks_list) {
            logger << log4cpp::Priority::ERROR << "IP address " << request->ip_address() << " is not belongs to our networks.";
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "This IP not belongs to our subnets");
        }

        ban_list_ipv6.add_to_blackhole(ipv6_address, current_attack);
    }

    logger << log4cpp::Priority::INFO << "API call ban handlers manually";
    call_blackhole_actions_per_host(attack_action_t::ban, client_ip, ipv6_address, ipv6, current_attack,
                      attack_detection_source_t::Automatic, flow_attack_details, empty_simple_packets_buffer, empty_raw_packets_buffer);

    return grpc::Status::OK;
}

::grpc::Status FastnetmonApiServiceImpl::ExecuteUnBan(ServerContext* context,
                                              const fastnetmoninternal::ExecuteBanRequest* request,
                                              fastnetmoninternal::ExecuteBanReply* reply) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;

    logger << log4cpp::Priority::INFO << "API: We asked for unban for IP: " << request->ip_address();

    if (!validate_ipv6_or_ipv4_host(request->ip_address())) {
        logger << log4cpp::Priority::ERROR << "You specified malformed IP address";
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Malformed IP address");
    }

    // At this step IP should be valid IPv4 or IPv6 address
    bool ipv6 = false;

    if (request->ip_address().find(":") != std::string::npos) {
        ipv6 = true;
    }

    bool ipv4 = !ipv6;

    uint32_t client_ip = 0;

    subnet_ipv6_cidr_mask_t ipv6_address;
    ipv6_address.cidr_prefix_length = 128;

    attack_details_t current_attack;


    if (ipv4) {
        bool parse_res = convert_ip_as_string_to_uint_safe(request->ip_address(), client_ip);

        if (!parse_res) {
            logger << log4cpp::Priority::ERROR << "Can't parse IPv4 address: " << request->ip_address();
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Can't parse IPv4 address");
        }   

        bool is_blackholed_ipv4 = ban_list_ipv4.is_blackholed(client_ip);

        if (!is_blackholed_ipv4) {
            logger << log4cpp::Priority::ERROR << "API: Could not find IPv4 address in ban list";
            return grpc::Status::CANCELLED;
        }

        bool get_details = ban_list_ipv4.get_blackhole_details(client_ip, current_attack);

        if (!get_details) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Could not get IPv4 blackhole details");
        }

        ban_list_ipv4.remove_from_blackhole(client_ip);
    } else {
        bool parsed_ipv6 = read_ipv6_host_from_string(request->ip_address(), ipv6_address.subnet_address);

        if (!parsed_ipv6) {
            logger << log4cpp::Priority::ERROR << "Can't parse IPv6 address: " << request->ip_address();
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Can't parse IPv6 address");
        }

        bool is_blackholed_ipv6 = ban_list_ipv6.is_blackholed(ipv6_address);

        if (!is_blackholed_ipv6) {
            logger << log4cpp::Priority::ERROR << "API: Could not find IPv6 address in ban list";
            return grpc::Status::CANCELLED;
        }

        bool get_details = ban_list_ipv6.get_blackhole_details(ipv6_address, current_attack);

        if (!get_details) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Could not get IPv6 blackhole details");
        }

        ban_list_ipv6.remove_from_blackhole(ipv6_address);
    }

    // It's empty for unban
    std::string flow_attack_details;

    // These are empty too
    boost::circular_buffer<simple_packet_t> simple_packets_buffer;
    boost::circular_buffer<fixed_size_packet_storage_t> raw_packets_buffer;

    call_blackhole_actions_per_host(attack_action_t::unban, client_ip, ipv6_address, ipv6,
            current_attack, attack_detection_source_t::Automatic, flow_attack_details, simple_packets_buffer, raw_packets_buffer);

    return grpc::Status::OK;
}

void fill_total_traffic_counters_api(::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer,
                                     const direction_t& packet_direction,
                                     const total_speed_counters_t& total_counters,
                                     bool return_per_protocol_metrics,
                                     const std::string& unit) {
    std::string direction_as_string = get_direction_name(packet_direction);

    fastnetmoninternal::SixtyFourNamedCounter reply;
    reply.set_counter_name(direction_as_string + " traffic");
    reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].total.packets);
    reply.set_counter_unit("pps");

    writer->Write(reply);

    if (return_per_protocol_metrics) {

        // tcp
        reply.set_counter_name(direction_as_string + " tcp traffic");
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].tcp.packets);
        reply.set_counter_unit("pps");

        writer->Write(reply);

        // udp
        reply.set_counter_name(direction_as_string + " udp traffic");
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].udp.packets);
        reply.set_counter_unit("pps");

        writer->Write(reply);

        // icmp
        reply.set_counter_name(direction_as_string + " icmp traffic");
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].icmp.packets);
        reply.set_counter_unit("pps");

        writer->Write(reply);

        // fragmented
        reply.set_counter_name(direction_as_string + " fragmented traffic");
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].fragmented.packets);
        reply.set_counter_unit("pps");

        writer->Write(reply);

        // tcp_syn
        reply.set_counter_name(direction_as_string + " tcp_syn traffic");
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].tcp_syn.packets);
        reply.set_counter_unit("pps");

        writer->Write(reply);

        // dropped
        reply.set_counter_name(direction_as_string + " dropped traffic");
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].dropped.packets);
        reply.set_counter_unit("pps");

        writer->Write(reply);
    }

    // Write traffic speed with same name but with other unit
    reply.set_counter_name(direction_as_string + " traffic");

    if (unit == "bps") {
        reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].total.bytes * 8);
        reply.set_counter_unit("bps");
    } else {
        reply.set_counter_value(
            convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].total.bytes));
        reply.set_counter_unit("mbps");
    }

    writer->Write(reply);

    if (return_per_protocol_metrics) {

        // tcp
        reply.set_counter_name(direction_as_string + " tcp traffic");

        if (unit == "bps") {
            reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].tcp.bytes * 8);
            reply.set_counter_unit("bps");
        } else {
            reply.set_counter_value(
                convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].tcp.bytes));
            reply.set_counter_unit("mbps");
        }

        writer->Write(reply);

        // udp
        reply.set_counter_name(direction_as_string + " udp traffic");

        if (unit == "bps") {
            reply.set_counter_unit("bps");
            reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].udp.bytes * 8);
        } else {
            reply.set_counter_value(
                convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].udp.bytes));
            reply.set_counter_unit("mbps");
        }

        writer->Write(reply);

        // icmp
        reply.set_counter_name(direction_as_string + " icmp traffic");

        if (unit == "bps") {
            reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].icmp.bytes * 8);
            reply.set_counter_unit("bps");
        } else {
            reply.set_counter_value(
                convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].icmp.bytes));
            reply.set_counter_unit("mbps");
        }

        writer->Write(reply);

        // fragmented
        reply.set_counter_name(direction_as_string + " fragmented traffic");

        if (unit == "bps") {
            reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].fragmented.bytes * 8);
            reply.set_counter_unit("bps");
        } else {
            reply.set_counter_value(
                convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].fragmented.bytes));
            reply.set_counter_unit("mbps");
        }

        writer->Write(reply);

        // tcp_syn
        reply.set_counter_name(direction_as_string + " tcp_syn traffic");

        if (unit == "bps") {
            reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].tcp_syn.bytes * 8);
            reply.set_counter_unit("bps");
        } else {
            reply.set_counter_value(
                convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].tcp_syn.bytes));
            reply.set_counter_unit("mbps");
        }

        writer->Write(reply);

        // dropped
        reply.set_counter_name(direction_as_string + " dropped traffic");

        if (unit == "bps") {
            reply.set_counter_value(total_counters.total_speed_average_counters[packet_direction].dropped.bytes * 8);
            reply.set_counter_unit("bps");
        } else {
            reply.set_counter_value(
                convert_speed_to_mbps(total_counters.total_speed_average_counters[packet_direction].dropped.bytes));
            reply.set_counter_unit("mbps");
        }

        writer->Write(reply);
    }
}


::grpc::Status
FastnetmonApiServiceImpl::GetTotalTrafficCounters([[maybe_unused]] ::grpc::ServerContext* context,
                                                  const ::fastnetmoninternal::GetTotalTrafficCountersRequest* request,
                                                  ::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer) {
    extern uint64_t incoming_total_flows_speed;
    extern uint64_t outgoing_total_flows_speed;

    extern total_speed_counters_t total_counters;

    logger << log4cpp::Priority::DEBUG << "API we asked for GetTotalTrafficCounters";
    extern total_speed_counters_t total_counters;

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    bool get_per_protocol_metrics = request->get_per_protocol_metrics();

    extern bool enable_connection_tracking;

    std::string unit = request->unit();

    for (auto packet_direction : directions) {
        // Forward our total counters to API format
        fill_total_traffic_counters_api(writer, packet_direction, total_counters, get_per_protocol_metrics, unit);

        if (enable_connection_tracking) {
            fastnetmoninternal::SixtyFourNamedCounter reply;

            std::string direction_as_string = get_direction_name(packet_direction);

            reply.set_counter_name(direction_as_string + " traffic");

            // Populate flow per second rates
            if (packet_direction == INCOMING) {
                reply.set_counter_unit("flows");
                reply.set_counter_value(incoming_total_flows_speed);

                writer->Write(reply);
            } else if (packet_direction == OUTGOING) {
                reply.set_counter_unit("flows");
                reply.set_counter_value(outgoing_total_flows_speed);

                writer->Write(reply);
            }
        }
    }

    return grpc::Status::OK;
}

::grpc::Status
FastnetmonApiServiceImpl::GetTotalTrafficCountersV6([[maybe_unused]] ::grpc::ServerContext* context,
                                                    const ::fastnetmoninternal::GetTotalTrafficCountersRequest* request,
                                                    ::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer) {
    extern total_speed_counters_t total_counters_ipv6;

    logger << log4cpp::Priority::DEBUG << "API we asked for GetTotalTrafficCountersV6";

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    bool get_per_protocol_metrics = request->get_per_protocol_metrics();

    std::string unit = request->unit();

    for (auto packet_direction : directions) {
        // Forward our total counters to API format
        fill_total_traffic_counters_api(writer, packet_direction, total_counters_ipv6, get_per_protocol_metrics, unit);
    }

    return grpc::Status::OK;
}

::grpc::Status
FastnetmonApiServiceImpl::GetTotalTrafficCountersV4([[maybe_unused]] ::grpc::ServerContext* context,
                                                    const ::fastnetmoninternal::GetTotalTrafficCountersRequest* request,
                                                    ::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer) {

    extern uint64_t incoming_total_flows_speed;
    extern uint64_t outgoing_total_flows_speed;

    extern total_speed_counters_t total_counters_ipv4;

    logger << log4cpp::Priority::DEBUG << "API we asked for GetTotalTrafficCounters";
    extern total_speed_counters_t total_counters_ipv4;
    extern bool enable_connection_tracking;

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    bool get_per_protocol_metrics = request->get_per_protocol_metrics();

    std::string unit = request->unit();

    for (auto packet_direction : directions) {
        fill_total_traffic_counters_api(writer, packet_direction, total_counters_ipv4, get_per_protocol_metrics, unit);

        if (enable_connection_tracking) {
            fastnetmoninternal::SixtyFourNamedCounter reply;

            std::string direction_as_string = get_direction_name(packet_direction);

            reply.set_counter_name(direction_as_string + " traffic");

            // Populate flow per second rates
            if (packet_direction == INCOMING) {
                reply.set_counter_unit("flows");
                reply.set_counter_value(incoming_total_flows_speed);

                writer->Write(reply);
            } else if (packet_direction == OUTGOING) {
                reply.set_counter_unit("flows");
                reply.set_counter_value(outgoing_total_flows_speed);

                writer->Write(reply);
            }
        }
    }

    return grpc::Status::OK;
}


