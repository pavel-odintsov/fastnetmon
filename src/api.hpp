
Status FastnetmonApiServiceImpl::GetBanlist(::grpc::ServerContext* context,
                                            const ::fastmitigation::BanListRequest* request,
                                            ::grpc::ServerWriter<::fastmitigation::BanListReply>* writer) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;
    extern bool hash_counters;


    logger << log4cpp::Priority::INFO << "API we asked for banlist";

    // IPv4
    if (hash_counters) { 
        std::map<uint32_t, banlist_item_t> ban_list_ipv4_copy;

        // Get whole ban list content atomically
        ban_list_ipv4.get_whole_banlist(ban_list_ipv4_copy);

        for (auto itr : ban_list_ipv4_copy) {
            BanListReply reply;

            reply.set_ip_address(convert_ip_as_uint_to_string(itr.first) + "/32");
            
            writer->Write(reply);
        }
    } else {

        for (auto itr = ban_list.begin(); itr != ban_list.end(); ++itr) {
            std::string client_ip_as_string = convert_ip_as_uint_to_string(itr->first);

            BanListReply reply;
            reply.set_ip_address(client_ip_as_string + "/32");
            writer->Write(reply);
        }

    }

    // IPv6
    std::map<subnet_ipv6_cidr_mask_t, banlist_item_t> ban_list_ipv6_copy;

    // Get whole ban list content atomically
    ban_list_ipv6.get_whole_banlist(ban_list_ipv6_copy);


    for (auto itr : ban_list_ipv6_copy) {
        BanListReply reply;
        reply.set_ip_address(print_ipv6_cidr_subnet(itr.first));
        writer->Write(reply);
    }

    return Status::OK;
}

Status FastnetmonApiServiceImpl::ExecuteBan(ServerContext* context,
                                            const fastmitigation::ExecuteBanRequest* request,
                                            fastmitigation::ExecuteBanReply* reply) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;
    extern bool hash_counters;

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

        if (hash_counters) {
            ban_list_ipv4.add_to_blackhole(client_ip, current_attack);
        } else {

            {
                std::lock_guard<std::mutex> lock_guard(ban_list_mutex);
                ban_list[client_ip] = current_attack;
            }

            {
                std::lock_guard<std::mutex> lock_guard(ban_list_details_mutex);
                ban_list_details[client_ip] = std::vector<simple_packet_t>();
            }

        }
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
    call_ban_handlers(client_ip, ipv6_address, ipv6, current_attack, flow_attack_details,
                      attack_detection_source_t::Automatic, empty_simple_packets_buffer);

    return Status::OK;
}

Status FastnetmonApiServiceImpl::ExecuteUnBan(ServerContext* context,
                                              const fastmitigation::ExecuteBanRequest* request,
                                              fastmitigation::ExecuteBanReply* reply) {
    extern blackhole_ban_list_t<subnet_ipv6_cidr_mask_t> ban_list_ipv6;
    extern blackhole_ban_list_t<uint32_t> ban_list_ipv4;
    extern bool hash_counters;

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

        if (hash_counters) { 
            bool is_blackholed_ipv4 = ban_list_ipv4.is_blackholed(client_ip);

            if (!is_blackholed_ipv4) {
                logger << log4cpp::Priority::ERROR << "API: Could not find IPv4 address in ban list";
                return Status::CANCELLED;
            }

            bool get_details = ban_list_ipv4.get_blackhole_details(client_ip, current_attack);

            if (!get_details) {
                return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Could not get IPv4 blackhole details");
            }

            ban_list_ipv4.remove_from_blackhole(client_ip);
        } else {
            if (ban_list.count(client_ip) == 0) {
                logger << log4cpp::Priority::ERROR << "API: Could not find IP in ban list";
                return Status::CANCELLED;
            }

            current_attack = ban_list[client_ip];

            logger << log4cpp::Priority::INFO << "API: call unban handlers";

            logger << log4cpp::Priority::INFO << "API: remove IP from ban list";

            {
                std::lock_guard<std::mutex> lock_guard(ban_list_mutex);
                ban_list.erase(client_ip);
            }
        }
    } else {
        bool parsed_ipv6 = read_ipv6_host_from_string(request->ip_address(), ipv6_address.subnet_address);

        if (!parsed_ipv6) {
            logger << log4cpp::Priority::ERROR << "Can't parse IPv6 address: " << request->ip_address();
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Can't parse IPv6 address");
        }

        bool is_blackholed_ipv6 = ban_list_ipv6.is_blackholed(ipv6_address);

        if (!is_blackholed_ipv6) {
            logger << log4cpp::Priority::ERROR << "API: Could not find IPv6 address in ban list";
            return Status::CANCELLED;
        }

        bool get_details = ban_list_ipv6.get_blackhole_details(ipv6_address, current_attack);

        if (!get_details) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Could not get IPv6 blackhole details");
        }

        ban_list_ipv6.remove_from_blackhole(ipv6_address);
    }

    call_unban_handlers(client_ip, ipv6_address, ipv6, current_attack, attack_detection_source_t::Automatic);

    return Status::OK;
}
