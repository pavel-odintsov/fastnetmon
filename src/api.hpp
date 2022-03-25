
    Status FastnetmonApiServiceImpl::GetBanlist(::grpc::ServerContext* context,
                      const ::fastmitigation::BanListRequest* request,
                      ::grpc::ServerWriter< ::fastmitigation::BanListReply>* writer) {
        logger << log4cpp::Priority::INFO << "API we asked for banlist";

        for (std::map<uint32_t, banlist_item_t>::iterator itr = ban_list.begin(); itr != ban_list.end(); ++itr) {
            std::string client_ip_as_string = convert_ip_as_uint_to_string(itr->first);

            BanListReply reply;
            reply.set_ip_address(client_ip_as_string + "/32");
            writer->Write(reply);
        }

        // IPv6
        std::map<subnet_ipv6_cidr_mask_t, banlist_item_t> ban_list_copy;

        // Get whole ban list content atomically
        ban_list_ipv6_ng.get_whole_banlist(ban_list_copy);


        for (auto itr : ban_list_copy) {
            BanListReply reply;
            reply.set_ip_address( print_ipv6_cidr_subnet(itr.first) );
            writer->Write(reply);
        }

        return Status::OK;
    }

    Status FastnetmonApiServiceImpl::ExecuteBan(ServerContext* context,
                      const fastmitigation::ExecuteBanRequest* request,
                      fastmitigation::ExecuteBanReply* reply) {
        logger << log4cpp::Priority::INFO << "API we asked for ban for IP: " << request->ip_address();

        if (!is_v4_host(request->ip_address())) {
            logger << log4cpp::Priority::ERROR << "IP bad format";
            return Status::CANCELLED;
        }

        uint32_t client_ip = convert_ip_as_string_to_uint(request->ip_address());

        attack_details_t current_attack;
        ban_list_mutex.lock();
        ban_list[client_ip] = current_attack;
        ban_list_mutex.unlock();

        ban_list_details_mutex.lock();
        ban_list_details[client_ip] = std::vector<simple_packet_t>();
        ban_list_details_mutex.unlock();


        subnet_ipv6_cidr_mask_t zero_ipv6_address;
        boost::circular_buffer<simple_packet_t> empty_simple_packets_buffer;

        logger << log4cpp::Priority::INFO << "API call ban handlers manually";

        std::string flow_attack_details = "manually triggered attack";
        call_ban_handlers(client_ip, zero_ipv6_address, false, current_attack, flow_attack_details, attack_detection_source_t::Automatic, "", empty_simple_packets_buffer);

        return Status::OK;
    }

    Status FastnetmonApiServiceImpl::ExecuteUnBan(ServerContext* context,
                        const fastmitigation::ExecuteBanRequest* request,
                        fastmitigation::ExecuteBanReply* reply) {
        logger << log4cpp::Priority::INFO << "API: We asked for unban for IP: " << request->ip_address();

        if (!is_v4_host(request->ip_address())) {
            logger << log4cpp::Priority::ERROR << "IP bad format";
            return Status::CANCELLED;
        }

        uint32_t banned_ip = convert_ip_as_string_to_uint(request->ip_address());

        if (ban_list.count(banned_ip) == 0) {
            logger << log4cpp::Priority::ERROR << "API: Could not find IP in ban list";
            return Status::CANCELLED;
        }

        banlist_item_t ban_details = ban_list[banned_ip];

        logger << log4cpp::Priority::INFO << "API: call unban handlers";
        
        subnet_ipv6_cidr_mask_t zero_ipv6_address;
        call_unban_handlers(banned_ip, zero_ipv6_address, false, ban_details, attack_detection_source_t::Automatic);

        logger << log4cpp::Priority::INFO << "API: remove IP from ban list";

        ban_list_mutex.lock();
        ban_list.erase(banned_ip);
        ban_list_mutex.unlock();

        return Status::OK;
    }
