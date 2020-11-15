#include "gobgp_action.h"
#include "../fastnetmon_actions.h"
#include "../fastnetmon_types.h"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif // __GNUC__

#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc/grpc.h>

#include "attribute.pb.h"
#include "gobgp.grpc.pb.h"

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__


unsigned int gobgp_client_connection_timeout = 5;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using gobgpapi::GobgpApi;

class GrpcClient {
    public:
    GrpcClient(std::shared_ptr<Channel> channel) : stub_(GobgpApi::NewStub(channel)) {
    }

    bool AnnounceUnicastPrefix(std::string announced_address,
                               std::string announced_prefix_nexthop,
                               bool is_withdrawal,
                               unsigned int cidr_mask) {
        grpc::ClientContext context;

        // Set timeout for API
        std::chrono::system_clock::time_point deadline =
        std::chrono::system_clock::now() + std::chrono::seconds(gobgp_client_connection_timeout);
        context.set_deadline(deadline);

        auto gobgp_ipv4_unicast_route_family = new gobgpapi::Family;
        gobgp_ipv4_unicast_route_family->set_afi(gobgpapi::Family::AFI_IP);
        gobgp_ipv4_unicast_route_family->set_safi(gobgpapi::Family::SAFI_UNICAST);

        gobgpapi::AddPathRequest request;
        request.set_table_type(gobgpapi::TableType::GLOBAL);

        gobgpapi::Path* current_path = new gobgpapi::Path;

        current_path->set_allocated_family(gobgp_ipv4_unicast_route_family);

        if (is_withdrawal) {
            current_path->set_is_withdraw(true);
        }

        // Configure required announce
        google::protobuf::Any* current_nlri = new google::protobuf::Any;
        gobgpapi::IPAddressPrefix current_ipaddrprefix;
        current_ipaddrprefix.set_prefix(announced_address);
        current_ipaddrprefix.set_prefix_len(cidr_mask);

        current_nlri->PackFrom(current_ipaddrprefix);
        current_path->set_allocated_nlri(current_nlri);

        // Updating OriginAttribute info for current_path
        google::protobuf::Any* current_origin = current_path->add_pattrs();
        gobgpapi::OriginAttribute current_origin_t;
        current_origin_t.set_origin(0);
        current_origin->PackFrom(current_origin_t);

        // Updating NextHopAttribute info for current_path
        google::protobuf::Any* current_next_hop = current_path->add_pattrs();
        gobgpapi::NextHopAttribute current_next_hop_t;
        current_next_hop_t.set_next_hop(announced_prefix_nexthop);
        current_next_hop->PackFrom(current_next_hop_t);

        /*
        // Updating CommunitiesAttribute for current_path
        google::protobuf::Any *current_communities = current_path->add_pattrs();
        gobgpapi::CommunitiesAttribute current_communities_t;
        current_communities_t.add_communities(100);
        current_communities->PackFrom(current_communities_t);
            */

        request.set_allocated_path(current_path);

        gobgpapi::AddPathResponse response;

        // Don't be confused by name, it also can withdraw announces
        auto status = stub_->AddPath(&context, request, &response);

        if (!status.ok()) {
            logger << log4cpp::Priority::ERROR
                   << "AddPath request to BGP daemon failed with code: " << status.error_code()
                   << " message " << status.error_message();

            return false;
        }


        return true;
    }

    private:
    std::unique_ptr<GobgpApi::Stub> stub_;
};

GrpcClient* gobgp_client = NULL;
std::string gobgp_nexthop = "0.0.0.0";
bool gobgp_announce_whole_subnet = false;
bool gobgp_announce_host = false;

void gobgp_action_init() {
    logger << log4cpp::Priority::INFO << "GoBGP action module loaded";
    gobgp_client =
    new GrpcClient(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    if (configuration_map.count("gobgp_next_hop")) {
        gobgp_nexthop = configuration_map["gobgp_next_hop"];
    }

    if (configuration_map.count("gobgp_announce_host")) {
        gobgp_announce_host = configuration_map["gobgp_announce_host"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet")) {
        gobgp_announce_whole_subnet = configuration_map["gobgp_announce_whole_subnet"] == "on";
    }
}

void gobgp_action_shutdown() {
    delete gobgp_client;
}

void gobgp_ban_manage(std::string action, std::string ip_as_string, attack_details_t current_attack) {
    bool is_withdrawal = false;

    std::string action_name;

    if (action == "ban") {
        is_withdrawal = false;
        action_name = "announce";
    } else {
        is_withdrawal = true;
        action_name = "withdraw";
    }

    if (gobgp_announce_whole_subnet) {
        std::string subnet_as_string_with_mask = convert_subnet_to_string(current_attack.customer_network);
        logger << log4cpp::Priority::INFO << action_name << " "
               << convert_subnet_to_string(current_attack.customer_network) << " to GoBGP";

        gobgp_client->AnnounceUnicastPrefix(convert_ip_as_uint_to_string(
                                            current_attack.customer_network.subnet_address),
                                            gobgp_nexthop, is_withdrawal,
                                            current_attack.customer_network.cidr_prefix_length);
    }

    if (gobgp_announce_host) {
        std::string ip_as_string_with_mask = ip_as_string + "/32";

        logger << log4cpp::Priority::INFO << action_name << " " << ip_as_string_with_mask << " to GoBGP";

        gobgp_client->AnnounceUnicastPrefix(ip_as_string, gobgp_nexthop, is_withdrawal, 32);
    }
}
