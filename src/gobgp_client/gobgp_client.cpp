#include "gobgp_client.hpp"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif // __GNUC__

//
// MinGW has quite weird definitions which clash with field names in gRPC bindinds
// We need to apply some trickery to avoid complilation errors: 
// https://github.com/pavel-odintsov/fastnetmon/issues/977
//

#ifdef _WIN32

// Save previous values of these defines
#pragma push_macro("interface")
#pragma push_macro("IN")
#pragma push_macro("OUT")

#undef interface
#undef IN
#undef OUT

#endif


#include "../gobgp_client/attribute.pb.h"

#ifdef _WIN32

// Restore original values of these defines
#pragma pop_macro("interface")
#pragma pop_macro("IN")
#pragma pop_macro("OUT")

#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__

#include "../all_logcpp_libraries.hpp"

#include "../fast_library.hpp"

unsigned int gobgp_client_connection_timeout = 5;

extern log4cpp::Category& logger;

GrpcClient::GrpcClient(std::shared_ptr<grpc::Channel> channel) : stub_(apipb::GobgpApi::NewStub(channel)) {

}

bool GrpcClient::AnnounceUnicastPrefixIPv4(std::string announced_address,
                               std::string announced_prefix_nexthop,
                               bool is_withdrawal,
                               unsigned int cidr_mask,
                               uint32_t community_as_32bit_int) {
    grpc::ClientContext context;

    // Set timeout for API
    std::chrono::system_clock::time_point deadline =
        std::chrono::system_clock::now() + std::chrono::seconds(gobgp_client_connection_timeout);
    context.set_deadline(deadline);

    auto gobgp_ipv4_unicast_route_family = new apipb::Family;
    gobgp_ipv4_unicast_route_family->set_afi(apipb::Family::AFI_IP);
    gobgp_ipv4_unicast_route_family->set_safi(apipb::Family::SAFI_UNICAST);

    apipb::AddPathRequest request;
    request.set_table_type(apipb::TableType::GLOBAL);

    apipb::Path* current_path = new apipb::Path;

    current_path->set_allocated_family(gobgp_ipv4_unicast_route_family);

    if (is_withdrawal) {
        current_path->set_is_withdraw(true);
    }

    // Configure required announce
    google::protobuf::Any* current_nlri = new google::protobuf::Any;
    apipb::IPAddressPrefix current_ipaddrprefix;
    current_ipaddrprefix.set_prefix(announced_address);
    current_ipaddrprefix.set_prefix_len(cidr_mask);

    current_nlri->PackFrom(current_ipaddrprefix);
    current_path->set_allocated_nlri(current_nlri);

    // Updating OriginAttribute info for current_path
    google::protobuf::Any* current_origin = current_path->add_pattrs();
    apipb::OriginAttribute current_origin_t;
    current_origin_t.set_origin(0);
    current_origin->PackFrom(current_origin_t);

    // Updating NextHopAttribute info for current_path
    google::protobuf::Any* current_next_hop = current_path->add_pattrs();
    apipb::NextHopAttribute current_next_hop_t;
    current_next_hop_t.set_next_hop(announced_prefix_nexthop);
    current_next_hop->PackFrom(current_next_hop_t);

    // Updating CommunitiesAttribute for current_path
    google::protobuf::Any* current_communities = current_path->add_pattrs();
    apipb::CommunitiesAttribute current_communities_t;
    current_communities_t.add_communities(community_as_32bit_int);
    current_communities->PackFrom(current_communities_t);

    request.set_allocated_path(current_path);

    apipb::AddPathResponse response;

    // Don't be confused by name, it also can withdraw announces
    auto status = stub_->AddPath(&context, request, &response);

    if (!status.ok()) {
        logger << log4cpp::Priority::ERROR << "AddPath request to BGP daemon failed with code: " << status.error_code()
               << " message " << status.error_message();

        return false;
    }


    return true;
}

bool GrpcClient::AnnounceUnicastPrefixIPv6(const subnet_ipv6_cidr_mask_t& client_ipv6,
                               const subnet_ipv6_cidr_mask_t& ipv6_next_hop,
                               bool is_withdrawal,
                               uint32_t community_as_32bit_int) {
    grpc::ClientContext context;

    // Set timeout for API
    std::chrono::system_clock::time_point deadline =
        std::chrono::system_clock::now() + std::chrono::seconds(gobgp_client_connection_timeout);
    context.set_deadline(deadline);

    auto gobgp_ipv6_unicast_route_family = new apipb::Family;
    gobgp_ipv6_unicast_route_family->set_afi(apipb::Family::AFI_IP6);
    gobgp_ipv6_unicast_route_family->set_safi(apipb::Family::SAFI_UNICAST);

    apipb::AddPathRequest request;
    request.set_table_type(apipb::TableType::GLOBAL);

    apipb::Path* current_path = new apipb::Path;

    current_path->set_allocated_family(gobgp_ipv6_unicast_route_family);

    if (is_withdrawal) {
        current_path->set_is_withdraw(true);
    }

    // Configure required announce
    google::protobuf::Any* current_nlri = new google::protobuf::Any;
    apipb::IPAddressPrefix current_ipaddrprefix;
    current_ipaddrprefix.set_prefix(print_ipv6_address(client_ipv6.subnet_address));
    current_ipaddrprefix.set_prefix_len(client_ipv6.cidr_prefix_length);

    current_nlri->PackFrom(current_ipaddrprefix);
    current_path->set_allocated_nlri(current_nlri);

    // Updating OriginAttribute info for current_path
    google::protobuf::Any* current_origin = current_path->add_pattrs();
    apipb::OriginAttribute current_origin_t;
    current_origin_t.set_origin(0);
    current_origin->PackFrom(current_origin_t);

    // Updating NextHopAttribute info for current_path
    google::protobuf::Any* current_next_hop = current_path->add_pattrs();
    apipb::NextHopAttribute current_next_hop_t;
    current_next_hop_t.set_next_hop(print_ipv6_address(ipv6_next_hop.subnet_address));
    current_next_hop->PackFrom(current_next_hop_t);

    // Updating CommunitiesAttribute for current_path
    google::protobuf::Any* current_communities = current_path->add_pattrs();
    apipb::CommunitiesAttribute current_communities_t;
    current_communities_t.add_communities(community_as_32bit_int);
    current_communities->PackFrom(current_communities_t);

    request.set_allocated_path(current_path);

    apipb::AddPathResponse response;

    // Don't be confused by name, it also can withdraw announces
    auto status = stub_->AddPath(&context, request, &response);

    if (!status.ok()) {
        logger << log4cpp::Priority::ERROR << "AddPath request to BGP daemon failed with code: " << status.error_code()
               << " message " << status.error_message();

        return false;
    }


    return true;
}
