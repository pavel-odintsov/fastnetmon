#pragma once

#include <grpc/grpc.h>
#include <grpc++/channel.h>

#include "../fastnetmon_networks.hpp"

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


#include "../gobgp_client/gobgp.grpc.pb.h"

#ifdef _WIN32

// Restore original values of these defines
#pragma pop_macro("interface")
#pragma pop_macro("IN")
#pragma pop_macro("OUT")

#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__


class GrpcClient {
    public:
    GrpcClient(std::shared_ptr<grpc::Channel> channel);

    bool AnnounceUnicastPrefixIPv4(std::string announced_address,
                                   std::string announced_prefix_nexthop,
                                   bool is_withdrawal,
                                   unsigned int cidr_mask,
                                   uint32_t community_as_32bit_int);

    bool AnnounceUnicastPrefixIPv6(const subnet_ipv6_cidr_mask_t& client_ipv6,
                                   const subnet_ipv6_cidr_mask_t& ipv6_next_hop,
                                   bool is_withdrawal,
                                   uint32_t community_as_32bit_int);
    private:
    std::unique_ptr<apipb::GobgpApi::Stub> stub_;
};


