#pragma once

#include <grpc/grpc.h>
#include <grpc++/channel.h>

#include "../bgp_protocol.hpp"

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

    // Announce unicast or flow spec
    bool AnnounceCommonPrefix(dynamic_binary_buffer_t binary_nlri,
                              std::vector<dynamic_binary_buffer_t> bgp_attributes,
                              bool is_withdrawal,
                              unsigned int afi,
                              unsigned int safi);
    bool AnnounceUnicastPrefixLowLevelIPv4(const IPv4UnicastAnnounce& unicast_ipv4_announce, bool is_withdrawal);
    bool AnnounceUnicastPrefixLowLevelIPv6(const IPv6UnicastAnnounce& unicast_ipv6_announce, bool is_withdrawal);

    private:
    std::unique_ptr<apipb::GobgpApi::Stub> stub_;
};


