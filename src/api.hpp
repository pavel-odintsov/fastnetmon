#include "fastnetmon.grpc.pb.h"
#include <grpc++/grpc++.h>

// API declaration
using fastmitigation::BanListReply;
using fastmitigation::BanListRequest;
using fastmitigation::Fastnetmon;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

class FastnetmonApiServiceImpl final : public Fastnetmon::Service {
    Status GetBanlist(::grpc::ServerContext* context,
                      const ::fastmitigation::BanListRequest* request,
                      ::grpc::ServerWriter<::fastmitigation::BanListReply>* writer) override;

    Status ExecuteBan(ServerContext* context, const fastmitigation::ExecuteBanRequest* request, fastmitigation::ExecuteBanReply* reply) override;
    Status ExecuteUnBan(ServerContext* context,
                        const fastmitigation::ExecuteBanRequest* request,
                        fastmitigation::ExecuteBanReply* reply) override;
};
