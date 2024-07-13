#include "fastnetmon_internal_api.grpc.pb.h"
#include <grpc++/grpc++.h>

// API declaration
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;

class FastnetmonApiServiceImpl final : public fastnetmoninternal::Fastnetmon::Service {
    ::grpc::Status GetBanlist(::grpc::ServerContext* context,
                      const ::fastnetmoninternal::BanListRequest* request,
                      ::grpc::ServerWriter<::fastnetmoninternal::BanListReply>* writer) override;

    ::grpc::Status ExecuteBan(ServerContext* context, const fastnetmoninternal::ExecuteBanRequest* request, fastnetmoninternal::ExecuteBanReply* reply) override;
    ::grpc::Status ExecuteUnBan(ServerContext* context,
                        const fastnetmoninternal::ExecuteBanRequest* request,
                        fastnetmoninternal::ExecuteBanReply* reply) override;
    ::grpc::Status GetTotalTrafficCounters([[maybe_unused]] ::grpc::ServerContext* context,
                                           const ::fastnetmoninternal::GetTotalTrafficCountersRequest* request,
                                           ::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer) override;

    ::grpc::Status GetTotalTrafficCountersV6([[maybe_unused]] ::grpc::ServerContext* context,
                                             const ::fastnetmoninternal::GetTotalTrafficCountersRequest* request,
                                             ::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer) override;

    ::grpc::Status GetTotalTrafficCountersV4([[maybe_unused]] ::grpc::ServerContext* context,
                                             const ::fastnetmoninternal::GetTotalTrafficCountersRequest* request,
                                             ::grpc::ServerWriter<::fastnetmoninternal::SixtyFourNamedCounter>* writer) override;

};
