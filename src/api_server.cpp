#include <iostream>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "fastnetmon.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using fastmitigation::BanListRequest;
using fastmitigation::BanListReply;
using fastmitigation::Fastnetmon;

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Fastnetmon::Service {
    Status GetBanlist(::grpc::ServerContext* context, const ::fastmitigation::BanListRequest* request, ::grpc::ServerWriter< ::fastmitigation::BanListReply>* writer) override {
        std::cout << "Incoming request" << std::endl;

        BanListReply reply;
        reply.set_ip_address("192.168.1.2/32");
        writer->Write(reply);
       
        reply.set_ip_address("192.168.1.3/32");
        writer->Write(reply); 

        //reply->set_message(prefix + request->name());
        return Status::OK;
    }
};

void RunServer() {
    std::string server_address("0.0.0.0:50051");
    GreeterServiceImpl service;

    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&service);
    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}

void silent_logging_function(gpr_log_func_args *args) {
    // We do not want any logging here
}

int main(int argc, char** argv) {
    gpr_set_log_function(silent_logging_function);

    RunServer();

    return 0;
}
