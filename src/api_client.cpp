#include <iostream>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "fastnetmon.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using fastmitigation::BanListRequest;
using fastmitigation::BanListReply;
using fastmitigation::Fastnetmon;

unsigned int client_connection_timeout = 5;

class GreeterClient {
    public:
        GreeterClient(std::shared_ptr<Channel> channel) : stub_(Fastnetmon::NewStub(channel)) {}

        // Assambles the client's payload, sends it and presents the response back
        // from the server.
        void GetBanList(const std::string& user) {
            // Data we are sending to the server.
            BanListRequest request;
            request.set_name(user);

            // Container for the data we expect from the server.
            BanListReply reply;

            // Context for the client. It could be used to convey extra information to
            // the server and/or tweak certain RPC behaviors.
            ClientContext context;

            std::chrono::system_clock::time_point deadline =
                std::chrono::system_clock::now() + std::chrono::seconds(client_connection_timeout);

            context.set_deadline(deadline);

            // The actual RPC.
            Status status = stub_->GetBanlist(&context, request, &reply);

            // Act upon its status.
            if (status.ok()) {
                std::cout << "Server answer: " << reply.message() << std::endl;
            } else {
                if (status.error_code() == grpc::DEADLINE_EXCEEDED) {
                    std::cerr << "Could not connect to API server. Timeout exceed" << std::endl;
                    return;
                } else {
                    std::cerr << "RPC failed " + status.error_message();
                    return;
                }
            }
        }

    private:
        std::unique_ptr<Fastnetmon::Stub> stub_;
};

void silent_logging_function(gpr_log_func_args *args) {
    // We do not want any logging here
}

int main(int argc, char** argv) {
    gpr_set_log_function(silent_logging_function);

    // Instantiate the client. It requires a channel, out of which the actual RPCs
    // are created. This channel models a connection to an endpoint (in this case,
    // localhost at port 50051). We indicate that the channel isn't authenticated
    // (use of InsecureCredentials()).
    GreeterClient greeter( grpc::CreateChannel("localhost:50051", grpc::InsecureCredentials()));

    std::cout << "Sending request\n" << std::endl;
    std::string user("Paul");
    greeter.GetBanList(user);

    return 0;
}
