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

class FastnetmonClient {
    public:
        FastnetmonClient(std::shared_ptr<Channel> channel) : stub_(Fastnetmon::NewStub(channel)) {}

        void ExecuteBan(std::string host, bool is_ban) {
            ClientContext context;
            fastmitigation::ExecuteBanRequest request;
            fastmitigation::ExecuteBanReply reply;

            request.set_ip_address(host);

            Status status;
    
            if (is_ban) {
                status = stub_->ExecuteBan(&context, request, &reply);
            } else {
                status = stub_->ExecuteUnBan(&context, request, &reply);
            }
    
            if (status.ok()) {
                
            } else {
                if (status.error_code() == grpc::DEADLINE_EXCEEDED) {
                    std::cerr << "Could not connect to API server. Timeout exceed" << std::endl;
                    return;
                } else {
                    std::cerr << "RPC failed " + status.error_message() << std::endl;
                    return;       
                }
            }
        }

        void GetBanList() {
            // This request haven't any useful data
            BanListRequest request;

            // Container for the data we expect from the server.
            BanListReply reply;

            // Context for the client. It could be used to convey extra information to
            // the server and/or tweak certain RPC behaviors.
            ClientContext context;

            // Set timeout for API
            std::chrono::system_clock::time_point deadline =
                std::chrono::system_clock::now() + std::chrono::seconds(client_connection_timeout);

            context.set_deadline(deadline);

            // The actual RPC.
            auto announces_list = stub_->GetBanlist(&context, request);

            while (announces_list->Read(&reply)) {
                std::cout << reply.ip_address() << std::endl;
            }

            // Get status and handle errors
            auto status = announces_list->Finish(); 
            
            if (!status.ok()) {
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
    if (argc <= 1) {
        std::cerr << "Please provide request" << std::endl;
        return 1;
    }

    gpr_set_log_function(silent_logging_function);

    // Instantiate the client. It requires a channel, out of which the actual RPCs
    // are created. This channel models a connection to an endpoint (in this case,
    // localhost at port 50051). We indicate that the channel isn't authenticated
    // (use of InsecureCredentials()).
    FastnetmonClient fastnetmon( grpc::CreateChannel("localhost:50051", grpc::InsecureCredentials()));

    std::string request_command = argv[1];

    if (request_command == "get_banlist") {
        fastnetmon.GetBanList();
    } else if (request_command == "ban" or request_command == "unban") {
        if (argc < 2) {
            std::cerr << "Please provide IP for action" << std::endl;
            return(1);
        }

        std::string ip_for_ban = argv[2];

        if (request_command == "ban") {
            fastnetmon.ExecuteBan(ip_for_ban, true);
        } else {
            fastnetmon.ExecuteBan(ip_for_ban, false);
        }
    } else {
        std::cerr << "Unknown command" << std::endl;
    }

    return 0;
}
