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

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Fastnetmon::NewStub(channel)) {}

  // Assambles the client's payload, sends it and presents the response back
  // from the server.
  std::string GetBanList(const std::string& user) {
    // Data we are sending to the server.
    BanListRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    BanListReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->GetBanlist(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Fastnetmon::Stub> stub_;
};

int main(int argc, char** argv) {
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint (in this case,
  // localhost at port 50051). We indicate that the channel isn't authenticated
  // (use of InsecureCredentials()).
  GreeterClient greeter(
      grpc::CreateChannel("localhost:50051", grpc::InsecureCredentials()));
  std::string user("Paul");
  std::string reply = greeter.GetBanList(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}
