#include "gobgp_action.h"
#include "../fastnetmon_actions.h"
#include "../fastnetmon_types.h"

#include <dlfcn.h>

extern "C" {
    // Gobgp library
    #include "libgobgp.h"
}

#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

#include "gobgp_api_client.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using gobgpapi::GobgpApi;

// Create function pointers
typedef path* (*serialize_path_dynamic_t)(int p0, char* p1);
typedef char* (*decode_path_dynamic_t)(path* p0);

serialize_path_dynamic_t serialize_path_dynamic = NULL;
decode_path_dynamic_t decode_path_dynamic = NULL;

class GrpcClient {
    public:
        GrpcClient(std::shared_ptr<Channel> channel) : stub_(GobgpApi::NewStub(channel)) {}

        void GetAllActiveAnnounces(unsigned int route_family) {
            ClientContext context;
            gobgpapi::Arguments arguments;

            arguments.set_rf(route_family);
            // We could specify certain neighbor here
            arguments.set_name("");
            arguments.set_resource(gobgpapi::Resource::GLOBAL);

            auto destinations_list = stub_->GetRib(&context, arguments);

            gobgpapi::Destination current_destination;

            logger << log4cpp::Priority::INFO << "List of announced prefixes for route family: " << route_family;
            while (destinations_list->Read(&current_destination)) {
                 logger << log4cpp::Priority::INFO  << "Prefix: " << current_destination.prefix();
    
                //std::cout << "Paths size: " << current_destination.paths_size() << std::endl;

                gobgpapi::Path my_path = current_destination.paths(0);

                // std::cout << "Pattrs size: " << my_path.pattrs_size() << std::endl;

                buf my_nlri;
                my_nlri.value = (char*)my_path.nlri().c_str();
                my_nlri.len = my_path.nlri().size();

                path_t gobgp_lib_path;
                gobgp_lib_path.nlri = my_nlri;
                // Not used in library code!
                gobgp_lib_path.path_attributes_cap = 0;
                gobgp_lib_path.path_attributes_len = my_path.pattrs_size();

                buf* my_path_attributes[ my_path.pattrs_size() ];
                for (int i = 0; i < my_path.pattrs_size(); i++) {
                    my_path_attributes[i] = (buf*)malloc(sizeof(buf));
                    my_path_attributes[i]->len = my_path.pattrs(i).size();
                    my_path_attributes[i]->value = (char*)my_path.pattrs(i).c_str();
                }
            
                gobgp_lib_path.path_attributes = my_path_attributes;

                 logger << log4cpp::Priority::INFO << "NLRI: " << decode_path_dynamic(&gobgp_lib_path); 
            }

            Status status = destinations_list->Finish();
            if (!status.ok()) {
                // error_message
                 logger << log4cpp::Priority::INFO << "Problem with RPC: " << status.error_code() << " message " << status.error_message();
            } else {
                // std::cout << "RPC working well" << std::endl;
            }
        }

        void AnnounceFlowSpecPrefix() {
            const gobgpapi::ModPathArguments current_mod_path_arguments;

            unsigned int AFI_IP = 1;
            unsigned int SAFI_FLOW_SPEC_UNICAST = 133;
            unsigned int ipv4_flow_spec_route_family = AFI_IP<<16 | SAFI_FLOW_SPEC_UNICAST;   

            gobgpapi::Path* current_path = new gobgpapi::Path;
            // If you want withdraw, please use it 
            // current_path->set_is_withdraw(true);

            /*
            buf:
                char *value;
                int len;
            path:
                buf   nlri;
                buf** path_attributes;
                int   path_attributes_len;
                int   path_attributes_cap;
            */

            path* path_c_struct = serialize_path_dynamic(ipv4_flow_spec_route_family, (char*)"match destination 10.0.0.0/24 protocol tcp source 20.0.0.0/24 then redirect 10:10");

            // printf("Decoded NLRI output: %s, length %d raw string length: %d\n", decode_path_dynamic(path_c_struct), path_c_struct->nlri.len, strlen(path_c_struct->nlri.value));

            for (int path_attribute_number = 0; path_attribute_number < path_c_struct->path_attributes_len; path_attribute_number++) {
                current_path->add_pattrs(path_c_struct->path_attributes[path_attribute_number]->value, 
                    path_c_struct->path_attributes[path_attribute_number]->len);
            }

            current_path->set_nlri(path_c_struct->nlri.value, path_c_struct->nlri.len);

            gobgpapi::ModPathArguments request;
            request.set_resource(gobgpapi::Resource::GLOBAL);

            google::protobuf::RepeatedPtrField< ::gobgpapi::Path >* current_path_list = request.mutable_paths(); 
            current_path_list->AddAllocated(current_path);
            request.set_name("");

            ClientContext context;

            gobgpapi::Error return_error;

            // result is a std::unique_ptr<grpc::ClientWriter<gobgpapi::ModPathArguments> >
            auto send_stream = stub_->ModPath(&context, &return_error);

            bool write_result = send_stream->Write(request);

            if (!write_result) {
                 logger << log4cpp::Priority::INFO << "Write to API failed\n";
            }

            // Finish all writes
            send_stream->WritesDone();

            auto status = send_stream->Finish();
    
            if (status.ok()) {
                //std::cout << "modpath executed correctly" << std::cout; 
            } else {
                 logger << log4cpp::Priority::INFO << "modpath failed with code: " << status.error_code()
                    << " message " << status.error_message();
            }
        }

        void AnnounceUnicastPrefix(std::string announced_prefix, std::string announced_prefix_nexthop, bool is_withdrawal) {
            const gobgpapi::ModPathArguments current_mod_path_arguments;

            unsigned int AFI_IP = 1;
            unsigned int SAFI_UNICAST = 1;
            unsigned int ipv4_unicast_route_family = AFI_IP<<16 | SAFI_UNICAST;

            gobgpapi::Path* current_path = new gobgpapi::Path;

            if (is_withdrawal) {
                current_path->set_is_withdraw(true);
            }

            /*
            buf:
                char *value;
                int len;
            path:
                buf   nlri;
                buf** path_attributes;
                int   path_attributes_len;
                int   path_attributes_cap;
            */
           
            std::string announce_line = announced_prefix + " nexthop " + announced_prefix_nexthop;

            path* path_c_struct = serialize_path_dynamic(ipv4_unicast_route_family, (char*)announce_line.c_str());

            if (path_c_struct == NULL) {
                logger << log4cpp::Priority::ERROR << "Could not generate path\n";
                return;
            }

            // printf("Decoded NLRI output: %s, length %d raw string length: %d\n", decode_path_dynamic(path_c_struct), path_c_struct->nlri.len, strlen(path_c_struct->nlri.value));

            for (int path_attribute_number = 0; path_attribute_number < path_c_struct->path_attributes_len; path_attribute_number++) {
                current_path->add_pattrs(path_c_struct->path_attributes[path_attribute_number]->value, 
                    path_c_struct->path_attributes[path_attribute_number]->len);
            }

            current_path->set_nlri(path_c_struct->nlri.value, path_c_struct->nlri.len);

            gobgpapi::ModPathArguments request;
            request.set_resource(gobgpapi::Resource::GLOBAL);
            google::protobuf::RepeatedPtrField< ::gobgpapi::Path >* current_path_list = request.mutable_paths(); 
            current_path_list->AddAllocated(current_path);
            request.set_name("");

            ClientContext context;

            gobgpapi::Error return_error;

            // result is a std::unique_ptr<grpc::ClientWriter<api::ModPathArguments> >
            auto send_stream = stub_->ModPath(&context, &return_error);

            bool write_result = send_stream->Write(request);

            if (!write_result) {
                logger << log4cpp::Priority::ERROR << "Write to API failed\n";
                return;
            }

            // Finish all writes
            send_stream->WritesDone();

            auto status = send_stream->Finish();
    
            if (status.ok()) {
                //std::cout << "modpath executed correctly" << std::cout; 
            } else {
                logger << log4cpp::Priority::ERROR << "modpath failed with code: " << status.error_code()
                    << " message " << status.error_message();

                return;
            }
        }

        std::string GetAllNeighbor(std::string neighbor_ip) {
            gobgpapi::Arguments request;
            request.set_rf(4);
            request.set_name(neighbor_ip);

            ClientContext context;

            gobgpapi::Peer peer;
            grpc::Status status = stub_->GetNeighbor(&context, request, &peer);

            if (status.ok()) {
                gobgpapi::PeerConf peer_conf = peer.conf();
                gobgpapi::PeerInfo peer_info = peer.info();

                std::stringstream buffer;
  
                buffer
                    << "Peer AS: " << peer_conf.remote_as() << "\n"
                    << "Peer router id: " << peer_conf.id() << "\n"
                    << "Peer flops: " << peer_info.flops() << "\n"
                    << "BGP state: " << peer_info.bgp_state();

                return buffer.str();
            } else {
                return "Something wrong"; 
            }
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
    gobgp_client = new GrpcClient(grpc::CreateChannel("localhost:8080", grpc::InsecureCredentials()));

    if (configuration_map.count("gobgp_next_hop")) {
        gobgp_nexthop = configuration_map["gobgp_next_hop"];
    }

    if (configuration_map.count("gobgp_announce_host")) {
        gobgp_announce_host = configuration_map["gobgp_announce_host"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet")) {
        gobgp_announce_whole_subnet = configuration_map["gobgp_announce_whole_subnet"] == "on";
    }

    // According to this bug report: https://github.com/golang/go/issues/12873 
    // We have significant issues with popen, daemonization and Go's runtime

    // We use non absoulte path here and linker will find it fir us
    void* gobgdp_library_handle = dlopen("libgobgp.so", RTLD_NOW);

    if (gobgdp_library_handle == NULL) {
        logger << log4cpp::Priority::ERROR << "Could not load gobgp binary library: " << dlerror();
        exit(1);
    } 

    dlerror();    /* Clear any existing error */

    /* According to the ISO C standard, casting between function
        pointers and 'void *', as done above, produces undefined results.
        POSIX.1-2003 and POSIX.1-2008 accepted this state of affairs and
        proposed the following workaround:
    */

    serialize_path_dynamic = (serialize_path_dynamic_t)dlsym(gobgdp_library_handle, "serialize_path");
    if (serialize_path_dynamic == NULL) {
        logger << log4cpp::Priority::ERROR << "Could not load function serialize_path from the dynamic library";
        exit(1);
    }

    decode_path_dynamic = (decode_path_dynamic_t)dlsym(gobgdp_library_handle, "decode_path");

    if (decode_path_dynamic == NULL) {
        logger << log4cpp::Priority::ERROR << "Could not load function decode_path from the dynamic library";
        exit(1);
    }
}

void gobgp_action_shutdown() {
    delete gobgp_client;
}

void gobgp_ban_manage(std::string action, std::string ip_as_string, attack_details current_attack) {
    bool is_withdrawal = false;

    if (action == "ban") {
        is_withdrawal = false;
    } else {
        is_withdrawal = true;
    }

    if (gobgp_announce_whole_subnet) {
        std::string subnet_as_string_with_mask = convert_subnet_to_string(current_attack.customer_network);

        gobgp_client->AnnounceUnicastPrefix(subnet_as_string_with_mask, gobgp_nexthop, is_withdrawal);
    }

    if (gobgp_announce_host) {
        std::string ip_as_string_with_mask = ip_as_string + "/32";

        gobgp_client->AnnounceUnicastPrefix(ip_as_string_with_mask, gobgp_nexthop, is_withdrawal);
    }
}
