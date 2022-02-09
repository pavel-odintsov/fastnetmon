#include "gobgp_action.h"
#include "../fastnetmon_actions.h"
#include "../fastnetmon_types.h"

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif  // __GNUC__

#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc/grpc.h>

#include "gobgp.grpc.pb.h"
#include "attribute.pb.h"

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__


unsigned int gobgp_client_connection_timeout = 5;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using gobgpapi::GobgpApi;

class GrpcClient {
    public:
    GrpcClient(std::shared_ptr<Channel> channel) : stub_(GobgpApi::NewStub(channel)) {
    }
    void GetAllActiveAnnounces(unsigned int route_family) {
	/*
        ClientContext context;
        gobgpapi::Table table;

        table.set_family(route_family);
        // We could specify certain neighbor here
        table.set_name("");
        table.set_type(gobgpapi::Resource::GLOBAL);

        gobgpapi::Table response_table;

        auto status = stub_->GetRib(&context, table, &response_table);

        if (!status.ok()) {
            // error_message
            logger << log4cpp::Priority::INFO << "Problem with RPC: " << status.error_code()
                   << " message " << status.error_message();
            // std::cout << "Problem with RPC: " << status.error_code() << " message " << status.error_message() << std::endl;
            return;
        } else {
            // std::cout << "RPC working well" << std::endl;
        }

        std::cout << "List of announced prefixes for route family: " << route_family << std::endl
                  << std::endl;

        for (auto current_destination : response_table.destinations()) {
            logger << log4cpp::Priority::INFO << "Prefix: " << current_destination.prefix();
            // std::cout << "Prefix: " << current_destination.prefix() << std::endl;

            // std::cout << "Paths size: " << current_destination.paths_size() << std::endl;

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

            buf* my_path_attributes[my_path.pattrs_size()];
            for (int i = 0; i < my_path.pattrs_size(); i++) {
                my_path_attributes[i] = (buf*)malloc(sizeof(buf));
                my_path_attributes[i]->len = my_path.pattrs(i).size();
                my_path_attributes[i]->value = (char*)my_path.pattrs(i).c_str();
            }

            gobgp_lib_path.path_attributes = my_path_attributes;

            logger << log4cpp::Priority::INFO << "NLRI: " << decode_path_dynamic(&gobgp_lib_path);
            // std::cout << "NLRI: " << decode_path(&gobgp_lib_path) << std::endl;
        }
	*/
    }

    void AnnounceFlowSpecPrefix(bool withdraw) {
        /*	
        const gobgpapi::ModPathArguments current_mod_path_arguments;

        unsigned int AFI_IP = 1;
        unsigned int SAFI_FLOW_SPEC_UNICAST = 133;
        unsigned int ipv4_flow_spec_route_family = AFI_IP << 16 | SAFI_FLOW_SPEC_UNICAST;

        gobgpapi::Path* current_path = new gobgpapi::Path;
        current_path->set_is_withdraw(withdraw);
        */

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

	/*
        path* path_c_struct =
        serialize_path_dynamic(ipv4_flow_spec_route_family,
                               (char*)"match destination 10.0.0.0/24 protocol tcp source "
                                      "20.0.0.0/24 then redirect 10:10");

        // printf("Decoded NLRI output: %s, length %d raw string length: %d\n", decode_path(path_c_struct), path_c_struct->nlri.len, strlen(path_c_struct->nlri.value));

        for (int path_attribute_number = 0;
             path_attribute_number < path_c_struct->path_attributes_len; path_attribute_number++) {
            current_path->add_pattrs(path_c_struct->path_attributes[path_attribute_number]->value,
                                     path_c_struct->path_attributes[path_attribute_number]->len);
        }

        current_path->set_nlri(path_c_struct->nlri.value, path_c_struct->nlri.len);

        gobgpapi::ModPathsArguments request;
        request.set_resource(gobgpapi::Resource::GLOBAL);

        google::protobuf::RepeatedPtrField< ::gobgpapi::Path>* current_path_list = request.mutable_paths();
        current_path_list->AddAllocated(current_path);
        request.set_name("");

        ClientContext context;

        gobgpapi::Error return_error;

        // result is a std::unique_ptr<grpc::ClientWriter<gobgpapi::ModPathArguments> >
        auto send_stream = stub_->ModPaths(&context, &return_error);

        bool write_result = send_stream->Write(request);

        if (!write_result) {
            logger << log4cpp::Priority::INFO << "Write to API failed\n";
            // std::cout << "Write to API failed\n";
        }

        // Finish all writes
        send_stream->WritesDone();

        auto status = send_stream->Finish();

        if (status.ok()) {
            // std::cout << "modpath executed correctly" << std::cout;
        } else {
            logger << log4cpp::Priority::INFO << "modpath failed with code: " << status.error_code()
                   << " message " << status.error_message();
            // std::cout << "modpath failed with code: " << status.error_code()
            //    << " message " << status.error_message() << std::endl;
        }
	*/
    }

    bool AnnounceUnicastPrefix(std::string announced_address, std::string announced_prefix_nexthop, bool is_withdrawal, unsigned int cidr_mask) {
	grpc::ClientContext context;

	// Set timeout for API
	std::chrono::system_clock::time_point deadline =
            std::chrono::system_clock::now() + std::chrono::seconds(gobgp_client_connection_timeout);
	context.set_deadline(deadline);

	auto gobgp_ipv4_unicast_route_family = new gobgpapi::Family;
	gobgp_ipv4_unicast_route_family->set_afi(gobgpapi::Family::AFI_IP);
	gobgp_ipv4_unicast_route_family->set_safi(gobgpapi::Family::SAFI_UNICAST);

	gobgpapi::AddPathRequest request;
        request.set_table_type(gobgpapi::TableType::GLOBAL);

	gobgpapi::Path* current_path = new gobgpapi::Path;

        current_path->set_allocated_family(gobgp_ipv4_unicast_route_family);

	if (is_withdrawal) {
            current_path->set_is_withdraw(true);
	}

        // Configure required announce
	google::protobuf::Any *current_nlri = new google::protobuf::Any;
	gobgpapi::IPAddressPrefix current_ipaddrprefix;
	current_ipaddrprefix.set_prefix(announced_address);
	current_ipaddrprefix.set_prefix_len(cidr_mask);

	current_nlri->PackFrom(current_ipaddrprefix);
	current_path->set_allocated_nlri(current_nlri);

        // Updating OriginAttribute info for current_path
	google::protobuf::Any *current_origin = current_path->add_pattrs();
	gobgpapi::OriginAttribute current_origin_t;
	current_origin_t.set_origin(0);
	current_origin->PackFrom(current_origin_t);

        // Updating NextHopAttribute info for current_path
	google::protobuf::Any *current_next_hop = current_path->add_pattrs();
	gobgpapi::NextHopAttribute current_next_hop_t;
	current_next_hop_t.set_next_hop(announced_prefix_nexthop);
	current_next_hop->PackFrom(current_next_hop_t);
	
	/*
	// Updating CommunitiesAttribute for current_path
	google::protobuf::Any *current_communities = current_path->add_pattrs();
	gobgpapi::CommunitiesAttribute current_communities_t;
	current_communities_t.add_communities(100);
	current_communities->PackFrom(current_communities_t);
        */

        request.set_allocated_path(current_path);

	gobgpapi::AddPathResponse response;

        // Don't be confused by name, it also can withdraw announces
        auto status = stub_->AddPath(&context, request, &response);

        if (!status.ok()) {
            logger << log4cpp::Priority::ERROR << "AddPath request to BGP daemon failed with code: " << status.error_code()
               << " message " << status.error_message();

           return false;
        }


	return true;
    }

    std::string GetNeighbor(std::string neighbor_ip) {
	return "not implemented";
	/*
        gobgpapi::Arguments request;
        request.set_family(4);
        request.set_name(neighbor_ip);

        ClientContext context;

        gobgpapi::Peer peer;
        grpc::Status status = stub_->GetNeighbor(&context, request, &peer);

        if (status.ok()) {
            gobgpapi::PeerConf peer_conf = peer.conf();
            gobgpapi::PeerState peer_info = peer.info();

            std::stringstream buffer;

            buffer << "Peer AS: " << peer_conf.peer_as() << "\n"
                   << "Peer router id: " << peer_conf.id() << "\n"
                   << "Peer flops: " << peer_info.flops() << "\n"
                   << "BGP state: " << peer_info.bgp_state();

            return buffer.str();
        } else {
            return "Something wrong";
        }
	*/
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
    gobgp_client = new GrpcClient(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));

    if (configuration_map.count("gobgp_next_hop")) {
        gobgp_nexthop = configuration_map["gobgp_next_hop"];
    }

    if (configuration_map.count("gobgp_announce_host")) {
        gobgp_announce_host = configuration_map["gobgp_announce_host"] == "on";
    }

    if (configuration_map.count("gobgp_announce_whole_subnet")) {
        gobgp_announce_whole_subnet = configuration_map["gobgp_announce_whole_subnet"] == "on";
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

	logger << log4cpp::Priority::ERROR << "Per network GoBGP announces are not supported yet";
        // gobgp_client->AnnounceUnicastPrefix(subnet_as_string_with_mask, gobgp_nexthop, is_withdrawal, );
    }

    if (gobgp_announce_host) {
        std::string ip_as_string_with_mask = ip_as_string + "/32";

        gobgp_client->AnnounceUnicastPrefix(ip_as_string, gobgp_nexthop, is_withdrawal, 32);
    }
}
