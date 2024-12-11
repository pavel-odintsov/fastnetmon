#include "../../abstract_subnet_counters.hpp"
#include "../../fastnetmon_configuration_scheme.hpp"
#include "../../bgp_protocol_flow_spec.hpp"
#include "../../netflow_plugin/netflow_collector.hpp"
#include "../../sflow_plugin/sflow_collector.hpp"
#include "../../fastnetmon_logic.hpp"


log4cpp::Category& logger = log4cpp::Category::getRoot();
time_t current_inaccurate_time = 0;
fastnetmon_configuration_t fastnetmon_global_configuration;
packet_buckets_storage_t<subnet_ipv6_cidr_mask_t> packet_buckets_ipv6_storage;
bool DEBUG_DUMP_ALL_PACKETS = false;
bool DEBUG_DUMP_OTHER_PACKETS = false;
uint64_t total_ipv6_packets         = 0;
uint64_t total_ipv4_packets         = 0;
patricia_tree_t *lookup_tree_ipv4;
patricia_tree_t *lookup_tree_ipv6;

uint64_t total_flowspec_whitelist_packets         = 0;
uint64_t total_simple_packets_processed         = 0;
uint64_t unknown_ip_version_packets         = 0;
bool process_incoming_traffic = true;
bool process_outgoing_traffic = true;
bool enable_connection_tracking = true;

std::vector<flow_spec_rule_t> static_flowspec_based_whitelist;
packet_buckets_storage_t<uint32_t> packet_buckets_ipv4_storage;

total_speed_counters_t total_counters_ipv4;
total_speed_counters_t total_counters_ipv6;

abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_network_counters;
abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_host_counters;
abstract_subnet_counters_t<subnet_cidr_mask_t, subnet_counter_t> ipv4_network_counters;
abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters;

map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
std::mutex flow_counter_mutex;

extern process_packet_pointer sflow_process_func_ptr = process_packet;

__AFL_FUZZ_INIT();
int main(int argc, char** argv) {
        uint32_t client_ipv4_address = 128;
        std::string ip_add =  "192.168.0.1";
        uint16_t version = 5;

        unsigned char* udp_buffer = __AFL_FUZZ_TESTCASE_BUF;
        udp_buffer[0] = (version >> 8) & 0xFF; // Higher byte
        udp_buffer[1] = version & 0xFF;

        while (__AFL_LOOP(10000)) {
               unsigned int received_bytes  = __AFL_FUZZ_TESTCASE_LEN;
                parse_sflow_v5_packet( (uint8_t*)udp_buffer, received_bytes, client_ipv4_address);
        }
        return 0;
}