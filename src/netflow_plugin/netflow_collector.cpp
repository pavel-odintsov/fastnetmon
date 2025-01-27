/* netflow plugin body */

// TODO: add timestamp to netflow templates stored at disk
// TODO: do not kill disk with netflow template writes to disk

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>  // sockaddr_in6
#include <ws2tcpip.h> // getaddrinfo
#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <fstream>
#include <map>
#include <mutex>
#include <vector>

#include "../fast_library.hpp"
#include "../ipfix_fields/ipfix_rfc.hpp"

#include "../all_logcpp_libraries.hpp"

#include "../fastnetmon_plugin.hpp"

#include "netflow.hpp"

// Protocol specific things
#include "netflow_v5.hpp"
#include "netflow_v9.hpp"

#include "netflow_template.hpp"
#include "netflow_collector.hpp"

#include <boost/serialization/map.hpp>
#include <boost/serialization/vector.hpp>

#include <boost/archive/xml_iarchive.hpp>
#include <boost/archive/xml_oarchive.hpp>

// For Netflow lite parsing
#include "../simple_packet_parser_ng.hpp"

#include <boost/algorithm/string.hpp>

#include "../fastnetmon_configuration_scheme.hpp"

#include "ipfix_collector.hpp"

#include "netflow_v5_collector.hpp"

#include "netflow_v9_collector.hpp"

#include "netflow_meta_info.hpp"

// Get it from main programme
extern log4cpp::Category& logger;

extern fastnetmon_configuration_t fastnetmon_global_configuration;

// Per router packet counters
std::mutex netflow5_packets_per_router_mutex;
std::map<std::string, uint64_t> netflow5_packets_per_router;

std::mutex netflow9_packets_per_router_mutex;
std::map<std::string, uint64_t> netflow9_packets_per_router;

std::mutex ipfix_packets_per_router_mutex;
std::map<std::string, uint64_t> ipfix_packets_per_router;

// Counters section start

std::string netflow_ipfix_total_ipv4_packets_desc = "Total number of Netflow or IPFIX UDP packets received over IPv4 protocol";
uint64_t netflow_ipfix_total_ipv4_packets         = 0;

std::string netflow_ipfix_total_ipv6_packets_desc = "Total number of Netflow or IPFIX UDP packets received over IPv6 protocol";
uint64_t netflow_ipfix_total_ipv6_packets         = 0;

std::string netflow_ipfix_total_packets_desc = "Total number of Netflow or IPFIX UDP packets received";
uint64_t netflow_ipfix_total_packets         = 0;

std::string netflow_ipfix_all_protocols_total_flows_desc =
    "Total number of flows summarized for all kinds of Netflow and IPFIX";
uint64_t netflow_ipfix_all_protocols_total_flows = 0;

std::string netflow_ipfix_udp_packet_drops_desc = "Number of UDP packets dropped by system on our socket";
uint64_t netflow_ipfix_udp_packet_drops         = 0;

std::string netflow_ipfix_unknown_protocol_version_desc =
    "Number of packets with unknown Netflow version. In may be sign that some another protocol like sFlow is being "
    "send to Netflow or IPFIX port";
uint64_t netflow_ipfix_unknown_protocol_version = 0;

std::string template_update_attempts_with_same_template_data_desc =
    "Number of templates received with same data as inside known by us";
uint64_t template_update_attempts_with_same_template_data = 0;


std::string template_netflow_ipfix_disk_writes_desc =
    "Number of times when we write Netflow or ipfix templates to disk";
uint64_t template_netflow_ipfix_disk_writes = 0;


std::string netflow_ignored_long_flows_desc = "Number of flows which exceed specified limit in configuration";
uint64_t netflow_ignored_long_flows         = 0;

// END of counters section


void increment_duration_counters_ipfix(int64_t duration);

// We limit number of flowsets in packet Netflow v9 / IPFIX packets with some reasonable number to reduce possible attack's surface and reduce probability of infinite loop
uint64_t sets_per_packet_maximum_number = 256;

// TODO: add per source uniq templates support
process_packet_pointer netflow_process_func_ptr = NULL;

std::vector<system_counter_t> get_netflow_stats() {
    std::vector<system_counter_t> system_counter;

    // Netflow v5
    std::vector<system_counter_t> netflow_v5_stats = get_netflow_v5_stats();
    
    // Append Netflow v5 stats
    system_counter.insert(system_counter.end(), netflow_v5_stats.begin(), netflow_v5_stats.end());

    // Get Netflow v9 stats
    std::vector<system_counter_t> netflow_v9_stats = get_netflow_v9_stats();

    // Append Netflow v9 stats
    system_counter.insert(system_counter.end(), netflow_v9_stats.begin(), netflow_v9_stats.end());
 
    // Get IPFIX stats
    std::vector<system_counter_t> ipfix_stats = get_ipfix_stats();

    // Append IPFIX stats
    system_counter.insert(system_counter.end(), ipfix_stats.begin(), ipfix_stats.end());

    // Common

    system_counter.push_back(system_counter_t("netflow_ipfix_total_packets", netflow_ipfix_total_packets,
                                              metric_type_t::counter, netflow_ipfix_total_packets_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_total_ipv4_packets", netflow_ipfix_total_ipv4_packets,
                                              metric_type_t::counter, netflow_ipfix_total_ipv4_packets_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_total_ipv6_packets", netflow_ipfix_total_ipv6_packets,
                                              metric_type_t::counter, netflow_ipfix_total_ipv6_packets_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_all_protocols_total_flows", netflow_ipfix_all_protocols_total_flows,
                                              metric_type_t::counter, netflow_ipfix_all_protocols_total_flows_desc));
    system_counter.push_back(system_counter_t("netflow_ipfix_udp_packet_drops", netflow_ipfix_udp_packet_drops,
                                              metric_type_t::counter, netflow_ipfix_udp_packet_drops_desc));

    system_counter.push_back(system_counter_t("netflow_ipfix_unknown_protocol_version", netflow_ipfix_unknown_protocol_version,
                                              metric_type_t::counter, netflow_ipfix_unknown_protocol_version_desc));

    system_counter.push_back(system_counter_t("template_update_attempts_with_same_template_data",
                                              template_update_attempts_with_same_template_data, metric_type_t::counter,
                                              template_update_attempts_with_same_template_data_desc));

    system_counter.push_back(system_counter_t("netflow_ignored_long_flows", netflow_ignored_long_flows,
                                              metric_type_t::counter, netflow_ignored_long_flows_desc));

    system_counter.push_back(system_counter_t("template_netflow_ipfix_disk_writes", template_netflow_ipfix_disk_writes,
                                              metric_type_t::counter, template_netflow_ipfix_disk_writes_desc));

    return system_counter;
}

// Returns fancy name of protocol version
std::string get_netflow_protocol_version_as_string(const netflow_protocol_version_t& netflow_protocol_version) {
    std::string protocol_name = "unknown";

    if (netflow_protocol_version == netflow_protocol_version_t::netflow_v9) {
        protocol_name = "Netflow v9";
    } else if (netflow_protocol_version == netflow_protocol_version_t::ipfix) {
        protocol_name = "IPFIX";
    }

    return protocol_name;
}


/* Prototypes */
void add_update_peer_template(const netflow_protocol_version_t& netflow_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_addres_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template);

int nf9_rec_to_flow(uint32_t record_type,
                    uint32_t record_length,
                    uint8_t* data,
                    simple_packet_t& packet,
                    std::vector<template_record_t>& template_records,
                    netflow_meta_info_t& flow_meta);

const template_t* peer_find_template(const std::map<std::string, std::map<uint32_t, template_t>>& table_for_lookup,
                                      std::mutex& table_for_lookup_mutex,
                                      uint32_t source_id,
                                      uint32_t template_id,
                                      const std::string& client_addres_in_string_format) {

    // We use source_id for distinguish multiple netflow agents with same IP
    std::string key = client_addres_in_string_format + "_" + std::to_string(source_id);

    std::lock_guard<std::mutex> lock(table_for_lookup_mutex);

    auto itr = table_for_lookup.find(key);

    if (itr == table_for_lookup.end()) {
        return NULL;
    }



    // We found entry for specific agent instance and we need to find specific template in it
    auto itr_template_id = itr->second.find(template_id);

    // We have no such template
    if (itr_template_id == itr->second.end()) {
        return NULL;
    }

    // Return pointer to element
    return &itr_template_id->second;
}

// Overrides some fields from specified nested packet
void override_packet_fields_from_nested_packet(simple_packet_t& packet, const simple_packet_t& nested_packet) {
    // Copy IP addresses
    packet.src_ip = nested_packet.src_ip;
    packet.dst_ip = nested_packet.dst_ip;

    packet.src_ipv6 = nested_packet.src_ipv6;
    packet.dst_ipv6 = nested_packet.dst_ipv6;

    packet.ip_protocol_version = nested_packet.ip_protocol_version;
    packet.ttl                 = nested_packet.ttl;

    // Ports
    packet.source_port      = nested_packet.source_port;
    packet.destination_port = nested_packet.destination_port;

    packet.protocol          = nested_packet.protocol;
    packet.length            = nested_packet.length;
    packet.ip_length         = nested_packet.ip_length;
    packet.number_of_packets = 1;
    packet.flags             = nested_packet.flags;
    packet.ip_fragmented     = nested_packet.ip_fragmented;
    packet.ip_dont_fragment  = nested_packet.ip_dont_fragment;
    packet.vlan              = nested_packet.vlan;

    // Copy Ethernet MAC addresses to main packet structure using native C++ approach to avoid touching memory with memcpy
    std::copy(std::begin(nested_packet.source_mac), std::end(nested_packet.source_mac), std::begin(packet.source_mac));

    std::copy(std::begin(nested_packet.destination_mac), std::end(nested_packet.destination_mac), std::begin(packet.destination_mac));
}

void add_update_peer_template(
                              const netflow_protocol_version_t& netflow_protocol_version,
                              std::map<std::string, std::map<uint32_t, template_t>>& table_for_add,
                              std::mutex& table_for_add_mutex,
                              uint32_t source_id,
                              uint32_t template_id,
                              const std::string& client_address_in_string_format,
                              const template_t& field_template,
                              bool& updated,
                              bool& updated_existing_template) {

    std::string key = client_address_in_string_format + "_" + std::to_string(source_id);

    if (logger.getPriority() == log4cpp::Priority::DEBUG) {
        logger << log4cpp::Priority::DEBUG << "Received " << get_netflow_protocol_version_as_string(netflow_protocol_version)
            << " template with id " << template_id << " from host " << client_address_in_string_format
            << " source id: " << source_id;  
    }

    // We need to put lock on it
    std::lock_guard<std::mutex> lock(table_for_add_mutex);

    auto itr = table_for_add.find(key);

    if (itr == table_for_add.end()) {
        std::map<uint32_t, template_t> temp_template_storage;
        temp_template_storage[template_id] = field_template;

        table_for_add[key] = temp_template_storage;
        updated            = true;

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "We had no "
                << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " templates for source " << key;

            logger << log4cpp::Priority::DEBUG << "Added " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " template with ID " << template_id << " for " << key; 
        }

        return;
    }

    // We have information about this agent

    // Try to find actual template id here
    if (itr->second.count(template_id) == 0) {

        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "We had no information about " 
                << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " template with ID " << template_id << " for " << key;

            logger << log4cpp::Priority::DEBUG << "Added " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                << " template with ID " << template_id << " for " << key;
        }

        itr->second[template_id] = field_template;
        updated                  = true;

        return;
    }

    // TODO: Should I track timestamp here and drop old templates after some time?
    if (itr->second[template_id] != field_template) {
        //
        // We can see that template definition actually changed
        //
        // In case of IPFIX this is clear protocol violation:
        // https://datatracker.ietf.org/doc/html/rfc7011#section-8.1
        //

        //
        // If a Collecting Process receives a new Template Record or Options
        // Template Record for an already-allocated Template ID, and that
        // Template or Options Template is different from the already-received
        // Template or Options Template, this indicates a malfunctioning or
        // improperly implemented Exporting Process.  The continued receipt and
        // unambiguous interpretation of Data Records for this Template ID are
        // no longer possible, and the Collecting Process SHOULD log the error.
        // Further Collecting Process actions are out of scope for this
        // specification.
        //

        //
        // We cannot follow RFC recommendation for IPFIX as it will break our on disk template caching.
        // I.e. we may have template with specific list of fields in cache
        // Then after firmware upgrade vendor changes list of fields but does not change template id
        // We have to accept new one and update to be able to decode data
        //
        
        // 
        // Netflow v9 explicitly prohibits template content updates: https://www.ietf.org/rfc/rfc3954.txt
        // 
        // A newly created Template record is assigned an unused Template ID
        // from the Exporter. If the template configuration is changed, the
        // current Template ID is abandoned and SHOULD NOT be reused until the
        // NetFlow process or Exporter restarts.
        //
        // 

        // 
        // But in same time Netflow v9 RFC allows template update for collector and that's exactly what we do:
        //
        // If a Collector should receive a new definition for an already existing Template ID, it MUST discard 
        // the previous template definition and use the new one.
        //

        // On debug level we have to print templates
        if (logger.getPriority() == log4cpp::Priority::DEBUG) {
            logger << log4cpp::Priority::DEBUG << "Old " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                <<" template: " << print_template(itr->second[template_id]);

            logger << log4cpp::Priority::DEBUG << "New " << get_netflow_protocol_version_as_string(netflow_protocol_version)
                <<" template: " << print_template(field_template);
        }

        // We use ERROR level as this behavior is definitely not a common and must be carefully investigated
        logger << log4cpp::Priority::ERROR << get_netflow_protocol_version_as_string(netflow_protocol_version)
            << " template " << template_id << " was updated for " << key;

        // Warn user that something bad going on
        logger << log4cpp::Priority::ERROR << get_netflow_protocol_version_as_string(netflow_protocol_version)
            << " template update may be sign of RFC violation by vendor and if you observe this behaviour please reach support@fastnetmon.com and share information about your equipment and firmware versions"; 


        itr->second[template_id] = field_template;

        // We need to track this case as it's pretty unusual and in some cases it may be very destructive when router does it incorrectly
        updated_existing_template = true;

        updated = true;
    } else {
        template_update_attempts_with_same_template_data++;
    }

    return;
}

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - record_length), data, record_length);

// Safe version of BE_COPY macro
bool be_copy_function(const uint8_t* data, uint8_t* target, uint32_t target_field_length, uint32_t record_field_length) {
    if (target_field_length < record_field_length) {
        return false;
    }

    memcpy(target + (target_field_length - record_field_length), data, record_field_length);
    return true;
}


// Updates flow timeouts from device
void update_device_flow_timeouts(const device_timeouts_t& device_timeouts,
                                 std::mutex& structure_mutex,
                                 std::map<std::string, device_timeouts_t>& timeout_storage,
                                 const std::string& client_addres_in_string_format,
                                 const netflow_protocol_version_t& netflow_protocol_version) {

    // We did not receive any information about timeouts
    // We do not expect that devices reports only active or any inactive timeouts as it does not make any sense
    if (!device_timeouts.active_timeout.has_value() && !device_timeouts.inactive_timeout.has_value()) {
        return;
    }

    std::lock_guard<std::mutex> lock(structure_mutex);

    auto current_timeouts = timeout_storage.find(client_addres_in_string_format);

    if (current_timeouts == timeout_storage.end()) {
        timeout_storage[client_addres_in_string_format] = device_timeouts;

        logger << log4cpp::Priority::INFO
               << "Learnt new active flow timeout value: " << device_timeouts.active_timeout.value_or(0) << " seconds "
               << "and inactive flow timeout value: " << device_timeouts.inactive_timeout.value_or(0)
               << " seconds for device " << client_addres_in_string_format << " protocol " << get_netflow_protocol_version_as_string(netflow_protocol_version);

        return;
    }

    auto old_flow_timeouts = current_timeouts->second;

    // They're equal with previously received, nothing to worry about
    if (old_flow_timeouts == device_timeouts) {
        return;
    }

    // We had values previously
    logger << log4cpp::Priority::INFO << "Update old active flow timeout value "
           << current_timeouts->second.active_timeout.value_or(0) << " to " << device_timeouts.active_timeout.value_or(0)
           << " for " << client_addres_in_string_format << " protocol " << get_netflow_protocol_version_as_string(netflow_protocol_version);
    
    logger << log4cpp::Priority::INFO << "Update old inactive flow timeout value "
           << current_timeouts->second.inactive_timeout.value_or(0) << " to " << device_timeouts.inactive_timeout.value_or(0)
           << " for " << client_addres_in_string_format << " protocol " << get_netflow_protocol_version_as_string(netflow_protocol_version);

    current_timeouts->second = device_timeouts;
    return;
}

bool process_netflow_packet(uint8_t* packet, uint32_t len, std::string& client_addres_in_string_format, uint32_t client_ipv4_address) {
    netflow_header_common_t* hdr = (netflow_header_common_t*)packet;

    switch (ntohs(hdr->version)) {
    case 5:
        return process_netflow_packet_v5(packet, len, client_addres_in_string_format, client_ipv4_address);
    case 9:
        return process_netflow_packet_v9(packet, len, client_addres_in_string_format, client_ipv4_address);
    case 10:
        netflow_ipfix_total_packets++;
        return process_ipfix_packet(packet, len, client_addres_in_string_format, client_ipv4_address);
    default:
        netflow_ipfix_unknown_protocol_version++;
        logger << log4cpp::Priority::ERROR << "We do not support Netflow " << ntohs(hdr->version)
               << " we received this packet from " << client_addres_in_string_format;

        return false;
    }

    return true;
}

void start_netflow_collector(std::string netflow_host, unsigned int netflow_port, bool reuse_port);

void start_netflow_collection(process_packet_pointer func_ptr) {
    logger << log4cpp::Priority::INFO << "netflow plugin started";

    netflow_process_func_ptr = func_ptr;

    boost::thread_group netflow_collector_threads;

    logger << log4cpp::Priority::INFO << "Netflow plugin will listen on " << fastnetmon_global_configuration.netflow_ports.size() << " ports";

    for (const auto& netflow_port : fastnetmon_global_configuration.netflow_ports) {
        bool reuse_port = false;

        auto netflow_processing_thread = new boost::thread(start_netflow_collector,
	    fastnetmon_global_configuration.netflow_host, netflow_port, reuse_port);

        // Set unique name
        std::string thread_name = "netflow_" + std::to_string(netflow_port);
        set_boost_process_name(netflow_processing_thread, thread_name);

        netflow_collector_threads.add_thread(netflow_processing_thread);
    }

    netflow_collector_threads.join_all();

    logger << log4cpp::Priority::INFO << "Function start_netflow_collection was finished";
}

void start_netflow_collector(std::string netflow_host, unsigned int netflow_port, bool reuse_port) {
    logger << log4cpp::Priority::INFO << "netflow plugin will listen on " << netflow_host << ":" << netflow_port << " udp port";

    unsigned int udp_buffer_size = 65536;
    char udp_buffer[udp_buffer_size];

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);

    // Could be AF_INET6 or AF_INET
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    // This flag will generate wildcard IP address if we not specified certain IP
    // address for
    // binding
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

    struct addrinfo* servinfo = NULL;

    const char* address_for_binding = NULL;

    if (!netflow_host.empty()) {
        address_for_binding = netflow_host.c_str();
    }

    char port_as_string[16];
    sprintf(port_as_string, "%d", netflow_port);

    int getaddrinfo_result = getaddrinfo(address_for_binding, port_as_string, &hints, &servinfo);

    if (getaddrinfo_result != 0) {
        logger << log4cpp::Priority::ERROR << "Netflow getaddrinfo function failed with code: " << getaddrinfo_result
               << " please check netflow_host";
        return;
    }

    int sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

    if (reuse_port) {
        // Windows does not support this setsockopt but they may add such logic in future.
        // Instead of disabling this logic I prefer to define missing constant to address compilation failure
#ifdef _WIN32
#define SO_REUSEPORT 15
#endif

        int reuse_port_optval = 1;

        // Windows uses char* as 4rd argument: https://learn.microsoft.com/en-gb/windows/win32/api/winsock/nf-winsock-getsockopt and we need to add explicit cast
        // Linux uses void* https://linux.die.net/man/2/setsockopt
        // So I think char* works for both platforms
        auto set_reuse_port_res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (char*)&reuse_port_optval, sizeof(reuse_port_optval));

        if (set_reuse_port_res != 0) {
            logger << log4cpp::Priority::ERROR << "Cannot enable reuse port mode";
            return;
        }
    }

    int bind_result = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);

    if (bind_result) {
        logger << log4cpp::Priority::ERROR << "Can't listen on port: " << netflow_port << " on host " << netflow_host
               << " errno:" << errno << " error: " << strerror(errno);
        return;
    }

    struct sockaddr_in6 peer;
    memset(&peer, 0, sizeof(peer));

    /* We should specify timeout there for correct toolkit shutdown */
    /* Because otherwise recvfrom will stay in blocked mode forever */
    struct timeval tv;
    tv.tv_sec  = 1; /* X Secs Timeout */
    tv.tv_usec = 0; // Not init'ing this can cause strange errors

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));

    while (true) {
        // This approach provide ability to store both IPv4 and IPv6 client's
        // addresses
        struct sockaddr_storage client_address;
        // It's MUST
        memset(&client_address, 0, sizeof(struct sockaddr_storage));
        socklen_t address_len = sizeof(struct sockaddr_storage);

        int received_bytes = recvfrom(sockfd, udp_buffer, udp_buffer_size, 0, (struct sockaddr*)&client_address, &address_len);

        // logger << log4cpp::Priority::ERROR << "Received " << received_bytes << " with netflow UDP server";

        if (received_bytes > 0) {
            uint32_t client_ipv4_address = 0;

            if (client_address.ss_family == AF_INET) {
                // Convert to IPv4 structure
                struct sockaddr_in* sockaddr_in_ptr = (struct sockaddr_in*)&client_address;

                client_ipv4_address = sockaddr_in_ptr->sin_addr.s_addr;
                // logger << log4cpp::Priority::ERROR << "client ip: " << convert_ip_as_uint_to_string(client_ip_address);
            } else if (client_address.ss_family == AF_INET6) {
                // We do not support them now
            } else {
                // Should not happen
            }


            // Pass host and port as numbers without any conversion
            int getnameinfo_flags = NI_NUMERICSERV | NI_NUMERICHOST;
            char host[NI_MAXHOST];
            char service[NI_MAXSERV];

            // TODO: we should check return value here
            int result = getnameinfo((struct sockaddr*)&client_address, address_len, host, NI_MAXHOST, service,
                                     NI_MAXSERV, getnameinfo_flags);

            // We sill store client's IP address as string for allowing IPv4 and IPv6
            // processing in same time
            std::string client_addres_in_string_format = std::string(host);
            // logger<< log4cpp::Priority::INFO<<"We receive packet from IP:
            // "<<client_addres_in_string_format;

            netflow_ipfix_total_packets++;
            process_netflow_packet((uint8_t*)udp_buffer, received_bytes, client_addres_in_string_format, client_ipv4_address);
        } else {

            if (received_bytes == -1) {
                if (errno == EAGAIN) {
                    // We got timeout, it's OK!
                } else {
                    logger << log4cpp::Priority::ERROR << "netflow data receive failed with error number: " << errno << " "
                           << "error name: " << strerror(errno);
                }
            }
        }

        // Add interruption point for correct application shutdown
        boost::this_thread::interruption_point();
    }

    logger << log4cpp::Priority::INFO << "Netflow processing thread for " << netflow_host << ":" << netflow_port << " was finished";
    freeaddrinfo(servinfo);
}
