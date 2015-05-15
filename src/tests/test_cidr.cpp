#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string>
#include <arpa/inet.h>
#include <iostream>

uint32_t convert_cidr_to_binary_netmask(unsigned int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF;
    binary_netmask = binary_netmask << (32 - cidr);
    // htonl from host byte order to network
    // ntohl from network byte order to host

    // We need network byte order at output
    return htonl(binary_netmask);
}

uint32_t convert_ip_as_string_to_uint(std::string ip) {
    struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);

    // in network byte order
    return ip_addr.s_addr;
}

int main() {
    uint32_t network_zero = convert_ip_as_string_to_uint("10.10.10.0");
    uint32_t network_200 = convert_ip_as_string_to_uint("10.10.10.200");
    uint32_t binary_netmask = convert_cidr_to_binary_netmask(24);

    uint32_t generated_subnet_address = network_200 & binary_netmask;

    std::cout << "network byte order" << std::endl;
    std::cout << "10.10.10.200/24\tnetwork byte order:" << network_200
              << " host byte order:" << ntohl(network_200) << std::endl;
    std::cout << "10.10.10.0/24\tnetwork byte order:" << network_zero
              << " host byte order:" << ntohl(network_zero) << std::endl;

    std::cout << "generated \tnetwork byte order:" << generated_subnet_address
              << " host byte order:" << ntohl(generated_subnet_address) << std::endl;
}
