#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string>
#include <arpa/inet.h>
#include <iostream>

uint32_t convert_ip_as_string_to_uint(std::string ip) {
    struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);

    // in network byte order
    return ip_addr.s_addr;
}

int main() {
    std::cout<<"network byte order"<<std::endl;
    std::cout<<"10.10.10.200/24\tnetwork byte order:"<<convert_ip_as_string_to_uint("10.10.10.200")<<" host byte order:"<<ntohl(convert_ip_as_string_to_uint("10.10.10.200"))<<std::endl;
    std::cout<<"10.10.10.0/24\tnetwork byte order:"  <<convert_ip_as_string_to_uint("10.10.10.0")<<" host byte order:"<<ntohl(convert_ip_as_string_to_uint("10.10.10.0"))<<std::endl;
    
     
}
