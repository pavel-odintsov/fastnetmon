#include <iostream>
#include <tins/tins.h>

// g++ tins_parser.cpp -ltins
using namespace Tins;

bool callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>(); // Find the IP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>(); // Find the TCP layer
    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> " 
              << ip.dst_addr() << ':' << tcp.dport() << std::endl;
    return true;
}

int main() {
    Sniffer("eth0").sniff_loop(callback);
}

