#include <stdio.h>
#include <iostream>
#include <string>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

// For pooling operations
#include <poll.h>

// Compilation on FreeBSD 10: clang++ netmap.cpp

void consume_pkt(u_char* buffer, int len) {
    printf("Got packet with length: %d", len);
}

void receiver(void) {
    struct  nm_desc *netmap_descriptor;
    struct  pollfd fds;
    struct  nm_pkthdr h;
    u_char* buf;

    std::string interface = "netmap:em0"; 
    netmap_descriptor = nm_open(interface.c_str(), NULL, 0, 0);

    if (netmap_descriptor == NULL) {
        printf("Can't open netmap device %s", interface.c_str());
        return;
    }


    fds.fd  = NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    for (;;) {
        poll(&fds,  1, -1);
        
        while ( (buf = nm_nextpkt(netmap_descriptor, &h)) )
            consume_pkt(buf, h.len);
        }

     nm_close(netmap_descriptor);
}

int main() {
    printf("Hello\n");
    receiver();
}

