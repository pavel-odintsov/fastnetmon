#include <stdio.h>
#include <iostream>
#include <string>
#define NETMAP_WITH_LIBS

#include <net/netmap_user.h>

#include <boost/thread.hpp>

// For pooling operations
#include <poll.h>

/*
    How to compile

    FreeBSD:
    clang++ netmap.cpp -I /usr/local/include -L/usr/local/lib -lboost_thread -lboost_system

    Linux:
    g++ netmap.cpp -I/usr/src/fastnetmon/tests/netmap_includes
*/

int number_of_packets = 0;

void consume_pkt(u_char* buffer, int len) {
    //printf("Got packet with length: %d\n", len);
    __sync_fetch_and_add(&number_of_packets, 1);
}

void receiver(void) {
    struct  nm_desc	*netmap_descriptor;
    struct  pollfd fds;
    struct  nm_pkthdr h;
    u_char* buf;

    std::string interface = "netmap:em0"; 
    netmap_descriptor = nm_open(interface.c_str(), NULL, 0, 0);

    if (netmap_descriptor == NULL) {
        printf("Can't open netmap device %s", interface.c_str());
        return;
    }


    fds.fd     = NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    for (;;) {
        poll(&fds,	1, -1);
        
        while ( (buf = nm_nextpkt(netmap_descriptor, &h)) )
            consume_pkt(buf, h.len);
        }

     nm_close(netmap_descriptor);
}

int main() {
    boost::thread netmap_thread(receiver);

    for (;;) {
        sleep(1);
        printf("We received %d packets in 1 second\n", number_of_packets);
	number_of_packets = 0;
    }
  
    netmap_thread.join();
}
