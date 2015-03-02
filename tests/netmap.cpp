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
    g++ netmap.cpp -I/usr/src/fastnetmon/tests/netmap_includes -lboost_thread -lboost_system
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

    std::string interface = "netmap:eth4"; 
    netmap_descriptor = nm_open(interface.c_str(), NULL, 0, 0);

    if (netmap_descriptor == NULL) {
        printf("Can't open netmap device %s\n", interface.c_str());
        exit(1);
        return;
    }

    fds.fd     = NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    for (;;) {
        // We will wait 1000 microseconds for retry, for infinite timeout please use -1
        int poll_result = poll(&fds, 1, 1000);
       
        if (poll_result == 0) {
            printf("poll return 0 return code\n");
            continue;
        }

        if (poll_result == -1) {
            printf("poll failed with return code -1\n");
        }
 
        while ( (buf = nm_nextpkt(netmap_descriptor, &h)) ) {
            consume_pkt(buf, h.len);
        }
    }

     nm_close(netmap_descriptor);
}

int main() {
    //receiver();

    boost::thread netmap_thread(receiver);

    for (;;) {
        sleep(1);
        printf("We received %d packets in 1 second\n", number_of_packets);
	number_of_packets = 0;
    }
  
    netmap_thread.join();
}
