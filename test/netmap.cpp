#include <stdio.h>
#include <iostream>
#include <string>
#define NETMAP_WITH_LIBS

#include <net/netmap_user.h>
#include <boost/thread.hpp>

// For pooling operations
#include <poll.h>

#include "fastnetmon_packet_parser.h"

int number_of_packets = 0;

/* prototypes */
void netmap_thread(struct nm_desc* netmap_descriptor, int netmap_thread);
void consume_pkt(u_char* buffer, int len);

int receive_packets(struct netmap_ring* ring) {
    u_int cur, rx, n;

    cur = ring->cur;
    n = nm_ring_space(ring);

    for (rx = 0; rx < n; rx++) {
        struct netmap_slot* slot = &ring->slot[cur];
        char* p = NETMAP_BUF(ring, slot->buf_idx);

        // process data
        consume_pkt((u_char*)p, slot->len);

        cur = nm_ring_next(ring, cur);
    }

    ring->head = ring->cur = cur;
    return (rx);
}

void consume_pkt(u_char* buffer, int len) {
    // static char packet_data[2000];
    // printf("Got packet with length: %d\n", len);
    // memcpy(packet_data, buffer, len);
    struct pfring_pkthdr l2tp_header;
    memset(&l2tp_header, 0, sizeof(l2tp_header));
    l2tp_header.len = len;
    l2tp_header.caplen = len;

    fastnetmon_parse_pkt((u_char*)buffer, &l2tp_header, 4, 1, 0);

    // char print_buffer[512];
    // fastnetmon_print_parsed_pkt(print_buffer, 512, (u_char*)buffer, &l2tp_header);
    // printf("%s\n", print_buffer);


    __sync_fetch_and_add(&number_of_packets, 1);
}

void receiver(void) {
    struct nm_desc* netmap_descriptor;

    u_int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("We have %d cpus\n", num_cpus);

    struct nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));

    // Magic from pkt-gen.c
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    std::string interface = "netmap:eth4";
    netmap_descriptor = nm_open(interface.c_str(), &base_nmd, 0, NULL);

    if (netmap_descriptor == NULL) {
        printf("Can't open netmap device %s\n", interface.c_str());
        exit(1);
        return;
    }

    printf("Mapped %dKB memory at %p\n", netmap_descriptor->req.nr_memsize >> 10, netmap_descriptor->mem);
    printf("We have %d tx and %d rx rings\n", netmap_descriptor->req.nr_tx_rings,
           netmap_descriptor->req.nr_rx_rings);

    /*
        protocol stack and may cause a reset of the card,
        which in turn may take some time for the PHY to
        reconfigure. We do the open here to have time to reset.
    */

    int wait_link = 2;
    printf("Wait %d seconds for NIC reset\n", wait_link);
    sleep(wait_link);

    boost::thread* boost_threads_array[num_cpus];
    for (int i = 0; i < num_cpus; i++) {
        struct nm_desc nmd = *netmap_descriptor;
        // This operation is VERY important!
        nmd.self = &nmd;

        uint64_t nmd_flags = 0;

        if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
            printf("SHIT SHIT SHIT HAPPINED\n");
        }

        nmd.req.nr_flags = NR_REG_ONE_NIC;
        nmd.req.nr_ringid = i;

        /* Only touch one of the rings (rx is already ok) */
        nmd_flags |= NETMAP_NO_TX_POLL;

        struct nm_desc* new_nmd =
        nm_open(interface.c_str(), NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

        if (new_nmd == NULL) {
            printf("Can't open netmap descripto for netmap\n");
            exit(1);
        }

        printf("My first ring is %d and last ring id is %d I'm thread %d\n", new_nmd->first_rx_ring,
               new_nmd->last_rx_ring, i);

        printf("Start new thread %d\n", i);
        // Start thread and pass netmap descriptor to it
        boost_threads_array[i] = new boost::thread(netmap_thread, new_nmd, i);
    }

    printf("Wait for thread finish\n");
    // Wait all threads for completion
    for (int i = 0; i < num_cpus; i++) {
        boost_threads_array[i]->join();
    }
}

void netmap_thread(struct nm_desc* netmap_descriptor, int thread_number) {
    struct nm_pkthdr h;
    u_char* buf;
    struct pollfd fds;
    fds.fd = netmap_descriptor->fd; // NETMAP_FD(netmap_descriptor);
    fds.events = POLLIN;

    struct netmap_ring* rxring = NULL;
    struct netmap_if* nifp = netmap_descriptor->nifp;

    printf("Reading from fd %d thread id: %d\n", netmap_descriptor->fd, thread_number);

    for (;;) {
        // We will wait 1000 microseconds for retry, for infinite timeout please use -1
        int poll_result = poll(&fds, 1, 1000);

        if (poll_result == 0) {
            // printf("poll return 0 return code\n");
            continue;
        }

        if (poll_result == -1) {
            printf("poll failed with return code -1\n");
        }

        for (int i = netmap_descriptor->first_rx_ring; i <= netmap_descriptor->last_rx_ring; i++) {
            // printf("Check ring %d from thread %d\n", i, thread_number);
            rxring = NETMAP_RXRING(nifp, i);

            if (nm_ring_empty(rxring)) {
                continue;
            }

            int m = receive_packets(rxring);
        }

        // while ( (buf = nm_nextpkt(netmap_descriptor, &h)) ) {
        //    consume_pkt(buf, h.len);
        //}
    }

    // nm_close(netmap_descriptor);
}

int main() {
    // receiver();
    boost::thread netmap_thread(receiver);

    for (;;) {
        sleep(1);
        printf("We received %d packets in 1 second\n", number_of_packets);
        number_of_packets = 0;
    }

    netmap_thread.join();
}
