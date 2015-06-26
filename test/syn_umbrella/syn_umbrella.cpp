#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <numa.h>

#include "pfring.h"
#include "pfring_zc.h"

#include <string>
#include <crafter.h>

// ./syn_umbrella -i zc:eth4 -c 1 -o zc:eth4 -g 0 -c 0 -v
// Installing crafter: http://www.stableit.ru/2014/12/c-crafter.html

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768


static struct timeval startTime;
u_int8_t bidirectional = 0, wait_for_packet = 1, flush_packet = 0, do_shutdown = 0, verbose = 0;

pfring_zc_cluster *zc;

struct dir_info {
    u_int64_t __padding 
    __attribute__((__aligned__(64)));

    pfring_zc_queue *inzq, *outzq;
    pfring_zc_pkt_buff *tmpbuff;

    u_int64_t numPkts;
    u_int64_t numBytes;
  
    int bind_core;
    pthread_t thread
    __attribute__((__aligned__(64)));
};

struct dir_info dir[2];

int bind2core(int core_id) {
    cpu_set_t cpuset;
    int s;

    if (core_id < 0)
        return -1; 

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
        fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s); 
        return -1; 
    } else {
        return 0;
    }
}

int max_packet_len(const char *device) { 
    int max_len = 0;

    pfring* ring = pfring_open(device, 1536, PF_RING_PROMISC);

    if (ring == NULL)
        return 1536;

// pfring_get_card_settings have added in 6.0.3
#if RING_VERSION_NUM >= 0x060003
    pfring_card_settings settings;
    pfring_get_card_settings(ring, &settings);
    max_len = settings.max_packet_size;
#else
    if (ring->dna.dna_mapped_device) {
        max_len = ring->dna.dna_dev.mem_info.rx.packet_memory_slot_len;
    } else {
        max_len = pfring_get_mtu_size(ring);
        if (max_len == 0) max_len = 9000 /* Jumbo */;
            max_len += 14 /* Eth */ + 4 /* VLAN */;
    }
#endif

    pfring_close(ring);

    return max_len;
}

double delta_time (struct timeval * now, struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }

  return ((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

void print_stats() {
    struct timeval endTime;
    double deltaMillisec;
    static u_int8_t print_all;
    static u_int64_t lastPkts = 0;
    static u_int64_t lastBytes = 0;
    double diff, bytesDiff;
    static struct timeval lastTime;
    char buf1[64], buf2[64], buf3[64];
    unsigned long long nBytes = 0, nPkts = 0;
    int i;

    if (startTime.tv_sec == 0) {
        gettimeofday(&startTime, NULL);
        print_all = 0;
    } else
        print_all = 1;

    gettimeofday(&endTime, NULL);
    deltaMillisec = delta_time(&endTime, &startTime);

    for (i = 0; i < 1 + bidirectional; i++) {
        nBytes = dir[i].numBytes;
        nPkts = dir[i].numPkts;
    }

    fprintf(stderr, "=========================\n"
        "Absolute Stats: %s pkts - %s bytes\n", 
	pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

    if (print_all && (lastTime.tv_sec > 0)) {
        char buf[256];

        deltaMillisec = delta_time(&endTime, &lastTime);
        diff = nPkts-lastPkts;
        bytesDiff = nBytes - lastBytes;
        bytesDiff /= (1000*1000*1000)/8;

        snprintf(buf, sizeof(buf),
	    "Actual Stats: %s pps - %s Gbps",
	    pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	    pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
            
        fprintf(stderr, "%s\n", buf);
    }
    
    fprintf(stderr, "=========================\n\n");

    lastPkts = nPkts, lastBytes = nBytes;

    lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

void sigproc(int sig) {
    static int called = 0;
    fprintf(stderr, "Leaving...\n");
    if (called) return; else called = 1;

    do_shutdown = 1;

    print_stats();
  
    pfring_zc_queue_breakloop(dir[0].inzq);
    if (bidirectional) pfring_zc_queue_breakloop(dir[1].inzq);
}

void printHelp(void) {
    printf("zbounce - (C) 2014 ntop.org\n");
    printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
    printf("A packet forwarder application between interfaces.\n\n");
    printf("-h              Print this help\n");
    printf("-i <device>     Ingress device name\n");
    printf("-o <device>     Egress device name\n");
    printf("-c <cluster id> cluster id\n");
    printf("-b              Bridge mode (forward in both directions)\n");
    printf("-g <core id>    Bind this app to a core (with -b use <core id>:<core id>)\n");
    printf("-a              Active packet wait\n");
    printf("-f              Flush packets immediately\n");
    printf("-v              Verbose\n");
    exit(-1);
}

void *packet_consumer_thread(void *_i) {
    struct dir_info *i = (struct dir_info *) _i;
    int tx_queue_not_empty = 0;

    static bool is_syn_received = false;
    static bool is_first_ack_received = false;

    if (i->bind_core >= 0)
        bind2core(i->bind_core);

    while(!do_shutdown) {
        if (pfring_zc_recv_pkt(i->inzq, &i->tmpbuff, 0 /* wait_for_packet */) > 0) {

            if (unlikely(verbose)) {
                u_char* packet_pointer = pfring_zc_pkt_buff_data(i->tmpbuff, i->inzq);

                char bigbuf[4096];
                pfring_print_pkt(bigbuf, sizeof(bigbuf), packet_pointer, i->tmpbuff->len, i->tmpbuff->len);
                fputs(bigbuf, stdout);
            }

            u_char* packet_pointer = pfring_zc_pkt_buff_data(i->tmpbuff, i->inzq);

            Crafter::Packet recv_packet;
            recv_packet.PacketFromEthernet(packet_pointer, i->tmpbuff->len);
            
            //printf("Received\n\n");
            //recv_packet.Print();

            Crafter::Ethernet* recv_eth = recv_packet.GetLayer<Crafter::Ethernet>();
    
            if (recv_eth->GetType()  == 0x0806) {
                Crafter::ARP* recv_arp = recv_packet.GetLayer<Crafter::ARP>();

                //printf("We got ARP request\n");
                std::string filter_local_ip = "10.10.10.200";
                std::string filter_local_mac = "90:e2:ba:4a:d8:dc";                    

                // It's request
                // ARP, Request who-has 10.10.10.200 tell 10.10.10.100, length 46
                if (recv_arp->GetOperation() == 1 && recv_arp->GetTargetIP() == filter_local_ip) {
                    printf("We got request about us\n");    

                    // ARP, Reply 10.10.10.200 is-at 90:e2:ba:4a:d8:dc (oui Unknown), length 28
                    Crafter::Ethernet ether_header;
                    ether_header.SetSourceMAC(filter_local_mac);
                    ether_header.SetDestinationMAC(recv_arp->GetSenderMAC());

    
                    Crafter::ARP arp_header;
                    arp_header.SetOperation(Crafter::ARP::Reply);
                    arp_header.SetSenderIP(filter_local_ip);
                    arp_header.SetSenderMAC(filter_local_mac);

                    // Yes, we should put this data in packet twice: for ethernet and for ARP
                    arp_header.SetTargetIP(recv_arp->GetSenderIP());
                    arp_header.SetTargetMAC(recv_arp->GetSenderMAC());

                    Crafter::Packet arp_answer_packet;
                    arp_answer_packet.PushLayer(ether_header);
                    arp_answer_packet.PushLayer(arp_header);

                    const unsigned char* responce_data_perpared_for_send = arp_answer_packet.GetRawPtr();
                    memcpy( pfring_zc_pkt_buff_data(i->tmpbuff, i->inzq), responce_data_perpared_for_send, arp_answer_packet.GetSize());

                    while (unlikely(pfring_zc_send_pkt(i->outzq, &i->tmpbuff, flush_packet) < 0)) {
                        if (wait_for_packet)
                            usleep(1);
                    }

                    tx_queue_not_empty = 1;
            
                    continue;
                }
            }

            // Process only IP
            if (recv_eth->GetType() != 0x0800) {
                continue;
            }

            Crafter::IP* recv_ip = recv_packet.GetLayer<Crafter::IP>();
            // We process only TCP
            if (recv_ip->GetProtocol() != 6) {
                continue;
            }

            Crafter::TCP*                recv_tcp           = recv_packet.GetLayer<Crafter::TCP>();
            Crafter::TCPOptionTimestamp* recv_timestamp_opt = recv_packet.GetLayer<Crafter::TCPOptionTimestamp>();  
 
            Crafter::Ethernet reponse_eth_header;
            reponse_eth_header.SetDestinationMAC(recv_eth->GetSourceMAC());
            reponse_eth_header.SetSourceMAC(recv_eth->GetDestinationMAC());
            reponse_eth_header.SetType(recv_eth->GetType());
 
            Crafter::IP response_ip_header;
            response_ip_header.SetSourceIP(      recv_ip->GetDestinationIP()  );
            response_ip_header.SetDestinationIP( recv_ip->GetSourceIP()       );

            // We tune TTL like OpenVZ 2.6.32 kernel
            response_ip_header.SetTTL(64);

            if (recv_tcp->GetSYN() && !is_syn_received) {
                printf("Got initial syn packet from client\n");
                Crafter::TCP tcp_header;
           
                tcp_header.SetAckNumber( recv_tcp->GetSeqNumber() + 1 ); 
                tcp_header.SetSeqNumber( Crafter::RNG32() );
    
                tcp_header.SetSrcPort( recv_tcp->GetDstPort() );
                tcp_header.SetDstPort( recv_tcp->GetSrcPort() );
                tcp_header.SetFlags(Crafter::TCP::SYN | Crafter::TCP::ACK);

                /* Max segment size option */
                Crafter::TCPOptionMaxSegSize maxseg;
                maxseg.SetMaxSegSize(1460);

                Crafter::TCPOptionWindowScale wscale;
                wscale.SetShift(7);

                /* Time stamp option */
                Crafter::TCPOptionTimestamp tstamp;
                tstamp.SetValue(398303815); 

                /* a 4-byte echo reply timestamp value (the most recent timestamp received from you) */
                /* I should put there latest timestamp received from client */
                tstamp.SetEchoReply(recv_timestamp_opt->GetValue());

                /* We got 14480 from RHEL 6 OpenVZ kernel */
                tcp_header.SetWindowsSize(14480);
                Crafter::RawLayer payload("");

                Crafter::Packet reponse_packet = reponse_eth_header / response_ip_header /
                    tcp_header /
                        /* START Option (padding should be controlled by the user) */
                        maxseg                              / // 4 bytes
                        Crafter::TCPOptionSACKPermitted()   / // 2 bytes
                        tstamp                              / // 10 bytes
                        Crafter::TCPOption::NOP             / // 1 byte
                        wscale                              / // 3 byte                   
                        // Crafter::TCPOption::EOL          / // 1 bytes
                    payload;

                //printf("To Send\n\n");
                //reponse_packet.Print();

                //pfring_zc_pkt_buff *response_pkt_handle = pfring_zc_get_packet_handle(zc);
                const unsigned char* responce_data_perpared_for_send = reponse_packet.GetRawPtr();
                memcpy( pfring_zc_pkt_buff_data(i->tmpbuff, i->inzq), responce_data_perpared_for_send, reponse_packet.GetSize());

                is_syn_received = true;

                while (unlikely(pfring_zc_send_pkt(i->outzq, &i->tmpbuff, flush_packet) < 0 && !do_shutdown))
                    if (wait_for_packet)
                        usleep(1);

                    tx_queue_not_empty = 1;

            } else if (recv_tcp->GetACK()) {
                if (is_syn_received && !is_first_ack_received) {
                    printf ("We received ACK from client for TCP handshake\n");
                    is_first_ack_received = true;
                }
            }

            i->numPkts++;
            i->numBytes += i->tmpbuff->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
        } else {
            if (tx_queue_not_empty) {
                pfring_zc_sync_queue(i->outzq, tx_only);
                tx_queue_not_empty = 0;
            }   

            if (wait_for_packet) 
                usleep(1);
        }
    }

    if (!flush_packet) pfring_zc_sync_queue(i->outzq, tx_only);
    pfring_zc_sync_queue(i->inzq, rx_only);

    return NULL;
}

int init_direction(int direction, char *in_dev, char *out_dev) {
    dir[direction].tmpbuff = pfring_zc_get_packet_handle(zc);

    if (dir[direction].tmpbuff == NULL) {
        fprintf(stderr, "pfring_zc_get_packet_handle error\n");
        return -1;
    }

    dir[direction].inzq = pfring_zc_open_device(zc, in_dev, rx_only, 0);

    if (dir[direction].inzq == NULL) {
        fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
     	strerror(errno), in_dev);
            
        return -1;
    }

    dir[direction].outzq = pfring_zc_open_device(zc, out_dev, tx_only, 0);

    if (dir[direction].outzq == NULL) {
        fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	    strerror(errno), out_dev);
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    /* Init the library */
    Crafter::InitCrafter();

    char *device1 = NULL, *device2 = NULL, *bind_mask = NULL, c;
    int cluster_id = -1;
    u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

    dir[0].bind_core = dir[1].bind_core = -1;

    startTime.tv_sec = 0;

    while((c = getopt(argc,argv,"abc:g:hi:o:fv")) != '?') {
        if((c == 255) || (c == -1)) break;

        switch(c) {
        case 'h':
            printHelp();
            break;
        case 'a':
            wait_for_packet = 0;
            break;
        case 'f':
            flush_packet = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'b':
            bidirectional = 1;
            break;
        case 'c':
            cluster_id = atoi(optarg);
            break;
        case 'i':
            device1 = strdup(optarg);
            break;
        case 'o':
            device2 = strdup(optarg);
            break;
        case 'g':
            bind_mask = strdup(optarg);
        break;
        }
  }
  
    if (device1 == NULL) printHelp();
    if (device2 == NULL) printHelp();
    if (cluster_id < 0)  printHelp();

    if (bind_mask != NULL) {
        char *id;
    
        if ((id = strtok(bind_mask, ":")) != NULL)
            dir[0].bind_core = atoi(id) % numCPU;
    
        if ((id = strtok(NULL, ":")) != NULL)
            dir[1].bind_core = atoi(id) % numCPU;
    }

    zc = pfring_zc_create_cluster(
        cluster_id, 
        max_packet_len(device1), 
        0, 
        (2 * MAX_CARD_SLOTS) + 1 + bidirectional,
        numa_node_of_cpu(dir[0].bind_core), 
        NULL /* auto hugetlb mountpoint */ 
    );

    if (zc == NULL) {
        fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
        return -1;
    }

    if (init_direction(0, device1, device2) < 0) 
        return -1;

    if (bidirectional)
        if (init_direction(1, device2, device1) < 0) 
            return -1;

    signal(SIGINT,  sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGINT,  sigproc);

    pthread_create(&dir[0].thread, NULL, packet_consumer_thread, (void *) &dir[0]);
    if (bidirectional) pthread_create(&dir[1].thread, NULL, packet_consumer_thread, (void *) &dir[1]);

    if (!verbose) while (!do_shutdown) {
        sleep(ALARM_SLEEP);
        print_stats();
    }

    pthread_join(dir[0].thread, NULL);
    if (bidirectional) pthread_join(dir[1].thread, NULL);

    sleep(1);

    pfring_zc_destroy_cluster(zc);

    return 0;
}

