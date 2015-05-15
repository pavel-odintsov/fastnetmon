#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

int ban_ip() {
    int exabgp_pipe = open("/var/run/exabgp.cmd", O_WRONLY);

    if (exabgp_pipe <= 0) {
        printf("Can't open exabgp PIPE");
        exit(1);
    }

    char bgp_message[256];
    char* ip_cidr_form = "10.10.10.123/32";
    char* next_hop = "10.0.3.114";
    char* exabgp_community = "65001:666";
    // withdraw
    char* action = "announce";

    sprintf(bgp_message, "%s route %s next-hop %s community %s\n", action, ip_cidr_form, next_hop, exabgp_community);
    int wrote_bytes = write(exabgp_pipe, bgp_message, strlen(bgp_message));

    printf("We wrote %d bytes\n", wrote_bytes);

    close(exabgp_pipe);
}

int unban_ip() {
    char bgp_message[256];
    char* ip_cidr_form = "10.10.10.123/32";

    int exabgp_pipe = open("/var/run/exabgp.cmd", O_WRONLY);

    if (exabgp_pipe <= 0) {
        printf("Can't open exabgp PIPE");
        exit(1);
    }

    char* action = "withdraw";
    sprintf(bgp_message, "%s route %s\n", action, ip_cidr_form);
    int wrote_bytes = write(exabgp_pipe, bgp_message, strlen(bgp_message));
    printf("We wrote %d bytes\n", wrote_bytes);
    close(exabgp_pipe);
}

int main() {
    unban_ip();
}
