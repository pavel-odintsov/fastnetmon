#!/usr/bin/perl

use strict;
use warnings;

#
# This script suiable for pps/bps measure for drop date in ipfw
#

my $prev_total_bytes = 0;
my $prev_total_packets = 0;

while (1) {
    my $current_total_bytes = 0;
    my $current_total_packets = 0;

    for my $cpu (0 ..7) {
        my @stats = `IPFW_PORT="555$cpu" /usr/src/netmap-ipfw/ipfw/ipfw list -a 2>&1`;
        chomp @stats;

        for my $line (@stats) {
            # 00100   768722348   35361228008 deny ip from any to any
            if ($line =~ /\d+\s+(\d+)\s+(\d+)\s+deny ip from any to any/) {
                my ($packets, $bytes) = ($1, $2);

                $current_total_packets += $packets;
                $current_total_bytes += $bytes;
            } else {
                next;
            }
        }

        my @stats_lines    
    }

    my $packets_for_current_second = $current_total_packets - $prev_total_packets;
    my $bytes_for_current_second = $current_total_bytes - $prev_total_bytes; 

    my $mpps = sprintf("%.1f", $packets_for_current_second / 10**6);
    my $gbps = sprintf("%.1f", $bytes_for_current_second  / 1024**3 * 8);

    # Do not print first calculation
    if ($prev_total_packets > 0 && $prev_total_bytes > 0) {
        print "Gbps: $gbps MPPS: $mpps\n"; 
    }

    $prev_total_packets = $current_total_packets;
    $prev_total_bytes   = $current_total_bytes;    

    sleep(1);
}

