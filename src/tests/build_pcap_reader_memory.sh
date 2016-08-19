#!/bin/sh

g++ pcap_reader_memory.cpp ../fastnetmon_packet_parser.c ../fast_dpi.cpp -I/usr/include/libndpi-1.7.0/ -L/usr/lib64/ -lndpi -g -o pcap_reader_memory