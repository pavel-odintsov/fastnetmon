#!/bin/bash

# apt-get install -y libhiredis-dev redis-server

g++ -O3  ../../fastnetmon_packet_parser.c  -c -o fastnetmon_packet_parser.o -fPIC
g++ -O3 ../../fastnetmon_pcap_format.cpp -c -o  fastnetmon_pcap_format.o -fPIC 
g++ -O3  ../../fast_dpi.cpp -c -o  fast_dpi.o `PKG_CONFIG_PATH=/opt/ndpi/lib/pkgconfig pkg-config  pkg-config --cflags --libs libndpi` -fPIC
g++ -O3  -shared -o ndpicallback.so -fPIC ndpicallback.cpp fastnetmon_pcap_format.o fast_dpi.o fastnetmon_packet_parser.o `PKG_CONFIG_PATH=/opt/ndpi/lib/pkgconfig pkg-config  pkg-config --cflags --libs libndpi` -std=c++11 -fPIC -lhiredis
