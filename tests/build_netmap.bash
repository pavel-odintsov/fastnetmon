#!/bin/bash

clang++ pf_ring_packet_parser.cpp -c -opf_ring_packet_parser.o
g++ netmap.cpp -I/usr/src/fastnetmon/tests/netmap_includes -lboost_thread -lboost_system pf_ring_packet_parser.o

