#!/usr/bin/env bash

clang++ fastnetmon_packet_parser.cpp -c -ofastnetmon_packet_parser.o
clang++ netmap.cpp -I/usr/local/include -L/usr/local/lib -I/usr/src/fastnetmon/src/plugins/netmap/netmap_includes -lboost_thread -lboost_system fastnetmon_packet_parser.o

