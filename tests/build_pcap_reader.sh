#!/bin/bash

clang++ ../netflow_plugin/netflow_collector.cpp -c -onetflow_collector.o
clang ../fastnetmon_packet_parser.cpp -c -ofastnetmon_packet_parser.o
clang++ pcap_reader.cpp fastnetmon_packet_parser.o netflow_collector.o -o pcap_reader -llog4cpp

rm -f fastnetmon_packet_parser.o
