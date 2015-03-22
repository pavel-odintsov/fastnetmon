#!/usr/bin/env bash

clang++ ../ipfix_rfc.cpp -c -oipfix_rfc.o
clang++ ../fast_library.cpp -c -ofast_library.o
clang++ ../netflow_plugin/netflow_collector.cpp -c -onetflow_collector.o -I/opt/local/include
clang ../fastnetmon_packet_parser.c -c -ofastnetmon_packet_parser.o
clang++ pcap_reader.cpp fastnetmon_packet_parser.o ipfix_rfc.o fast_library.o netflow_collector.o -I/opt/local/include -L/opt/local/lib -o pcap_reader -llog4cpp -lboost_system -lboost_regex

rm -f fastnetmon_packet_parser.o
