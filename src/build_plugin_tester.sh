#!/usr/bin/env bash

g++ ipfix_rfc.cpp -c -oipfix_rfc.o
g++ fast_library.cpp -c -ofast_library.o
g++ fastnetmon_packet_parser.c -c -o fastnetmon_packet_parser.o

g++ netflow_plugin/netflow_collector.cpp -c -onetflow_collector.o
g++ sflow_plugin/sflow_collector.cpp -c -osflow_collector.o
g++ pcap_plugin/pcap_collector.cpp -c  -opcap_collector.o
g++ pfring_plugin/pfring_collector.cpp -c -opfring_collector.o -I/opt/pf_ring/include 
g++ netmap_plugin/netmap_collector.cpp -c -onetmap_collector.o -Inetmap_plugin/netmap_includes

g++ plugin_runner.cpp -lnuma -lpcap -llog4cpp ipfix_rfc.o fast_library.o netflow_collector.o sflow_collector.o pcap_collector.o fastnetmon_packet_parser.o netmap_collector.o pfring_collector.o -oplugin_tester -I/opt/pf_ring/include -lpfring -lpthread -L/opt/pf_ring/lib -lboost_regex -lboost_system -lboost_thread
rm -f netflow_collector.o ipfix_rfc.o sflow_collector.o pcap_collector.o netmap_collector.o fastnetmon_packet_parser.o


