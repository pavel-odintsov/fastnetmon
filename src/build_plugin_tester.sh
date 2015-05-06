#!/usr/bin/env bash

g++ ipfix_rfc.cpp -c -oipfix_rfc.o
g++ fast_library.cpp -c -ofast_library.o
g++ netflow_plugin/netflow_collector.cpp -c -onetflow_collector.o
g++ sflow_plugin/sflow_collector.cpp -c -osflow_collector.o
g++ pcap_plugin/pcap_collector.cpp -c  -opcap_collector.o
g++ pfring_plugin/pfring_collector.cpp -c  -opfring_collector.o -I/opt/pf_ring/include 

g++ plugin_runner.cpp -lnuma -lpcap -llog4cpp ipfix_rfc.o fast_library.o netflow_collector.o sflow_collector.o pcap_collector.o pfring_collector.o -oplugin_tester -I/opt/pf_ring/include -lpfring -lpthread -L/opt/pf_ring/lib -lboost_regex -lboost_system
rm -f netflow_collector.o ipfix_rfc.o sflow_collector.o pcap_collector.o

