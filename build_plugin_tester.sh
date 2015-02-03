#!/bin/bash

g++ netflow_plugin/netflow_collector.cpp -c -onetflow_collector.o
g++ sflow_plugin/sflow_collector.cpp -c -osflow_collector.o
g++ pcap_plugin/pcap_collector.cpp -c  -opcap_collector.o
g++ pfring_plugin/pfring_collector.cpp -c  -opfring_collector.o -I/opt/pf_ring/include -lpfring
g++ plugin_runner.cpp -lpcap -llog4cpp netflow_collector.o sflow_collector.o pcap_collector.o pfring_collector.o -oplugin_tester
rm -f netflow_collector.o sflow_collector.o pcap_collector.o

