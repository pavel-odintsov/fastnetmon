#!/bin/bash

ENGINE=ULOG2
ENGINE=PCAP

g++ libipulog.c -c -o libipulog.o -Wno-write-strings
g++ -D$ENGINE fastnetmon.cpp libipulog.o -lpcap -o fastnetmon
