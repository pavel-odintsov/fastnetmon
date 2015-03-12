#!/bin/bash
gcc picohttpparser.c -c -o picohttpparser.o
g++ ../fastnetmon_packet_parser.cpp -c -o fastnetmon_packet_parser.o -Wno-write-strings
g++ shield.cpp picohttpparser.o fastnetmon_packet_parser.o -lpcap -opicohttpparser -oshield
