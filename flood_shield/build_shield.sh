#!/bin/bash

g++ ipset_management.cpp -lipset -c -o ipset_management.o -I/opt/ipset/include -L/opt/ipset/lib
gcc picohttpparser.c -c -o picohttpparser.o
g++ shield.cpp picohttpparser.o ipset_management.o -opicohttpparser -oshield -I/opt/pf_ring/include -L/opt/pf_ring/lib -lpfring -lnuma -lpcap -lipset -L/opt/ipset/lib
