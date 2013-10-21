#!/bin/bash

ENGINE=ULOG2
#ENGINE=PCAP

# we use C++ 11 threads. We must include pthread library due gcc bug
LIBS="-l pthread"

if [ "PCAP" == $ENGINE ]; then
    LIBS="$LIBS -lpcap"
fi

# enabled by default
REDIS_SUPPORT="yes"

if [ "yes" == $REDIS_SUPPORT ]; then
    LIBS="$LIBS -lhiredis"
fi


# TODO вынести в опции подключаемые либы

g++ libipulog.c -c -o libipulog.o -Wno-write-strings
# -std=c++11 
g++ -DREDIS -D$ENGINE fastnetmon.cpp libipulog.o $LIBS -o fastnetmon  -std=c++11 -lpthread
