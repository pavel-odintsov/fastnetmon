#!/bin/bash

ENGINE=ULOG2
#ENGINE=PCAP

LIBS=""

if [ "PCAP" == $ENGINE ]; then
    LIBS="$LIBS -lpcap"
fi

# enabled by default
REDIS_SUPPORT="yes"

if [ "yes" == $REDIS_SUPPORT ]; then
    LIBS="$LIST -lhiredis"
fi


# TODO вынести в опции подключаемые либы

g++ libipulog.c -c -o libipulog.o -Wno-write-strings
g++ -DREDIS -D$ENGINE fastnetmon.cpp libipulog.o $LIBS -o fastnetmon
