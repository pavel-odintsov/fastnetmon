#!/bin/bash

g++ libipulog.c -c -o libipulog.o -Wno-write-strings
g++ fastnetmon.cpp libipulog.o -lpcap
