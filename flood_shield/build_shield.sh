#!/bin/bash

gcc picohttpparser.c -c -o picohttpparser.o
g++ shield.cpp picohttpparser.o -opicohttpparser -oshield -I/opt/pf_ring/include -L/opt/pf_ring/lib -lpfring

