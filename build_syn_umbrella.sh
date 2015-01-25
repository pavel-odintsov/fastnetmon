#!/bin/bash

g++ syn_umbrella.cpp -I/opt/crafter/include -I/opt/pf_ring/include -lpthread -l/opt/pf_ring/lib/libpfring.so -lnuma -l/opt/crafter/lib/libcrafter.so -o umbrella 
