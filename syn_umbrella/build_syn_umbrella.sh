#!/bin/bash

g++ syn_umbrella.cpp -I/opt/crafter/include -I/opt/pf_ring/include -lpthread -l/opt/pf_ring/lib/libpfring.so -lnuma -l/opt/crafter/lib/libcrafter.so -o synumbrella

# ./umbrella -i zc:eth4 -c 1 -o zc:eth4 -g 0 -v 
