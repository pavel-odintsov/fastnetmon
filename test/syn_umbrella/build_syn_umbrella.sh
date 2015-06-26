#!/usr/bin/env bash

g++ syn_umbrella.cpp -I/opt/crafter/include -I/opt/pf_ring/include -lpthread -L/opt/pf_ring/lib/ -lpfring -lnuma -L/opt/crafter/lib -lcrafter -o syn_umbrella
# ./umbrella -i zc:eth4 -c 1 -o zc:eth4 -g 0 -v
