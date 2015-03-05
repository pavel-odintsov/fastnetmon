#!/bin/bash

g++ netmap.cpp -I/usr/src/fastnetmon/tests/netmap_includes -I/opt/pf_ring/include/ -L/opt/pf_ring/lib -lpfring -lboost_thread -lboost_system

