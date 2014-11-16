#!/bin/bash
g++ performance_tests.cpp -lrt -lpthread -lboost_thread -ltbb  -std=c++11

g++ lpm_performance_tests.cpp libpatricia/patricia.o -olpm_performance_tests -lrt
