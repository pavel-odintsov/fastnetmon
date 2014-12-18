#!/bin/bash

COMPILER=clang
CPP_COMPILER=clang++

gcc -O3 ../libpatricia/patricia.c -c -o patricia.o 
g++ -O3 lpm_performance_tests.cpp patricia.o -olpm_performance_tests -lrt

#$COMPILER -O4 ../libpatricia/patricia.c -c -o patricia.o
#ar q patricia.a patricia.o
#$CPP_COMPILER lpm_performance_tests.cpp -olpm_performance_tests.o -c 
#$CPP_COMPILER -v -O4 lpm_performance_tests.o patricia.a -olpm_performance_tests -lrt 

