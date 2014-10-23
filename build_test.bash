#!/bin/bash
g++ performance_tests.cpp -lrt -lpthread -lboost_thread -ltbb  -std=c++11
