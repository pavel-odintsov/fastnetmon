#!/bin/bash

g++ performance_tests.cpp -lrt -lpthread -lboost_thread  -std=c++11 -ltbb
