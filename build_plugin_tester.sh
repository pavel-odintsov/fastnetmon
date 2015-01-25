#!/bin/bash

g++ netflow_plugin/netflow_collector.cpp -c -onetflow_collector.o
g++ plugin_runner.cpp  -llog4cpp netflow_collector.o -oplugin_tester

