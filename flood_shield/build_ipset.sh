#!/bin/bash

g++ ipset.cpp  -I/opt/ipset/include/ -L/opt/ipset/lib -lipset
