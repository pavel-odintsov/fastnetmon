#!/bin/bash

gcc ipset.c  -I/opt/ipset/include/ -L/opt/ipset/lib -lipset
# gcc ipset.c -lipset
