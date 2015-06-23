#!/usr/bin/env python

import shelve
database = shelve.open("/var/lib/bgp_network_collector.db")
for key in sorted(database):
    print key
