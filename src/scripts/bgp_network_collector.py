#!/usr/bin/env python
 
import os
import sys
import time
import json
from StringIO import StringIO
import pprint
import shelve
import shelve

#
# Add withdrawal option
#

database = shelve.open("/var/lib/bgp_network_collector.db")

while True:
    try:
        line = sys.stdin.readline().strip()
        # print >> sys.stderr, "GOT A LINE: ", line
        sys.stdout.flush()

        io = StringIO(line) 
        decoded_update = json.load(io) 
 
        pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)
        #pp.pprint(decoded_update)

        try: 
            current_announce = decoded_update["neighbor"]["message"]["update"]["announce"]["ipv4 unicast"]
            #pp.pprint(current_announce)

            for next_hop in current_announce:
                current_announce_for_certain_next_hop = current_announce[next_hop]
           
                for prefix_announce in current_announce_for_certain_next_hop:
                    #pp.pprint(current_announce_for_certain_next_hop[prefix_announce])
                    pp.pprint(prefix_announce)

                    # drop default gateway
                    if prefix_announce == "0.0.0.0/0":
                        continue

                    if type(prefix_announce) != str:
                        prefix_announce = prefix_announce.encode('utf8')

                    if not database.has_key(prefix_announce):
                        #print >> sys.stderr, "New data"
                        database[prefix_announce] = 1;
                    else:
                        pass 
                        #print >> sys.stderr, "I already have this subnet"

            # call sync for each data portion
            database.sync()
        except KeyError:
            pass
    except KeyboardInterrupt:
        database.close()
        sys.exit(0)
    except IOError:
        # most likely a signal during readline
        database.close()
        sys.exit(0)

