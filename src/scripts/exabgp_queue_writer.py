#!/usr/bin/env python
 
import os
import sys
import time
from redis import Redis
from rq import Queue
import json
from StringIO import StringIO
import pprint

# apt-get install -y python-redis python-pip
# pip install rq

# Run worker:
# rqworker  --path /usr/src/fastnetmon/src/scripts
exabgp_log = open("/tmp/exabgp.log", "a")

import firewall_queue

q = Queue(connection=Redis())

while True:
    try:
        line = sys.stdin.readline().strip()
        # print >> sys.stderr, "GOT A LINE"

        sys.stdout.flush()
        if line == "":
            counter += 1
            if counter > 100:
                break
            continue
 
        counter = 0

# { "exabgp": "3.5.0", "time": 1431716393, "host" : "synproxied.fv.ee", "pid" : 2599, "ppid" : 2008, "counter": 1, "type": "update", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "direction": "receive", "message": { "update": { "attribute": { "origin": "igp", "as-path": [ 65001 ], "confederation-path": [], "extended-community": [ 9225060886715039744 ] }, "announce": { "ipv4 flow": { "no-nexthop": { "flow-0": { "destination-ipv4": [ "10.0.0.2/32" ], "source-ipv4": [ "10.0.0.1/32" ], "protocol": [ "=tcp" ], "destination-port": [ "=3128" ], "string": "flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128" } } } } } } } }
# { "exabgp": "3.5.0", "time": 1431716393, "host" : "synproxied.fv.ee", "pid" : 2599, "ppid" : 2008, "counter": 11, "type": "update", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "direction": "receive", "message": { "eor": { "afi" : 11.22.33.44

# u'destination-ipv4': [u'10.0.0.2/32'],
# u'destination-port': [u'=3128'],
# u'protocol': [u'=tcp'],
# u'source-ipv4': [u'10.0.0.1/32'],
# u'string': u'flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128'}

        io = StringIO(line)
        decoded_update = json.load(io) 

        pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)
        # pp.pprint(decoded_update)

        try:
            current_flow_announce = decoded_update["neighbor"]["message"]["update"]["announce"]["ipv4 flow"]

            for next_hop in current_flow_announce:
                flow_announce_with_certain_hop = current_flow_announce[next_hop]

                for flow in flow_announce_with_certain_hop: 
                    pp.pprint(flow_announce_with_certain_hop[flow])
                    q.enqueue(firewall_queue.execute_ip_ban, flow_announce_with_certain_hop[flow])
        except KeyError:
            pass

        exabgp_log.write(line + "\n")
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

