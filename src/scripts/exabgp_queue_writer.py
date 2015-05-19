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
        counter = 0

# { "exabgp": "3.5.0", "time": 1431716393, "host" : "synproxied.fv.ee", "pid" : 2599, "ppid" : 2008, "counter": 1, "type": "update", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "direction": "receive", "message": { "update": { "attribute": { "origin": "igp", "as-path": [ 65001 ], "confederation-path": [], "extended-community": [ 9225060886715039744 ] }, "announce": { "ipv4 flow": { "no-nexthop": { "flow-0": { "destination-ipv4": [ "10.0.0.2/32" ], "source-ipv4": [ "10.0.0.1/32" ], "protocol": [ "=tcp" ], "destination-port": [ "=3128" ], "string": "flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128" } } } } } } } }
# { "exabgp": "3.5.0", "time": 1431716393, "host" : "synproxied.fv.ee", "pid" : 2599, "ppid" : 2008, "counter": 11, "type": "update", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "direction": "receive", "message": { "eor": { "afi" : 11.22.33.44

# u'destination-ipv4': [u'10.0.0.2/32'],
# u'destination-port': [u'=3128'],
# u'protocol': [u'=tcp'],
# u'source-ipv4': [u'10.0.0.1/32'],
# u'string': u'flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128'}

# Peer shutdown notification: 
# { "exabgp": "3.5.0", "time": 1431900440, "host" : "filter.fv.ee", "pid" : 8637, "ppid" : 8435, "counter": 21, "type": "state", "neighbor": { "address": { "local": "10.0.3.115", "peer": "10.0.3.114" }, "asn": { "local": "1234", "peer": "65001" }, "state": "down", "reason": "in loop, peer reset, message [closing connection] error[the TCP connection was closed by the remote end]" } }

        # Fix bug: https://github.com/Exa-Networks/exabgp/issues/269
        line = line.replace('0x800900000000000A', '"0x800900000000000A"')
        io = StringIO(line)
        print >> sys.stderr, line
        decoded_update = json.load(io) 

        pp = pprint.PrettyPrinter(indent=4, stream=sys.stderr)
        pp.pprint(decoded_update)

        try:
            current_flow_announce = decoded_update["neighbor"]["message"]["update"]["announce"]["ipv4 flow"]
            peer_ip = decoded_update['neighbor']['address']['peer']

            for next_hop in current_flow_announce:
                flow_announce_with_certain_hop = current_flow_announce[next_hop]

                for flow in flow_announce_with_certain_hop: 
                    pp.pprint(flow_announce_with_certain_hop[flow])
                    q.enqueue(firewall_queue.manage_flow, 'announce', peer_ip, flow_announce_with_certain_hop[flow])
        except KeyError:
            pass
    
        # We got notification about neighbor status
        if 'type' in decoded_update and decoded_update['type'] == 'state': 
            if 'state' in decoded_update['neighbor'] and decoded_update['neighbor']['state'] == 'down':
                peer_ip = decoded_update['neighbor']['address']['peer']
                print >> sys.stderr, "We received notification about peer down for: " + peer_ip 

                q.enqueue(firewall_queue.manage_flow, 'withdrawal', peer_ip, None)

        exabgp_log.write(line + "\n")
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

