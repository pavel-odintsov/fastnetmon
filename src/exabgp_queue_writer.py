#!/usr/bin/env python
 
import os
import sys
import time
from redis import Redis
from rq import Queue

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

        q.enqueue(firewall_queue.execute_ip_ban, line)
        exabgp_log.write(line + "\n")
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

