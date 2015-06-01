#!/usr/bin/python

import time
my_dict = {}


# Intel(R) Core(TM) i7-3635QM CPU @ 2.40GHz:                    4.8 MOPS
# Intel(R) Core(TM) i7-3820 CPU @ 3.60GHz:   python 2.7         7.0 MOPS
# Intel(R) Core(TM) i7-3820 CPU @ 3.60GHz:   python 2.7/pypy:   8.6 MOPS

iterations = 10**6*14

start = time.time()

# Emulate 14.6 mpps
for index in range(0, iterations):
    my_dict[index] = index

stop = time.time()
interval = stop - start

print iterations / interval / 10**6, "millions of iterations per second"

