#!/usr/bin/python

import time
my_dict = {}


# Intel(R) Core(TM) i7-3635QM CPU @ 2.40GHz: 4.8 MOPS
# Intel(R) Core(TM) i7-3820 CPU @ 3.60GHz: 7.0 MOPS

iterations = 10**6*14

start = time.time()
# Emulate 14.6 mpps
for i in range(1, iterations):
    my_dict[i] = i

stop = time.time()

print iterations / (stop - start) / 10**6, "millions of iterations per second"

