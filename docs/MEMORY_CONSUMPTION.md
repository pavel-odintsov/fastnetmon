### Memory consumption

Required amount of memory is depends on total number of monitored hosts.

You could use this formula for calculations:
```bash
total_number_of_hosts * 208 * 3
```

- 3 is a number of counters (data counter, current speed counter, smoothed speed counter).
- 208 is a total size of traffic countring structure for 1.1.3 version.

Example computations:
- /16, 65535 hosts - 40 mb of RAM
- /8, 16 millions of hosts - 10GB ram

But please keep in mind! We need to iterate across all counters with single CPU core in ~1 second. Then, for big number of hosts you need to have fast CPU core.

