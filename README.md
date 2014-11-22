FastNetMon
===========
Author: Pavel Odintsov pavel.odintsov at gmail.com
License: GPLv2

FastNetMon - high performance DoS/DDoS and load analyzer builded on top of PF_RING.

What we do? We can detect hosts in OUR network with big amount of packets per second incoming or outgoing from certain host. And we can call external bash script which can send notify, switch off server or blackhole this client.

Why we write it? Because we can't find any software for solving this problem not in proprietary world not in open source. NetFlow based solutions has some [critical limitations](NETFLOW_DISADVANTAGES.md) for this task.

Features:
- Can process incoming and outgoing traffic
- Can trigger block script if certain IP load network with big amount of packets per second
- Can trigger block script if certain IP load network with big amount of bytes per second
- Can trigger block script if certain IP load network with big amount of flows per second
- VLAN untagging
- MPLS traffic processing
- Can work on mirror ports
- Can work on server/soft-router
- Can detect DoS/DDoS in 1-2 seconds

What is "flow" in FastNetMon terms? It's one or multiple connection udp, tcp, icmp with unique src IP, dst IP, src port, dst port and protocol.

Main programm screen image:

![Main screen image](fastnetmon_screen.png)

Example for cpu load for Intel i7 2600 with Intel X540 NIC on 250 kpps load:
![Cpu consumption](fastnetmon_stats.png)

Example deployment scheme:
![Network diagramm](network_map.png)

[Install manual](INSTALL.md)

Example of first notification:
```bash
subject: Myflower Guard: IP xx.xx.xx.xx blocked because incoming attack with power 120613 pps
body:
IP: XX.XX.XX.XX
Initial attack power: 98285 packets per second
Peak attack power: 98285 packets per second
Attack direction: outgoing
Incoming traffic: 62 mbps
Outgoing traffic: 65 mbps
Incoming pps: 66628 packets per second
Outgoing pps: 98285 packets per second
Incoming flows: 16
Outgoing flows: 16
Incoming

UDP
xx.xx.xx.xx:33611 < 216.239.32.109:53 729021 bytes 5927 packets
xx.xx.xx.xx:33611 < 216.239.34.109:53 231609 bytes 1883 packets
xx.xx.xx.xx:33611 < 216.239.36.109:53 728652 bytes 5924 packets
xx.xx.xx.xx:33611 < 216.239.38.109:53 414387 bytes 3369 packets
xx.xx.xx.xx:38458 < 216.239.32.109:53 724347 bytes 5889 packets
xx.xx.xx.xx:38458 < 216.239.34.109:53 222753 bytes 1811 packets
xx.xx.xx.xx:38458 < 216.239.36.109:53 729267 bytes 5929 packets
xx.xx.xx.xx:38458 < 216.239.38.109:53 383514 bytes 3118 packets
xx.xx.xx.xx:42279 < 216.239.32.109:53 687201 bytes 5587 packets
xx.xx.xx.xx:42279 < 216.239.34.109:53 248091 bytes 2017 packets
xx.xx.xx.xx:42279 < 216.239.36.109:53 737508 bytes 5996 packets
xx.xx.xx.xx:42279 < 216.239.38.109:53 321276 bytes 2612 packets
xx.xx.xx.xx:51469 < 216.239.32.109:53 735663 bytes 5981 packets
xx.xx.xx.xx:51469 < 216.239.34.109:53 237267 bytes 1929 packets
xx.xx.xx.xx:51469 < 216.239.36.109:53 735663 bytes 5981 packets
xx.xx.xx.xx:51469 < 216.239.38.109:53 318570 bytes 2590 packets


Outgoing

UDP
xx.xx.xx.xx:33611 > 216.239.32.109:53 531309 bytes 6107 packets
xx.xx.xx.xx:33611 > 216.239.34.109:53 531222 bytes 6106 packets
xx.xx.xx.xx:33611 > 216.239.36.109:53 531222 bytes 6106 packets
xx.xx.xx.xx:33611 > 216.239.38.109:53 531222 bytes 6106 packets
xx.xx.xx.xx:38458 > 216.239.32.109:53 527220 bytes 6060 packets
xx.xx.xx.xx:38458 > 216.239.34.109:53 527133 bytes 6059 packets
xx.xx.xx.xx:38458 > 216.239.36.109:53 527133 bytes 6059 packets
xx.xx.xx.xx:38458 > 216.239.38.109:53 527220 bytes 6060 packets
xx.xx.xx.xx:42279 > 216.239.32.109:53 539052 bytes 6196 packets
xx.xx.xx.xx:42279 > 216.239.34.109:53 539052 bytes 6196 packets
xx.xx.xx.xx:42279 > 216.239.36.109:53 539139 bytes 6197 packets
xx.xx.xx.xx:42279 > 216.239.38.109:53 539139 bytes 6197 packets
xx.xx.xx.xx:51469 > 216.239.32.109:53 532701 bytes 6123 packets
xx.xx.xx.xx:51469 > 216.239.34.109:53 532701 bytes 6123 packets
xx.xx.xx.xx:51469 > 216.239.36.109:53 532701 bytes 6123 packets
xx.xx.xx.xx:51469 > 216.239.38.109:53 532788 bytes 6124 packets
```

Example of second notification:
```bash
subject: Myflower Guard: IP xx.xx.xx.xx blocked because incoming attack with power 120613 pps
body:
IP: xx.zz.xx.1
Attack power: 95267 packets per second
Peak attack power: 269017 packets per second
Attack direction: incoming
Incoming traffic: 43 mbps
Outgoing traffic: 15 mbps
Incoming pps: 95267 packets per second
Outgoing pps: 31119 packets per second

2014-07-04 13:59:54.778872 xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
2014-07-04 13:59:54.778874 xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
2014-07-04 13:59:54.778875 xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
2014-07-04 13:59:54.778877 xx.xx.xx.xx:46804 > xx.xx.xx.xx:80 protocol: tcp size: 52 bytes
2014-07-04 13:59:54.778878 xx.xx.xx.xx:46804 > xx.xx.xx.xx:80 protocol: tcp size: 52 bytes
2014-07-04 13:59:54.778882 xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
2014-07-04 13:59:54.778884 xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
2014-07-04 13:59:54.778885 xx.xx.xx.xx:46804 > xx.xx.xx.xx:80 protocol: tcp size: 52 bytes
```

You can find more info and graphics [here](http://forum.nag.ru/forum/index.php?showtopic=89703)
