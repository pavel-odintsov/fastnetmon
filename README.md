FastNetMon
===========
Author: Pavel Odintsov pavel.odintsov at gmail.com
License: GPLv2

FastNetMon - High Performance Network DDoS and Load Analyzer with PCAP/PF_RING support. But I recommends only PF_RING variant because other variants is so slow and use big amount of CPU and expected big packetloss.

What we do? We can detect hosts in OUR network with big amount of packets per second (30 000 pps in standard configuration) incoming or outgoing from certain host. And we can call external bash script which can send notify, switch off server or blackhole this client.

Why we write it? Because we can't find any software for solving this problem not in proprietary world not in open sourcу. NetFlow based solutions is so slow and can't react on attack with acceptable speed.

Main programm screen image:

![Main screen image](fastnetmon_screen.png)

Example for cpu load for Intel i7 2600 with Intel X540 NIC on 250 kpps load:
![Cpu consumption](fastnetmon_stats.png)

Network map:
![Network diagramm](network_map.png)

Features:
- VLAN untagging
- MPLS traffic processing
- Ability to work on mirror ports
- Ability to work on router

[Install manual](INSTALL.md)

Example program screen:
```bash
FastNetMon v1.0 all IPs ordered by: packets

Incoming Traffic        96667 pps 240 mbps
xx.xx.xx.xx             7950 pps 3 mbps
xx.xx.xx.xx             5863 pps 65 mbps
xx.xx.xx.xx             2306 pps 1 mbps
xx.xx.xx.xx             1535 pps 16 mbps
xx.xx.xx.xx             1312 pps 14 mbps
xx.xx.xx.xx             1153 pps 0 mbps
xx.xx.xx.xx             1145 pps 0 mbps

Outgoing traffic        133265 pps 952 mbps
xx.xx.xx.xx             7414 pps 4 mbps
xx.xx.xx.xx             5047 pps 4 mbps
xx.xx.xx.xx             3458 pps 3 mbps
xx.xx.xx.xx             2959 pps 35 mbps
xx.xx.xx.xx             2612 pps 29 mbps
xx.xx.xx.xx             2334 pps 26 mbps
xx.xx.xx.xx             1906 pps 21 mbps

Internal traffic        0 pps

Other traffic           1815 pps

Packets received:       6516913578
Packets dropped:        0
Packets dropped:        0.0 %

Ban list:
yy.yy.yy.yy/20613 pps incoming
```

Enable programm start on server startup, please add to /etc/rc.local this lines:
```bash
cd /root/fastnetmon && screen -S fastnetmon -d -m ./fastnetmon eth3,eth4
```

When incoming or outgoing attack arrives programm call bash script (when it exists): /usr/local/bin/notify_about_attack.sh two times. First time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit what did happens.

Example of first notification:
```bash
subject: Myflower Guard: IP xx.xx.xx.xx blocked because incoming attack with power 120613 pps
body: blank
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

What is "flow" in FastNetMon terms? It's one or multiple connection (udp, tcp, icmp) with unique src IP, dst IP, src port, dst port and protocol. 
