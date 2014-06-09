FastNetMon
===========

FastNetMon - High Performance Network DDoS and Load Analyzer with PCAP/ULOG2/PF_RING support. But I recommends only PF_RING variant because other variants is so slow and use big amount of CPU and expected big packetloss.

What we do? We can detect hosts in OUR network with big amount of packets per second (30 000 pps in standard configuration) incoming or outgoing from certain host. And we can call external bash script which can send notify, switch off server or blackhole this client.

Why you write it? Because we can't find any software for solving this problem not in proprietary world not in open sourcу. NetFlow based solutions is so slow and can't react on atatck with acceptable speed.

At now we start usage of C++11 and you can build this programm only on Debian 7 Wheezy, CentOS 6 has so old g++ compiler and can't compile it (but with CentOS 7 everything will be fine but it's not released yet). But you can use precompiled version on Debian 6, 7 and CentOS 6 without any problems.

Main programm screen image:

![Main screen image](fastnetmon_screen.png)

Example for cpu load for Intel i7 2600 with Intel X540 NIC on 250 kpps load:
![Cpu consumption](fastnetmon_stats.png)

At first you should install PF_RING (you can install any latest version):

```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/ntop/PF_RING/PF_RING-6.0.1.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fntop%2Ffiles%2FPF_RING%2F&ts=1402307916&use_mirror=cznic' -OPF_RING-6.0.1.tar.gz
tar -xf PF_RING-6.0.1.tar.gz 
cd PF_RING-6.0.1
# Debian way
apt-get install build-essential bison flex linux-headers-$(uname -r) libnuma-dev
# CentOS
yum install -y make bison flex kernel-devel 
# CentOS openvz case 
yum install -y make bison flex vzkernel-devel
```

Build PF_RING kernel module:
```bash
cd kernel
make 
make install
modprobe pf_ring
```

You can use precompiled and statically linced version of this tool without any compiling:
```bash
mkdir /root/fastnetmon
cd /root/fastnetmon
wget  https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/fastnetmon
chmod +x fastnetmon
./fastnetmon eth0
```

If you want to use static version you can skip this guide to part about "networks_list".

Build lib (We disabled bpf because it requires linking to PCAP):
```bash
cd /usr/src/PF_RING-5.6.2/userland/lib
./configure  --disable-bpf --prefix=/opt/pf_ring
```

Install FastNetMon:

```bash
   # Debian 7 Wheezy
   apt-get install -y git libpcap-dev g++ gcc libboost-all-dev make

   # If you need traffic counting
   apt-get install -y libhiredis-dev

   # If you need PF_RING abilities 
   apt-get install -y libnuma-dev

   # If you need ASN/geoip stats
   apt-get install -y libgeoip-dev 

   cd /usr/src
   git clone https://github.com/FastVPSEestiOu/fastnetmon.git
   cd fastnetmon
```

You should start fastnetmon using this options:
```bash
LD_LIBRARY_PATH=/opt/pf_ring/lib/ ./fastnetmon eth3,eth4
```

If you want to avoid LD_LIBRARY_PATH on every call you should add pf_ring path to system:
```bash
echo "/opt/pf_ring/lib" > /etc/ld.so.conf.d/pf_ring.conf
ldconfig -v
```

Select backend, we use PF_RING as default, if you need PCAP/ULOG2 you must change variable ENGINE in Makefile.

Compile it:
```bash
make
```

Download GeoIP database to current folder:
```bash
http://dev.maxmind.com/geoip/legacy/geolite/
http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip GeoIPASNum.dat.gz
```

It's REQUIRED to add all your networks in CIDR form to file /etc/networks_list if form when one subnet on one line. Please aggregate your networks because long networks list will significatly slow down programm. And please change REDIS_SUPPORT = yes to no in Makefile if you do not need traffic counting feature. When you running this software in OpenVZ node you may did not specify networks explicitly, we can read it from file /proc/vz/veip.

You can add whitelist subnets in similar form to /etc/networks_whitelist (CIDR masks too).

Copy standard config file to /etc:
```bash
cp fastnetmon.conf /etc/fastnetmon.conf
```

Start it:
```bash
./fastnetmon eth1,eth2
```


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
xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
xx.xx.xx.xx:46804 > xx.xx.xx.xx:80 protocol: tcp size: 52 bytes
xx.xx.xx.xx:46804 > xx.xx.xx.xx:80 protocol: tcp size: 52 bytes
xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
xx.xx.xx.xx:80 > xx.xx.xx.xx:46804 protocol: tcp size: 233 bytes
xx.xx.xx.xx:46804 > xx.xx.xx.xx:80 protocol: tcp size: 52 bytes
```


I recommend you to disable CPU freq scaling for gain max performance (max frequency):
```bash
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

You can use this script for irq balancing on heavy loaded networks:
```bash
#!/bin/bash

# from http://habrahabr.ru/post/108240/
ncpus=`grep -ciw ^processor /proc/cpuinfo`
test "$ncpus" -gt 1 || exit 1

n=0
for irq in `cat /proc/interrupts | grep eth | awk '{print $1}' | sed s/\://g`
do
    f="/proc/irq/$irq/smp_affinity"
    test -r "$f" || continue
    cpu=$[$ncpus - ($n % $ncpus) - 1]
    if [ $cpu -ge 0 ]
            then
                mask=`printf %x $[2 ** $cpu]`
                echo "Assign SMP affinity: eth queue $n, irq $irq, cpu $cpu, mask 0x$mask"
                echo "$mask" > "$f"
                let n+=1
    fi
done
```

You can find more info and graphics [here](http://forum.nag.ru/forum/index.php?showtopic=89703)

Author: Pavel Odintsov pavel.odintsov at gmail.com

Obsolet documentation.

Install guide in CentOS 6:
```bash
   # CentOS 6
   yum install -y git libpcap-devel gcc-c++ boost-devel boost make
```

Server configuration for PCAP: no configuration needed

Server configuration for ULOG2:
```bash
iptables -A FORWARD -i br0 -j ULOG --ulog-nlgroup 1 --ulog-cprange 32 --ulog-qthreshold 45
```

If you use PCAP, u can set monitored interface as command line parameter (u can set 'any' as inerface name but it work not so fine):
```bash
./fastnetmon br0
``` 
