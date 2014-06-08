fastnetmon
===========

FastNetMon - High Performance Network Load Analyzer with PCAP/ULOG2 support. But I recommends only PF_RING variant because other variants is so slow and use big amount of CPU and produce big packetloss.

What we do? We can detect hosts in OUR network with big amount of packets per second (30 000 pps in standard configuration) incoming or outgoing from certain host. And we can call external bash script which can send notify, switch off server or blackhole this client.

Why you write it? Because we can't find any software for solving this problem not in proprietary world not in open source. NetFlow based solutions is so slow and can't react on atatck with fast speed.

At now we start usage of C++11 and you can build this programm only on Debian 7 Wheezy, CentOS 6 has so old g++ compiler and can't compile it (but with CentOS 7 everything will be fine but it's not released yet). 

Main programm screen image:

![Main screen image](fastnetmon_screen.png)


Install:

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

If you want use PF_RING you should install it.

```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/ntop/PF_RING/PF_RING-5.6.2.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fntop%2Ffiles%2FPF_RING%2F&ts=1393755620&use_mirror=kent' -OPF_RING-5.6.2.tar.gz
tar -xf PF_RING-5.6.2.tar.gz 
cd PF_RING-5.6.2
apt-get install build-essential bison flex linux-headers-$(uname -r) libnuma-dev
```

Build PF_RING kernel module:
```bash
cd kernel
make 
make install
modprobe pf_ring
```

Build lib (We disabled bpf because it requires linking to PCAP):
```bash
cd /usr/src/PF_RING-5.6.2/userland/lib
./configure  --disable-bpf --prefix=/opt/pf_ring
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

Select backend, we use PF_RING as default, if you need PCAP/ULOG2 u must change variable ENGINE in Makefile.

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

It's REQUIRED to add all your networks in CIDR form to file /etc/networks_list if form when one subnet on one line.

Start it:
```bash
./fastnetmon
```


Example program screen:
```bash
Below you can see all clients with more than 2000 pps

Incoming Traffic    66167 pps 88 mbps
xx.yy.zz.15         3053  pps 0  Mbps
xx.yy.zz.248        2948  pps 0  Mbps
xx.yy.zz.192        2643  pps 0  Mbps

Outgoing traffic    91676 pps 728 mbps
xx.yy.zz.15         4471  pps 40  Mbps
xx.yy.zz.248        4468  pps 40  Mbps
xx.yy.zz.192        3905  pps 32  Mbps
xx.yy.zz.157        2923  pps 24  Mbps
xx.yy.zz.169        2809  pps 24  Mbps
xx.yy.zz            2380  pps 24  Mbps
xx.yy.zz            2105  pps 16  Mbps

Internal traffic    1 pps

Other traffic       25 pps

ULOG buffer errors: 2 (0%)
ULOG packets received: 19647
```

Example for cpu load for Intel i7 2600 with Intel X540 NIC on 250 kpps load:
![My image](fastnetmon_stats.png)

Enable programm start on server startup, please add to /etc/rc.local this lines:
```bash
cd /root/fastnetmon && screen -S fastnetmon -d -m ./fastnetmon eth3,eth4
```

I recommend you to disable CPU freq scaling for gain max performance (max frequency):
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

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
