fastnetmon
==========

FastNetMon - High Performance Network Load Analyzer with PCAP/ULOG2 support

Install

```bash
   # Debian
   apt-get install -y git libpcap-dev g++ gcc libboost-all-dev
   # CentOS
   yum install -y git libpcap-devel gcc-c++ boost-devel boost

   git clone https://github.com/FastVPSEestiOu/fastnetmon.git
   cd fastnetmon
```

Select backend, we use ULOG2 as default, if you need PCAP u must change variable ENGINE in build.sh to PCAP

Compile it:
```bash
./build.sh
```

Start it:
```bash
./fastnetmon
```
Server configuration for PCAP:
 no configuration needed

Server configuration for ULOG2:
```bash
iptables -A FORWARD -i br0 -j ULOG --ulog-nlgroup 1 --ulog-cprange 32 --ulog-qthreshold 45
```

If you use PCAP, u can set monitored interface as command line parameter (u can set 'any' as inerface name but it work not so fine):
```bash
./fastnetmon br0
``` 
