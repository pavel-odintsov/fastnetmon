### This article will describe everything about sFLOW from hardware side

### Extreme

Please be aware! Extreme XOS operating system before 15.4 release lack of support for ingress sflow, only for egress ([source](http://extrcdn.extremenetworks.com/wp-content/uploads/2014/01/EXOS_Command_Reference_Guide_15_4.pdf)). Please use 15.4 version or more recent.

Example of sFLOW configuration for Extreme XOS:
```bash
configure sflow collector 10.0.2.33 port 6343 vr "VR-Default" # add collector
configure sflow agent 10.0.2.15 # agent address
configure sflow poll-interval 1 # send data to collector once per second 
configure sflow sample-rate 1024 # sampling rate
enable sflow ports 1:39,1:40,2:39 both # add ports to sFLOW monitoring for egress and ingress traffic.
enable sflow #  enable sflow globally
```

Check configuration for correctness:
```bash
show sflow
 
SFLOW Global Configuration
Global Status: enabled
Polling interval: 1
Sampling rate: 2048
Maximum cpu sample limit: 2000
SFLOW Configured Agent IP: 10.0.2.15 Operational Agent IP: 10.0.2.15
Collectors
Collector IP 10.0.2.33, Port 6343, VR "VR-Default"
SFLOW Port Configuration
Port      Status           Sample-rate         Subsampling
                       Config   /  Actual      factor     
1:39      enabled     1024      /  1024         1             
1:40      enabled     1024      /  1024         1             
2:39      enabled     1024      /  1024         1
```

### Juniper EX

Juniper EX sFLOW configuration: [link](http://kb.juniper.net/InfoCenter/index?page=content&id=KB14855).

### sFLOW configuration on Linux

We recommend this [project](http://host-sflow.sourceforge.net/).

You could use this reference for configurarion on Debian 8 Jessie BOX:
```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/host-sflow/Latest/hsflowd_1.27.3-1_amd64.deb?r=&ts=1435142676&use_mirror=netcologne' -Ohsflowd_1.27.3-1_amd64.deb
dpkg -i hsflowd_1.27.3-1_amd64.deb
```

Configure iptables:
```bash
MOD_STATISTIC="-m statistic --mode random --probability 0.0025"
ULOG_CONFIG="--ulog-nlgroup 1 --ulog-prefix SFLOW --ulog-qthreshold 1"
iptables -I INPUT -j ULOG $MOD_STATISTIC $ULOG_CONFIG
iptables -I OUTPUT -j ULOG $MOD_STATISTIC $ULOG_CONFIG
```

Configure daemon ```vim /etc/hsflowd.conf```:
```bash
DNSSD=off

ulogGroup = 1
ulogProbability = 0.0025


collector {
    ip = 127.0.0.1
    udpport = 6343
}
```

Let's start:
```bash
systemctl restart hsflowd
```

### Qtech switches 

Qtech QSW-8200-52T and Qtech QSW-2850-28T has some bugs in sFLOW implementation. Sflowtool could not parse they too. Waiting answer from developers.
