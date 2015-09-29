I recommend you to disable CPU freq scaling for gain max performance (max frequency):
```bash
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

You can use script [irq_balance_manually.sh](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/src/irq_balance_manually.sh) for irq balancing on heavy loaded networks.

Running tool without root permissions:
```bash
useradd fastnetmon
setcap cap_net_admin+eip fastnetmon
su fastnetmon
./fastnetmon eth0,eth1
```

Please keep in mind when run tool on OpenVZ because without root permissions tool can't get all VE ips and you should pass it explicitly.

Debugging flags.

DUMP_ALL_PACKETS will enable all packets dumping to /var/log/fastnetmon.log. It's very useful for testing tool on non standard platforms.

```bash
DUMP_ALL_PACKETS=yes ./fastnetmon
```

If you want to dump only "other" (we could not detect direction for this packets) packets, please use: DUMP_OTHER_PACKETS.

Recommended configuration options for ixgbe Intel X540 driver (netmap mode):
```bash
cat /etc/modprobe.d/ixgbe.conf
options ixgbe IntMode=2,2 MQ=1,1 DCA=2,2 RSS=8,8 VMDQ=0,0 max_vfs=0,0 L2LBen=0,0 InterruptThrottleRate=1,1 FCoE=0,0 LRO=1,1 allow_unsupported_sfp=0,0
```

I got very big packet size (more than mtu) in attack log? In PF_RING this behaviour will be related with offload features of NIC. For Intel 82599 I recommend disable all offload:
```bash
ethtool -K eth0 gro off gso off tso off
```

How I can compile FastNetMon without PF_RING support?
```bash
cmake .. -DDISABLE_PF_RING_SUPPORT=ON
```

If you saw intel_idle in perf top with red higlihting you can disable it with following kernel params (more details you can find Performance_Tuning_Guide_for_Mellanox_Network_Adapters.pdf):
```bash
intel_idle.max_cstate=0 processor.max_cstate=1
```

If you want build with clang:
```bash
cmake -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ ..
```

If tou want build tool with debug info:
```bash
cmake -DCMAKE_BUILD_TYPE=Debug  ..
```

If you want speedup build process please build with ninja instead of make:
```bash
apt-get install -y ninja-build
cd build
cmake -GNinja ..
ninja
```

Ninja use all CPUs for build process:
```bash
1  [||||||||||||||||||||||||||||||||||||||||||||||100.0%]     Tasks: 53, 103 thr, 64 kthr; 6 running
2  [||||||||||||||||||||||||||||||||||||||||||||||100.0%]     Load average: 1.32 0.45 0.19 
3  [||||||||||||||||||||||||||||||||||||||||||||||100.0%]     Uptime: 1 day, 12:58:40
4  [||||||||||||||||||||||||||||||||||||||||||||||100.0%]
```

Build script for reading Netflow (v5, v9, ipfix) data from pcap dump:
```bash
cmake .. -DBUILD_PCAP_READER=ON
```

Run pcap data:
```bash
./fastnetmon_pcap_reader sflow dump.pcap
./fastnetmon_pcap_reader netflow dump.pcap
```

How to run tests?

Compile and install Google Test Library:
```bash
cd /usr/src/
wget https://googletest.googlecode.com/files/gtest-1.7.0.zip
unzip  gtest-1.7.0.zip
cd gtest-1.7.0
mkdir build
cd build
cmake ..
mkdir /opt/gtest
mkdir /opt/gtest/lib
cp -R ../include/ /opt/gtest/
cp libgtest_main.a  libgtest.a /opt/gtest/lib/
```

Build and run tests:
```bash
cmake -DBUILD_TESTS=ON ..
./fastnetmon_tests
```

Build script for running packet capture plugins without analyzer backend:
```bash
cmake .. -DBUILD_PLUGIN_RUNNER=ON
```

Examples for different plugins (plugin name could be netflow, netmap, sflow, pfring, pcap):
```bash
./fastnetmon_plugin_runner netflow
```

How to collect data for debugging netflow:
```bash
tcpdump -w /root/netflow_data.pcap -n 'udp dst port 2055' 
```

How to collect data for debugging sFLOW:
```bash
 tcpdump -w /root/sflow_data.pcap -n 'udp dst port 6343'
```

Performance tuning:
- Do not use short prefixes (lesser then /24)
- Do not use extremely big prefixes (/8, /16) because memory consumption will be very big

How I can enable ZC support for PF_RING? Please install DNA/ZC dreivers, load they and add interface name with zc prefix in config file (i.e. zc:eth3)

For development new code, please check .clang-format as code guide example.

You can find more info and graphics [here](http://forum.nag.ru/forum/index.php?showtopic=89703)
