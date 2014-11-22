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


Running tool without root permissions:
```bash
useradd fastnetmon
setcap cap_net_admin+eip fastnetmon
su fastnetmon
./fastnetmon eth0,eth1
```

Please keep in mind when run tool on OpenVZ because without root permissions tool can't get all VE ips and you should pass it explicitly.


Debugging flags.

DUMP_ALL_PACKETS will enable all packets dumping to console. It's very useful for testing tool on non standard platforms.

```bash
DUMP_ALL_PACKETS=yes ./fastnetmon eth3,eth4
```

How I can disable ban for testing purposes?
```bash
DISABLE_BAN=1 ./fastnetmon eth3,eth4
```

Recommended configuration options for ixgbe Intel X540 driver:
```bash
cat /etc/modprobe.d/ixgbe.conf
options ixgbe IntMode=2,2 MQ=1,1 DCA=2,2 RSS=8,8 VMDQ=0,0 max_vfs=0,0 L2LBen=0,0 InterruptThrottleRate=1,1 FCoE=0,0 LRO=1,1 allow_unsupported_sfp=0,0
```

I got very big packet size (more than mtu) in attack log? This issue will be related with offload features of NIC. For INtel 82599 I recommend disable all offload:
```bash
ethtool -K eth0 gro off gso off tso off
```


How I can enable hardware filtration for Intel 82599 NIC? Install patched ixgbe driver from PF_RING distro and apply this patch to Makefile and recompile tool:
```bash
fastnetmon.o: fastnetmon.cpp
-       $(COMPILER) $(STATIC) $(DEFINES) $(HEADERS) -c fastnetmon.cpp -o fastnetmon.o $(BUILD_FLAGS)
+       $(COMPILER) $(STATIC) $(DEFINES) $(HEADERS) -c fastnetmon.cpp -o fastnetmon.o $(BUILD_FLAGS) -DHWFILTER_LOCKING
```

If you saw intel_idle in perf top with red higlihting you can disable it with following kernel params (more details you can find Performance_Tuning_Guide_for_Mellanox_Network_Adapters.pdf):
```bash
intel_idle.max_cstate=0 processor.max_cstate=1
```

You can find more info and graphics [here](http://forum.nag.ru/forum/index.php?showtopic=89703)
