At first you should install PF_RING (you can install any latest version

```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/ntop/PF_RING/PF_RING-6.0.3.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fntop%2Ffiles%2FPF_RING%2F&ts=1402307916&use_mirror=cznic' -OPF_RING-6.0.3.tar.gz
tar -xf PF_RING-6.0.3.tar.gz 
cd PF_RING-6.0.3
# Debian way
apt-get install build-essential bison flex linux-headers-$(uname -r) libnuma-dev
# CentOS
yum install -y make bison flex kernel-devel gcc gcc-c++
# CentOS openvz case 
yum install -y make bison flex vzkernel-devel gcc gcc-c++
```

Build PF_RING kernel module:
```bash
cd kernel
make
make install
modprobe pf_ring
```

Build lib:
```bash
# Debian
apt-get install -y libnuma-dev
# CentOS
yum install -y numactl-devel
cd /usr/src/PF_RING-6.0.3/userland/lib
./configure --prefix=/opt/pf_ring
make
make install
```

Install FastNetMon:

```bash
   # Debian 7 Wheezy
   apt-get install -y git  g++ gcc libboost-all-dev make libgpm-dev libncurses5-dev liblog4cpp5-dev libnuma-dev libgeoip-dev libhiredis-dev libpcap-dev
   # CentOS 
   yum install -y git make gcc gcc-c++ boost-devel GeoIP-devel log4cpp-devel ncurses-devel glibc-static ncurses-static gpm-static gpm-devel 

   # For compiling on CentOS please remove line "STATIC = -static" from file Makefile and replace line "LIBS += -lboost_thread" by line "LIBS += -lboost_thread-mt"

   cd /usr/src
   git clone https://github.com/FastVPSEestiOu/fastnetmon.git
   cd fastnetmon/src
```

Build FastNetMon with cmake:
```bash
cd /usr/src/fastnetmon/cmake
mkdir build
cd build
cmake ..
make
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

Enable programm start on server startup, please add to /etc/rc.local this lines:
```bash
screen -S fastnetmon -d -m /root/fastnetmon/fastnetmon
```

When incoming or outgoing attack arrives programm call bash script (when it exists): /usr/local/bin/notify_about_attack.sh two times. First time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit what did happens.


==Command Line Reference 
* --version gives FNM version
* --daemonize start in daemon mode
* --configuration_file CONFIG_FILE specify alternative config file to read
