Let us assume you have full Slackware install. It is tested with version 14.1
First we need to install libnuma. Download ftp://oss.sgi.com/www/projects/libnuma/download/numactl-2.0.10.tar.gz (or newer version if any).

```bash
cd /usr/src
wget ftp://oss.sgi.com/www/projects/libnuma/download/numactl-2.0.10.tar.gz
tar -xvf numactl-2.0.10.tar.gz
cd numactl-2.0.10/
./autogen.sh
./configure
make
As root:
make install
```

Now install log4cpp:
```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/log4cpp/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.1.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Flog4cpp%2Ffiles%2Flog4cpp-1.1.x%2520%2528new%2529%2F&ts=1422275810&use_mirror=cznic' -Olog4cpp-1.1.1.tar.gz
tar -xvf log4cpp-1.1.1.tar.gz
cd log4cpp
./configure
make
As root:
make install
```

Now install PF_RING

```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/ntop/PF_RING/PF_RING-6.0.3.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fntop%2Ffiles%2FPF_RING%2F&ts=1402307916&use_mirror=cznic' -OPF_RING-6.0.3.tar.gz
tar -xvf PF_RING-6.0.3.tar.gz
cd PF_RING-6.0.3

Install kernel module:
```bash
cd kernel
make
As root:
make install
modprobe pf_ring
```

Install library:
```
cd /usr/src/PF_RING-6.0.3/userland/lib
./configure --disable-bpf --prefix=/opt/pf_ring
make
As root:
make install
```

You must add this line to /etc/ld.so.conf: ```/opt/pf_ring/lib```

Then execute command as root: ```ldconfig```

Now you have all you need for compiling fastnetmon.

```bash
cd /usr/src
git clone https://github.com/FastVPSEestiOu/fastnetmon.git
cd fastnetmon/src
In file CMakeLists.txt coment out the line:
target_link_libraries(fastnetmon pcap)
mkdir build
cd build
cmake ..
make
```

If you have some 'boost' related errors it is recomended to remove your version of 'boost' and install the newest from source. If compiling finishes without errors - you have two binaries - fastnetmon and fastnetmon_client. You can put them for example in /usr/local/bin. You can put /usr/src/fastnetmon/notify_about_attack there too. Copy /usr/src/fastnetmon/fastnetmon.conf to /etc and edit it for your needs. Create /etc/networks_list with your networks in CIDR format (one per line). And you are done - you have installed fastnetmon.

Author: Martin Stoyanov 
