FreeBSD 9, 10, 11 and Dragonfly BSD 4.0

Install dependencies:
```bash
pkg install cmake git ncurses boost-all log4cpp
```

Update linker paths:
```
/etc/rc.d/ldconfig restart
```


```bash
mkdir /usr/local/src
cd /usr/local/src
git clone https://github.com/FastVPSEestiOu/fastnetmon.git -b v1.1.2
cd fastnetmon/src
mkdir build
cd build
cmake ..
make
```

Or you can try native FreeBSD port (will be added to port tree soon):
```bash
pkg install cmake git ncurses boost-all log4cpp
/etc/rc.d/ldconfig restart

mkdir /usr/local/src
cd /usr/local/src
git clone https://github.com/FastVPSEestiOu/fastnetmon.git
cd fastnetmon/src/FreeBSD_port/
make makesum
make install 
```

And please switch capture interface to promisc mode.

Add into /etc/rc.conf following line (for applying this option at boot time):
```bash
ifconfig_ix1="up promisc"
```

And switch it with ifconfig for already running system:
```bash
ifconfig ix1 promisc
```

Please put your networks in CIDR format here: /usr/local/etc/networks_list.

For netmap support you may need compile kernel manually with this [manual](BUILDING_FREEBSD_KERNEL_FOR_NETMAP.md).

On 32 bit FreeBSD you could hit this issue:
```bash
fastnetmon.cpp:(.text+0xc979): undefined reference to `__sync_fetch_and_add_8'
```

It could be fixed by this patch.

 Please add this lines before line "post-patch" line:
```bash
.include <bsd.port.pre.mk>

# Port requires 64 bit atomics
#.if ${ARCH} == i386 && empty(MACHINE_CPU:Mi586)
CFLAGS+= -march=i586
#.endif
```

And replace last string ```.include <bsd.port.mk>``` by ```.include
<bsd.port.post.mk>```.
