Installing netmap in FreeBSD

Try to build kernel module for current kernel:
```bash
cd /usr/src/sys/modules/netmap
make 
make install
kldload netmap
```

But you could hit this bug:
```bash
KLD netmap.ko: depends on kernel - not available or version mismatch
linker_load_file: Unsupported file type
```

Enable netmap startup on server load:
```bash
echo 'netmap_load="YES"' >> /boot/loader.conf
```
To activate Netmap on your server you have to turn your interface on promiscuous mode:
ifconfig <interface> promisc

And should rebuild kernel manually.

Install SVN:
```bash
pkg install devel/subversion
```

Download base repository for FreeBSD 10 stable (replace 10 by your FreeBSD version):
```svn checkput https://svn0.ru.freebsd.org/base/stable/10 /usr/src```

Build and install new kernel:
```bash
cd /usr/src/sys/amd64/conf
cp GENERIC KERNELWITHNETMAP
cd /usr/src
make buildkernel KERNCONF=KERNELWITHNETMAP
make installkernel KERNCONF=KERNELWITHNETMAP
```

