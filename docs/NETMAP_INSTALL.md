Build netmap on Debian 7 Wheezy with ixgbe 10GE NIC (82599):

If you want _stable_ driver with all modern features, please use this reference instead [here](http://www.stableit.ru/2014/10/netmap-debian-7-wheezy-intel-82599.html)

Get kernel sources:
```bash
cd /usr/src
apt-get source  linux-image-3.2.0-4-amd64
```

Download netmap kernel module code:
```bash
cd /usr/src
git clone https://code.google.com/p/netmap/ 
cd netmap/LINUX/
```

Build netmap with drivers:
```
./configure --kernel-sources=/usr/src/linux-3.2.65 --drivers=ixgbe
make
make install
```

Load modules:
```
insmod ./netmap.ko
modprobe mdio
modprobe ptp
modprobe dca 
insmod ixgbe/ixgbe.ko
```

Enable interfaces:
```bash
ifconfig eth0 up
ifconfig eth0 promisc
```

Add to /etc/rc.local:
```bash
rmmod ixgbe
insmod /usr/src/netmap/LINUX/netmap.ko
modprobe mdio
modprobe ptp
modprobe dca 
insmod /usr/src/netmap/LINUX/ixgbe/ixgbe.ko
ifconfig eth0 up
ifconfig eth0 promisc
```

