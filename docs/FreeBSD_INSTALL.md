FreeBSD 9, 10, 11 and Dragonfly BSD 4.0

Stable version 1.1.2 is already in [official FreeBSD ports](https://freshports.org/net-mgmt/fastnetmon/) but if you want to hack it or install development version, please use this script.

Please install wget:
```bash
pkg install -y wget perl5
```

Install stable 1.1.2 version:
```bash
wget --no-check-certificate https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl
```

Install development version:
```
wget --no-check-certificate https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl --use-git-master
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
