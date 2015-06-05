### This guide fill describe how build iso image of VyOS with bundled FastNetMon

First af all, you need _only_ Debian Squeeze for building this image!

Install VyOS keyring:
```bash
apt-get install debian-archive-keyring
wget http://vyos.net/so3group_maintainers.key
gpg --import so3group_maintainers.key
```

Enable Backports repo and install Squashfs tools:
```bash
echo "deb http://backports.debian.org/debian-backports squeeze-backports main" >> /etc/apt/sources.list
apt-get update
apt-get -t squeeze-backports install squashfs-tools
```

Install packages for building iso image:
```bash
apt-get install git autoconf automake dpkg-dev live-helper syslinux genisoimage
```

Install FastNetMon build deps:
```bash
apt-get install -y  cmake libboost-thread-dev libboost-system-dev libboost-regex-dev libpcap-dev libnuma-dev liblog4cpp5-dev libboost-all-dev libgpm-dev libncurses5-dev libgeoip-dev clang
```

New manual:
```bash
git clone https://github.com/pavel-odintsov/build-iso.git
cd build-iso
git submodule update --init pkgs/fastnetmon/
export PATH=/sbin:/usr/sbin:$PATH
autoreconf -i
echo -e "libboost-regex1.42.0\nlibboost-thread1.42.0\nliblog4cpp5\nlibpcap0.8\nfastnetmon" >> livecd/config.vyatta/chroot_local-packageslists/vyatta-full.list
```

Replace depends for ```vim pkgs/fastnetmon/debian/control```
```bash
Depends: ${shlibs:Depends}, ${misc:Depends}, libboost-thread1.42.0, libboost-system1.42.0 , libboost-regex1.42.0, libpcap0.8, liblog4cpp5
```

```bash
cd pkgs/fastnetmon
ln -s ../src/fastnetmon_init_script_debian_6_7 debian/fastnetmon.init
ln -s ../src/fastnetmon.service debian/fastnetmon.service
cd ..
cd ..
make fastnetmon


cd pkgs
wget http://ftp.us.debian.org/debian/pool/main/b/boost1.42/libboost-regex1.42.0_1.42.0-4_amd64.deb
wget http://ftp.us.debian.org/debian/pool/main/b/boost1.42/libboost-thread1.42.0_1.42.0-4_amd64.deb
wget http://ftp.us.debian.org/debian/pool/main/l/log4cpp/liblog4cpp5_1.0-4_amd64.deb
wget http://ftp.us.debian.org/debian/pool/main/libp/libpcap/libpcap0.8_1.1.1-2+squeeze1_amd64.deb
cd ..

./configure
make iso
```
