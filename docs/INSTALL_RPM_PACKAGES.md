We have precompiled packages for CentOS 6 and CentOS 7 (soon!).

First of all, please install Epel repo:
- CentOS 6: ```rpm -ihv http://fedora-mirror01.rbc.ru/pub/epel/6/i386/epel-release-6-8.noarch.rpm```
- CentOS 7: ```yum install -y epel-release```

Enable ntop repo (need for PF_RING kernel module and library): ```vim /etc/yum.repos.d/ntop.repo```

Repo file (it's nightbuild version. Stable did not work correctly and haven't headers for ZC version):
```bash
[ntop]
name=ntop packages
baseurl=http://www.nmon.net/centos/$releasever/$basearch/
enabled=1
gpgcheck=1
gpgkey=http://www.nmon.net/centos/RPM-GPG-KEY-deri
[ntop-noarch]
name=ntop packages
baseurl=http://www.nmon.net/centos/$releasever/noarch/
enabled=1
gpgcheck=1
gpgkey=http://www.nmon.net/centos/RPM-GPG-KEY-deri
```

And install pfring kernel module and libs:
```bash
yum install -y pfring
```

Install FastNetMon on CentOS 6:
```bash
yum install -y https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/packages/CentOS6/fastnetmon-1.1.1-1.x86_64.rpm
```

If you want build rpm package manually please use script [build_rpm.sh](https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/build_rpm.sh). Please build on same Linux distro version as target platform for best results.

