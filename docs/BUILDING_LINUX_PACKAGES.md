Please build on same Linux distro version as target platform for best results.

First of all, please install Epel repo:
- CentOS 6: ```rpm -ihv http://fedora-mirror01.rbc.ru/pub/epel/6/i386/epel-release-6-8.noarch.rpm```
- CentOS 7: ```yum install -y epel-release```

Enable ntop repo: ```vim /etc/yum.repos.d/ntop.repo```

Repo file:
```bash
[ntop]
name=ntop packages
baseurl=http://www.nmon.net/centos-stable/$releasever/$basearch/
enabled=1
gpgcheck=1
gpgkey=http://www.nmon.net/centos-stable/RPM-GPG-KEY-deri
[ntop-noarch]
name=ntop packages
baseurl=http://www.nmon.net/centos-stable/$releasever/noarch/
enabled=1
gpgcheck=1
gpgkey=http://www.nmon.net/centos-stable/RPM-GPG-KEY-deri
```

And install pfring kernel module and libs:
```bash
yum install -y pfring
```

If you want build rpm package manually please use script [build_rpm.sh](https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/build_rpm.sh).
