### It's your favorite place if you are hate any "installer scripts" 

So we spent so much time and would like to offer rpm and deb packages for all most popular distros! We have only x86_64 pakages.

Pleasee be aware! It's beta packaegs builded for current (25 aug 2015) version of Git master!

#### Ubuntu LTS 12.04

```bash
wget http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-ubuntu-12.04-x86_64.deb
apt-get update
dpkg -i fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-ubuntu-12.04-x86_64.deb
apt-get install -f
service fastnetmon start
```

#### Ubuntu LTS 14.04

```bash
wget http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-ubuntu-14.04-x86_64.deb
apt-get update
dpkg -i fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-ubuntu-14.04-x86_64.deb
apt-get install -f
service fastnetmon start
```

#### CentOS 6

```bash
yum install -y http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-centos-6-x86_64.rpm
service fastnetmon start
```

#### CentOS 7

```bash
yum install -y http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-centos-7-x86_64.rpm
systemctl fastnetmon start 
```

#### Debian 6 Squeeze

```bash
wget http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-6.0-x86_64.deb
apt-get update
dpkg -i fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-6.0-x86_64.deb
apt-get install -f
service fastnetmon start
```

#### Debian 7 Wheezy 

```bash
wget http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-7.0-x86_64.deb
apt-get update
dpkg -i fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-7.0-x86_64.deb
apt-get install -f
service fastnetmon start
```

### Debian 8 Jessy

```bash
wget http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-8.0-x86_64.deb
apt-get update
dpkg -i fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-8.0-x86_64.deb
apt-get install -f
systemctl start fastnetmon
```
