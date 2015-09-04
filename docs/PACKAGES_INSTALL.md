### It's your favorite place if you are hate any "installer scripts" 

So we spent so much time and would like to offer rpm and deb packages for all most popular distros! We have only x86_64 paсkages.

Please be aware! It's beta packages builded from current (25 aug 2015) version of Git master!

Dear Debian and Ubuntu user, please do not panic if you got error from dpkg command about missing deps! It's OK! It will be fixed by second call of apt-get install -f.


#### Initial configuration

It's REQUIRED to add all of your networks in CIDR notation (11.22.33.0/24) to the file /etc/networks_list in the form of one prefix per line. After this you could run /opt/fastnetmon/fastnetmon_client and check output. 

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
systemctl start fastnetmon
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

#### VyOS 

We need to enable Squeeze repository for some dependencies. 
```bash
configure
# squeeze
set system package repository squeeze components 'main contrib non-free'
set system package repository squeeze distribution 'squeeze'
set system package repository squeeze url 'http://mirrors.kernel.org/debian'

# lts
set system package repository squeeze-lts components 'main contrib non-free'
set system package repository squeeze-lts distribution 'squeeze-lts'
set system package repository squeeze-lts url 'http://mirrors.kernel.org/debian'
commit
save
exit
```

```bash
wget http://178.62.227.110/fastnetmon_binary_repository/test_package_build/fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-6.0-x86_64.deb
wget http://vyos.net/so3group_maintainers.key
sudo apt-key add ./so3group_maintainers.key
sudo apt-get update
sudo dpkg -i fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-debian-6.0-x86_64.deb
sudo apt-get install -f
sudo insserv fastnetmon
sudo service fastnetmon start
```
