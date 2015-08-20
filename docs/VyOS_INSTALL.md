# VyOS install reference

This guide well tested with VyOS 1.1.5 only.

First of all you should enable Debian Squeeze stable and lts repos on VyOS box:
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

Update packages list:```sudo apt-get update```

Run installer with curl:
```bash
curl https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl > fastnetmon_install.pl
sudo perl fastnetmon_install.pl
```
