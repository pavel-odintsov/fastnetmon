#!/bin/bash

# Download all images
# vztmpl-dl --update centos-6-x86_64 centos-6-x86 centos-7-x86_64 debian-7.0-x86 debian-7.0-x86_64 debian-8.0-x86_64 ubuntu-12.04-x86 ubuntu-12.04-x86_64 ubuntu-14.04-x86 ubuntu-14.04-x86_64 debian-6.0-x86_64

# Please configure NAT before:

# Fix /etc/modprobe.d/openvz.conf to following content:
# options nf_conntrack ip_conntrack_disable_ve0=0
# vim /etc/sysct.conf

# Uncomment:
# net.ipv4.ip_forward=1
# sysctl -p
# iptables -t nat -A POSTROUTING -s 10.10.10.1/24 -o eth0 -j SNAT --to 192.168.0.241

# Save iptables config
# /etc/init.d/iptables save

export CTID=1001
export IP=10.10.10.1
export OS_TEMPLATE="centos-7-x86_64"

vzctl create 1001 --ostemplate $OS_TEMPLATE --config vswap-4g --layout simfs --ipadd $IP --diskspace 20G --hostname "$OS_TEMPLATE.test.com"

vzctl set $CTID --onboot yes --save
vzctl start $CTID

# We need this timeout for network initilization
sleep 5

vzctl exec $CTID "wget --no-check-certificate https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl -O/root/fastnetmon_install.pl"
vzctl exec $CTID "perl /root/fastnetmon_install.pl --use-git-master --create-binary-bundle --build-binary-environment"

vzctl stop $CTID
vzctl destroy $CTID

