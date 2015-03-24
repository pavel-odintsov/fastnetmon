#!/usr/bin/env bash

# Script for building RPM packages for FastNetMon
# http://www.stableit.ru/2009/12/rpm-centos-5.html

# yum install -y rpmdevtools yum-utils 
# Build deps: yum install -y boost-devel GeoIP-devel log4cpp-devel ncurses-devel boost-thread boost-regex libpcap-devel gpm-devel clang log4cpp-devel

VERSION=1.1.1
mkdir vzapi-$VERSION

mkdir -p /root/rpmbuild/SOURCES
# Folder inside archive should be named as "fastnetmon-1.1.1"
wget https://github.com/FastVPSEestiOu/fastnetmon/archive/master.zip -O"/root/rpmbuild/SOURCES/fastnetmon-$VERSION.tar.gz"
#wget https://github.com/FastVPSEestiOu/fastnetmon/archive/v1.1.1.tar.gz -O"/root/rpmbuild/SOURCES/fastnetmon-$VERSION.tar.gz"

# Download spec file 
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon.spec -Ofastnetmon.spec

# TODO: drop CentOS 5 support
# Cross build for Centos5/centos6:
# http://www.stableit.ru/2013/11/how-to-build-rpm-package-for-rhel5-on.html
rpmbuild -bb fastnetmon.spec

# For CentOS 7 we should build log4cpp library
# Prepare log4cpp spec file:

# yum install -y automake libtool
# cd /usr/src
# wget 'http://sourceforge.net/projects/log4cpp/files/latest/download?source=files' -O/usr/src/log4cpp-1.1.1.tar.gz
# tar -xf log4cpp-1.1.1.tar.gz
# cd log4cpp
# ./configure --prefix=/opt/log4cpp

# In current folder we will get log4cpp file log4cpp.spec
# But it's buggy and pelase get log4cpp.spec from FastNetMon repo 

# Build log4cpp rpm package:
# wget 'http://sourceforge.net/projects/log4cpp/files/latest/download?source=files' -O/root/rpmbuild/SOURCES/log4cpp-1.1.1.tar.gz
# rpmbuild -bb log4cpp.spec 
