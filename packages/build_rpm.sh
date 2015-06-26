#!/usr/bin/env bash

# Script for building RPM packages for FastNetMon
# http://www.stableit.ru/2009/12/rpm-centos-5.html

# yum install -y rpmdevtools yum-utils 
# Build deps:
# yum install -y boost-devel GeoIP-devel log4cpp-devel ncurses-devel boost-thread boost-regex libpcap-devel gpm-devel 
# yum install -y clang log4cpp-devel cmake gcc git gcc-c++ 

VERSION=1.1.1
mkdir vzapi-$VERSION

mkdir -p /root/rpmbuild/SOURCES
# Folder inside archive should be named as "fastnetmon-1.1.1"
wget https://github.com/FastVPSEestiOu/fastnetmon/archive/master.zip -O"/root/rpmbuild/SOURCES/fastnetmon-$VERSION.tar.gz"

# For Fedora package we use specific commit
# wget https://github.com/FastVPSEestiOu/fastnetmon/archive/86b951b6dffae0fc1e6cbf66fe5f0f4aa61aaa5a/fastnetmon-86b951b6dffae0fc1e6cbf66fe5f0f4aa61aaa5a.tar.gz  -O"/root/rpmbuild/SOURCES/fastnetmon-86b951b6dffae0fc1e6cbf66fe5f0f4aa61aaa5a.tar.gz" 

# Download spec file 
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_centos6.spec -Ofastnetmon_centos6.spec
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_centos7.spec -Ofastnetmon_centos7.spec

# http://www.stableit.ru/2013/11/how-to-build-rpm-package-for-rhel5-on.html
# Build binary and source package
rpmbuild -ba fastnetmon.spec

# For CentOS 7 we will use log4cpp from EPEL 7 testing repository: http://koji.fedoraproject.org/koji/buildinfo?buildID=623067
