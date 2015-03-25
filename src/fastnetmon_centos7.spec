#
# Pre/post params: https://fedoraproject.org/wiki/Packaging:ScriptletSnippets
#

%global  fastnetmon_attackdir   %{_localstatedir}/log/fastnetmon_attacks
%global  fastnetmon_user        root
%global  fastnetmon_group       %{fastnetmon_user}
%global  fastnetmon_config_path %{_sysconfdir}/fastnetmon.conf

Name:              fastnetmon
Version:           1.1.1
Release:           1%{?dist}

Summary:           A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).
Group:             System Environment/Daemons
License:           GPLv2
URL:               https://github.com/FastVPSEestiOu/fastnetmon

# Top level fodler inside archive should be named as "fastnetmon-1.1.1" 
#Source0:           https://github.com/FastVPSEestiOu/fastnetmon/archive/v%{version}.tar.gz
Source0:            https://github.com/FastVPSEestiOu/fastnetmon/archive/fastnetmon-%{version}.tar.gz

# Yes, it's bad idea to specify fixed version of PF_RING but they have strange issue when we use another library version 

BuildRequires:     git, make, gcc, gcc-c++, boost-devel, GeoIP-devel, log4cpp-devel
BuildRequires:     ncurses-devel, boost-thread, boost-regex, libpcap-devel, gpm-devel, clang, cmake
BuildRequires:     pfring >= 6.0.3-9154
BuildRequires:     systemd

Requires:          pfring >= 6.0.3-9154
Requires:          log4cpp, libpcap, boost-thread, boost-thread, boost-regex
Requires(pre):     shadow-utils
Requires(post):    systemd
Requires(preun):   systemd
Requires(postun):  systemd

Provides:          fastnetmon

%description
A high performance DoS/DDoS load analyzer built on top of multiple packet capture
engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).

%prep
# For production
# %setup -n fastnetmon-%{version}
# Testing
# Specify name of folder inside rpm package
%setup -n fastnetmon-master

%build
cd src
mkdir build
cd build
# You could disable PF_RING support with param: -DDISABLE_PF_RING_SUPPORT=ON
cmake .. -DWE_USE_PFRING_FROM_NTOP=ON
make

%install
# install init script
install -p -D -m 0755 src/fastnetmon.service %{buildroot}%{_sysconfdir}/systemd/system/fastnetmon.service

# install daemon binary file
install -p -D -m 0755 src/build/fastnetmon %{buildroot}%{_sbindir}/fastnetmon

# install client binary file 
install -p -D -m 0755 src/build/fastnetmon_client %{buildroot}%{_bindir}/fastnetmon_client

# install config
install -p -D -m 0755 src/fastnetmon.conf %{buildroot}%{fastnetmon_config_path}

# Create log folder
install -p -d -m 0700 %{buildroot}%{fastnetmon_attackdir}

%pre

exit 0

%post
%systemd_post fastnetmon.service

if [ $1 -eq 1 ]; then
    # It's install
    # Enable autostart
    /usr/bin/systemctl enable fastnetmon.service
    /usr/bin/systemctl start fastnetmon.service

    # Fix pfring issue with library path
    echo "/usr/local/lib" > /etc/ld.so.conf.d/pfring.conf
    /sbin/ldconfig
fi


if [ $1 -eq 2 ]; then
    # upgrade
    chmod 700 %{fastnetmon_attackdir}
fi

%preun
%systemd_preun fastnetmon.service

# Pre remove
#if [ $1 -eq 0 ]; then
    # Uninstall
#fi

%postun
%systemd_postun_with_restart fastnetmon.service 

%files
#%doc LICENSE CHANGES README
# init.d script
%{_sysconfdir}/systemd/system

# binary daemon
%{_sbindir}/fastnetmon
%{_bindir}/fastnetmon_client

%config(noreplace) %{_sysconfdir}/fastnetmon.conf
%attr(700,%{fastnetmon_user},%{fastnetmon_group}) %dir %{fastnetmon_attackdir}


%changelog
* Mon Mar 23 2015 Pavel Odintsov <pavel.odintsov@gmail.com> - 1.1.1-1
- First RPM package release
