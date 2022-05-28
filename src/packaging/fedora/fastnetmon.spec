%global  fastnetmon_attackdir      %{_localstatedir}/log/fastnetmon_attacks
%global  fastnetmon_user           fastnetmon
%global  fastnetmon_group          %{fastnetmon_user}
%global  fastnetmon_config_path    %{_sysconfdir}/fastnetmon.conf

%global  commit0 420e7b873253fdc1b52b517d9c28db39bf384427
%global  shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%global  date 20220528

Name:              fastnetmon
Version:           1.2.1
Release:           1.%{date}git%{shortcommit0}%{?dist}

Summary:           A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFlow, PCAP)
License:           GPLv2
URL:               https://fastnetmon.com

Source0:           https://github.com/pavel-odintsov/fastnetmon/archive/%{commit0}.tar.gz
Source1:           fastnetmon.sysusers

BuildRequires:     make
BuildRequires:     gcc
BuildRequires:     gcc-c++
BuildRequires:     boost-devel
BuildRequires:     log4cpp-devel
BuildRequires:     ncurses-devel
BuildRequires:     boost-thread
BuildRequires:     boost-regex
BuildRequires:     libpcap-devel
BuildRequires:     gpm-devel
BuildRequires:     cmake
BuildRequires:     capnproto-devel
BuildRequires:     capnproto
BuildRequires:     grpc-devel
BuildRequires:     grpc-cpp
BuildRequires:     abseil-cpp-devel
BuildRequires:     grpc-plugins
BuildRequires:     mongo-c-driver-devel
BuildRequires:     json-c-devel
BuildRequires:     systemd
BuildRequires:     systemd-rpm-macros

Requires(pre):     shadow-utils

%{?systemd_requires}

%description
A high performance DoS/DDoS load analyzer built on top of multiple packet capture
engines (NetFlow, IPFIX, sFlow, PCAP).

%prep
%autosetup -n %{name}-%{commit0}

%build

%cmake -DENABLE_CUSTOM_BOOST_BUILD=FALSE -DDO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD=FALSE -DCMAKE_SKIP_BUILD_RPATH=TRUE -DLINK_WITH_ABSL=TRUE -S src

%cmake_build

%install
# install systemd unit file
install -p -D -m 0644 src/packaging/fedora/fastnetmon.service %{buildroot}%{_unitdir}/fastnetmon.service

# install daemon binary
install -p -D -m 0755 %__cmake_builddir/fastnetmon %{buildroot}%{_sbindir}/fastnetmon

# install client binary 
install -p -D -m 0755 %__cmake_builddir/fastnetmon_client %{buildroot}%{_bindir}/fastnetmon_client

# install api client binary
install -p -D -m 0755 %__cmake_builddir/fastnetmon_api_client %{buildroot}%{_bindir}/fastnetmon_api_client

# install config
install -p -D -m 0644 src/fastnetmon.conf %{buildroot}%{fastnetmon_config_path}

# Create log folder
install -p -d -m 0700 %{buildroot}%{fastnetmon_attackdir}

# Create sysuser manifest to create dynamic user for us
install -D -p -m 0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/fastnetmon.conf

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post fastnetmon.service

%preun
%systemd_preun fastnetmon.service

%postun
%systemd_postun_with_restart fastnetmon.service 

%files

%{_unitdir}/fastnetmon.service

%{_sysusersdir}/fastnetmon.conf

# Binary daemon
%{_sbindir}/fastnetmon
%{_bindir}/fastnetmon_client
%{_bindir}/fastnetmon_api_client

%config(noreplace) %{fastnetmon_config_path}
%attr(700,%{fastnetmon_user},%{fastnetmon_group}) %dir %{fastnetmon_attackdir}

%license LICENSE
%doc README.md SECURITY.md THANKS.md

%changelog
* Sat May 28 2022 Pavel Odintsov <pavel.odintsov@gmail.com> - 1.2.1-1
- First RPM package release

