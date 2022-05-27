%global  fastnetmon_attackdir      %{_localstatedir}/log/fastnetmon_attacks
%global  fastnetmon_user           root
%global  fastnetmon_group          %{fastnetmon_user}
%global  fastnetmon_config_path    %{_sysconfdir}/fastnetmon.conf
%global  fastnetmon_logrotate_path %{_sysconfdir}/logrotate.d/fastnetmon

%global  fastnetmon_commit       master
%global  fastnetmon_project_name fastnetmon
%global  fastnetmon_company      FastNetMon LTD

Name:              fastnetmon
Version:           1.2.2
Release:           1%{?dist}

Summary:           A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFlow, PCAP).
License:           GPLv2
URL:               https://fastnetmon.com

Source0:           https://github.com/pavel-odintsov/fastnetmon/archive/master.tar.gz

BuildRequires:     git
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

Provides:          fastnetmon

%description
A high performance DoS/DDoS load analyzer built on top of multiple packet capture
engines (NetFlow, IPFIX, sFlow, PCAP).

%prep
%autosetup -n %{name}-%{fastnetmon_commit}

%build

%cmake -DENABLE_CUSTOM_BOOST_BUILD=FALSE -DDO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD=FALSE -DCMAKE_SKIP_BUILD_RPATH=TRUE -DLINK_WITH_ABSL=TRUE src

%cmake_build

%install
# install systemd unit file
install -p -D -m 0644 src/fastnetmon_fedora.service %{buildroot}%{_unitdir}/fastnetmon.service

# install daemon binary
install -p -D -m 0755 %__cmake_builddir/fastnetmon %{buildroot}%{_sbindir}/fastnetmon

# install client binary 
install -p -D -m 0755 %__cmake_builddir/fastnetmon_client %{buildroot}%{_bindir}/fastnetmon_client

# install api client binary
install -p -D -m 0755 %__cmake_builddir/fastnetmon_api_client %{buildroot}%{_bindir}/fastnetmon_api_client

# install config
install -p -D -m 0644 src/fastnetmon.conf %{buildroot}%{fastnetmon_config_path}

# install logrotate confioguration
install -p -D -m 0644 src/fastnetmon_logrotate  %{buildroot}%{fastnetmon_logrotate_path}

# Create log folder
install -p -d -m 0700 %{buildroot}%{fastnetmon_attackdir}

# Create sysuser manifest to create dynamic user for us
install -D -p -m 0644 src/fastnetmon.sysusers %{buildroot}%{_sysusersdir}/fastnetmon.conf

%pre
%sysusers_create_compat src/fastnetmon.sysusers

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
%config(noreplace) %{fastnetmon_logrotate_path}
%attr(700,%{fastnetmon_user},%{fastnetmon_group}) %dir %{fastnetmon_attackdir}

%changelog
* Saturday May 27 2022 Pavel Odintsov <pavel.odintsov@gmail.com> - 1.2.2-1
- First RPM package release

