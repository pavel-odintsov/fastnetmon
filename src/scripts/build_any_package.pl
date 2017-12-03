#!/usr/bin/perl

use strict;
use warnings;

unless (scalar @ARGV == 2) {
    die "Please specify type and original binary file name: rpm fastnetmon-binary-git-0cfdfd5e2062ad94de24f2f383576ea48e6f3a07-debian-6.0.10-x86_64";
}

my $package_type = $ARGV[0];
my $archive_name = $ARGV[1];

if ($package_type eq 'rpm') {
    build_rpm_package();
} elsif ($package_type eq 'deb') {
    build_deb_package();
}

sub build_rpm_package {
    print "Install packages for crafting rpm packages\n";
    `yum install -y rpmdevtools yum-utils`;

    mkdir '/root/rpmbuild';
    mkdir '/root/rpmbuild/SOURCES';

    my $system_v_init_script = <<'DOC';
#!/bin/bash
#
# fastnetmon        Startup script for FastNetMon 
#
# chkconfig: - 85 15
# description: FastNetMon - high performance DoS/DDoS analyzer with sflow/netflow/mirror support
# processname: fastnemon
# config: /etc/fastnetmon.conf
# pidfile: /var/run/fastnetmon.pid
#
### BEGIN INIT INFO
# Provides: fastnetmon
# Required-Start: $local_fs $remote_fs $network
# Required-Stop: $local_fs $remote_fs $network
# Should-Start: 
# Short-Description: start and stop FastNetMon
# Description:  high performance DoS/DDoS analyzer with sflow/netflow/mirror support
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

# We do not use this configs
#if [ -f /etc/sysconfig/fastnetmon ]; then
#        . /etc/sysconfig/fastnetmon
#fi


FASTNETMON=/opt/fastnetmon/fastnetmon
PROGNAME="fastnetmon"
PIDFILE=/var/run/fastnetmon.pid
RETVAL=0
ARGS="--daemonize"

start() {
        echo -n $"Starting $PROGNAME: "
        $FASTNETMON $ARGS > /dev/null 2>&1 && echo_success || echo_failure
        RETVAL=$?
        echo ""
        return $RETVAL
}

stop() {
        echo -n $"Stopping $PROGNAME: "
        killproc -p $PIDFILE $FASTNETMON
        RETVAL=$?
        echo ""
        rm -f $PIDFILE
}
reload() {
    echo "Reloading is not supported now, sorry"
    #echo -n $"Reloading $PROGNAME: "
    #kill -HUP `cat $PIDFILE`
}

# See how we were called.
case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
        status -p ${PIDFILE} $PROGNAME
    RETVAL=$?
    ;;
  restart)
    stop
        sleep 1
    start
    ;;
  reload)
        reload
    ;;
  *)
    echo $"Usage: $prog {start|stop|restart|reload|status}"
    RETVAL=2
esac

exit $RETVAL
DOC

    my $systemd_init_script = <<'DOC';
[Unit]
Description=FastNetMon - DoS/DDoS analyzer with sflow/netflow/mirror support
After=syslog.target network.target remote-fs.target
 
[Service]
Type=forking
ExecStart=/opt/fastnetmon/fastnetmon --daemonize
PIDFile=/run/fastnetmon.pid

#ExecReload=/bin/kill -s HUP $MAINPID
#ExecStop=/bin/kill -s QUIT $MAINPID
 
[Install]
WantedBy=multi-user.target
DOC

    my $rpm_sources_path = '/root/rpmbuild/SOURCES';

    # Copy bundle to build tree
    `cp $archive_name $rpm_sources_path/archive.tar.gz`;

    `wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon.conf -O$rpm_sources_path/fastnetmon.conf`;
   
    open my $system_v_init_fl, ">", "$rpm_sources_path/system_v_init";
    print {$system_v_init_fl} $system_v_init_script;
    close $system_v_init_fl;

    open my $systemd_init_fl, ">", "$rpm_sources_path/systemd_init";
    print {$systemd_init_fl} $systemd_init_script;
    close $systemd_init_fl;

    # Create files list from archive
    # ./luajit_2.0.4/
    my @files_list = `tar -tf /root/rpmbuild/SOURCES/archive.tar.gz`;
    chomp  @files_list;

    # Replace path
    @files_list = map { s#^\.#/opt#; $_ } @files_list;

    # Filter out folders
    @files_list = grep { ! m#/$# } @files_list;

    my $systemd_spec_file = <<'DOC';
#
# Pre/post params: https://fedoraproject.org/wiki/Packaging:ScriptletSnippets
#

%global  fastnetmon_attackdir   %{_localstatedir}/log/fastnetmon_attacks
%global  fastnetmon_user        root
%global  fastnetmon_group       %{fastnetmon_user}
%global  fastnetmon_config_path %{_sysconfdir}/fastnetmon.conf

Name:              fastnetmon
Version:           1.1.3
Release:           1%{?dist}

Summary:           A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).
Group:             System Environment/Daemons
License:           GPLv2
URL:               https://fastnetmon.com

# Top level fodler inside archive should be named as "fastnetmon-1.1.1" 
Source0:           http://178.62.227.110/fastnetmon_binary_repository/test_binary_builds/this_fake_path_do_not_check_it/archive.tar.gz

# Disable any sort of dynamic dependency detection for our own custom bunch of binaries
AutoReq:           no
AutoProv:          no

Requires:          libpcap, numactl, libicu
Requires(pre):     shadow-utils
Requires(post):    systemd
Requires(preun):   systemd
Requires(postun):  systemd
Provides:          fastnetmon

%description
A high performance DoS/DDoS load analyzer built on top of multiple packet capture
engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).

%prep

rm -rf fastnetmon-tree
mkdir fastnetmon-tree
mkdir fastnetmon-tree/opt
tar -xvvf /root/rpmbuild/SOURCES/archive.tar.gz -C fastnetmon-tree/opt

# Copy service scripts
mkdir fastnetmon-tree/etc
cp /root/rpmbuild/SOURCES/systemd_init fastnetmon-tree/etc
cp /root/rpmbuild/SOURCES/fastnetmon.conf fastnetmon-tree/etc

%build

# We do not build anything
exit 0

%install

mkdir %{buildroot}/opt
cp -R fastnetmon-tree/opt/* %{buildroot}/opt
chmod 755 %{buildroot}/opt/fastnetmon/fastnetmon
chmod 755 %{buildroot}/opt/fastnetmon/fastnetmon_client

# install init script
install -p -D -m 0755 fastnetmon-tree/etc/systemd_init %{buildroot}%{_sysconfdir}/systemd/system/fastnetmon.service

# install config
install -p -D -m 0644 fastnetmon-tree/etc/fastnetmon.conf %{buildroot}%{fastnetmon_config_path}

# Create log folder
install -p -d -m 0700 %{buildroot}%{fastnetmon_attackdir}

exit 0

%pre

exit 0

%post

%systemd_post fastnetmon.service

if [ $1 -eq 1 ]; then
    # It's install
    # Enable autostart
    /usr/bin/systemctl enable fastnetmon.service
    /usr/bin/systemctl start fastnetmon.service
fi


#if [ $1 -eq 2 ]; then
    # upgrade
    #/sbin/service %{name} restart >/dev/null 2>&1
#fi

%preun

%systemd_preun fastnetmon.service

%postun

%systemd_postun_with_restart fastnetmon.service 

%files
#%doc LICENSE CHANGES README

{files_list}

%{_sysconfdir}/systemd/system
%config(noreplace) %{_sysconfdir}/fastnetmon.conf
%attr(700,%{fastnetmon_user},%{fastnetmon_group}) %dir %{fastnetmon_attackdir}

%changelog
* Mon Mar 23 2015 Pavel Odintsov <pavel.odintsov@gmail.com> - 1.1.1-1
- First RPM package release
DOC

    my $spec_file = <<'DOC';
#
# Pre/post params: https://fedoraproject.org/wiki/Packaging:ScriptletSnippets
#

%global  fastnetmon_attackdir   %{_localstatedir}/log/fastnetmon_attacks
%global  fastnetmon_user        root
%global  fastnetmon_group       %{fastnetmon_user}
%global  fastnetmon_config_path %{_sysconfdir}/fastnetmon.conf

Name:              fastnetmon
Version:           1.1.3
Release:           1%{?dist}

Summary:           A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).
Group:             System Environment/Daemons
License:           GPLv2
URL:               https://fastnetmon.com

# Top level fodler inside archive should be named as "fastnetmon-1.1.1" 
Source0:           http://178.62.227.110/fastnetmon_binary_repository/test_binary_builds/this_fake_path_do_not_check_it/archive.tar.gz

# Disable any sort of dynamic dependency detection for our own custom bunch of binaries
AutoReq:           no
AutoProv:          no

Requires:          libpcap, numactl, libicu
Requires(pre):     shadow-utils
Requires(post):    chkconfig
Requires(preun):   chkconfig, initscripts
Requires(postun):  initscripts
Provides:          fastnetmon

%description
A high performance DoS/DDoS load analyzer built on top of multiple packet capture
engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).

%prep

rm -rf fastnetmon-tree
mkdir fastnetmon-tree
mkdir fastnetmon-tree/opt
tar -xvvf /root/rpmbuild/SOURCES/archive.tar.gz -C fastnetmon-tree/opt

# Copy service scripts
mkdir fastnetmon-tree/etc
cp /root/rpmbuild/SOURCES/system_v_init fastnetmon-tree/etc
cp /root/rpmbuild/SOURCES/fastnetmon.conf fastnetmon-tree/etc

%build

# We do not build anything
exit 0

%install

mkdir %{buildroot}/opt
cp -R fastnetmon-tree/opt/* %{buildroot}/opt
chmod 755 %{buildroot}/opt/fastnetmon/fastnetmon
chmod 755 %{buildroot}/opt/fastnetmon/fastnetmon_client

# install init script
install -p -D -m 0755 fastnetmon-tree/etc/system_v_init %{buildroot}%{_initrddir}/fastnetmon

# install config
install -p -D -m 0644 fastnetmon-tree/etc/fastnetmon.conf %{buildroot}%{fastnetmon_config_path}

# Create log folder
install -p -d -m 0700 %{buildroot}%{fastnetmon_attackdir}

exit 0

%pre

exit 0

%post

if [ $1 -eq 1 ]; then
    # It's install
    /sbin/chkconfig --add %{name}
    /sbin/chkconfig %{name} on
    /sbin/service %{name} start
fi


#if [ $1 -eq 2 ]; then
    # upgrade
    #/sbin/service %{name} restart >/dev/null 2>&1
#fi

%preun

# Pre remove
if [ $1 -eq 0 ]; then
    # Uninstall
    # Stops fastnetmon and disable it loading at startup
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
# Post remove

%files
#%doc LICENSE CHANGES README

{files_list}

%{_initrddir}/fastnetmon
%config(noreplace) %{_sysconfdir}/fastnetmon.conf
%attr(700,%{fastnetmon_user},%{fastnetmon_group}) %dir %{fastnetmon_attackdir}

%changelog
* Mon Mar 23 2015 Pavel Odintsov <pavel.odintsov@gmail.com> - 1.1.1-1
- First RPM package release
DOC

    my $selected_spec_file = $spec_file;

    # For CentOS we use systemd
    if ($archive_name =~ m/centos-7/) {
        $selected_spec_file = $systemd_spec_file;
    }

    my $joined_file_list = join "\n", @files_list;
    $selected_spec_file =~ s/\{files_list\}/$joined_file_list/;

    open my $fl, ">", "generated_spec_file.spec" or die "Can't create spec file\n";
    print {$fl} $selected_spec_file;
    system("rpmbuild -bb generated_spec_file.spec");

    mkdir "/tmp/result_data";
    `cp /root/rpmbuild/RPMS/x86_64/* /tmp/result_data`;
}

sub build_deb_package {
    print "We will build deb from $archive_name\n";

    my $fastnetmon_systemd_unit = <<'DOC';
[Unit]
Description=FastNetMon - DoS/DDoS analyzer with sflow/netflow/mirror support
After=network.target remote-fs.target
 
[Service]
Type=forking
ExecStart=/opt/fastnetmon/fastnetmon --daemonize
PIDFile=/run/fastnetmon.pid

#ExecReload=/bin/kill -s HUP $MAINPID
#ExecStop=/bin/kill -s QUIT $MAINPID
 
[Install]
WantedBy=multi-user.target
DOC

my $fastnetmon_systemv_init = <<'DOC';
#!/bin/sh
### BEGIN INIT INFO
# Provides:          fastnetmon
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Fast DDoS detection toolkit.
# Description:       Fast DDoS detection toolkit with sFLOW/Netflow/netmap/pf_ring support.
### END INIT INFO

# test -r /etc/default/fastnetmon && . /etc/default/fastnetmon

NAME="fastnetmon"

. /lib/lsb/init-functions

PIDFILE="/var/run/${NAME}.pid"
DAEMON="/opt/fastnetmon/fastnetmon"

DAEMON_OPTS="--daemonize"
START_OPTS="--start --background --exec ${DAEMON} -- ${DAEMON_OPTS}"
STOP_OPTS="--stop --pidfile ${PIDFILE}"
STATUS_OPTS="--status --pidfile ${PIDFILE}"

case "$1" in
  start)
        echo -n "Starting $NAME: "
    start-stop-daemon $START_OPTS
    echo "$NAME."
        ;;
  stop)
        echo -n "Stopping $NAME: "
    start-stop-daemon $STOP_OPTS
        rm -f $PIDFILE
    echo "$NAME."
        ;;
  restart)
        $0 stop
        sleep 2
        $0 start
        ;;
  force-reload)
        $0 restart
        ;;
# no support of status on Debian squeeze
#  status)
#   start-stop-daemon $STATUS_OPTS
#   ;;
  *)
        N=/etc/init.d/$NAME
        echo "Usage: $N {start|stop|restart}" >&2
        exit 1
        ;;
esac

exit 0
DOC

    # dpkg-deb: warning: '/tmp/tmp.gbd1VXGPQB/DEBIAN/control' contains user-defined field '#Standards-Version'
my $fastnetmon_control_file = <<'DOC';
Package: fastnetmon
Maintainer: Pavel Odintsov <pavel.odintsov@gmail.com>
Section: misc
Priority: optional
Architecture: amd64
Version: 1.1.3
Depends: libpcap0.8, libnuma1
Description: Very fast DDoS analyzer with sflow/netflow/mirror support
 FastNetMon - A high performance DoS/DDoS attack sensor.
DOC

    my $folder_for_build = `mktemp -d`;
    chomp $folder_for_build;

    unless (-e $folder_for_build) {
        die "Can't create temp folder\n";
    }

    chdir $folder_for_build;

    mkdir "$folder_for_build/DEBIAN";
    put_text_to_file("$folder_for_build/DEBIAN/control", $fastnetmon_control_file);

    # Create init files for different versions of Debian like OS 
    mkdir "$folder_for_build/etc";
    mkdir "$folder_for_build/etc/init.d";

    put_text_to_file("$folder_for_build/etc/init.d/fastnetmon", $fastnetmon_systemv_init);
    chmod 0755, "$folder_for_build/etc/init.d/fastnetmon";

    # systemd
    mkdir "$folder_for_build/lib";
    mkdir "$folder_for_build/lib/systemd";
    mkdir "$folder_for_build/lib/systemd/system";
 
    put_text_to_file("$folder_for_build/lib/systemd/system/fastnetmon.service", $fastnetmon_systemd_unit);

    # Configuration file
    put_text_to_file("$folder_for_build/DEBIAN/conffiles", "etc/fastnetmon.conf\n");

    # Create folder for config
    mkdir("$folder_for_build/etc");
    print `wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon.conf -O$folder_for_build/etc/fastnetmon.conf`;

    `cp $archive_name $folder_for_build/archive.tar.gz`;

    mkdir "$folder_for_build/opt";
    print `tar -xf $folder_for_build/archive.tar.gz  -C $folder_for_build/opt`;
    unlink("$folder_for_build/archive.tar.gz");

    mkdir "/tmp/result_data";
    system("dpkg-deb --build $folder_for_build /tmp/result_data/fastnetmon_package.deb");
}

sub put_text_to_file {
    my ($path, $text) = @_; 

    open my $fl, ">", $path or die "Can't open $! for writing\n";
    print {$fl} $text;
    close $fl;
}
