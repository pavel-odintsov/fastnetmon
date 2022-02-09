#!/usr/bin/perl

use strict;
use warnings;

unless (scalar @ARGV == 3) {
    die "Please specify type, original binary file name and version: rpm fastnetmon-binary-git-0cfdfd5e2062ad94de24f2f383576ea48e6f3a07-debian-6.0.10-x86_64 2.0.1";
}


my $package_type = $ARGV[0];
my $archive_name = $ARGV[1];
my $package_version = $ARGV[2];

unless ($package_type && $archive_name && $package_version) {
    die "Please specify package type, archive name and package version\n";
}

# Gzip does not compress well, let's use xz instead
my $dpkg_deb_options = '-Zxz -z1';

my $debian_architecture_name = 'amd64';

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
# processname: fastnetmon
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
    
    print `ls -la /tmp/result_data`;
}

sub build_deb_package {
    print "We will build deb from $archive_name\n";

    my $fastnetmon_systemd_unit = <<'DOC';
[Unit]
Description=FastNetMon - DoS/DDoS analyzer with sFlow/netflow/mirror support
After=network.target remote-fs.target
 
[Service]
Type=forking
ExecStart=/opt/fastnetmon/fastnetmon --daemonize
PIDFile=/run/fastnetmon.pid
 
[Install]
WantedBy=multi-user.target
DOC

my $fastnetmon_upstart_init = <<'DOC';
description "FastNetMon DDoS detection daemon"
author "Pavel Odintsov <pavel.odintsov@gmail.com>"

start on (filesystem and net-device-up IFACE=lo and started mongod)
stop on runlevel [!2345]

env DAEMON=/opt/fastnetmon/fastnetmon
env DAEMON_OPTIONS="--daemonize"
env PID=/run/fastnetmon.pid

# Expect 2 forks from service
expect daemon
#respawn
#respawn limit 10 5
#oom never

# We are using SIGINT for correct shutdown instead of SIGTERM
kill signal SIGINT

# We should give some time to polite tool shutdown
# and we will wait this time until we send SIGKILL to toolkit
kill timeout 5

exec $DAEMON $DAEMON_OPTIONS
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

my $fastnetmon_control_file = <<DOC;
Package: fastnetmon
Maintainer: Pavel Odintsov <pavel.odintsov\@gmail.com>
Section: misc
Priority: optional
Architecture: $debian_architecture_name
Version: $package_version
Description: Very fast DDoS analyzer with sFlow/Netflow/IPFIX and mirror support
 FastNetMon - A high performance DoS/DDoS attack sensor.
DOC

my $fastnetmon_prerm_hook = <<DOC;
#!/bin/sh

# Stop fastnetmon correctly
/usr/sbin/service fastnetmon stop

exit 0
DOC

# Prevent /opt remove by apt-get remove of our package
# http://stackoverflow.com/questions/13021002/my-deb-file-removes-opt
my $fastnetmon_server_postrm_hook = <<DOC;
#!/bin/sh

# If apt-get decided to remove /opt, let's create it again
/bin/mkdir -p -m 755 /opt
/bin/chmod 755 /opt

exit 0
DOC

my $fastnetmon_postinst_hook = <<DOC;
#!/bin/sh

if [ -e "/sbin/initctl" ]; then
    # Update Upstart configuration
    /sbin/initctl reload-configuration
else
    # Update systemd configuration
    /bin/systemctl daemon-reload
fi

# Start daemon correctly
/usr/sbin/service fastnetmon start

exit 0
DOC

    my $folder_for_build = `mktemp -d`;
    chomp $folder_for_build;

    unless (-e $folder_for_build) {
        die "Can't create temp folder\n";
    }

    # I see no reasons why we should keep it secure
    system("chmod 755 $folder_for_build");

    chdir $folder_for_build;

    mkdir "$folder_for_build/DEBIAN";
    put_text_to_file("$folder_for_build/DEBIAN/control", $fastnetmon_control_file);
    
    put_text_to_file("$folder_for_build/DEBIAN/prerm", $fastnetmon_prerm_hook);
    put_text_to_file("$folder_for_build/DEBIAN/postinst", $fastnetmon_postinst_hook);
    put_text_to_file("$folder_for_build/DEBIAN/postrm", $fastnetmon_server_postrm_hook);

    `chmod +x $folder_for_build/DEBIAN/postrm`;
    `chmod +x $folder_for_build/DEBIAN/prerm`;
    `chmod +x $folder_for_build/DEBIAN/postinst`;

    # Create init files for different versions of Debian like OS 
    mkdir "$folder_for_build/etc";
    mkdir "$folder_for_build/etc/init";
    mkdir "$folder_for_build/etc/init.d";

    put_text_to_file("$folder_for_build/etc/init.d/fastnetmon", $fastnetmon_systemv_init);
    chmod 0755, "$folder_for_build/etc/init.d/fastnetmon";

    # Create folders for system service file
    mkdir "$folder_for_build/lib";
    mkdir "$folder_for_build/lib/systemd";
    mkdir "$folder_for_build/lib/systemd/system";

    # Create symlinks to call commands without full path
    mkdir "$folder_for_build/usr";
    mkdir "$folder_for_build/usr/bin";

    system("ln -s /opt/fastnetmon/fastnetmon_client $folder_for_build/usr/bin/fastnetmon_client");
    system("ln -s /opt/fastnetmon/fastnetmon_api_client $folder_for_build/usr/bin/fastnetmon_api_client");
    system("ln -s /opt/fastnetmon/fastnetmon $folder_for_build/usr/bin/fastnetmon");

    put_text_to_file("$folder_for_build/lib/systemd/system/fastnetmon.service", $fastnetmon_systemd_unit);
    put_text_to_file("$folder_for_build/etc/init/fastnetmon.conf", $fastnetmon_upstart_init);

    # Configuration file
    put_text_to_file("$folder_for_build/DEBIAN/conffiles", "etc/fastnetmon.conf\n");

    # Create folder for config
    mkdir("$folder_for_build/etc");
    print `wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon.conf -O$folder_for_build/etc/fastnetmon.conf`;

    `cp $archive_name $folder_for_build/archive.tar.gz`;

    mkdir "$folder_for_build/opt";
    `chmod 755 $folder_for_build/opt`;

    print `tar -xf $folder_for_build/archive.tar.gz  -C $folder_for_build/opt`;
    # unlink("$folder_for_build/archive.tar.gz");

    # Set new permissions again. Probably, they was overwritten by tar -xf command
    `chmod 755 $folder_for_build/opt`;

    # Change owner to root for all files inside build folder
    system("sudo chown root:root -R $folder_for_build");

    my $deb_build_command = "dpkg-deb  --debug  --verbose $dpkg_deb_options --build $folder_for_build /tmp/fastnetmon_${package_version}_${debian_architecture_name}.deb";

    print "Build command: $deb_build_command\n";

    system($deb_build_command);
}

sub put_text_to_file {
    my ($path, $text) = @_; 

    open my $fl, ">", $path or die "Can't open $! for writing\n";
    print {$fl} $text;
    close $fl;
}
