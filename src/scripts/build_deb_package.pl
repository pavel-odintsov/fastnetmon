#!/usr/bin/perl

use strict;
use warnings;

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

my $fastnetmon_control_file = <<'DOC';
Package: fastnetmon
Maintainer: Pavel Odintsov <pavel.odintsov@gmail.com>
Section: misc
Priority: optional
Standards-Version: 3.9.6
Architecture: amd64
Version: 1.1.3
Depends: libpcap0.8, libnuma1
Description: Very fast DDoS analyzer with sflow/netflow/mirror support
 FastNetMon - A high performance DoS/DDoS attack sensor.
DOC

build_deb();


sub put_text_to_file {
    my ($path, $text) = @_;

    open my $fl, ">", $path or die "Can't open $! for writing\n";
    print {$fl} $text;
    close $fl;
}

sub build_deb {
    my $folder_for_build = `mktemp -d`;
    chomp $folder_for_build;

    unless (-e $folder_for_build) {
        die "Can't create temp folder\n";
    }

    chdir $folder_for_build;

    mkdir "$folder_for_build/DEBIAN";
    put_text_to_file("$folder_for_build/DEBIAN/control", $fastnetmon_control_file);

    # Create init files for different versions of Debian like OS 
    put_text_to_file("$folder_for_build/DEBIAN/fastnetmon.service", $fastnetmon_systemd_unit);
    put_text_to_file("$folder_for_build/DEBIAN/fastnetmon.init", $fastnetmon_systemv_init);

    put_text_to_file("$folder_for_build/DEBIAN/conffiles", "etc/fastnetmon.conf\n");

    my $archive_path = 'http://178.62.227.110/fastnetmon_binary_repository/test_binary_builds/fastnetmon-binary-git-0cfdfd5e2062ad94de24f2f383576ea48e6f3a07-debian-6.0.10-x86_64.tar.gz';

    # Create folder for config
    mkdir("$folder_for_build/etc");
    print `wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon.conf -O$folder_for_build/etc/fastnetmon.conf`;

    print `$archive_path -O$folder_for_build/archive.tar.gz`;

    print `tar -xf $folder_for_build/archive.tar.gz  -C $folder_for_build`;
    unlink("$folder_for_build/archive.tar.gz");

    system("dpkg-deb --build $folder_for_build");
}
