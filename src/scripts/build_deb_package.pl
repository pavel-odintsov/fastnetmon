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
    put_text_to_file("$folder_for_build/DEBIAN/fastnetmon.service", $fastnetmon_systemd_unit);

    put_text_to_file("$folder_for_build/DEBIAN/conffiles", "etc/fastnetmon.conf\n");

    # Create folder for config
    mkdir("$folder_for_build/etc");
    print `wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon.conf -O$folder_for_build/etc/fastnetmon.conf`;

    print `wget http://178.62.227.110/fastnetmon_binary_repository/test_binary_builds/fastnetmon-binary-git-28894964690011c5aa076bb92d8536fa4f641757-debian-8.1-x86_64.tar.gz -O$folder_for_build/archive.tar.gz`;

    print `tar -xf $folder_for_build/archive.tar.gz  -C $folder_for_build`;
    unlink("$folder_for_build/archive.tar.gz");

    system("dpkg-deb --build $folder_for_build");
}
