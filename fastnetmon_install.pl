#!/usr/bin/perl

use strict;
use warnings;

my $distro_type = '';
my $distro_version = '';

my $pf_ring_version = '6.0.2';
my $pf_ring_url = "http://sourceforge.net/projects/ntop/files/PF_RING/PF_RING-$pf_ring_version.tar.gz/download";
my $fastnetmon_git_path = 'https://github.com/FastVPSEestiOu/fastnetmon.git';

if (-e "/etc/debian_version") {
    $distro_type = 'debian';

    $distro_version = `cat /etc/debian_version`;
    chomp $distro_version;
}

if (-e "/etc/redhat-release") {
    $distro_type = 'centos';

    $distro_version = `cat /etc/redhat-release | awk '{print \$3}'`;
    chomp $distro_version;
}

unless ($distro_type) {
    die "This distro is unsupported, please do manual install";
}

install();

sub install {
    my $kernel_version = `uname -r`;
    chomp $kernel_version;

    print "Install PF_RING dependency with package manager\n";

    if ($distro_type eq 'debian') {
        `apt-get update`;
        `apt-get install -y --force-yes build-essential bison flex linux-headers-$kernel_version libnuma-dev wget tar make`;
    } elsif ($distro_type eq 'centos') {
        my $kernel_package_name = 'kernel-devel';

        # Fix deplist for OpenVZ
        if ($kernel_version =~ /stab/) {
            $kernel_package_name = 'vzkernel-devel';
        }

        `yum install -y make bison flex $kernel_package_name gcc gcc-c++`;
    }

    print "Download PF_RING $pf_ring_version sources\n";

    my $pf_ring_archive_path = "/usr/src/PF_RING-$pf_ring_version.tar.gz";
    my $pf_ring_sources_path = "/usr/src/PF_RING-$pf_ring_version";

    `wget $pf_ring_url -O$pf_ring_archive_path`;
    
    print "Unpack PF_RING\n";
    mkdir $pf_ring_sources_path;
    `tar -xf $pf_ring_archive_path -C /usr/src`;
    
    print "Build PF_RING kernel module\n";
    `make -C $pf_ring_sources_path/kernel clean`;
    `make -C $pf_ring_sources_path/kernel`;
    `make -C $pf_ring_sources_path/kernel install`;

    print "Unloade PF_RING if it was installed earlier\n";
    `rmmod pf_ring`;

    print "Load PF_RING module into kernel\n";
    `modprobe pf_ring`;

    my @dmesg = `dmesg`;
    chomp @dmesg;
    
    if (scalar grep (/\[PF_RING\] Initialized correctly/, @dmesg) > 0) {
        print "PF_RING loaded correctly\n";
    } else {
        die "PF_RING load error!";
    }

    print "Build PF_RING lib\n";
    # Because we can't run configure from another folder because it can't find ZC dependency :(
    chdir "$pf_ring_sources_path/userland/lib";
    `./configure --prefix=/opt/pf_ring_$pf_ring_version`;
    `make`;
    `make install`; 

    print "Create library symlink\n";
    unlink "/opt/pf_ring";
    `ln -s /opt/pf_ring_$pf_ring_version /opt/pf_ring`;

    print "Add pf_ring to ld.so.conf\n";
    my $pf_ring_ld_so_conf = "/etc/ld.so.conf.d/pf_ring.conf";
    
    open my $pf_ring_ld_so_conf_handle, ">", $pf_ring_ld_so_conf or die "Can't open $! for writing\n";
    print {$pf_ring_ld_so_conf_handle} "/opt/pf_ring/lib";
    close $pf_ring_ld_so_conf_handle;

    print "Run ldconfig\n";
    `ldconfig`; 

    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian') {
        my @fastnetmon_deps = ("git", "g++", "gcc", "libboost-all-dev", "libgpm-dev", "libncurses5-dev", "liblog4cpp5-dev", "libnuma-dev", "libgeoip-dev","libpcap-dev");

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        `apt-get install -y --force-yes $fastnetmon_deps_as_string`;
    } elsif ($distro_type eq 'centos') {
        my @fastnetmon_deps = ('git', 'make', 'gcc', 'gcc-c++', 'boost-devel', 'GeoIP-devel', 'log4cpp-devel', 'ncurses-devel', 'glibc-static', 'ncurses-static', 'boost-thread', 'libpcap-devel', 'gpm-static', 'gpm-devel');

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        `yum install -y $fastnetmon_deps_as_string`;
    }

    print "Clone FastNetMon repo\n";
    chdir "/usr/src";
    `git clone $fastnetmon_git_path`;

    chdir "/usr/src/fastnetmon";

    # Hmmmmmm..... I reinvented configure! :'(
    if ($distro_type eq 'centos') {
        `sed -i 's/boost_thread/boost_thread-mt/' Makefile`;
    }

    `make`;

    my $fastnetmon_dir = "/opt/fastnetmon";

    my $fastnetmon_build_binary_path = "/usr/src/fastnetmon/fastnetmon";

    unless (-e $fastnetmon_build_binary_path) {
        die "Can't build fastnetmon!";
    }

    mkdir $fastnetmon_dir;

    print "Install fastnetmon to dir $fastnetmon_dir";
    `cp $fastnetmon_build_binary_path $fastnetmon_dir/fastnetmon`;

    my $fastnetmon_config_path = "/etc/fastnetmon.conf";
    unless (-e $fastnetmon_config_path) {
        print "Create stub conif\n";
        `cp fastnetmon.conf $fastnetmon_config_path`;
    
        my @interfaces = get_active_network_interfaces();
        my $interfaces_as_list = join ',', @interfaces;
        print "Select $interfaces_as_list as active interfaces\n";

        print "Tune config\n";
        `sed -i 's/interfaces.*/interfaces = $interfaces_as_list/' $fastnetmon_config_path`;
    }

    print "Please add your subnets in /etc/networks_list in CIDR format one subnet per line\n";
    print "You can run fastnetmon with command: $fastnetmon_dir/fastnetmon\n";
}

sub get_active_network_interfaces {
    my @interfaces = `netstat -i|egrep -v 'lo|Iface|Kernel'|awk '{print \$1}'`;
    chomp @interfaces;

    my @clean_interfaces = ();

    for my $iface (@interfaces) {
        # skip aliases
        if ($iface =~ /:/) {
            next;
        }

        push @clean_interfaces, $iface;
    }

    return  @clean_interfaces;
}
