#!/usr/bin/perl

use strict;
use warnings;

my $distro_type = '';
my $distro_version = '';

my $pf_ring_version = '6.0.3';

my $pf_ring_url = "https://github.com/ntop/PF_RING/archive/v$pf_ring_version.tar.gz";
my $fastnetmon_git_path = 'https://github.com/FastVPSEestiOu/fastnetmon.git';
my $stable_branch_name = 'v1.1.2';

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = '';

sub read_file {
    my $file_name = shift;

    my $res = open my $fl, "<", $file_name;

    unless ($res) {
        return "";
    }

    my $content = join '', <$fl>;
    chomp $content;

    return $content;
}

# Detect VyOS
if (-e "/etc/issue") {
    my $issue_content = read_file("/etc/issue");

    if ($issue_content =~ /Welcome to VyOS/) {
        $appliance_name = 'vyos';
    }
}

if (-e "/etc/debian_version") {
    $distro_type = 'debian';

    $distro_version = `cat /etc/debian_version`;
    chomp $distro_version;

    # VyOS have strange version and we should fix it
    if ($distro_version =~ /^(\d+)\.\d+\.\d+$/) {
        $distro_version = $1;
    }
}

if (-e "/etc/redhat-release") {
    $distro_type = 'centos';

    my $distro_version_raw = `cat /etc/redhat-release`;
    chomp $distro_version_raw;

    # CentOS 6:
    # CentOS release 6.6 (Final)
    # CentOS 7:
    # CentOS Linux release 7.0.1406 (Core) 
    # Fedora release 21 (Twenty One)
    if ($distro_version_raw =~ /(\d+)/) {
        $distro_version = $1;
    }    
}

unless ($distro_type) {
    die "This distro is unsupported, please do manual install";
}

install();

sub install {
    my $kernel_version = `uname -r`;
    chomp $kernel_version;

    my $we_have_pfring_support = '';

    print "Install PF_RING dependency with package manager\n";

    if ($distro_type eq 'debian') {
        `apt-get update`;
        my @debian_packages_for_pfring = ('build-essential', 'bison', 'flex',
            'libnuma-dev', 'wget', 'tar', 'make', 'dpkg-dev', 'dkms', 'debhelper');
   
        my $kernel_headers_package_name = "linux-headers-$kernel_version";
  
        if ($appliance_name eq 'vyos') { 
            # VyOS uses another name for package for building kernel modules
            $kernel_headers_package_name = 'linux-vyatta-kbuild';
        }

        push @debian_packages_for_pfring, $kernel_headers_package_name;
    
        # We install one package per apt-get call because installing multiple packages in one time could fail of one
        # pacakge broken
        for my $package (@debian_packages_for_pfring) {
            `apt-get install -y --force-yes $package`;

            if ($? != 0) {
                print "Package '$package' install failed with code $?\n"
            }  
        }


        if ($appliance_name eq 'vyos') {
            # By default we waven't this symlink and should add it manually
            `ln -s /usr/src/linux-image/debian/build/build-amd64-none-amd64-vyos/ /lib/modules/$kernel_version/build`;
        }
    } elsif ($distro_type eq 'centos') {
        my $kernel_package_name = 'kernel-devel';

        # Fix deplist for OpenVZ
        if ($kernel_version =~ /stab/) {
            $kernel_package_name = "vzkernel-devel-$kernel_version";
        }

        `yum install -y make bison flex $kernel_package_name gcc gcc-c++ dkms numactl-devel`;
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

    print "Unload PF_RING if it was installed earlier\n";
    `rmmod pf_ring`;

    print "Load PF_RING module into kernel\n";
    `modprobe pf_ring`;

    my @dmesg = `dmesg`;
    chomp @dmesg;
    
    if (scalar grep (/\[PF_RING\] Initialized correctly/, @dmesg) > 0) {
        print "PF_RING loaded correctly\n";

        $we_have_pfring_support = 1;
    } else {
        warn "PF_RING load error! We disable PF_RING plugin\n";

        $we_have_pfring_support = '';
    }

    if ($we_have_pfring_support) {
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
    }

    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian') {
        my @fastnetmon_deps = ("git", "g++", "gcc", "libgpm-dev", "libncurses5-dev",
            "liblog4cpp5-dev", "libnuma-dev", "libgeoip-dev","libpcap-dev", "clang", "cmake"
        );

        # We add this dependencies because package libboost-all-dev is broken on VyOS
        if ($appliance_name eq 'vyos') {
            push @fastnetmon_deps, ('libboost-regex-dev', 'libboost-system-dev', 'libboost-thread-dev');
        } else {
            push @fastnetmon_deps, "libboost-all-dev";
        }

        # We install one package per apt-get call because installing multiple packages in one time could fail of one
        # package is broken
        for my $package (@fastnetmon_deps) {
            `apt-get install -y --force-yes $package`;

            if ($? != 0) {
                print "Package '$package' install failed with code $?\n"
            }
        }
    } elsif ($distro_type eq 'centos') {
        my @fastnetmon_deps = ('git', 'make', 'gcc', 'gcc-c++', 'boost-devel', 'GeoIP-devel', 'log4cpp-devel',
            'ncurses-devel', 'glibc-static', 'ncurses-static', 'boost-thread', 'libpcap-devel', 'gpm-static',
            'gpm-devel', 'clang', 'cmake'
        );

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        `yum install -y $fastnetmon_deps_as_string`;
    }

    print "Clone FastNetMon repo\n";
    chdir "/usr/src";

    my $fastnetmon_code_dir = "/usr/src/fastnetmon/src";

    if (-e $fastnetmon_code_dir) {
        # Code already downloaded
        chdir $fastnetmon_code_dir;
        `git pull`;
    } else {
        # Update code
        `git clone $fastnetmon_git_path --branch $stable_branch_name`;
    }

    `mkdir -p $fastnetmon_code_dir/build`;
    chdir "$fastnetmon_code_dir/build";

    my $cmake_params = "";

    unless ($we_have_pfring_support) {
        $cmake_params .= " -DDISABLE_PF_RING_SUPPORT=ON";
    }

    if ($distro_type eq 'centos' && $distro_version == 6) {
        # Disable cmake script from Boost package because it's broken:
        # http://public.kitware.com/Bug/view.php?id=15270
        $cmake_params .= " -DBoost_NO_BOOST_CMAKE=BOOL:ON";
    }

    `cmake .. $cmake_params`;
    `make`;

    my $fastnetmon_dir = "/opt/fastnetmon";
    my $fastnetmon_build_binary_path = "$fastnetmon_code_dir/build/fastnetmon";

    unless (-e $fastnetmon_build_binary_path) {
        die "Can't build fastnetmon!";
    }

    mkdir $fastnetmon_dir;

    print "Install fastnetmon to dir $fastnetmon_dir\n";
    `cp $fastnetmon_build_binary_path $fastnetmon_dir/fastnetmon`;
    `cp $fastnetmon_code_dir/build/fastnetmon_client $fastnetmon_dir/fastnetmon_client`;

    my $fastnetmon_config_path = "/etc/fastnetmon.conf";
    unless (-e $fastnetmon_config_path) {
        print "Create stub configuration file\n";
        `cp $fastnetmon_code_dir/fastnetmon.conf $fastnetmon_config_path`;
    
        my @interfaces = get_active_network_interfaces();
        my $interfaces_as_list = join ',', @interfaces;
        print "Select $interfaces_as_list as active interfaces\n";

        print "Tune config\n";
        `sed -i 's/interfaces.*/interfaces = $interfaces_as_list/' $fastnetmon_config_path`;
    }

    # If we are on systemd distro
    if ( ($distro_type eq 'debian' && $distro_version >= 7) or ($distro_type eq 'centos' && $distro_version >= 7) ) {
        my $systemd_service_path = "/etc/systemd/system/fastnetmon.service";
        `cp $fastnetmon_code_dir/fastnetmon.service $systemd_service_path`;
 
        `sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $systemd_service_path`;

        print "We found systemd enabled distro and created service: fastnetmon.service\n";
        print "You could run it with command: systemctl start fastnetmon.service\n";        
    }

    print "Please add your subnets in /etc/networks_list in CIDR format one subnet per line\n";
    print "You can run fastnetmon with command: $fastnetmon_dir/fastnetmon\n";
}

sub get_active_network_interfaces {
    my @interfaces = `LANG=C netstat -i|egrep -v 'lo|Iface|Kernel'|awk '{print \$1}'`;
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
