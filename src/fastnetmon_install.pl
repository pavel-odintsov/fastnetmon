#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;

my $pf_ring_version = '6.0.3';
my $pf_ring_url = "https://github.com/ntop/PF_RING/archive/v$pf_ring_version.tar.gz";

my $fastnetmon_git_path = 'https://github.com/FastVPSEestiOu/fastnetmon.git';
my $fastnetmon_code_dir = "/usr/src/fastnetmon/src";

# Official mirror: https://github.com/ntop/nDPI.git
# But we have some patches for NTP and DNS protocols here
my $ndpi_repository = 'https://github.com/pavel-odintsov/nDPI.git';

my $stable_branch_name = 'v1.1.2';
my $we_use_code_from_master = '';

my $distro_type = ''; 
my $distro_version = ''; 
# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = ''; 

# Get options from command line
GetOptions('use-git-master' => \$we_use_code_from_master);

my $we_have_ndpi_support = '';
my $we_have_luajit_support = '';
my $we_have_pfring_support = '';

if ($we_use_code_from_master) {
    $we_have_ndpi_support = 1;
    $we_have_luajit_support = 1;
}

main();

### Functions start here
sub main {
    detect_distribution();

    install_pf_ring();

    if ($we_have_ndpi_support) {
        install_ndpi();
    }

    if ($we_have_luajit_support) {
        install_luajit();
        install_luajit_libs();
    }

    install_fastnetmon();
}

sub install_luajit {
    chdir "/usr/src";

    print "Download Luajit\n";
    `wget http://luajit.org/download/LuaJIT-2.0.4.tar.gz`;

    print "Unpack Luajit\n";
    `tar -xf LuaJIT-2.0.4.tar.gz`;
    chdir "LuaJIT-2.0.4";

    `sed -i 's#export PREFIX= /usr/local#export PREFIX= /opt/luajit_2.0.4#' Makefile`; 

    print "Build and install Luajit";
    `make install`;

    put_library_path_to_ld_so("/etc/ld.so.conf.d/luajit.conf", "/opt/luajit_2.0.4/lib");
}

sub install_luajit_libs {
    install_lua_lpeg();
    install_lua_json();
} 

sub install_lua_lpeg {
    print "Install LUA lpeg module\n";

    print "Download archive\n";
    chdir "/usr/src";
    `wget http://www.inf.puc-rio.br/~roberto/lpeg/lpeg-0.12.2.tar.gz`;

    `tar -xf lpeg-0.12.2.tar.gz`;
    chdir "lpeg-0.12.2";

    # Set path
    print "Install lpeg library\n";
    `sed -i 's#LUADIR = ../lua/#LUADIR = /opt/luajit_2.0.4/include/luajit-2.0#' makefile`; 
    `cp lpeg.so /opt/luajit_2.0.4/lib/lua/5.1`;
}

sub install_lua_json {
    print "Install LUA json module\n";
    
    chdir "/usr/src";

    print "Download archive\n";
    `wget https://github.com/harningt/luajson/archive/1.3.3.tar.gz`;
    `tar -xf 1.3.3.tar.gz`;

    chdir "luajson-1.3.3";

    print "Install it\n";
    `PREFIX=/opt/luajit_2.0.4 make install`;
}

sub install_init_scripts {
    # Init file for any systemd aware distro
    if ( ($distro_type eq 'debian' && $distro_version > 7) or ($distro_type eq 'centos' && $distro_version >= 7) ) {
        my $systemd_service_path = "/etc/systemd/system/fastnetmon.service";
        `cp $fastnetmon_code_dir/fastnetmon.service $systemd_service_path`;

        `sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $systemd_service_path`;

        print "We found systemd enabled distro and created service: fastnetmon.service\n";
        print "You could run it with command: systemctl start fastnetmon.service\n";

        return 1;
    }

    # Init file for CentOS 6
    if ($distro_type eq 'centos' && $distro_version == 6) {
        my $system_init_path = '/etc/init.d/fastnetmon';
        `cp $fastnetmon_code_dir/fastnetmon_init_script_centos6 $system_init_path`;

        `sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $system_init_path`;

        print "We created service fastnetmon for you\n";
        print "You could run it with command: /etc/init.d/fastnetmon start\n";

        return 1;
    }

    # For Gentoo
    if ( $distro_type eq 'gentoo' ) {
        my $init_path_in_src = "$fastnetmon_code_dir/fastnetmon_init_script_gentoo";
        my $system_init_path = '/etc/init.d/fastnetmon';

        # Checker for source code version, will work only for 1.1.3+ versions
        if (-e $init_path_in_src) {
            `cp $init_path_in_src $system_init_path`;

            print "We created service fastnetmon for you\n";
            print "You could run it with command: /etc/init.d/fastnetmon start\n";

            return 1;
        }
    }

    # For Debian Squeeze and Wheezy 
    # And any stable Ubuntu version
    if ( ($distro_type eq 'debian' && ($distro_version == 6 or $distro_version == 7)) or $distro_type eq 'ubuntu') {
        my $init_path_in_src = "$fastnetmon_code_dir/fastnetmon_init_script_debian_6_7";
        my $system_init_path = '/etc/init.d/fastnetmon';

        # Checker for source code version, will work only for 1.1.3+ versions
        if (-e $init_path_in_src) {
           `cp $init_path_in_src $system_init_path`;

            `sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $system_init_path`;

            print "We created service fastnetmon for you\n";
            print "You could run it with command: /etc/init.d/fastnetmon start\n";

            return 1;
        }
    }
}

# We use global variable $ndpi_repository here
sub install_ndpi {
    if ($distro_type eq 'debian') {
        `apt-get update`;
        `apt-get install -y --force-yes git autoconf`;
    } elsif ($distro_type eq 'centos') {
        `yum install -y git autoconf automake libtool`;
    }   

    if (-e "/usr/src/nDPI") {
        # Get new code from the repository
        chdir "/usr/src/nDPI";
        `git pull`;
    } else {
        chdir "/usr/src";
        `git clone $ndpi_repository`;
        chdir "/usr/src/nDPI";
    }   

    `./autogen.sh`;
    `./configure --prefix=/opt/ndpi`;

    `make install`;

    print "Add ndpi to ld.so.conf\n";
    put_library_path_to_ld_so("/etc/ld.so.conf.d/ndpi.conf", "/opt/ndpi/lib"); 
}

sub put_library_path_to_ld_so {
    my ($ld_so_file_path, $library_path) = @_; 

    open my $ld_so_conf_handle, ">", $ld_so_file_path or die "Can't open $! for writing\n";
    print {$ld_so_conf_handle} $library_path;
    close $ld_so_conf_handle;

    `ldconfig`;
}

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

# Detect operating system of this machine
sub detect_distribution { 
    # We use following global variables here:
    # $distro_type, $distro_version, $appliance_name

    if (-e "/etc/debian_version") {
        # Well, on this step it could be Ubuntu or Debian

        # We need check issue for more details 
        my @issue = `cat /etc/issue`;
        chomp @issue;

        my $issue_first_line = $issue[0];

        # Possible /etc/issue contents: 
        # Debian GNU/Linux 8 \n \l
        # Ubuntu 14.04.2 LTS \n \l
        # Welcome to VyOS - \n \l 
        if ($issue_first_line =~ m/Debian/) {
            $distro_type = 'debian';

            $distro_version = `cat /etc/debian_version`;
            chomp $distro_version;
        } elsif ($issue_first_line =~ m/Ubuntu (\d+)/) {
            $distro_type = 'ubuntu';
            $distro_version = $1;
        } elsif ($issue_first_line =~ m/VyOS/) {
            # Yes, VyOS is a Debian
            $distro_type = 'debian';
            $appliance_name = 'vyos';

            my $vyos_distro_version = `cat /etc/debian_version`;
            chomp $vyos_distro_version;

            # VyOS have strange version and we should fix it
            if ($vyos_distro_version =~ /^(\d+)\.\d+\.\d+$/) {
                $distro_version = $1;
            }
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

    if (-e "/etc/gentoo-release") {
        $distro_type = 'gentoo';

        my $distro_version_raw = `cat /etc/gentoo-release`;
        chomp $distro_version_raw;
    }

    unless ($distro_type) {
        die "This distro is unsupported, please do manual install";
    }

}

sub install_pf_ring {
    my $pf_ring_archive_path = "/usr/src/PF_RING-$pf_ring_version.tar.gz";
    my $pf_ring_sources_path = "/usr/src/PF_RING-$pf_ring_version";

    my $kernel_version = `uname -r`;
    chomp $kernel_version;

    my $we_could_install_kernel_modules = 1;

    # TODO: we should offer some way to build only userspace library 
    if (-e "/.dockerinit") {
        # On Docker we can't build kernel modules
        $we_could_install_kernel_modules = 0;
    }
 
    print "Install PF_RING dependencies with package manager\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        `apt-get update`;
        my @debian_packages_for_pfring = ('build-essential', 'bison', 'flex', 'subversion',
            'libnuma-dev', 'wget', 'tar', 'make', 'dpkg-dev', 'dkms', 'debhelper');
  
        # Install kernel headers only when we could compile kernel modules there
        if ($we_could_install_kernel_modules) {
            my $kernel_headers_package_name = "linux-headers-$kernel_version";
  
            if ($appliance_name eq 'vyos') { 
                # VyOS uses another name for package for building kernel modules
                $kernel_headers_package_name = 'linux-vyatta-kbuild';
            }

            push @debian_packages_for_pfring, $kernel_headers_package_name;
        }    

        # We install one package per apt-get call because installing multiple packages in one time could fail of one
        # pacakge broken
        for my $package (@debian_packages_for_pfring) {
            `apt-get install -y --force-yes $package`;

            if ($? != 0) {
                print "Package '$package' install failed with code $?\n"
            }  
        }

        if ($appliance_name eq 'vyos' && $we_could_install_kernel_modules) {
            # By default we waven't this symlink and should add it manually

            # x86_64 or i686
            my $server_architecture = `uname -m`;
            chomp $server_architecture;

            if ($server_architecture eq 'x86_64') {  
                `ln -s /usr/src/linux-image/debian/build/build-amd64-none-amd64-vyos/ /lib/modules/$kernel_version/build`;
            } else {
                # i686
                `ln -s /usr/src/linux-image/debian/build/build-i386-none-586-vyos/ /lib/modules/$kernel_version/build`;
            }
        }
    } elsif ($distro_type eq 'centos') {
        my $kernel_package_name = 'kernel-devel';

        # Fix deplist for OpenVZ
        if ($kernel_version =~ /stab/) {
            $kernel_package_name = "vzkernel-devel-$kernel_version";
        }

        `yum install -y make bison flex $kernel_package_name gcc gcc-c++ dkms numactl-devel subversion`;
    } elsif ($distro_type eq 'gentoo') {
        my @gentoo_packages_for_pfring = ('subversion', 'sys-process/numactl', 'wget', 'tar');

        my $gentoo_packages_for_pfring_as_string = join " ", @gentoo_packages_for_pfring;
        `emerge -vu $gentoo_packages_for_pfring_as_string`;

        if ($? != 0) {
            print "Emerge fail with code $?\n";
        }
    }

    if ($we_could_install_kernel_modules) {
        print "Download PF_RING $pf_ring_version sources\n";

        `wget --quiet $pf_ring_url -O$pf_ring_archive_path`;
   
        if ($? == 0) {
            print "Unpack PF_RING\n";
            mkdir $pf_ring_sources_path;
            `tar -xf $pf_ring_archive_path -C /usr/src`;

            print "Build PF_RING kernel module\n";
            `make -C $pf_ring_sources_path/kernel clean`;
            `make -C $pf_ring_sources_path/kernel`;
            `make -C $pf_ring_sources_path/kernel install`;

            print "Unload PF_RING if it was installed earlier\n";
            `rmmod pf_ring 2>/dev/null`;

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
        } else {
            warn "Can't download PF_RING source code. Disable support of PF_RING\n";
        } 
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
        put_library_path_to_ld_so("/etc/ld.so.conf.d/pf_ring.conf", "/opt/pf_ring/lib");
    }
}

sub install_fastnetmon {
    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @fastnetmon_deps = ("git", "g++", "gcc", "libgpm-dev", "libncurses5-dev",
            "liblog4cpp5-dev", "libnuma-dev", "libgeoip-dev","libpcap-dev", "clang", "cmake", "pkg-config", "libhiredis-dev",
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
            'gpm-devel', 'clang', 'cmake', 'pkgconfig', 'hiredis-devel',
        );

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        `yum install -y $fastnetmon_deps_as_string`;

        if ($distro_version == 7) {
            print "Your distro haven't log4cpp in stable EPEL packages and we install log4cpp from testing of EPEL\n";
            `yum install -y https://kojipkgs.fedoraproject.org//packages/log4cpp/1.1.1/1.el7/x86_64/log4cpp-devel-1.1.1-1.el7.x86_64.rpm https://kojipkgs.fedoraproject.org//packages/log4cpp/1.1.1/1.el7/x86_64/log4cpp-1.1.1-1.el7.x86_64.rpm`;
        }
    } elsif ($distro_type eq 'gentoo') {
        my @fastnetmon_deps = ("dev-vcs/git", "gcc", "sys-libs/gpm", "sys-libs/ncurses", "dev-libs/log4cpp", "dev-libs/geoip", 
            "net-libs/libpcap", "dev-util/cmake", "pkg-config", "dev-libs/hiredis", "dev-libs/boost"
        );

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        `emerge -vu $fastnetmon_deps_as_string`;

        if ($? != 0) {
            print "Emerge fail with code $?\n";
        }
    }

    print "Clone FastNetMon repo\n";
    chdir "/usr/src";

    if (-e $fastnetmon_code_dir) {
        # Code already downloaded
        chdir $fastnetmon_code_dir;

        # Switch to master if we on stable branch
        if ($we_use_code_from_master) {
            `git checkout master`;
            printf("\n");
        }

        `git pull`;
    } else {
        # Pull new code
    if ($we_use_code_from_master) {
            `git clone $fastnetmon_git_path --quiet 2>/dev/null`;
        } else {
            `git clone $fastnetmon_git_path --branch $stable_branch_name --quiet 2>/dev/null`;
        }

        if ($? != 0) {
            die "Can't clone source code\n";
        }
    }

    `mkdir -p $fastnetmon_code_dir/build`;
    chdir "$fastnetmon_code_dir/build";

    my $cmake_params = "";

    # So, we have this option in master branch ;)
    if ($we_use_code_from_master) {
        $cmake_params .= " -DENABLE_DPI_SUPPORT=ON";
    }

    unless ($we_have_pfring_support) {
        $cmake_params .= " -DDISABLE_PF_RING_SUPPORT=ON";
    }

    if ($we_have_luajit_support) {
        $cmake_params .= " -DENABLE_LUA_SUPPORT=ON";
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

    print "If you have any issues, please check /var/log/fastnetmon.log file contents\n";
    print "Please add your subnets in /etc/networks_list in CIDR format one subnet per line\n";

    my $init_script_result = install_init_scripts();

    # Print unified run message 
    unless ($init_script_result) {
        print "You can run fastnetmon with command: $fastnetmon_dir/fastnetmon\n";
    }
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

