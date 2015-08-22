#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;

my $pf_ring_version = '6.0.3';
my $pf_ring_url = "https://github.com/ntop/PF_RING/archive/v$pf_ring_version.tar.gz";

my $fastnetmon_git_path = 'https://github.com/FastVPSEestiOu/fastnetmon.git';

my $temp_folder_for_building_project = `mktemp -d /tmp/fastnetmon.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    die "Can't create temp folder in /tmp for building project: $temp_folder_for_building_project\n";
}

my $start_time = time();

my $fastnetmon_code_dir = "$temp_folder_for_building_project/fastnetmon/src";

my $install_log_path = '/tmp/fastnetmon_install.log';

# Official mirror: https://github.com/ntop/nDPI.git
# But we have some patches for NTP and DNS protocols here
my $ndpi_repository = 'https://github.com/pavel-odintsov/nDPI.git';

my $stable_branch_name = 'v1.1.2';
my $we_use_code_from_master = '';

my $distro_type = ''; 
my $distro_version = ''; 
my $distro_architecture = '';

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = ''; 

# So, you could disable this option but without this feature we could not improve FastNetMon for your distribution
my $do_not_track_me = '';

my $cpus_number = get_logical_cpus_number();

# We could pass options to make with this variable
my $make_options = '';

# We could pass options to configure with this variable
my $configure_options = '';

# We could get huge speed benefits with this option
if ($cpus_number > 1) {
    print "You have really nice server with $cpus_number CPU's and we will use they all for build process :)\n";
    $make_options = "-j $cpus_number";
}

# We will build gcc, stdc++ and boost for this distribution from sources
my $build_binary_environment = '';

# With this option we could build full binary package
my $create_binary_bundle = '';

# Get options from command line
GetOptions(
    'use-git-master' => \$we_use_code_from_master,
    'do-not-track-me' => \$do_not_track_me,
    'build-binary-environment' => \$build_binary_environment,
    'create-binary-bundle' => \$create_binary_bundle,
);

my $we_have_ndpi_support = '';
my $we_have_luajit_support = '';
my $we_have_hiredis_support = '';
my $we_have_log4cpp_support = '';

# Actually, we haven't PF_RING on some platforms
my $we_have_pfring_support = 1;

if ($we_use_code_from_master) {
    $we_have_ndpi_support = 1;
    $we_have_luajit_support = 1;
    $we_have_hiredis_support = 1;
    $we_have_log4cpp_support = 1;
}

main();

sub get_logical_cpus_number {
    my @cpuinfo = `cat /proc/cpuinfo`;
    chomp @cpuinfo;
        
    my $cpus_number = scalar grep {/processor/} @cpuinfo;
    
    return $cpus_number;
}

sub install_additional_repositories {
    if ($distro_type eq 'centos') {
        if ($distro_version == 6) {
            print "Install EPEL repository for your system\n"; 
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm');
        }    

        if ($distro_version == 7) {
            print "Install EPEL repository for your system\n"; 
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm');
        } 
    }
}

### Functions start here
sub main {
    detect_distribution();

    # CentOS base repository is very very poor and we need EPEL for some dependencies
    install_additional_repositories();

    # Refresh information about packages
    init_package_manager();

    send_tracking_information('started');

    if ($build_binary_environment) {
        install_gcc();
        install_boost_builder();
        install_boost();
    }

    if ($we_have_pfring_support) {
        install_pf_ring();
    }

    if ($we_use_code_from_master) {
        install_json_c();
    }   

    if ($we_have_ndpi_support) {
        install_ndpi();
    }

    if ($we_have_luajit_support) {
        install_luajit();
        install_luajit_libs();
    }

    if ($we_have_hiredis_support) {
        install_hiredis();
    }

    if ($we_have_log4cpp_support) {
        install_log4cpp();
    }

    install_fastnetmon();

    send_tracking_information('finished');

    if ($create_binary_bundle) {
        create_binary_bundle();
    }

    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
}

sub create_binary_bundle {
    chdir $temp_folder_for_building_project;
    chdir "fastnetmon";

    my $bundle_version = '';

    if ($we_use_code_from_master) {
        my $git_last_commit_id = `git log --format="%H" -n 1`;
        chomp $git_last_commit_id;

        $bundle_version = "git-$git_last_commit_id";
    } else {
        $bundle_version = $stable_branch_name;
    }

    my $bundle_file_name = "fastnetmon-binary-$bundle_version-$distro_type-$distro_version-$distro_architecture.tar.gz";
    my $full_bundle_path = "/tmp/$bundle_file_name";

    print "We will create bundle with name $bundle_file_name\n";

    exec_command("$temp_folder_for_building_project/fastnetmon/src/scripts/build_libary_bundle.pl $full_bundle_path");
    print "You could download bundle here $full_bundle_path\n";
}

sub send_tracking_information {
    my $step = shift;

    unless ($do_not_track_me) {
        my $stats_url = "http://178.62.227.110/new_fastnetmon_installation";
        my $post_data = "distro_type=$distro_type&distro_version=$distro_version&distro_architecture=$distro_architecture&step=$step";
        my $user_agent = 'FastNetMon install tracker v1';

        `wget --post-data="$post_data" --user-agent="$user_agent" -q '$stats_url'`;
    }
}

sub exec_command {
    my $command = shift;

    open my $fl, ">>", $install_log_path;
    print {$fl} "We are calling command: $command\n\n";
 
    my $output = `$command 2>&1 >> $install_log_path`;
  
    print {$fl} "Command finished with code $?\n\n";

    if ($? == 0) {
        return 1;
    } else {
        return '';
    }
}

sub get_sha1_sum {
    my $path = shift;
    my $output = `sha1sum $path`;
    chomp $output;
    
    my ($sha1) = ($output =~ m/^(\w+)\s+/);

    return $sha1;
}

sub download_file {
    my ($url, $path, $expected_sha1_checksumm) = @_;

    `wget --no-check-certificate --quiet '$url' -O$path`;

    if ($? != 0) {
        print "We can't download archive $url correctly\n";
        return '';
    }

    if ($expected_sha1_checksumm) {
        if (get_sha1_sum($path) eq $expected_sha1_checksumm) {
            return 1;
        } else {
            print "Downloaded archive has incorrect sha1\n";
            return '';
        }      
    } else {
        return 1;
    }     
}

sub install_binary_gcc {
    my $binary_repository_path = 'http://192.168.0.127/~pavel-odintsov/FastNetMon_gcc_toolchain';
    my $package_distro_version = '';

    if ($distro_type eq 'debian') {
        # Debian 6: 6.0.10
        # Debian 7: 7.8
        # Debian 8: 8.1

        if ($distro_version =~ m/^(6)/) {
            $package_distro_version = $1;
        } else {
            $package_distro_version = int($distro_version);
        }
    } elsif ($distro_type eq 'ubuntu') {
        $package_distro_version = $distro_version;
    } elsif ($distro_type eq 'centos') {
        $package_distro_version = $distro_version;
    }

    chdir $temp_folder_for_building_project;

    my $distribution_file_name = "gcc-5.2.0-$distro_type-$package_distro_version-$distro_architecture.tar.gz"; 
    my $full_path = "$binary_repository_path/$distribution_file_name";

    print "We will try to download prebuilded binary gcc package for your distribution\n";
    print "We will download from $full_path\n";
    my $gcc_binary_download_result = download_file($full_path, $distribution_file_name);

    unless ($gcc_binary_download_result) {
        print "Download failed, skip to source compilation\n";
        return '';
    }

    print "Unpack gcc binary package\n";
    # Unpack file to opt
    exec_command("tar -xf $distribution_file_name -C /opt"); 

    return 1;
}

sub install_gcc {
    my $result = install_binary_gcc();

    # Add new compiler to configure options
    # It's mandatory for log4cpp
    $configure_options = "CC=/opt/gcc520/bin/gcc CXX=/opt/gcc520/bin/g++";

    # More detailes about jam lookup: http://www.boost.org/build/doc/html/bbv2/overview/configuration.html

    # We use non standard gcc compiler for Boost builder and Boost and specify it this way
    open my $fl, ">", "/root/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$fl} "using gcc : 5.2 : /opt/gcc520/bin/g++ ;\n";
    close $fl;

    # When we run it with vzctl exec we ahve broken env and should put config in /etc too
    open my $etcfl, ">", "/etc/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$etcfl} "using gcc : 5.2 : /opt/gcc520/bin/g++ ;\n";
    close $etcfl; 

    # Install gcc from sources
    if ($distro_type eq 'debian') {
        my @dependency_list = ('libmpfr-dev', 'libmpc-dev');

        if ($distro_version <= 7) {
            # We have another name for Debian 6 Squeeze
            push @dependency_list, 'libgmp3-dev';
        } else {
            push @dependency_list, 'libgmp-dev';
        }

        apt_get(@dependency_list);
    } elsif ($distro_type eq 'ubuntu') {
        my @dependency_list = ('libmpfr-dev', 'libmpc-dev', 'libgmp-dev');

        apt_get(@dependency_list);
    } elsif ($distro_type eq 'centos') {
        if ($distro_version == 6) { 
            # We haven't libmpc in base repository here and should enable EPEL
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm');
        }    

        my @dependency_list = ('gmp-devel', 'mpfr-devel', 'libmpc-devel');

        yum(@dependency_list);
    } 

    # Please be careful! This libs required for binary version of gcc! We should install they!
    # Do not call source compilation in this case
    if ($result) {
        return;
    }    

    print "Download gcc archive\n";
    chdir $temp_folder_for_building_project;

    my $archive_file_name = 'gcc-5.2.0.tar.gz';
    my $gcc_download_result = download_file("ftp://ftp.mpi-sb.mpg.de/pub/gnu/mirror/gcc.gnu.org/pub/gcc/releases/gcc-5.2.0/$archive_file_name", $archive_file_name, '713211883406b3839bdba4a22e7111a0cff5d09b');

    unless ($gcc_download_result) {
        die "Can't download gcc sources\n";
    }

    print "Unpack archive\n";
    exec_command("tar -xf $archive_file_name");
    exec_command("mkdir $temp_folder_for_building_project/gcc-5.2.0-objdir");

    chdir "$temp_folder_for_building_project/gcc-5.2.0-objdir";

    print "Configure build system\n";
    exec_command("$temp_folder_for_building_project/gcc-5.2.0/configure --prefix=/opt/gcc520 --enable-languages=c,c++ --disable-multilib");

    print "Build gcc\n";
    exec_command("make $make_options");
    exec_command("make $make_options install");

    # We do not add it to ld.so.conf.d path because it could broke system
}

sub install_boost {
    chdir '/opt';
    my $archive_file_name = 'boost_1_58_0.tar.gz';

    print "Install Boost dependencies\n";

    # libicu dependencies
    if ($distro_type eq 'ubuntu') {

        if ($distro_version eq '14.04') {
            apt_get('libicu52');
        }

        if ($distro_version eq '12.04') {
            apt_get('libicu48');
        }
    }

    print "Download Boost source code\n";
    my $boost_download_result = download_file("http://downloads.sourceforge.net/project/boost/boost/1.58.0/boost_1_58_0.tar.gz?r=http%3A%2F%2Fwww.boost.org%2Fusers%2Fhistory%2Fversion_1_58_0.html&ts=1439207367&use_mirror=cznic", $archive_file_name, 'a27b010b9d5de0c07df9dddc9c336767725b1e6b');

    unless ($boost_download_result) {
        die "Can't download Boost source code\n";
    }

    print "Unpack Boost source code\n";
    exec_command("tar -xf $archive_file_name");
    
    # Remove archive
    unlink "$archive_file_name";

    chdir "boost_1_58_0";

    print "Build Boost\n";
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path 
    # So without HOME=/root nothing worked correctly due to another "openvz" feature
    my $b2_build_result = exec_command("HOME=/root PATH=\$PATH:/opt/gcc520/bin /opt/boost_build1.5.8/bin/b2 --build-dir=/tmp/boost_build_temp_directory_1_5_8 toolset=gcc-5.2 --without-test --without-python --without-wave --without-graph --without-coroutine --without-math --without-log --without-graph_parallel --without-mpi"); 

    # We should not do this check because b2 build return bad return code even in success case... when it can't build few non important targets
    unless ($b2_build_result) {
        ### die "Can't execute b2 build correctly\n";
    }
}

sub install_boost_builder { 
    chdir $temp_folder_for_building_project;

    # We need libc headers for compilation of this code
    if ($distro_type eq 'centos') {
        yum('glibc-devel');
    }

    # We use another name because it uses same name as boost distribution
    my $archive_file_name = 'boost-builder-1.58.0.tar.gz';

    print "Download boost builder\n";
    my $boost_build_result = download_file("https://github.com/boostorg/build/archive/boost-1.58.0.tar.gz", $archive_file_name,
        'e86375ed83ed07a79a33c76e80e8648d969b3218');

    unless ($boost_build_result) {
        die "Can't download boost builder\n";
    }

    print "Unpack boost builder\n";
    exec_command("tar -xf $archive_file_name");

    chdir "build-boost-1.58.0";

    print "Build Boost builder\n";
    # We haven't system compiler here and we will use custom gcc for compilation here
    my $bootstrap_result = exec_command("CC=/opt/gcc520/bin/gcc CXX=/opt/gcc520/bin/g++ ./bootstrap.sh --with-toolset=cc");

    unless ($bootstrap_result) {
        die "bootstrap of Boost Builder failed, please check logs\n";
    }

    # We should specify toolset here if we want to do build with custom compiler
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path 
    my $b2_install_result = exec_command("PATH=\$PATH:/opt/gcc520/bin ./b2 install --prefix=/opt/boost_build1.5.8 toolset=gcc");
    
    unless ($b2_install_result) {
        die "Can't execute b2 install\n";
    }
}

sub install_luajit {
    chdir $temp_folder_for_building_project;

    my $archive_file_name = "LuaJIT-2.0.4.tar.gz";

    print "Download Luajit\n";
   
    my $luajit_download_result = download_file(
        "http://luajit.org/download/$archive_file_name",
        $archive_file_name,
        '6e533675180300e85d12c4bbeea2d0e41ad21172'
    ); 

    unless ($luajit_download_result) {
        die "Can't download luajit\n";
    }

    print "Unpack Luajit\n";
    exec_command("tar -xf LuaJIT-2.0.4.tar.gz");
    chdir "LuaJIT-2.0.4";

    exec_command("sed -i 's#export PREFIX= /usr/local#export PREFIX= /opt/luajit_2.0.4#' Makefile"); 

    print "Build and install Luajit\n";
    exec_command("make $make_options install");

    put_library_path_to_ld_so("/etc/ld.so.conf.d/luajit.conf", "/opt/luajit_2.0.4/lib");
}

sub install_luajit_libs {
    install_lua_lpeg();
    install_lua_json();
} 

sub install_lua_lpeg {
    print "Install LUA lpeg module\n";

    print "Download archive\n";
    chdir $temp_folder_for_building_project;

    my $archive_file_name = 'lpeg-0.12.2.tar.gz';

    my $lpeg_download_result = download_file("http://www.inf.puc-rio.br/~roberto/lpeg/$archive_file_name",
        $archive_file_name, '69eda40623cb479b4a30fb3720302d3a75f45577'); 

    unless ($lpeg_download_result) {
        die "Can't download lpeg\n";
    }

    exec_command("tar -xf lpeg-0.12.2.tar.gz");
    chdir "lpeg-0.12.2";

    # Set path
    print "Install lpeg library\n";
    exec_command("sed -i 's#LUADIR = ../lua/#LUADIR = /opt/luajit_2.0.4/include/luajit-2.0#' makefile");
    exec_command("make $make_options");
    exec_command("cp lpeg.so /opt/luajit_2.0.4/lib/lua/5.1");
}

sub install_json_c {
    my $archive_name  = 'json-c-0.12-20140410.tar.gz';
    my $install_path = '/opt/json-c-0.12';

    print "Install json library\n";

    chdir $temp_folder_for_building_project;

    print "Download archive\n";
    
    my $json_c_download_result = download_file("https://github.com/json-c/json-c/archive/$archive_name",
        $archive_name,
        'b33872f8b2837c7909e9bd8734855669c57a67ce');

    unless ($json_c_download_result) {
        die "Can't download json-c sources\n";
    }
    
    print "Uncompress it\n";       
    exec_command("tar -xf $archive_name");
    chdir "json-c-json-c-0.12-20140410";

    # Fix bugs (assigned but not used variable) which prevent code compilation 
    exec_command("sed -i '355 s#^#//#' json_tokener.c");
    exec_command("sed -i '360 s#^#//#' json_tokener.c");

    print "Build it\n";
    exec_command("./configure --prefix=$install_path");

    print "Install it\n";
    exec_command("make $make_options install");

    put_library_path_to_ld_so("/etc/ld.so.conf.d/json-c.conf", "$install_path/lib");
}

sub install_lua_json {
    print "Install LUA json module\n";
    
    chdir $temp_folder_for_building_project;

    print "Download archive\n";

    my $archive_file_name = '1.3.3.tar.gz';

    my $lua_json_download_result = download_file("https://github.com/harningt/luajson/archive/$archive_file_name", $archive_file_name,
        '53455f697c3f1d7cc955202062e97bbafbea0779');

    unless ($lua_json_download_result) {
        die "Can't download lua json\n";
    }

    exec_command("tar -xf $archive_file_name");

    chdir "luajson-1.3.3";

    print "Install it\n";
    exec_command("PREFIX=/opt/luajit_2.0.4 make $make_options install");
}

sub install_init_scripts {
    # Init file for any systemd aware distro
    if ( ($distro_type eq 'debian' && $distro_version > 7) or ($distro_type eq 'centos' && $distro_version >= 7) ) {
        my $systemd_service_path = "/etc/systemd/system/fastnetmon.service";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.service $systemd_service_path");

        exec_command("sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $systemd_service_path");

        print "We found systemd enabled distro and created service: fastnetmon.service\n";
        print "You could run it with command: systemctl start fastnetmon.service\n";

        return 1;
    }

    # Init file for CentOS 6
    if ($distro_type eq 'centos' && $distro_version == 6) {
        my $system_init_path = '/etc/init.d/fastnetmon';
        exec_command("cp $fastnetmon_code_dir/fastnetmon_init_script_centos6 $system_init_path");

        exec_command("sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $system_init_path");

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
            exec_command("cp $init_path_in_src $system_init_path");

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
           exec_command("cp $init_path_in_src $system_init_path");

            exec_command("sed -i 's#/usr/sbin/fastnetmon#/opt/fastnetmon/fastnetmon#' $system_init_path");

            print "We created service fastnetmon for you\n";
            print "You could run it with command: /etc/init.d/fastnetmon start\n";

            return 1;
        }
    }
}

sub install_log4cpp {
    my $distro_file_name = 'log4cpp-1.1.1.tar.gz';
    my $log4cpp_url = 'https://sourceforge.net/projects/log4cpp/files/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.1.tar.gz/download';
    my $log4cpp_install_path = '/opt/log4cpp1.1.1';

    chdir $temp_folder_for_building_project;

    print "Download log4cpp sources\n";
    my $log4cpp_download_result = download_file($log4cpp_url, $distro_file_name, '23aa5bd7d6f79992c92bad3e1c6d64a34f8fcf68');

    unless ($log4cpp_download_result) {
        die "Can't download log4cpp\n";
    }

    print "Unpack log4cpp sources\n";
    exec_command("tar -xf $distro_file_name");
    chdir "$temp_folder_for_building_project/log4cpp";

    print "Build log4cpp\n";

    # TODO: we need some more reliable way to specify options here
    if ($configure_options) {
        exec_command("$configure_options ./configure --prefix=$log4cpp_install_path");
    } else {
        exec_command("./configure --prefix=$log4cpp_install_path");
    }    

    exec_command("make $make_options install"); 

    print "Add log4cpp to ld.so.conf\n";
    put_library_path_to_ld_so("/etc/ld.so.conf.d/log4cpp.conf", "$log4cpp_install_path/lib");
}

sub install_hiredis {
    my $disto_file_name = 'v0.13.1.tar.gz'; 
    my $hiredis_install_path = '/opt/libhiredis_0_13';

    chdir $temp_folder_for_building_project;

    print "Download hiredis\n";
    my $hiredis_download_result = download_file("https://github.com/redis/hiredis/archive/$disto_file_name",
        $disto_file_name, '737c4ed101096c5ec47fcaeba847664352d16204');

    unless ($hiredis_download_result) {
        die "Can't download hiredis\n";
    }

    exec_command("tar -xf $disto_file_name");

    print "Build hiredis\n";
    chdir "hiredis-0.13.1";
    exec_command("PREFIX=$hiredis_install_path make $make_options install");

    print "Add hiredis to ld.so.conf\n";
    put_library_path_to_ld_so("/etc/ld.so.conf.d/hiredis.conf", "$hiredis_install_path/lib"); 
}

# We use global variable $ndpi_repository here
sub install_ndpi {
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        apt_get('git', 'autoconf', 'libtool', 'automake', 'libpcap-dev');
    } elsif ($distro_type eq 'centos') {
        # We have json-c-devel for CentOS 6 and 7 and will use it for nDPI build system
        yum('git', 'autoconf', 'automake', 'libtool', 'libpcap-devel', 'json-c-devel');
    }   

    print "Download nDPI\n";
    if (-e "$temp_folder_for_building_project/nDPI") {
        # Get new code from the repository
        chdir "$temp_folder_for_building_project/nDPI";
        exec_command("git pull");
    } else {
        chdir $temp_folder_for_building_project;
        exec_command("git clone $ndpi_repository");
        chdir "$temp_folder_for_building_project/nDPI";
    }   

    print "Configure nDPI\n";
    exec_command("./autogen.sh");

    # We have specified direct path to json-c here because it required for example app compilation
    exec_command("PKG_CONFIG_PATH=/opt/json-c-0.12/lib/pkgconfig ./configure --prefix=/opt/ndpi");

   if ($? != 0) {
        print "Configure failed\n";
        return;
    }

    print "Build and install nDPI\n";
    exec_command("make $make_options install");

    print "Add ndpi to ld.so.conf\n";
    put_library_path_to_ld_so("/etc/ld.so.conf.d/ndpi.conf", "/opt/ndpi/lib"); 
}

sub init_package_manager { 

    print "Update package manager cache\n";
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        exec_command("apt-get update");
    }
}

sub put_library_path_to_ld_so {
    my ($ld_so_file_path, $library_path) = @_; 

    open my $ld_so_conf_handle, ">", $ld_so_file_path or die "Can't open $! for writing\n";
    print {$ld_so_conf_handle} $library_path;
    close $ld_so_conf_handle;

    exec_command("ldconfig");
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

    # x86_64 or i686
    $distro_architecture = `uname -m`;
    chomp $distro_architecture;

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

            # Debian 6 example: 6.0.10
            # We will try transform it to decimal number
            if ($distro_version =~ /^(\d+\.\d+)\.\d+$/) {
                $distro_version = $1;
            }
        } elsif ($issue_first_line =~ m/Ubuntu (\d+(?:\.\d+)?)/) {
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
    my $pf_ring_archive_path = "$temp_folder_for_building_project/PF_RING-$pf_ring_version.tar.gz";
    my $pf_ring_sources_path = "$temp_folder_for_building_project/PF_RING-$pf_ring_version";

    my $kernel_version = `uname -r`;
    chomp $kernel_version;

    print "Install PF_RING dependencies with package manager\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @debian_packages_for_pfring = ('build-essential', 'bison', 'flex', 'subversion',
            'libnuma-dev', 'wget', 'tar', 'make', 'dpkg-dev', 'dkms', 'debhelper');
  
        # Install kernel headers only when we could compile kernel modules there
        my $kernel_headers_package_name = "linux-headers-$kernel_version";

        if ($appliance_name eq 'vyos') { 
            # VyOS uses another name for package for building kernel modules
            $kernel_headers_package_name = 'linux-vyatta-kbuild';
        }

        push @debian_packages_for_pfring, $kernel_headers_package_name;

        apt_get(@debian_packages_for_pfring);

        if ($appliance_name eq 'vyos') {
            # By default we waven't this symlink and should add it manually

            if ($distro_architecture eq 'x86_64') {  
                exec_command("ln -s /usr/src/linux-image/debian/build/build-amd64-none-amd64-vyos/ /lib/modules/$kernel_version/build");
            } else {
                # i686
                exec_command("ln -s /usr/src/linux-image/debian/build/build-i386-none-586-vyos/ /lib/modules/$kernel_version/build");
            }
        }
    } elsif ($distro_type eq 'centos') {
        my $kernel_package_name = 'kernel-devel';

        # Fix deplist for OpenVZ
        if ($kernel_version =~ /stab/) {
            $kernel_package_name = "vzkernel-devel-$kernel_version";
        }
    
        yum('make', 'bison', 'flex', $kernel_package_name, 'gcc', 'gcc-c++', 'dkms', 'numactl-devel', 'subversion');
    } elsif ($distro_type eq 'gentoo') {
        my @gentoo_packages_for_pfring = ('subversion', 'sys-process/numactl', 'wget', 'tar');

        my $gentoo_packages_for_pfring_as_string = join " ", @gentoo_packages_for_pfring;
        exec_command("emerge -vu $gentoo_packages_for_pfring_as_string");

        if ($? != 0) {
            print "Emerge fail with code $?\n";
        }
    }

    # Sometimes we do not want to build kernel module (Docker, KVM and other cases)
    my $we_could_install_kernel_modules = 1;
    if ($we_could_install_kernel_modules) {
        print "Download PF_RING $pf_ring_version sources\n";
        my $pfring_download_result = download_file($pf_ring_url, $pf_ring_archive_path, '9fb8080defd1a079ad5f0097e8a8adb5bc264d00');  

        unless ($pfring_download_result) {
            die "Can't download PF_RING sources\n";
        }
 
        my $archive_file_name = $pf_ring_archive_path;

        if ($? == 0) {
            print "Unpack PF_RING\n";
            mkdir $pf_ring_sources_path;
            exec_command("tar -xf $pf_ring_archive_path -C $temp_folder_for_building_project");

            print "Build PF_RING kernel module\n";
            exec_command("make $make_options -C $pf_ring_sources_path/kernel clean");
            exec_command("make $make_options -C $pf_ring_sources_path/kernel");
            exec_command("make $make_options -C $pf_ring_sources_path/kernel install");

            print "Unload PF_RING if it was installed earlier\n";
            exec_command("rmmod pf_ring 2>/dev/null");

            print "Load PF_RING module into kernel\n";
            exec_command("modprobe pf_ring");

            my @dmesg = `dmesg`;
            chomp @dmesg;
    
            if (scalar grep (/\[PF_RING\] Initialized correctly/, @dmesg) > 0) {
                print "PF_RING loaded correctly\n";

            } else {
                warn "PF_RING load error! Please fix this issue manually\n";

                # We need this headers for building userspace libs
                exec_command("cp $pf_ring_sources_path/kernel/linux/pf_ring.h /usr/include/linux");
            }
        } else {
            warn "Can't download PF_RING source code. Disable support of PF_RING\n";
        } 
    }

    print "Build PF_RING lib\n";
    # Because we can't run configure from another folder because it can't find ZC dependency :(
    chdir "$pf_ring_sources_path/userland/lib";
    exec_command("./configure --prefix=/opt/pf_ring_$pf_ring_version");
    exec_command("make $make_options");
    exec_command("make $make_options install"); 

    # We need do this for backward compatibility with old code (v1.1.2)
    exec_command("ln -s /opt/pf_ring_$pf_ring_version /opt/pf_ring");

    print "Create library symlink\n";

    print "Add pf_ring to ld.so.conf\n";
    put_library_path_to_ld_so("/etc/ld.so.conf.d/pf_ring.conf", "/opt/pf_ring_$pf_ring_version/lib");
}

sub apt_get {
    my @packages_list = @_; 

    # We install one package per apt-get call because installing multiple packages in one time could fail of one package is broken
    for my $package (@packages_list) {
        exec_command("apt-get install -y --force-yes $package");

        if ($? != 0) {
            print "Package '$package' install failed with code $?\n"
        }   
    }   
}

sub yum {
    my @packages_list = @_;

    for my $package (@packages_list) {
        exec_command("yum install -y $package");

        if ($? != 0) {
            print "Package '$package' install failed with code $?\n";
        }
    }
}

sub install_fastnetmon {
    print "Install FastNetMon dependency list\n";

    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        my @fastnetmon_deps = ("git", "g++", "gcc", "libgpm-dev", "libncurses5-dev",
            "liblog4cpp5-dev", "libnuma-dev", "libgeoip-dev","libpcap-dev", "cmake", "pkg-config", "libhiredis-dev",
        );

        # Do not install Boost when we build it manually
        unless ($build_binary_environment) {
            # We add this dependencies because package libboost-all-dev is broken on VyOS
            if ($appliance_name eq 'vyos') {
                push @fastnetmon_deps, ('libboost-regex-dev', 'libboost-system-dev', 'libboost-thread-dev');
            } else {
                push @fastnetmon_deps, "libboost-all-dev";
            }
        }

        apt_get(@fastnetmon_deps);
    } elsif ($distro_type eq 'centos') {
        my @fastnetmon_deps = ('git', 'make', 'gcc', 'gcc-c++', 'GeoIP-devel',
            'ncurses-devel', 'glibc-static', 'ncurses-static', 'libpcap-devel', 'gpm-static',
            'gpm-devel', 'cmake', 'pkgconfig', 'hiredis-devel',
        );

        # Do not install Boost when we build it manually
        unless ($build_binary_environment) {
            @fastnetmon_deps = (@fastnetmon_deps, 'boost-devel', 'boost-thread')
        }

        if ($distro_version == 7) {
            print "Your distro haven't log4cpp in stable EPEL packages and we install log4cpp from testing of EPEL\n";
            # We should install log4cpp packages only in this order!
            yum('https://kojipkgs.fedoraproject.org//packages/log4cpp/1.1.1/1.el7/x86_64/log4cpp-1.1.1-1.el7.x86_64.rpm',
                'https://kojipkgs.fedoraproject.org//packages/log4cpp/1.1.1/1.el7/x86_64/log4cpp-devel-1.1.1-1.el7.x86_64.rpm'),
        } else {
            push @fastnetmon_deps, 'log4cpp-devel';
        }

        yum(@fastnetmon_deps);
    } elsif ($distro_type eq 'gentoo') {
        my @fastnetmon_deps = ("dev-vcs/git", "gcc", "sys-libs/gpm", "sys-libs/ncurses", "dev-libs/log4cpp", "dev-libs/geoip", 
            "net-libs/libpcap", "dev-util/cmake", "pkg-config", "dev-libs/hiredis", "dev-libs/boost"
        );

        my $fastnetmon_deps_as_string = join " ", @fastnetmon_deps;
        exec_command("emerge -vu $fastnetmon_deps_as_string");

        if ($? != 0) {
            print "Emerge fail with code $?\n";
        }
    }

    print "Clone FastNetMon repo\n";
    chdir $temp_folder_for_building_project;

    if (-e $fastnetmon_code_dir) {
        # Code already downloaded
        chdir $fastnetmon_code_dir;

        # Switch to master if we on stable branch
        if ($we_use_code_from_master) {
            exec_command("git checkout master");
            printf("\n");
        }

        exec_command("git pull");
    } else {
        # Pull new code
        if ($we_use_code_from_master) {
            exec_command("git clone $fastnetmon_git_path --quiet 2>/dev/null");
        } else {
            exec_command("git clone $fastnetmon_git_path --quiet 2>/dev/null");
        }

        if ($? != 0) {
            die "Can't clone source code\n";
        }
    }

    if ($we_use_code_from_master) {

    } else {
        # We use this approach because older git versions do not support git clone -b ... correctly
        # warning: Remote branch v1.1.2 not found in upstream origin, using HEAD instead
        chdir "fastnetmon";
        exec_command("git checkout $stable_branch_name");
    } 

    exec_command("mkdir -p $fastnetmon_code_dir/build");
    chdir "$fastnetmon_code_dir/build";

    my $cmake_params = "";

    unless ($we_have_pfring_support) {
        $cmake_params .= " -DDISABLE_PF_RING_SUPPORT=ON";
    }

    if ($distro_type eq 'centos' && $distro_version == 6 && !$build_binary_environment) {
        # Disable cmake script from Boost package because it's broken:
        # http://public.kitware.com/Bug/view.php?id=15270
        $cmake_params .= " -DBoost_NO_BOOST_CMAKE=BOOL:ON";
    }

    # We should specify this option if we want to build with custom gcc compiler
    if ($build_binary_environment) {
        $cmake_params .= " -DENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT=ON ";

        # We should specify compilir this way
        $cmake_params .= " -DCMAKE_C_COMPILER=/opt/gcc520/bin/gcc -DCMAKE_CXX_COMPILER=/opt/gcc520/bin/g++ "; 
    }

    exec_command("cmake .. $cmake_params");
    exec_command("make $make_options");

    my $fastnetmon_dir = "/opt/fastnetmon";
    my $fastnetmon_build_binary_path = "$fastnetmon_code_dir/build/fastnetmon";

    unless (-e $fastnetmon_build_binary_path) {
        die "Can't build fastnetmon!";
    }

    mkdir $fastnetmon_dir;

    print "Install fastnetmon to dir $fastnetmon_dir\n";
    exec_command("cp $fastnetmon_build_binary_path $fastnetmon_dir/fastnetmon");
    exec_command("cp $fastnetmon_code_dir/build/fastnetmon_client $fastnetmon_dir/fastnetmon_client");

    my $fastnetmon_config_path = "/etc/fastnetmon.conf";
    unless (-e $fastnetmon_config_path) {
        print "Create stub configuration file\n";
        exec_command("cp $fastnetmon_code_dir/fastnetmon.conf $fastnetmon_config_path");
    
        my @interfaces = get_active_network_interfaces();
        my $interfaces_as_list = join ',', @interfaces;
        print "Select $interfaces_as_list as active interfaces\n";

        print "Tune config\n";
        exec_command("sed -i 's/interfaces.*/interfaces = $interfaces_as_list/' $fastnetmon_config_path");
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

