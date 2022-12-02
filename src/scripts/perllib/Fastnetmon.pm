package Fastnetmon;

use strict;
use warnings;

use File::Copy;
use File::Basename;

# Retrieve all required modules
BEGIN {

eval { require Env; };

if ($@) {
    die "Perl module Env is not installed, install it:\nsudo yum install -y perl-Env.noarch\n";
}

}

use Env qw(PATH);

BEGIN {

eval { require Archive::Tar; };

if ($@) {
    die "Perl module Archive::Tar is not installed, install it:\nsudo yum install -y perl-Archive-Tar.noarch\n";
}

}



use Archive::Tar;



require Exporter;
our @ISA = qw(Exporter);

our @EXPORT = qw(
detect_distribution
init_compiler
exec_command
get_sha1_sum
download_file
read_file
apt_get
yum
get_active_network_interfaces
);

our $dependency_map = {
    'boost' => [ 'boost_builder', 'icu' ]
};

my $ld_library_path_for_make = "";

my $build_with_clang = '';
# When we are working with clang it's not a good idea to use stdc++ because they are becoming a bit incompatible
my $use_libcpp_instead_stdcpp = '';

my $gcc_version = '12.1.0';

# We are using this for Boost build system
# 5.3 instead of 5.3.0
my $gcc_version_only_major = $gcc_version;
$gcc_version_only_major =~ s/\.\d$//;

my $gcc_c_compiler_path = '';
my $gcc_cpp_compiler_path = '';

my $clang_c_compiler_path = '';
my $clang_cpp_compiler_path = '';

# By default we haven't any make options
my $make_options = '';

my $boost_version = '1.80.0';

my $boost_version_with_underscore = $boost_version;
$boost_version_with_underscore =~ s/\./_/g;

# We need to know it because we could get huge speed improvements with this option
my $cpus_number = 1;

# We should specify custom compiler path
my $default_c_compiler_path = '';
my $default_cpp_compiler_path = '';

my $os_type = ''; 
my $distro_type = ''; 
my $distro_version = ''; 
my $distro_architecture = ''; 
my $appliance_name = ''; 

our $library_install_folder;
our $temp_folder_for_building_project;
our $install_log_path;

# We could store downloaded code here for download time optimization
my $use_cache = 1;

# Path to cache folder
my $cache_folder = '/var/cache/fastnetmon_build_system_cache';

# We need to specify custom compiler options
my $configure_options = '';

# We are using custom version of cmake
my $cmake_path = "/opt/fastnetmon-community/libraries/cmake_3_23_4/bin/cmake";

# We need it for all OpenSSL dependencies
my $openssl_folder_name = "openssl_1_1_1q";

my $current_distro_architecture = `uname -m`;
chomp $current_distro_architecture;

sub exec_command {
    my $command = shift;

    open my $fl, ">>", $install_log_path;
    print {$fl} "We are calling command: $command\n\n";
 
    my $output = `$command 2>&1`;
  
    print {$fl} "Command finished with code $?\n\n";

    if ($? == 0) {
        return 1;
    } else {
        warn "Command $command call failed with code $? and output: $output\n";
        return '';
    }
}

sub get_sha1_sum {
    my $path = shift;

    if ($os_type eq 'freebsd') {
        # # We should not use 'use' here because we haven't this package on non FreeBSD systems by default
        require Digest::SHA;

        # SHA1
        my $sha = Digest::SHA->new(1);

        $sha->addfile($path);

        return $sha->hexdigest; 
    }

    my $hasher_name = '';

    if ($os_type eq 'macosx') {
        $hasher_name = 'shasum';
    } elsif ($os_type eq 'freebsd') {
        $hasher_name = 'sha1';
    } else {
        # Linux
        $hasher_name = 'sha1sum';
    }

    my $output = `$hasher_name $path`;
    chomp $output;
   
    my ($sha1) = ($output =~ m/^(\w+)\s+/);

    return $sha1;
}

sub download_file {
    my ($url, $path, $expected_sha1_checksumm) = @_;

    my ($path_filename, $path_dirs, $path_suffix) = fileparse($path);

    my $file_path_in_cache = "$cache_folder/$path_filename";

    if ($use_cache) {
        unless (-e $cache_folder) {
            my $mkdir_result = mkdir $cache_folder;

            unless ($mkdir_result) {
                warn "Can't create cache folder\n";
                return '';
            }
        }

        if (-e $file_path_in_cache) {
            if ($expected_sha1_checksumm) {
                my $calculated_checksumm = get_sha1_sum($file_path_in_cache);

                if ($calculated_checksumm eq $expected_sha1_checksumm) {
                    my $copy_result = copy($file_path_in_cache, $path);

                    if (!$copy_result) {
                        warn "Could not copy file from cache to build folder\n";
                    } else {
                        warn "Got archive $path_filename from cache\n";
                        # All fine!
                        return 1;
                    }
                } else {
                    print "Archive from cache has incorrect sha1: $calculated_checksumm expected: $expected_sha1_checksumm\n";
                }
            } else {
                my $copy_result = copy($file_path_in_cache, $path);

                if (!$copy_result) {
                    warn "Could not copy file from cache to build folder\n";
                } else {
                    warn "Got archive $path_filename from cache\n";
                    # All fine!
                    return 1;
                }
            } 
        }

        `wget --no-check-certificate --quiet '$url' -O$path`;

        if ($? != 0) {
            print "We can't download archive $url correctly\n";
            return '';
        }
    }

    if ($expected_sha1_checksumm) {
        my $calculated_checksumm = get_sha1_sum($path);

        if ($calculated_checksumm eq $expected_sha1_checksumm) {
            if ($use_cache) {
                # Put file copy to cache folder
                my $copy_result = copy($path, $file_path_in_cache);
 
                if (!$copy_result) {
                    warn "Copy to cache failed\n";
                }
            }

            return 1;
        } else {
            print "Downloaded archive has incorrect sha1: $calculated_checksumm expected: $expected_sha1_checksumm\n";
            return '';
        }      
    } else {
        if ($use_cache) {
            print "We will copy file from $path to $file_path_in_cache\n";
            # Put file copy to cache folder
            my $copy_result = copy($path, $file_path_in_cache);

            if (!$copy_result) {
                warn "Copy to cache failed\n";
            }
        }

        return 1;
    }     
}

sub init_machine_information {
    my $machine_information = Fastnetmon::detect_distribution();

    unless ($machine_information) {
        die "Could not collect machine information\n";
    }   

    $distro_version = $machine_information->{distro_version};
    $distro_type = $machine_information->{distro_type};
    $os_type = $machine_information->{os_type};
    $distro_architecture = $machine_information->{distro_architecture};
    $appliance_name = $machine_information->{appliance_name}; 
}

# This code will init global compiler settings used in options for other packages build
sub init_compiler {
    init_machine_information();

    # 530 instead of 5.3.0
    my $gcc_version_for_path = $gcc_version;
    $gcc_version_for_path =~ s/\.//g;

    $gcc_c_compiler_path = "$library_install_folder/gcc$gcc_version_for_path/bin/gcc";
    $gcc_cpp_compiler_path = "$library_install_folder/gcc$gcc_version_for_path/bin/g++";

    $clang_c_compiler_path = "$library_install_folder/clang_7_0_0/bin/clang";
    $clang_cpp_compiler_path = "$library_install_folder/clang_7_0_0/bin/clang++";

    # Default compiler path
    if ($build_with_clang) {
        $default_c_compiler_path = $clang_c_compiler_path;
        $default_cpp_compiler_path = $clang_cpp_compiler_path;
    } else {
        $default_c_compiler_path =  $gcc_c_compiler_path;
        $default_cpp_compiler_path = $gcc_cpp_compiler_path;
    }

    # Add new compiler to configure options
    # It's mandatory for log4cpp
    $configure_options = "CC=$default_c_compiler_path CXX=$default_cpp_compiler_path";

    if ($use_libcpp_instead_stdcpp) {
        $configure_options = "$configure_options -stdlib=libc++";
    }

    my @make_library_path_list_options = ("$library_install_folder/gcc$gcc_version_for_path/lib64");

    if ($use_libcpp_instead_stdcpp) {
        @make_library_path_list_options = ("$library_install_folder/clang_7_0_0/lib");
    }

    $ld_library_path_for_make = "LD_LIBRARY_PATH=" . join ':', @make_library_path_list_options;

    # More detailes about jam lookup: http://www.boost.org/build/doc/html/bbv2/overview/configuration.html

    # We use non standard gcc compiler for Boost builder and Boost and specify it this way
    open my $fl, ">", "/root/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$fl} "using gcc : $gcc_version_only_major : $default_cpp_compiler_path ;\n";
    close $fl; 

    # When we run it with vzctl exec we ahve broken env and should put config in /etc too
    open my $etcfl, ">", "/etc/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$etcfl} "using gcc : $gcc_version_only_major : $default_cpp_compiler_path ;\n";
    close $etcfl;

    # Also we should tune number of threads for make
    $cpus_number = get_logical_cpus_number();

    # Boost and cmake compilation needs lots of memory, we need to reduce number of threads on CircleCI as it expose 32 threads but it's not real
    # Limit it by number of threads available on our plan: https://circleci.com/product/features/resource-classes/
    if (defined($ENV{'CI'}) && $ENV{'CI'}) {
        if ($cpus_number > 4) {
            $cpus_number = 4;
        }
    }

    # We could get huge speed benefits with this option
    if ($cpus_number > 1) {
        $make_options = "-j $cpus_number";
    }

}

sub install_libbpf {
    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        my @dependency_list = ('libelf-dev');
        apt_get(@dependency_list);
    } elsif ($distro_type eq 'centos') {
        yum('elfutils-libelf-devel');
    }

    my $libbpf_package_install_path = "$library_install_folder/libbpf_1_0_1";

    if (-e $libbpf_package_install_path) {
        warn "libbpf is installed, skip build\n";
        return 1;
    }

    my $archive_file_name = 'v1.0.1.tar.gz ';

    print "Download libbpf\n";
    chdir $temp_folder_for_building_project;

    my $lib_bpf_download_result = download_file("https://github.com/libbpf/libbpf/archive/refs/tags/v1.0.1.tar.gz",  $archive_file_name, '9350f196150892f544e0681cc6c1f78e603b5d95');

    unless ($lib_bpf_download_result) {
        die "Cannot download linux kernel\n";
    }

    print "Unpack libbpf\n";
    system("tar -xf $archive_file_name");

    chdir "libbpf-1.0.1/src";

    system("make");

    system("mkdir -p $libbpf_package_install_path");
    system("cp libbpf.a libbpf.so libbpf.so.1 libbpf.so.1.0.1 $libbpf_package_install_path");

    system("mkdir -p $libbpf_package_install_path/include/bpf");
    system("cp bpf.h libbpf.h libbpf_common.h libbpf_version.h libbpf_legacy.h $libbpf_package_install_path/include/bpf");

    return 1;
}

sub install_gcc {
    # 530 instead of 5.3.0
    my $gcc_version_for_path = $gcc_version;
    $gcc_version_for_path =~ s/\.//g;

    my $gcc_package_install_path = "$library_install_folder/gcc$gcc_version_for_path";

    if (-e $gcc_package_install_path) {
        warn "Found already installed gcc in $gcc_package_install_path. Skip compilation\n";
        return '1';
    }

    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        my @dependency_list = ('libmpfr-dev', 'libmpc-dev', 'libgmp-dev', 'gcc', 'g++');
        apt_get(@dependency_list);
    } elsif ($distro_type eq 'centos') {
        yum('gmp-devel', 'mpfr-devel', 'libmpc-devel', 'gcc', 'gcc-c++');
    }

    print "Download gcc archive\n";
    chdir $temp_folder_for_building_project;
 
    my $archive_file_name = "gcc-$gcc_version.tar.gz";
    my $gcc_download_result = download_file("http://ftp.mpi-sb.mpg.de/pub/gnu/mirror/gcc.gnu.org/pub/gcc/releases/gcc-$gcc_version/$archive_file_name", $archive_file_name, '7e79c695a0380ac838fa7c876a121cd28a73a9f5');

    unless ($gcc_download_result) {
        die "Can't download gcc sources\n";
    }

    print "Unpack archive\n";
    exec_command("tar -xf $archive_file_name");
    # Remove source archive
    unlink "$archive_file_name";
    exec_command("mkdir $temp_folder_for_building_project/gcc-$gcc_version-objdir");

    chdir "$temp_folder_for_building_project/gcc-$gcc_version-objdir";

    print "Configure build system\n";
    # We are using  --enable-host-shared because we should build gcc as dynamic library for jit compiler purposes
    unless (exec_command("$temp_folder_for_building_project/gcc-$gcc_version/configure --prefix=$gcc_package_install_path --enable-languages=c,c++,jit  --enable-host-shared --disable-multilib")) {
	warn "Cannot configure gcc\n";
	return '';
    }

    print "Build gcc\n";

    unless (exec_command("make $make_options")) {
	warn "Cannot make gcc\n";
	return '';
    }

    print "Install gcc\n";
    unless (exec_command("make $make_options install")) {
	warn "Cannot install gcc\n";
	return '';
    }

    return 1;
}

sub install_boost {
    my $boost_install_path = "$library_install_folder/boost_${boost_version_with_underscore}";

    if (-e $boost_install_path) {
        warn "Boost libraries already exist in $boost_install_path Skip build process\n";
        return 1;
    }

    chdir $library_install_folder;
    my $archive_file_name = "boost_${boost_version_with_underscore}.tar.gz";

    print "Install Boost dependencies\n";
    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        apt_get('bzip2');
    } elsif ($distro_type eq 'centos') {
        yum('bzip2');
    }

    print "Download Boost source code\n";
    my $boost_download_result = download_file("https://boostorg.jfrog.io/artifactory/main/release/$boost_version/source/boost_${boost_version_with_underscore}.tar.bz2", $archive_file_name, '690a2a2ed6861129828984b1d52a473d2c8393d1');
        
    unless ($boost_download_result) {
        die "Can't download Boost source code\n";
    }

    print "Unpack Boost source code\n";
    exec_command("tar -xf $archive_file_name");

    my $folder_name_inside_archive = "boost_$boost_version_with_underscore";

    print "Fix permissions\n";
    # Fix permissions because they are broken inside official archive
    exec_command("find $folder_name_inside_archive -type f -exec chmod 644 {} \\;");
    exec_command("find $folder_name_inside_archive -type d -exec chmod 755 {} \\;");
    exec_command("chown -R root:root $folder_name_inside_archive");

    print "Remove archive\n";
    unlink "$archive_file_name";

    chdir $folder_name_inside_archive;

    my $boost_build_threads = $cpus_number;

    # Boost compilation needs lots of memory, we need to reduce number of threads on CircleCI
    # Limit it by number of threads available on our plan: https://circleci.com/product/features/resource-classes/
    if (defined($ENV{'CI'}) && $ENV{'CI'}) {
        $boost_build_threads = 4;
    }

    print "Build Boost\n";
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path 
    # So without HOME=/root nothing worked correctly due to another "openvz" feature
    my $b2_build_result = exec_command("$ld_library_path_for_make $library_install_folder/boost_build_4_9_2/bin/b2 -j $boost_build_threads -sICU_PATH=$library_install_folder/libicu_65_1 linkflags=\"-Wl,-rpath,$library_install_folder/libicu_65_1/lib\" --build-dir=$temp_folder_for_building_project/boost_build_temp_directory_1_7_8 link=shared --without-test --without-python --without-wave --without-log --without-mpi");

    # We should not do this check because b2 build return bad return code even in success case... when it can't build few non important targets
    unless ($b2_build_result) {
        ### die "Can't execute b2 build correctly\n";
    }

    1;
}

sub install_boost_builder {
    chdir $temp_folder_for_building_project;

    # We use another name because it uses same name as boost distribution
    my $archive_file_name = '4.9.2.tar.gz';

    my $boost_builder_install_folder = "$library_install_folder/boost_build_4_9_2";

    if (-e $boost_builder_install_folder) {
        warn "Found installed Boost builder at $boost_builder_install_folder\n";
        return 1;
    }

    print "Download boost builder\n";
    my $boost_build_result = download_file("https://github.com/bfgroup/build/archive/$archive_file_name", $archive_file_name,
        '1c77d3fda9425fd89b783db8f7bd8ebecdf8f916');

    unless ($boost_build_result) {
        fast_die("Can't download boost builder\n");
    }

    print "Unpack boost builder\n";
    exec_command("tar -xf $archive_file_name");

    unless (chdir "b2-4.9.2") {
        fast_die("Cannot do chdir to build boost folder\n");
    }

    print "Build Boost builder\n";
    my $bootstrap_result = exec_command("$ld_library_path_for_make CC=$default_c_compiler_path CXX=$default_cpp_compiler_path  ./bootstrap.sh --with-toolset=gcc");

    unless ($bootstrap_result) {
        fast_die("bootstrap of Boost Builder failed, please check logs\n");
    }

    # We should specify toolset here if we want to do build with custom compiler
    my $b2_install_result = exec_command("$ld_library_path_for_make ./b2 install --prefix=$boost_builder_install_folder");

    unless ($b2_install_result) {
        fast_die("Can't execute b2 install\n");
    }

    1;
}

sub install_log4cpp {
    my $log_cpp_version_short = '1.1.3';

    my $log4cpp_install_path = "$library_install_folder/log4cpp" . $log_cpp_version_short;

    if (-e $log4cpp_install_path) {
	warn "We have log4cpp already, skip build\n";
	return 1;
    }

    my $distro_file_name = "log4cpp-$log_cpp_version_short.tar.gz";
    my $log4cpp_url = "https://sourceforge.net/projects/log4cpp/files/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-$log_cpp_version_short.tar.gz/download";

    chdir $temp_folder_for_building_project;

    print "Download log4cpp sources\n";
    my $log4cpp_download_result = download_file($log4cpp_url, $distro_file_name, '74f0fea7931dc1bc4e5cd34a6318cd2a51322041');

    unless ($log4cpp_download_result) {
        die "Can't download log4cpp\n";
    }

    print "Unpack log4cpp sources\n";
    exec_command("tar -xf $distro_file_name");
    chdir "$temp_folder_for_building_project/log4cpp";

    if ($distro_architecture eq 'aarch64') {
        # TODO: unfortunately, I removed these files and we need to switch to master build: https://git.code.sf.net/p/log4cpp/codegit
        # commit: 2e117d81e94ec4f9c5af42fcf76a0583a036e106
        # For arm64 build we need multiple fixes
        # checking build system type... config/config.guess: unable to guess system type
        # configure: error: cannot guess build type; you must specify one
        exec_command("curl https://raw.githubusercontent.com/pavel-odintsov/config/master/config.guess -o./config/config.guess");
        exec_command("curl https://raw.githubusercontent.com/pavel-odintsov/config/master/config.sub -o./config/config.sub");
    }

    print "Build log4cpp\n";

    # TODO: we need some more reliable way to specify options here
    if ($configure_options) {
        exec_command("$configure_options ./configure --prefix=$log4cpp_install_path");
    } else {
        exec_command("./configure --prefix=$log4cpp_install_path");
    }    

    my $make_result = exec_command("make $make_options install"); 

    if (!$make_result) {
        print "Make for log4cpp failed\n";
    }
    1;
}

sub install_grpc {
    my $grpc_git_commit = "v1.30.2";

    my $grpc_install_path = "$library_install_folder/grpc_1_30_2"; 

    if (-e $grpc_install_path) {
         print "gRPC is already installed, skip compilation\n";
         return 1;
    }

    chdir $temp_folder_for_building_project;
 
    print "Clone gRPC repository\n";
    exec_command("git clone https://github.com/grpc/grpc.git");
    chdir "grpc";

    # For back compatibility with old git
    exec_command("git checkout $grpc_git_commit");

    print "Update project submodules\n";
    exec_command("git submodule update --init");

    ### Patch makefile for custom gcc: https://github.com/grpc/grpc/issues/3893
    exec_command("sed -i '81i DEFAULT_CC=$default_c_compiler_path' Makefile");
    exec_command("sed -i '82i DEFAULT_CXX=$default_cpp_compiler_path' Makefile");

    print "Build gRPC\n";
    my $make_result = exec_command("$ld_library_path_for_make make $make_options");

    unless ($make_result) {
        die "Could not build gRPC: make failed";
    }

    print "Install gRPC\n";
    exec_command("$ld_library_path_for_make make install prefix=$grpc_install_path"); 

    1;
}

# Get git repository source code
sub git_clone_repository {
    my ($repo_url, $local_folder, $repo_commit) = @_;

    my $git_clone_result = exec_command("git clone $repo_url $local_folder");

    unless ($git_clone_result) {
        warn "Could not clone repository: $repo_url\n";
        return '';
    }

    # If we want certain commit
    if ($repo_commit ne 'master') {
        # Change current working directory to git repo
        chdir "$local_folder";

        my $checkout_branch_result = exec_command("git checkout $repo_commit");

        unless ($checkout_branch_result) {
            warn "Could not checkout commit $repo_commit for repository $repo_url\n";
            return '';
        }
    }

    return 1;
}

sub install_gobgp {
    chdir $temp_folder_for_building_project;
    my $distro_file_name = 'gobgp_2.27.0_linux_amd64.tar.gz';
    
    my $download_result = download_file("https://github.com/osrg/gobgp/releases/download/v2.27.0/$distro_file_name",
        $distro_file_name, 'dd906c552a727d3f226f3851bf2c92bfdafb92a7'); 

    unless ($download_result) {
        die "Could not download gobgp\n";
    }    

    my $unpack_result = exec_command("tar -xf $distro_file_name");

    unless ($unpack_result) {
        die "Could not unpack gobgp\n";
    }    

   
    my $gobgp_install_path = "$library_install_folder/gobgp_2_27_0";

    mkdir "$gobgp_install_path";
   
    `cp gobgp $gobgp_install_path`; 
    `cp gobgpd $gobgp_install_path`;

    1; 
}

sub install_protobuf {
    my $protobuf_install_path = "$library_install_folder/protobuf_3.11.4";

    if (-e $protobuf_install_path) {
        warn "Found installed Protobuf, skip compilation\n";
        return 1;
    }

    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        apt_get('make', 'autoconf', 'automake', 'git', 'libtool', 'curl');
    } elsif ($distro_type eq 'centos') {
        yum('make', 'autoconf', 'automake', 'git', 'libtool', 'curl');
    }

    my $distro_file_name = 'protobuf-all-3.11.4.tar.gz';

    chdir $temp_folder_for_building_project;
    print "Download protocol buffers\n";

    my $protobuf_download_result = download_file("https://github.com/protocolbuffers/protobuf/releases/download/v3.11.4/$distro_file_name",
        $distro_file_name, '318f4d044078285db7ae69b68e77f148667f98f4'); 

    unless ($protobuf_download_result) {
        die "Can't download protobuf\n";
    }

    print "Unpack protocol buffers\n";
    exec_command("tar -xf $distro_file_name");

    chdir "protobuf-3.11.4";
    print "Configure protobuf\n";

    print "Execute autogen\n";
    exec_command("./autogen.sh");

    exec_command("$configure_options ./configure --prefix=$protobuf_install_path");

    print "Build protobuf\n";
    # We have specified LD_LIBRARY path for fixing issue with version `GLIBCXX_3.4.21' not found 
    exec_command("$ld_library_path_for_make make $make_options install");
    1;
}

sub install_libelf {
    if (-e "$library_install_folder/elfutils_0_186") {
        warn "elfutils already exists\n";
        return 1;
    }

    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        apt_get(('zlib1g-dev'));
    } elsif ($distro_type eq 'centos') {
        yum('zlib-devel', 'm4');
    }

    my $res = install_configure_based_software("https://sourceware.org/pub/elfutils/0.186/elfutils-0.186.tar.bz2", "650d52024be684dabf18a5261a69836a16f84f72", "$library_install_folder/elfutils_0_186", '--disable-debuginfod --disable-libdebuginfod');

    unless ($res) { 
        die "Cannot install elfutils\n";
    }

    return 1;
}

sub install_capnproto {
    my $capnp_install_path = "$library_install_folder/capnproto_0_8_0";

    if (-e $capnp_install_path) {
        warn "Cap'n'proto already existis, skip compilation\n";
        return 1;
    }   

    my $res = install_configure_based_software("https://capnproto.org/capnproto-c++-0.8.0.tar.gz", 
        "fbc1c65b32748029f1a09783d3ebe9d496d5fcc4", $capnp_install_path, 
        '');

    unless ($res) { 
        die "Could not install capnproto";
    }

    return 1;
}

sub install_mongo_client {
    my $install_path = "$library_install_folder/mongo_c_driver_1_23_0";
    
    if (-e $install_path) {
	warn "mongo_c_driver is already installed, skip build";
        return 1;
    } 

    my $openssl_path = "$library_install_folder/$openssl_folder_name";

    # OpenSSL is mandatory for SCRAM-SHA-1 auth mode
    # I also use flag ENABLE_ICU=OFF to disable linking against icu system library. I do no think that we really need it
    my $res = install_cmake_based_software("https://github.com/mongodb/mongo-c-driver/releases/download/1.23.0/mongo-c-driver-1.23.0.tar.gz",
        "f6256acfe89ed094158be84a3ce2a56fd7f22637",
	$install_path,
	"$cmake_path -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:STRING=$library_install_folder/mongo_c_driver_1_23_0 -DCMAKE_C_COMPILER=$default_c_compiler_path -DOPENSSL_ROOT_DIR=$openssl_path -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -DENABLE_ICU=OFF -DMONGOC_TEST_USE_CRYPT_SHARED=OFF ..");

    if (!$res) {
        die "Could not install mongo c client\n";
    }

    return 1;
}

sub install_configure_based_software {
    my ($url_to_archive, $sha1_summ_for_archive, $library_install_path, $configure_options) = @_; 

    unless ($url_to_archive && $sha1_summ_for_archive && $library_install_path) {
        warn "You haven't specified all mandatory arguments for install_configure_based_software\n";
        return '';
    }

    unless (defined($configure_options)) {
        $configure_options = '';
    }

    chdir $temp_folder_for_building_project;

    my $file_name = get_file_name_from_url($url_to_archive);

    unless ($file_name) {
        die "Could not extract file name from URL $url_to_archive";
    }

    print "Download archive\n";
    my $archive_download_result = download_file($url_to_archive, $file_name, $sha1_summ_for_archive);

    unless ($archive_download_result) {
        die "Could not download URL $url_to_archive";
    }    

    unless (-e $file_name) {
        die "Could not find downloaded file in current folder";
    }

    print "Read file list inside archive\n";
    my $folder_name_inside_archive = get_folder_name_inside_archive("$temp_folder_for_building_project/$file_name"); 

    unless ($folder_name_inside_archive) {
        die "We could not extract folder name from tar archive '$temp_folder_for_building_project/$file_name'\n";
    }

    print "Unpack archive\n";
    my $unpack_result = exec_command("tar -xf $file_name");

    unless ($unpack_result) {
        die "Unpack failed";
    }

    chdir $folder_name_inside_archive;

    unless (-e "configure") {
        die "We haven't configure script here";
    }

    print "Execute configure\n";
    my $configure_command = "CC=$default_c_compiler_path CXX=$default_cpp_compiler_path ./configure --prefix=$library_install_path $configure_options";

    my $configure_result = exec_command($configure_command);

    unless ($configure_result) {
        die "Configure failed";
    } 

    ### TODO: this is ugly thing! But here you could find hack for poco libraries
    if ($url_to_archive =~ m/Poco/i) {
        exec_command("sed -i 's#^CC .*#CC = $default_c_compiler_path#' build/config/Linux");
        exec_command("sed -i 's#^CXX .*#CXX = $default_cpp_compiler_path#' build/config/Linux");

        #print `cat build/config/Linux`;
    }

    # librdkafka does not like make+make install approach, we should use them one by one
    print "Execute make\n";

    my $make_result = exec_command("$ld_library_path_for_make make $make_options");

    unless ($make_result) {
        die "Make failed";
    } 

    print "Execute make install\n";
    # We explicitly added path to library folders from our custom compiler here
    my $make_install_result = exec_command("$ld_library_path_for_make make install"); 

    unless ($make_install_result) {
        die "Make install failed";
    }

    return 1;
}

sub install_openssl {
    my $distro_file_name = 'openssl-1.1.1q.tar.gz';
    my $openssl_install_path = "$library_install_folder/openssl_1_1_1q";
 
    if (-e $openssl_install_path) {
        warn "We found already installed openssl in folder $openssl_install_path Skip compilation\n";
        return 1;
    }

    chdir $temp_folder_for_building_project;
   
    my $openssl_download_result = download_file("https://www.openssl.org/source/$distro_file_name", 
        $distro_file_name, '79511a8f46f267c533efd32f22ad3bf89a92d8e5');

    unless ($openssl_download_result) {   
        die "Could not download openssl";
    }

    exec_command("tar -xf $distro_file_name");
    chdir "openssl-1.1.1q";

    exec_command("CC=$default_c_compiler_path ./config shared --prefix=$openssl_install_path");
    exec_command("make -j $make_options");
    exec_command("make install");
    1;
}

sub install_icu {
    my $distro_file_name = 'icu4c-65_1-src.tgz';
   
    chdir $temp_folder_for_building_project;
 
    my $icu_install_path = "$library_install_folder/libicu_65_1";

    if (-e $icu_install_path) {
        warn "Found installed icu at $icu_install_path\n";
        return 1;
    }

    print "Download icu\n";
    my $icu_download_result = download_file("https://github.com/unicode-org/icu/releases/download/release-65-1/$distro_file_name",
        $distro_file_name, 'd1e6b58aea606894cfb2495b6eb1ad533ccd2a25');

    unless ($icu_download_result) {
        die "Could not download ibicu";
    }

    print "Unpack icu\n";
    exec_command("tar -xf $distro_file_name");
    chdir "icu/source";

    print "Build icu\n";
    exec_command("$configure_options ./configure --prefix=$icu_install_path");
    exec_command("$ld_library_path_for_make make $make_options");
    exec_command("$ld_library_path_for_make make $make_options install");
    1;
}

sub install_cmake {
    print "Install cmake\n";

    my $cmake_install_path = "$library_install_folder/cmake_3_23_4";

    if (-e $cmake_install_path) {
        warn "Found installed cmake at $cmake_install_path\n";
        return 1;
    }

    my $distro_file_name = "cmake-3.23.4.tar.gz"; 

    chdir $temp_folder_for_building_project;

    print "Download archive\n";
    my $cmake_download_result = download_file("https://github.com/Kitware/CMake/releases/download/v3.23.4/$distro_file_name", $distro_file_name, '05957280718e068df074f76c89cba77de1ddd4a2');

    unless ($cmake_download_result) {
        die "Can't download cmake\n";
    }

    exec_command("tar -xf $distro_file_name");

    chdir "cmake-3.23.4";

    my $openssl_path = "$library_install_folder/$openssl_folder_name";

    print "Execute bootstrap, it will need time\n";
    my $boostrap_result = exec_command("$ld_library_path_for_make CC=$default_c_compiler_path CXX=$default_cpp_compiler_path ./bootstrap --prefix=$cmake_install_path --parallel=$cpus_number -- -DOPENSSL_ROOT_DIR=$openssl_path");

    unless ($boostrap_result) {
        die("Cannot run bootstrap\n");
    }

    print "Make it\n";
    my $make_command = "$ld_library_path_for_make make $make_options";
    my $make_result = exec_command($make_command);

    unless ($make_result) {
        die "Make command '$make_command' failed\n";
    }

    print "Make install it\n";
    exec_command("$ld_library_path_for_make make install");

    return 1;
}

# Extract file name from URL
# https://github.com/mongodb/mongo-cxx-driver/archive/r3.0.0-rc0.tar.gz => r3.0.0-rc0.tar.gz
sub get_file_name_from_url {
    my $url = shift;

    # Remove prefix
    $url =~ s#https?://##;
    my @components = split '/', $url;

    return $components[-1]; 
}

sub install_cmake_based_software {
    my ($url_to_archive, $sha1_summ_for_archive, $library_install_path, $cmake_with_options) = @_;

    unless ($url_to_archive && $sha1_summ_for_archive && $library_install_path && $cmake_with_options) {
        return '';
    }

    chdir $temp_folder_for_building_project;

    my $file_name = get_file_name_from_url($url_to_archive);

    unless ($file_name) {
        die "Could not extract file name from URL $url_to_archive";
    }

    print "Download archive\n";
    my $archive_download_result = download_file($url_to_archive, $file_name, $sha1_summ_for_archive);

    unless ($archive_download_result) {
        die "Could not download URL $url_to_archive";
    }    

    unless (-e $file_name) {
        die "Could not find downloaded file in current folder";
    }

    print "Read file list inside archive\n";
    my $folder_name_inside_archive = get_folder_name_inside_archive("$temp_folder_for_building_project/$file_name"); 

    unless ($folder_name_inside_archive) {
        die "We could not extract folder name from tar archive: $temp_folder_for_building_project/$file_name\n";
    }

    print "Unpack archive\n";
    my $unpack_result = exec_command("tar -xf $file_name");

    unless ($unpack_result) {
        die "Unpack failed";
    }

    chdir $folder_name_inside_archive;

    unless (-e "CMakeLists.txt") {
        die "We haven't CMakeLists.txt in top project folder! Could not build project";
    }

    unless (-e "build") {
        mkdir "build";
    }

    chdir "build";

    print "Generate make file with cmake\n";
    # print "cmake command: $cmake_with_options\n";
    my $cmake_result = exec_command($cmake_with_options);

    unless ($cmake_result) {
        die "cmake command failed";
    }

    print "Build project with make\n";

    my $make_command = "$ld_library_path_for_make make $make_options";
    my $make_result = exec_command($make_command);

    unless ($make_result) {
        die "Make command '$make_command' failed\n";
    } 

    print "Install project to target directory\n";
    my $install_result = exec_command("make install");

    unless ($install_result) {
        die "Install failed";
    } 

    return 1;
}

# Get folder name from archive
sub get_folder_name_inside_archive {
    my $file_path = shift;

    unless ($file_path && -e $file_path) {
        return '';
    }

    my $tar = Archive::Tar->new;
    $tar->read($file_path);
    
    for my $file($tar->list_files()) { 
        # if name has / in the end we could assume it's folder
        if ($file =~ m#/$#) {
            return $file;
        }
    }

    # For some reasons we can have case when we do not have top level folder alone but we can extract it from path:
    # libcmime-0.2.1/VERSION
    for my $file($tar->list_files()) {
        # if name has / in the end we could assume it's folder
        if ($file =~ m#(.*?)/.*+$#) {
            return $1;
        }
    }  
 
    return '';
}

sub install_hiredis {
    my $disto_file_name = 'v0.14.0.tar.gz'; 
    my $hiredis_install_path = "$library_install_folder/libhiredis_0_14";

    if (-e $hiredis_install_path) {
	warn "hiredis is found at $hiredis_install_path skip build\n";
        return 1;
    }

    chdir $temp_folder_for_building_project;

    print "Download hiredis\n";
    my $hiredis_download_result = download_file("https://github.com/redis/hiredis/archive/$disto_file_name",
        $disto_file_name, 'd668b86756d2c68f0527e845dc10ace5a053bbd9');

    unless ($hiredis_download_result) {
        die "Can't download hiredis\n";
    }

    exec_command("tar -xf $disto_file_name");

    print "Build hiredis\n";
    chdir "hiredis-0.14.0";
    exec_command("PREFIX=$hiredis_install_path make $make_options install");
    1;
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

sub get_logical_cpus_number {
    if ($os_type eq 'linux') {
        my @cpuinfo = `cat /proc/cpuinfo`;
        chomp @cpuinfo;
    
        my $cpus_number = scalar grep {/processor/} @cpuinfo;
    
        return $cpus_number;
    } elsif ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        my $cpus_number = `sysctl -n hw.ncpu`;
        chomp $cpus_number;
    }   
}


# Detect operating system of this machine
sub detect_distribution { 
    my $os_type = '';
    my $distro_type = '';
    my $distro_version = '';
    my $appliance_name = '';
    my $distro_architecture = '';

    my $uname_s_output = `uname -s`;
    chomp $uname_s_output;

    # uname -a output examples:
    # FreeBSD  10.1-STABLE FreeBSD 10.1-STABLE #0 r278618: Thu Feb 12 13:55:09 UTC 2015     root@:/usr/obj/usr/src/sys/KERNELWITHNETMAP  amd64
    # Darwin MacBook-Pro-Pavel.local 14.5.0 Darwin Kernel Version 14.5.0: Wed Jul 29 02:26:53 PDT 2015; root:xnu-2782.40.9~1/RELEASE_X86_64 x86_64
    # Linux ubuntu 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

    if ($uname_s_output =~ /FreeBSD/) {
        $os_type = 'freebsd';
    } elsif ($uname_s_output =~ /Darwin/) {
        $os_type = 'macosx';
    } elsif ($uname_s_output =~ /Linux/) {
        $os_type = 'linux';
    } else {
        warn "Can't detect platform operating system\n";
    }

    if ($os_type eq 'linux') {
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
            my $is_proxmox = '';

            # Really hard to detect https://github.com/proxmox/pve-manager/blob/master/bin/pvebanner
            for my $issue_line (@issue) {
                if ($issue_line =~ m/Welcome to the Proxmox Virtual Environment/) {
                    $is_proxmox = 1;
                    $appliance_name = 'proxmox';
                    last;
                }
            }

            if ($issue_first_line =~ m/Debian/ or $is_proxmox) {
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

        print "We detected your OS as $distro_type Linux $distro_version\n";
    } elsif ($os_type eq 'macosx') {
        my $mac_os_versions_raw = `sw_vers -productVersion`;
        chomp $mac_os_versions_raw;

        if ($mac_os_versions_raw =~ /(\d+\.\d+)/) {
            $distro_version = $1; 
        }

        print "We detected your OS as Mac OS X $distro_version\n";
    } elsif ($os_type eq 'freebsd') {
        my $freebsd_os_version_raw = `uname -r`;
        chomp $freebsd_os_version_raw;

        if ($freebsd_os_version_raw =~ /^(\d+)\.?/) {
            $distro_version = $1;
        }

        print "We detected your OS as FreeBSD $distro_version\n";
    } 

    return { 
        'distro_version' => $distro_version,
        'distro_type' => $distro_type,
        'os_type' => $os_type,
        'distro_architecture' => $distro_architecture,
        'appliance_name' => $appliance_name,
    };
}

sub install_package_by_name_with_dependencies {
    my $package_name = shift;
    my @dependency_packages = ();

    die "Please specify package name" unless $package_name;

    if (defined $dependency_map->{$package_name} && $dependency_map->{$package_name}) {
        unless (ref $dependency_map->{$package_name} eq 'ARRAY') {
            die "Dependency list should be array!\n"
        }   

        @dependency_packages = @{ $dependency_map->{$package_name} };

        print "We have dependencies for this package: " . (join ',', @dependency_packages) . "\n";        
    }

    my @pckages_for_install = (@dependency_packages, $package_name);
    
    for my $package (@pckages_for_install) {
        install_package_by_name($package);
    }   
}

sub install_package_by_name {
    my $package_name = shift;

    unless (defined( &{ "install_$package_name" } )) {
        die "We haven't handler function for this library: $package_name\n";
    }   

    no strict 'refs';
    &{ "install_$package_name"}();
    use strict 'refs';
}

1;
