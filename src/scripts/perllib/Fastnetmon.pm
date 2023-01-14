package Fastnetmon;

use strict;
use warnings;

use File::Copy;
use File::Basename;

# Retrieve all required modules

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
install_build_dependencies
exec_command
get_sha1_sum
download_file
read_file
apt_get
yum
get_active_network_interfaces
);

our $dependency_map = {
    'boost' => [ 'boost_build', 'icu' ]
};

my $ld_library_path_for_make = "";

my $build_with_clang = '';
# When we are working with clang it's not a good idea to use stdc++ because they are becoming a bit incompatible
my $use_libcpp_instead_stdcpp = '';

my $gcc_version = '12.1.0';

# Name of bucket where we keep compiled dependencies
my $s3_bucket_binary_dependency_name = 'fastnetmon_community_binary_dependencies';

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

# Retrieves binary build of particular dependency from Google
# Expects argument in format: libbpf_1_0_1
# In case of success returns 1
# In case of any hash related issues returns 2
sub get_library_binary_build_from_google_storage {
    my $dependency_name = shift;

    my $dependency_archive_name = "$dependency_name.tar.gz";

    my $binary_path = "s3://$s3_bucket_binary_dependency_name/$distro_type/$distro_version/$dependency_archive_name";

    print "Will use following path to retrieve dependency: $binary_path\n";

    my $check_that_file_exists =
        system("s3cmd --disable-multipart  --host=storage.googleapis.com --host-bucket=\"%(bucket).storage.googleapis.com\" ls $binary_path");

    # We do not have it
    if ($check_that_file_exists != 0) {
        print "File does not exist on Google Storage side\n";
        return 0;
    }

    my $download_this_file =
        system("s3cmd --disable-multipart  --host=storage.googleapis.com --host-bucket=\"%(bucket).storage.googleapis.com\" get $binary_path /tmp/$dependency_archive_name");

    if ($download_this_file != 0) {
        print "Cannot download dependency file from Google Storage\n";
        return 0;
    }

    # Hashes for all distros
    my $data_hashes = shift;

    my $current_build_hash = $data_hashes->{ "$distro_type:$distro_version" };

    # Hash must exist for all our existing dependencies
    unless ($current_build_hash) {
        warn "Cannot get $dependency_name hash for Distro $distro_type $distro_version, please add it to build configuration";
        return 2;
    }

    print "Start sha-512 calculation\n";
    my $sha512 = get_sha_512_sum("/tmp/$dependency_archive_name");

    unless ($sha512) {
        warn "Cannot calculate SHA512 for file from S3\n";
        return 2;
    }

    print "Calculated sha-512 for $dependency_name $sha512\n";

    if ($sha512 ne $current_build_hash) {
        warn "Hash mismatch. Expected: $current_build_hash got: $sha512. It may be sign of data tampering, please validate data source\n";
        return 2;
    }

    print "Successfully validated sha-512 signatures\n";

    system("mkdir -p $library_install_folder");

    my $unpack_res = system("tar --use-compress-program=pigz -xf /tmp/$dependency_archive_name -C $library_install_folder");

    if ($unpack_res != 0) {
        print "Cannot unpack file\n";
        return 0;
    }

    return 1;
}


# Uploads binary build to Google
sub upload_binary_build_to_google_storage {
    my $dependency_name = shift;

    my $dependency_archive_name = "$dependency_name.tar.gz";

    my $binary_path = "s3://$s3_bucket_binary_dependency_name/$distro_type/$distro_version/$dependency_archive_name";

    my $archive_res = system("tar --use-compress-program=pigz -cpf /tmp/$dependency_archive_name -C $library_install_folder $dependency_name");

    if ($archive_res != 0) {
        print "Cannot pack dependency\n";
        return '';
    }

    my $upload_this_file =
        system("s3cmd --disable-multipart  --host=storage.googleapis.com --host-bucket=\"%(bucket).storage.googleapis.com\" put /tmp/$dependency_archive_name $binary_path");

    if ($upload_this_file != 0) {
        print "Cannot upload dependency file from Google Storage\n";
        return '';
    }

    print "Successfully uploaded\n";

    print "Start sha 512 calculations\n";
    my $sha512 = get_sha_512_sum("/tmp/$dependency_archive_name");

    unless ($sha512) {
        print "Cannot calculate sha-512 for file\n";
        return '';
    }

    print "Successfully calculated sha-512 for $dependency_name: $sha512\n";

    return 1
}


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

sub get_sha_512_sum {
    my $path = shift;
    
    my $hasher_name = 'sha512sum';

    my $output = `$hasher_name $path`;
    chomp $output;

    my ($sha_512) = ($output =~ m/^(\w+)\s+/);

    return $sha_512;
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

# Installs all dependencies required for build process
sub install_build_dependencies {
    my $machine_information = Fastnetmon::detect_distribution();

    unless ($machine_information) {
        die "Could not collect machine information\n";
    }

    my $distro_version = $machine_information->{distro_version};
    my $distro_type = $machine_information->{distro_type};

    # Install packages required for build
    if ($distro_type eq 'ubuntu' or $distro_type eq 'debian') {
        print "Update package manager cache\n";
        exec_command("apt-get update");
        apt_get('make', 'wget', 'git', 'pigz', 'autoconf', 'libtool', 'pkg-config');
    } elsif ( $distro_type eq 'centos') {
        # We need libmpc for our custom built gcc
        yum('make', 'wget', 'libmpc', 'glibc-devel', 'git', 'pigz', 'autoconf', 'libtool', 'pkgconfig');
    }
}

# This code will init global compiler settings used in options for other packages build
sub init_compiler {
    init_machine_information();

    # 5_3_0 instead of 5.3.0
    my $gcc_version_for_path = $gcc_version;
    $gcc_version_for_path =~ s/\./_/g;

    $gcc_c_compiler_path = "$library_install_folder/gcc_$gcc_version_for_path/bin/gcc";
    $gcc_cpp_compiler_path = "$library_install_folder/gcc_$gcc_version_for_path/bin/g++";

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

    my @make_library_path_list_options = ("$library_install_folder/gcc_$gcc_version_for_path/lib64");

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

sub install_bpf {
    my $folder_name = shift;

    my $libbpf_package_install_path = "$library_install_folder/$folder_name";

    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        my @dependency_list = ('libelf-dev');
        apt_get(@dependency_list);
    } elsif ($distro_type eq 'centos') {
        yum('elfutils-libelf-devel');
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

    system("$ld_library_path_for_make make");

    system("mkdir -p $libbpf_package_install_path");
    system("cp libbpf.a libbpf.so libbpf.so.1 libbpf.so.1.0.1 $libbpf_package_install_path");

    system("mkdir -p $libbpf_package_install_path/include/bpf");
    system("cp bpf.h libbpf.h libbpf_common.h libbpf_version.h libbpf_legacy.h $libbpf_package_install_path/include/bpf");

    return 1;
}

sub install_gcc {
    my $folder_name = shift;    

    my $gcc_package_install_path = "$library_install_folder/$folder_name";

    warn "Cannot get dependency from cache, do manual build\n";

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
    # We are using --enable-host-shared because we should build gcc as dynamic library for jit compiler purposes
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
    my $folder_name = shift;

    my $boost_version = '1.80.0';

    my $boost_version_with_underscore = "1_80_0";

    my $boost_install_path = "$library_install_folder/$folder_name";

    # TODO: not perfect option actually
    # We're going to build directly in install folder
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
    my $b2_build_result = exec_command("$ld_library_path_for_make $library_install_folder/boost_build_4_9_2/bin/b2 -j $boost_build_threads -sICU_PATH=$library_install_folder/icu_65_1 linkflags=\"-Wl,-rpath,$library_install_folder/icu_65_1/lib\" --build-dir=$temp_folder_for_building_project/boost_build_temp_directory link=shared --without-test --without-python --without-wave --without-log --without-mpi");

    # We should not do this check because b2 build return bad return code even in success case... when it can't build few non important targets
    unless ($b2_build_result) {
        ### die "Can't execute b2 build correctly\n";
    }

    1;
}

sub install_boost_build {
    my $folder_name = shift;

    chdir $temp_folder_for_building_project;

    # We use another name because it uses same name as boost distribution
    my $archive_file_name = '4.9.2.tar.gz';

    my $boost_builder_install_folder = "$library_install_folder/$folder_name";

    print "Download boost builder\n";
    my $boost_build_result = download_file("https://github.com/bfgroup/build/archive/$archive_file_name", $archive_file_name,
        '1c77d3fda9425fd89b783db8f7bd8ebecdf8f916');

    unless ($boost_build_result) {
        die("Can't download boost builder\n");
    }

    print "Unpack boost builder\n";
    exec_command("tar -xf $archive_file_name");

    unless (chdir "b2-4.9.2") {
        die("Cannot do chdir to build boost folder\n");
    }

    # Due to this bug:
    # https://github.com/boostorg/build/issues/705
    # I do not think that it actually fixed
    # We need to install system compiler
    
    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        apt_get('g++');
    } elsif ($distro_type eq 'centos') {
        yum('gcc-c++');
    }

    print "Build Boost builder\n";
    my $bootstrap_result = exec_command("$ld_library_path_for_make CC=$default_c_compiler_path CXX=$default_cpp_compiler_path  ./bootstrap.sh --with-toolset=gcc");

    unless ($bootstrap_result) {
        die("bootstrap of Boost Builder failed, please check logs\n");
    }

    my $b2_install_result = exec_command("$ld_library_path_for_make ./b2 install --prefix=$boost_builder_install_folder");

    unless ($b2_install_result) {
        die("Can't execute b2 install\n");
    }

    1;
}

sub install_log4cpp {
    my $folder_name = shift;

    my $log_cpp_version_short = '1.1.3';

    my $log4cpp_install_path = "$library_install_folder/$folder_name";

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

    my $make_result = exec_command("$ld_library_path_for_make make $make_options install"); 

    if (!$make_result) {
        print "make for log4cpp failed\n";
    }

    1;
}

sub install_cares {
    my $folder_name = shift;

    my $res = install_configure_based_software("https://github.com/c-ares/c-ares/releases/download/cares-1_18_1/c-ares-1.18.1.tar.gz",
        "9e2a99af58d163d084db6fcebb2165a960bdd1af", "$library_install_folder/$folder_name", "");

    unless ($res) {
        die "Cannot install C-Ares\n";
    }

    return 1;
}


sub install_zlib {
    my $folder_name = shift;

    my $res = install_configure_based_software("https://zlib.net/zlib-1.2.13.tar.gz",
        "55eaa84906f31ac20d725aa26cd20839196b6ba6", "$library_install_folder/$folder_name", "");

    unless ($res) {
        die "Cannot install zlib\n";
    }

    return 1;
}

sub install_grpc {
    my $folder_name = shift;

    my $grpc_install_path = "$library_install_folder/$folder_name";

    my $protobuf_install_path = "$library_install_folder/protobuf_21_12";

    my $abseil_install_path = "$library_install_folder/abseil_2022_06_23";

    my $openssl_path = "$library_install_folder/$openssl_folder_name";

    my $cares_path = "$library_install_folder/cares_1_18_1";

    my $zlib_path = "$library_install_folder/zlib_1_2_13";

    my $re2_path = "$library_install_folder/re2_2022_12_01";

    # There is a problem with official tar.gz from https://github.com/grpc/grpc/releases
    # When they prepare tar.gz they do not pull all required dependencies to third_party folder
    # https://github.com/grpc/grpc/issues/31760#issuecomment-1339944451
    # Such a great finding that you actually need to explicitly provide -DBUILD_SHARED_LIBS=ON to build dynamic libraries
    #
    # I decided to explicitly set CMAKE_INSTALL_RPATH to lib folder of installed library as we're dealing with some weird linker issues for gRPC dependencies
    # (libupb.so.10, libaddress_sorting.so.10 and it actually solved these issues
    #
    # Then I added all dependency libraries into CMAKE_INSTALL_RPATH as we had weird linking issues with Cares
    #
    my $res = install_cmake_based_software("https://github.com/grpc/grpc/archive/v1.49.2.tar.gz",
         "28ba57cb3648812a48fd06c0de4b1e89d41e6934",
         $grpc_install_path,
         "$ld_library_path_for_make $cmake_path -DCMAKE_C_COMPILER=$default_c_compiler_path -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -DCMAKE_INSTALL_PREFIX=$grpc_install_path -DgRPC_PROTOBUF_PROVIDER=package -DCMAKE_INSTALL_RPATH=\"$grpc_install_path/lib;$cares_path/lib;$openssl_path/lib;$abseil_install_path/lib;$re2_path/lib64;$re2_path/lib\" -DCMAKE_PREFIX_PATH=\"$protobuf_install_path;$openssl_path;$cares_path;$abseil_install_path/lib/cmake/absl;$abseil_install_path/lib64/cmake/absl;$zlib_path;$re2_path/lib64/cmake/re2;$re2_path/lib/cmake/re2\" -DgRPC_ZLIB_PROVIDER=package -DgRPC_SSL_PROVIDER=package -DgRPC_ABSL_PROVIDER=package -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DgRPC_CARES_PROVIDER=package -DgRPC_RE2_PROVIDER=package -DBUILD_SHARED_LIBS=ON ..");

    if (!$res) {
        die "Can't install gRPC\n";
    }

    return 1;
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

# We do not use cache for it yet
sub install_gobgp {
    my $folder_name = shift;

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

   
    my $gobgp_install_path = "$library_install_folder/$folder_name";

    mkdir "$gobgp_install_path";
   
    `cp gobgp $gobgp_install_path`; 
    `cp gobgpd $gobgp_install_path`;

    1; 
}

sub install_re2 {
    my $folder_name = shift;

    my $install_path = "$library_install_folder/$folder_name";

    my $res = install_cmake_based_software("https://github.com/google/re2/archive/refs/tags/2022-12-01.tar.gz",
        "8146fb81e2b8988a455f2f7291c7a8a4001e55a6",
        "$library_install_folder/$folder_name",
        "$ld_library_path_for_make $cmake_path -DCMAKE_C_COMPILER=$default_c_compiler_path -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$install_path ..");

    if (!$res) {
        die "Cannot install re2";
    }    

    return 1;
}


sub install_protobuf {
    my $folder_name = shift;

    my $install_path = "$library_install_folder/$folder_name";

    my $res = install_cmake_based_software("https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-all-21.12.tar.gz",
        "5dcaabdc890593b1c9c5dc5646a26ff82593ccb9",
        "$library_install_folder/$folder_name",
        "$ld_library_path_for_make $cmake_path -DCMAKE_C_COMPILER=$default_c_compiler_path -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -Dprotobuf_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$install_path ..");

    if (!$res) {
        die "Cannot install Protobuf";
    }

    return 1;
}

sub install_elfutils {
    my $folder_name = shift;

    if ($distro_type eq 'ubuntu' || $distro_type eq 'debian') {
        apt_get(('zlib1g-dev'));
    } elsif ($distro_type eq 'centos') {
        yum('zlib-devel', 'm4');
    }

    my $res = install_configure_based_software("https://sourceware.org/pub/elfutils/0.186/elfutils-0.186.tar.bz2",
        "650d52024be684dabf18a5261a69836a16f84f72",
        "$library_install_folder/$folder_name",
        '--disable-debuginfod --disable-libdebuginfod'
    );

    unless ($res) { 
        die "Cannot install elfutils\n";
    }

    return 1;
}

sub install_capnproto {
    my $folder_name = shift;

    my $capnp_install_path = "$library_install_folder/$folder_name";

    warn "Cannot get dependency from cache, do manual build\n";

    my $res = install_configure_based_software("https://capnproto.org/capnproto-c++-0.8.0.tar.gz", 
        "fbc1c65b32748029f1a09783d3ebe9d496d5fcc4", $capnp_install_path, 
        '');

    unless ($res) { 
        die "Could not install capnproto";
    }

    return 1;
}

sub install_abseil {
    my $folder_name = shift;

    my $install_path = "$library_install_folder/$folder_name";

    # We need explicitly enable PIC to successfully build against gRPC
    # https://github.com/abseil/abseil-cpp/pull/741
    # -DCMAKE_POSITION_INDEPENDENT_CODE=true
    my $res = install_cmake_based_software("https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.0.tar.gz",
        "144c2108e1532c642cdb6ca532ee26e91146cf28",
        "$library_install_folder/$folder_name",
        "$ld_library_path_for_make $cmake_path -DCMAKE_C_COMPILER=$default_c_compiler_path -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -DABSL_BUILD_TESTING=ON -DABSL_USE_GOOGLETEST_HEAD=ON -DABSL_ENABLE_INSTALL=ON -DCMAKE_CXX_STANDARD=11 -DCMAKE_POSITION_INDEPENDENT_CODE=true -DCMAKE_INSTALL_PREFIX=$install_path ..");

    if (!$res) {
        die "Cannot install abseil";
    }

    return 1;
}


sub install_mongo_c_driver {
    my $folder_name = shift;

    my $install_path = "$library_install_folder/$folder_name";
    
    my $openssl_path = "$library_install_folder/$openssl_folder_name";

    # OpenSSL is mandatory for SCRAM-SHA-1 auth mode
    # I also use flag ENABLE_ICU=OFF to disable linking against icu system library. I do no think that we really need it
    my $res = install_cmake_based_software("https://github.com/mongodb/mongo-c-driver/releases/download/1.23.0/mongo-c-driver-1.23.0.tar.gz",
        "f6256acfe89ed094158be84a3ce2a56fd7f22637",
	$install_path,
	"$ld_library_path_for_make $cmake_path -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:STRING=$library_install_folder/mongo_c_driver_1_23_0 -DCMAKE_C_COMPILER=$default_c_compiler_path -DOPENSSL_ROOT_DIR=$openssl_path -DCMAKE_CXX_COMPILER=$default_cpp_compiler_path -DENABLE_ICU=OFF -DMONGOC_TEST_USE_CRYPT_SHARED=OFF ..");

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
    my $folder_name = shift;

    my $distro_file_name = 'openssl-1.1.1q.tar.gz';
    my $openssl_install_path = "$library_install_folder/$folder_name";
 
    chdir $temp_folder_for_building_project;
   
    my $openssl_download_result = download_file("https://www.openssl.org/source/$distro_file_name", 
        $distro_file_name, '79511a8f46f267c533efd32f22ad3bf89a92d8e5');

    unless ($openssl_download_result) {   
        die "Could not download openssl";
    }

    exec_command("tar -xf $distro_file_name");
    chdir "openssl-1.1.1q";

    exec_command("CC=$default_c_compiler_path ./config shared --prefix=$openssl_install_path");
    exec_command("$ld_library_path_for_make make -j $make_options");
    exec_command("$ld_library_path_for_make make install");
    
    1;
}

sub install_icu {
    my $folder_name = shift;

    my $distro_file_name = 'icu4c-65_1-src.tgz';
   
    chdir $temp_folder_for_building_project;
 
    my $icu_install_path = "$library_install_folder/$folder_name";

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
    my $folder_name = shift;

    print "Install cmake\n";

    my $cmake_install_path = "$library_install_folder/$folder_name";

    warn "Cannot get dependency from cache, do manual build\n";
    
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
    my $unpack_result = exec_command("tar --no-same-owner -xf $file_name");

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
    my $install_result = exec_command("$ld_library_path_for_make make install");

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
    my $folder_name = shift;

    my $disto_file_name = 'v0.14.0.tar.gz'; 
    my $hiredis_install_path = "$library_install_folder/$folder_name";

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

    my $upload_binary_res = upload_binary_build_to_google_storage($folder_name);

    if (!$upload_binary_res) {
        warn "Cannot upload dependency to cache\n";
    }

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

# Gets OS type for our purposes
sub get_os_type {
    my $os_type = '';

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

    return $os_type;
}


sub get_logical_cpus_number {
    my $os_type = get_os_type();

    if ($os_type eq 'linux') {
        my @cpuinfo = `cat /proc/cpuinfo`;
        chomp @cpuinfo;

        my $cpus_number = scalar grep {/processor/} @cpuinfo;

        return $cpus_number;
    } elsif ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        my $cpus_number = `sysctl -n hw.ncpu`;
        chomp $cpus_number;
    } else {
        warn "Unknown platform: $os_type Cannot get number of CPUs";
        return 1;
    }
}

# Detect operating system of this machine
sub detect_distribution { 
    my $distro_type = '';
    my $distro_version = '';
    my $appliance_name = '';
    my $distro_architecture = '';

    my $os_type = get_os_type();

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

                # 
                # Debian 6 example: 6.0.10
                # We will try transform it to decimal number
                if ($distro_version =~ /^(\d+)\.\d+\.\d+$/) {
                    $distro_version = $1;
                } elsif ($distro_version =~ /^(\d+)\.\d+$/) {
                    # Examples: 9.13, 10.13, 11.5
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
    my $handler_name = shift;

    # libname_1_2_3
    my $full_package_name = shift;

    unless (defined( &{ "install_$handler_name" } )) {
        die "We have no handler function $handler_name for this library $full_package_name\n";
    }   

    no strict 'refs';
    &{ "install_$handler_name"}($full_package_name);
    use strict 'refs';
}

1;
