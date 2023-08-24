#!/usr/bin/perl

use strict;
use warnings;

my $error_message = "Please specify package type, original binary file name, version, distro name and version: rpm fastnetmon-binary-git-0cfdfd5e2062ad94de24f2f383576ea48e6f3a07-debian-6.0.10-x86_64 2.0.1 centos 8";

unless (scalar @ARGV == 5) {
    die "$error_message\n";
}


my $package_type = $ARGV[0];
my $archive_name = $ARGV[1];
my $package_version = $ARGV[2];
my $distro_name = $ARGV[3];
my $distro_version = $ARGV[4];

unless ($package_type && $archive_name && $package_version && $distro_name && $distro_version) {
    die "$error_message\n";
}

# Gzip does not compress well, let's use xz instead
# By default it uses compression level 6
my $dpkg_deb_options = '-Zxz -z6';

# It can be: x86_64 or aarch64
my $machine_architecture = `uname -m`;
chomp $machine_architecture;

# For number of places we need Debian specific name for particular architectures
my $debian_architecture_name = 'amd64';

if ($machine_architecture eq 'aarch64') {
    $debian_architecture_name = 'arm64';
} elsif ($machine_architecture eq 'x86_64') {
    $debian_architecture_name = 'amd64';
}

if ($package_type eq 'rpm') {
    build_rpm_package();
} elsif ($package_type eq 'deb') {
    build_deb_package();
}

sub build_rpm_package {
    print "Install packages for crafting rpm packages\n";
    my $packages_install = system("yum install -y rpmdevtools yum-utils");

    if ($packages_install != 0) {
        die "Cannot install build packages\n";
    }

    mkdir '/root/rpmbuild' or die "Cannot create rpmbuild folder";;
    mkdir '/root/rpmbuild/SOURCES' or die "Cannot create source folder";

    my $systemd_init_script = <<'DOC';
[Unit]
Description=FastNetMon - DoS/DDoS analyzer with sFlow/Netflow/mirror support
After=network.target remote-fs.target
 
[Service]
Type=simple
ExecStart=/opt/fastnetmon-community/app/bin/fastnetmon
LimitNOFILE=65535
# Restart service when it fails due to any reasons, we need to keep processing traffic no matter what happened
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
DOC

    my $rpm_sources_path = '/root/rpmbuild/SOURCES';

    # Copy bundle to build tree
    my $copy_res = system("cp $archive_name $rpm_sources_path/archive.tar.gz");

    if ($copy_res != 0) {
        die "Cannot copy file $archive_name to $rpm_sources_path/archive.tar.gz\n";
    }

    if (defined($ENV{'CIRCLECI'})) {
        my $conf_path = $ENV{'CIRCLE_WORKING_DIRECTORY'} . '/src/fastnetmon.conf';

        my $conf_copy_res = system("cp $conf_path $rpm_sources_path/fastnetmon.conf");

        if ($conf_copy_res != 0) {
            die "Cannot copy fastnetmon.conf from $conf_path to $rpm_sources_path/fastnetmon.conf\n";
        }
    } else {
        my $wget_res = system("wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon.conf -O$rpm_sources_path/fastnetmon.conf");
   
        if ($wget_res != 0) {
            die "Cannot download fastnetmon.conf\n";
        }
    }

    put_text_to_file("$rpm_sources_path/systemd_init", $systemd_init_script);

    # Create files list from archive
    # ./libname_1.2.3/
    my @files_list = `tar -tf /root/rpmbuild/SOURCES/archive.tar.gz`;
    chomp @files_list;

    # Replace path
    @files_list = map { s#^\.#/opt#; $_ } @files_list;

    # Filter out folders
    @files_list = grep { ! m#/$# } @files_list;

    if (scalar @files_list == 0) {
        die "Files must not be empty\n";
    }

    my $spec_file_header = <<'DOC';
#
# Pre/post params: https://fedoraproject.org/wiki/Packaging:ScriptletSnippets
#

%global  fastnetmon_attackdir   %{_localstatedir}/log/fastnetmon_attacks
%global  fastnetmon_user        root
%global  fastnetmon_group       %{fastnetmon_user}
%global  fastnetmon_config_path %{_sysconfdir}/fastnetmon.conf

Name:              fastnetmon

DOC

    # We do need variable interpolation here
    my $spec_file_version = <<DOC;

Version:           $package_version

DOC

    my $spec_file_summary_section = <<'DOC';
Release:           1%{?dist}

Summary:           A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFLOW, Netmap, PCAP).
Group:             System Environment/Daemons
License:           GPLv2
URL:               https://fastnetmon.com

# Top level fodler inside archive should be named as "fastnetmon-1.1.1" 
Source0:           http://178.62.227.110/fastnetmon_binary_repository/test_binary_builds/this_fake_path_do_not_check_it/archive.tar.gz

# Disable any sort of dynamic dependency detection for our own custom bunch of binaries
AutoReq:           no
AutoProv:          no

DOC

    my $spec_file_requires_systemd_section = <<'DOC';

Requires(pre):     shadow-utils
Requires(post):    systemd
Requires(preun):   systemd
Requires(postun):  systemd
Provides:          fastnetmon

DOC

    my $spec_file_description_section = <<'DOC';

%description
A high performance DoS/DDoS load analyzer built on top of multiple packet capture
engines (NetFlow, IPFIX, sFlow, Netmap, PCAP).


DOC

    my $spec_file_prep_section = <<'DOC';
%prep

rm -rf fastnetmon-tree
mkdir fastnetmon-tree
mkdir fastnetmon-tree/opt
tar -xvvf /root/rpmbuild/SOURCES/archive.tar.gz -C fastnetmon-tree/opt

DOC

my $spec_file_prep_footer_systemd_section = <<'DOC';

# Copy service scripts
mkdir fastnetmon-tree/etc
cp /root/rpmbuild/SOURCES/systemd_init fastnetmon-tree/etc
cp /root/rpmbuild/SOURCES/fastnetmon.conf fastnetmon-tree/etc

DOC

    my $systemd_spec_file = $spec_file_header . $spec_file_version . $spec_file_summary_section . $spec_file_requires_systemd_section . $spec_file_description_section . $spec_file_prep_section . $spec_file_prep_footer_systemd_section;

    $systemd_spec_file .= <<'DOC';
%build

# We do not build anything
exit 0

%install

# Create symlinks for better customer experience
mkdir %{buildroot}/usr
mkdir %{buildroot}/usr/bin
ln -s /opt/fastnetmon-community/app/bin/fastnetmon %{buildroot}/usr/bin/fastnetmon
ln -s /opt/fastnetmon-community/app/bin/fastnetmon_client %{buildroot}/usr/bin/fastnetmon_client
ln -s /opt/fastnetmon-community/app/bin/fastnetmon_api_client %{buildroot}/usr/bin/fastnetmon_api_client

mkdir %{buildroot}/opt
cp -R fastnetmon-tree/opt/* %{buildroot}/opt
chmod 755 %{buildroot}/opt/fastnetmon-community/app/bin/fastnetmon
chmod 755 %{buildroot}/opt/fastnetmon-community/app/bin/fastnetmon_client
chmod 755 %{buildroot}/opt/fastnetmon-community/app/bin/fastnetmon_api_client

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

/usr/bin/fastnetmon
/usr/bin/fastnetmon_client
/usr/bin/fastnetmon_api_client

{files_list}

%{_sysconfdir}/systemd/system
%config(noreplace) %{_sysconfdir}/fastnetmon.conf
%attr(700,%{fastnetmon_user},%{fastnetmon_group}) %dir %{fastnetmon_attackdir}

%changelog
* Mon Mar 23 2022 Pavel Odintsov <pavel.odintsov@gmail.com> - 1.2.1-1
- First RPM package release
DOC

    my $selected_spec_file = $systemd_spec_file;

    # Add full list of files into RPM spec
    my $joined_file_list = join "\n", @files_list;
    $selected_spec_file =~ s/\{files_list\}/$joined_file_list/;
    
    put_text_to_file("generated_spec_file.spec", $selected_spec_file);

    my $rpmbuild_res = system("rpmbuild -bb generated_spec_file.spec");

    if ($rpmbuild_res != 0) {
        die "Rpmbuild failed with code $rpmbuild_res\n";
    }

    mkdir "/tmp/result_data" or die "Cannot create result_data folder";
    my $copy_rpm_res = system("cp /root/rpmbuild/RPMS/$machine_architecture/* /tmp/result_data");
    
    if ($copy_rpm_res != 0) {
        die "Cannot copy result rpm\n";
    }

    print "Result RPM:\n";
    print `ls -la /tmp/result_data`;
}

sub build_deb_package {
    print "We will build deb from $archive_name\n";

    my $fastnetmon_systemd_unit = <<'DOC';
[Unit]
Description=FastNetMon - DoS/DDoS analyzer with sFlow/Netflow/mirror support
After=network.target remote-fs.target
 
[Service]
Type=simple
ExecStart=/opt/fastnetmon-community/app/bin/fastnetmon
LimitNOFILE=65535
# Restart service when it fails due to any reasons, we need to keep processing traffic no matter what happened
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
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

    chdir $folder_for_build or die "Cannot chdir to $folder_for_build\n";

    mkdir "$folder_for_build/DEBIAN" or die "Cannot create DEBIAN folder\n";;
    put_text_to_file("$folder_for_build/DEBIAN/control", $fastnetmon_control_file);
    
    put_text_to_file("$folder_for_build/DEBIAN/prerm", $fastnetmon_prerm_hook);
    put_text_to_file("$folder_for_build/DEBIAN/postinst", $fastnetmon_postinst_hook);
    put_text_to_file("$folder_for_build/DEBIAN/postrm", $fastnetmon_server_postrm_hook);

    # Set exec bits for all of them
    my @deb_hooks_list = ("$folder_for_build/DEBIAN/postrm", "$folder_for_build/DEBIAN/prerm", "$folder_for_build/DEBIAN/postinst");

    for my $hook_path (@deb_hooks_list) {
        my $chmod_res = system("chmod +x $hook_path");

        if ($chmod_res != 0) {
            die "Cannot set chmod for $hook_path\n";
        }
    }
    # Create init files for different versions of Debian like OS 
    mkdir "$folder_for_build/etc" or die "Cannot create etc folder\n";
    mkdir "$folder_for_build/etc/init" or die "Cannot create init folder\n";

    # Create folders for system service file
    mkdir "$folder_for_build/lib" or die "Cannot create lib folder";
    mkdir "$folder_for_build/lib/systemd" or die "Cannot create systemd folder";;
    mkdir "$folder_for_build/lib/systemd/system" or die "Cannot create systemd/system folder";

    # Create symlinks to call commands without full path
    mkdir "$folder_for_build/usr" or die "Cannot create usr folder";
    mkdir "$folder_for_build/usr/bin" or die "Cannot reate usr/bin folder";

    my $fastnetmon_client_ln_res = system("ln -s /opt/fastnetmon-community/app/bin/fastnetmon_client $folder_for_build/usr/bin/fastnetmon_client");

    if ($fastnetmon_client_ln_res != 0) {
        die "Cannot create symlink for fastnetmon_client";
    }

    my $fastnetmon_api_client_ln_res = system("ln -s /opt/fastnetmon-community/app/bin/fastnetmon_api_client $folder_for_build/usr/bin/fastnetmon_api_client");

    if ($fastnetmon_api_client_ln_res != 0) {
        die "Cannot create symlink for fastnetmon_api_client";
    }

    my $fastnetmon_ln_res = system("ln -s /opt/fastnetmon-community/app/bin/fastnetmon $folder_for_build/usr/bin/fastnetmon");

    if ($fastnetmon_ln_res != 0) {
        die "Cannot create symlink for fastnetmon";
    }

    put_text_to_file("$folder_for_build/lib/systemd/system/fastnetmon.service", $fastnetmon_systemd_unit);

    # Configuration file
    put_text_to_file("$folder_for_build/DEBIAN/conffiles", "/etc/fastnetmon.conf\n");

    # Create folder for config
    my $mkdir_etc_res = system("mkdir -p $folder_for_build/etc");

    if ($mkdir_etc_res != 0) {
        die "Cannot create folder $folder_for_build/etc\n";
    }


    if (defined($ENV{'CIRCLECI'})) {
        my $conf_path = $ENV{'CIRCLE_WORKING_DIRECTORY'} . '/src/fastnetmon.conf';

        my $conf_copy_res = system("cp $conf_path $folder_for_build/etc/fastnetmon.conf");

        if ($conf_copy_res != 0) {
            die "Cannot copy fastnetmon.conf from $conf_path to $folder_for_build/etc/fastnetmon.conf\n";
        }
    } else {
        my $wget_res = system("wget --no-check-certificate https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon.conf -O$folder_for_build/etc/fastnetmon.conf");
   
        if ($wget_res != 0) {
            die "Cannot download fastnetmon.conf\n";
        }
    }

    my $copy_archive_res = system("cp $archive_name $folder_for_build/archive.tar.gz");

    if ($copy_archive_res != 0) {
        die "Cannot cop archive\n";
    }

    mkdir "$folder_for_build/opt" or die "Cannot create opt folder";;
    my $chmod_opt_res = system("chmod 755 $folder_for_build/opt");

    if ($chmod_opt_res != 0) {
        die "Cannot set chmod for /opt";
    }

    my $tar_res = system("tar -xf $folder_for_build/archive.tar.gz  -C $folder_for_build/opt");

    if ($tar_res != 0) {
        die "Cannot decompress folder with error: $tar_res\n";
    }

    # unlink("$folder_for_build/archive.tar.gz");

    # Set new permissions again. Probably, they was overwritten by tar -xf command
    my $opt_chmod_res = system("chmod 755 $folder_for_build/opt");

    if ($opt_chmod_res != 0) {
        die "Cannot set chmod for /opt";
    }

    # Change owner to root for all files inside build folder
    my $opt_chown_res = system("chown root:root -R $folder_for_build");

    if ($opt_chown_res != 0) {
        die "Cannot chown /opt";
    }

    my $deb_build_start_time = time();

    my $deb_build_command = "dpkg-deb  --debug  --verbose $dpkg_deb_options --build $folder_for_build /tmp/fastnetmon_${package_version}_${debian_architecture_name}.deb";

    print "Build command: $deb_build_command\n";

    my $deb_build_res = system($deb_build_command);

    if ($deb_build_res != 0) {
        die "dpkg-deb failed with error code: $deb_build_res\n";
    }

    print "dpkg-deb finished in ", time() - $deb_build_start_time, " seconds\n";
}

sub put_text_to_file {
    my ($path, $text) = @_; 

    open my $fl, ">", $path or die "Can't open $! for writing\n";
    print {$fl} $text;
    close $fl;
}
