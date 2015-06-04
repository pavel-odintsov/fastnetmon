# Short reference about building deb packages

```bash
mkdir /usr/src/fastnetmon_deb
cd /usr/src/fastnetmon_deb
export PACKAGE_VERSION=1.1
wget https://github.com/FastVPSEestiOu/fastnetmon/archive/master.tar.gz -O"fastnetmon_$PACKAGE_VERSION.orig.tar.gz"
tar -xf "fastnetmon_$PACKAGE_VERSION.orig.tar.gz"
mv fastnetmon-master "fastnetmon-$PACKAGE_VERSION"
cd "fastnetmon-$PACKAGE_VERSION"
# Create symlinks for init files for systev and systemd
ln -s ../src/fastnetmon_init_script_debian_6_7 debian/fastnetmon.init
ln -s ../src/fastnetmon.service debian/fastnetmon.service
# We need this for Debian https://lintian.debian.org/tags/systemd-service-file-refers-to-obsolete-target.html
# But RHEL7 still uses it
sed -i 's/syslog.target //' src/fastnetmon.service
dpkg-source --commit . fix_systemd_service
# enter any patch name
debuild -us -uc
```
