# Short reference about building deb packages

```bash
mkdir /usr/src/fastnetmon_deb
cd /usr/src/fastnetmon_deb
export PACKAGE_VERSION=1.1
wget https://github.com/FastVPSEestiOu/fastnetmon/archive/master.tar.gz -O"fastnetmon_$PACKAGE_VERSION.orig.tar.gz"
tar -xf "fastnetmon_$PACKAGE_VERSION.orig.tar.gz"
mv fastnetmon-master "fastnetmon-$PACKAGE_VERSION"
cd "fastnetmon-$PACKAGE_VERSION"
cp packages/debian/ -R .
debuild -us -uc
```
