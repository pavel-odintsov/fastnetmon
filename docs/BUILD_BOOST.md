### We will describe here how to build Boost

Build builder:
```bash
cd /usr/src
wget https://github.com/boostorg/build/archive/boost-1.58.0.tar.gz -Oboost-1.58.0.tar.gz
tar -xf boost-1.58.0.tar.gz 
cd build-boost-1.58.0/
./bootstrap.sh
./b2 install --prefix=/opt/boost_build1.5.8
```

Download Boost source code:
```bash
cd /usr/src
wget 'http://downloads.sourceforge.net/project/boost/boost/1.58.0/boost_1_58_0.tar.gz?r=http%3A%2F%2Fwww.boost.org%2Fusers%2Fhistory%2Fversion_1_58_0.html&ts=1439207367&use_mirror=cznic' -Oboost_1_58_0.tar.gz
tar -xf boost_1_58_0.tar.gz
cd boost_1_58_0/
```

Start build process:
```bash
/opt/boost_build1.5.8/bin/b2 --build-dir=/tmp/boosе_build_temp_directory_1_5_8 toolset=gcc --without-test --without-python --without-wave --without-graph --without-coroutine --without-math --without-log --without-graph_parallel --without-mpi 
```

Add Boost library path to system path:
```bash
echo "/usr/src/boost_1_58_0/stage/lib" > /etc/ld.so.conf.d/boost.conf
ldconfig
```

Build time need about 5 minutes on i7 CPU.

For tests we could try to remove standard version of Boost.

Be careful before this actions! ```apt-get remove libboost1.55-dev```

And add Boost paths to top of CMakeLists.txt file:
```bash
set(BOOST_INCLUDEDIR "/usr/src/boost_1_58_0")
set(BOOST_LIBRARYDIR "/usr/src/boost_1_58_0/stage/lib/")
```


