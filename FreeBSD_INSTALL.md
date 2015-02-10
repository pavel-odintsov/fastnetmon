FreeBSD 9, 10, 11

Install dependencies:
```bash
pkg install cmake git ncurses boost-all log4cpp
```

Update linker paths:
```
/etc/rc.d/ldconfig restart
```


```bash
cd /usr/src/
git clone https://github.com/FastVPSEestiOu/fastnetmon.git
cd fastnetmon
mkdir build
cd build
cmake ..
make
```



