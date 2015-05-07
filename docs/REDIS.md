# Redis backend

I introduced Redis support for store information about attacks.

How to compile:

Install dependencies:
```bash
# Debian like distros
apt-get install -y libhiredis-dev
# RedHat like distros 
yum install -y hiredis-devel
```

Uncomment lines regarding redis in CMakeLists.txt

And compile:
```bash
cd /usr/src/fastnetmon/src/build
cmake ..
make
```

Please call ```redis-cli``` and input following commands

```bash
keys *
1) "10.10.10.200_flow_dump"
2) "10.10.10.200_information"
3) "10.10.10.200_packets_dump"
```

Basic information about attack (stored immediately)
```get 10.10.10.200_information```

Complete flow dump for attack if flow tracking enabled (stored immediately)
```get 10.10.10.200_flow_dump```

Complete per packet attack dump (stored with some delay; can be absent in some cases of slow attacks)
```get 10.10.10.200_packets_dump```


