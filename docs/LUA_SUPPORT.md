### We have LUA support for processing NetFlow flows

It supported only for NetFlow v5 at this moment. 

It's not compiled by default and you need build it explicitly.

Install dependency list (Debian 8 and Ubuntu 14.04 has it):
```bash
apt-get install -y libluajit-5.1-dev luajit
```

Build it:
```
cmake -DENABLE_LUA_SUPPORT=ON ..
make
```
