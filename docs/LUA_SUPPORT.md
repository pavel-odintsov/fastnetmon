### We have LUA support for processing NetFlow flows

It supported only for NetFlow v5 and sFLOW at this moment and enabled by default. 

Please be aware! In Ubuntu 14.04 lua-json 1.3.1 is [buggy](https://bugs.launchpad.net/ubuntu/+source/lua-json/+bug/1443288) and should be upgraded to 1.3.2.

Fast fix for lua-json for Ubuntu 14.04:
```bash
wget https://raw.githubusercontent.com/harningt/luajson/1.3.3/lua/json/decode/util.lua -O/usr/share/lua/5.1/json/decode/util.lua

wget https://raw.githubusercontent.com/harningt/luajson/1.3.3/lua/json/decode/strings.lua -O/usr/share/lua/5.1/json/decode/strings.lua
```
