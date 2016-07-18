### If you have segfault you will be interested in this page

Hi! Do you have any issues with FastNetMon segmentation fault? Yes, I know! So I could not help you here but I could help youi to create correct GitHub issue about it.

First of all, please be patient and try to understand what happened. Please review recent configuration changes and check last ~100 lines from /var/log/fastnetmon. If something looks strange, try to fix it!

When you saw something like this in dmesg:
```
Jul 18 17:21:41 monitor kernel: fastnetmon[30157]: segfault at 0 ip 0000000000445d2f sp 00007f832d861270 error 4 in fastnetmon[400000+90000]
``` 

It means some dangerous bug in FastNetMon. But we have some details about it and you could try to extract they. Please check your system about files with name "core.XXXXX" (where X is arbitrary number). You could find them inside toolkit folder or in the system root (/).

Then you should know full path to FastNetMon's binary which experienced segmentation fault. By default it should be: ```/opt/fastnetmon/fastnetmon```

Then you should install gdb package with yum or apt-get.

And run this command:
```gdb /opt/fastnetmon/fastnetmon /full/path/to/core.XXXXX```

Then you could get interactive shell with debugger. Here you should exter command "backtrace" and send their output to me with new issue (or update to existing issue). 

Or you could try to find issue manually and send pull request to me :) And I'll merge it!
