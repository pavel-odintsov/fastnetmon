### Developer notes 

FastNetMon has pretty huge list of supported platforms but we focused on following platforms:
* CentOS 6/7
* Ubuntu 12.04 / 14.04 / 16.04 only LTS releases
* Debian 7, 8

And your changes should work with they.

Also we are using Boost library as proven source of well tested code. 

Boost versions across different distributions:
* Debian 7 Wheezy: 1.49
* Debian 8 Jessie: 1.55
* Ubuntu Precise 12.04: 1.48
* Ubuntu Trusty 14.04: 1.54
* Ubuntu Xenial 16.04: 1.58
* CentOS 6: 1.41 according to http://mirror.centos.org/centos/6.8/os/x86_64/Packages/
* CentOS 7: 1.53

So at 25th of September of 2016 you could use features only from Boost 1.41 (I'm so sorry about it but we should keep compatibility with CentOS 6).

We are using gcc as main compiler. I like clang but some old distros has broken and very old clang and it could not be used. CentOS 6 has pretty old version of gcc without C++ 11 support and we could not use it (I'm so sorry about it also, it's huge pain).
