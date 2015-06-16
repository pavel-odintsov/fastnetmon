### How I can switch to current Git version?

First of all, please install FastNetMon with automatic installer [here](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/docs/INSTALL.md)

Than switch to master branch and rebuild toolkit:
```bash
cd /usr/src/fastnetmon
git checkout master
cd src/build
cmake ..
make
./fastnetmon 
```

You could use ```git log``` command for checking about last commits and compare with [GitHub](https://github.com/FastVPSEestiOu/fastnetmon/commits/master)
