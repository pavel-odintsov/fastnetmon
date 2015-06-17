# How to update to next version?

Well, if you need update from stable branch to developer branch, please follow [this reference](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/docs/DEV_VERSION.md). 

Please be aware! Binary packages could be out of date. 

Automatic [install script](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/docs/INSTALL.md) could be used for fresh install and upgrade.

Please consult [this page](https://github.com/FastVPSEestiOu/fastnetmon/releases) about new releases.

Before upgrade, please compare your config file with Git's version of NastNetMon [config file](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/src/fastnetmon.conf), add new params and tune old params (if something changes). We trying do not broke backward compatibility but please be careful.

After upgrade, please switch off 'ban' capability for some time and check toolkit behavour. 
