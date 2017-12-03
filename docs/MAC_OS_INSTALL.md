Build on Mac OS 10.10 Yosemite.

- Install XCode https://itunes.apple.com/us/app/xcode/id497799835 with Mac App Store
- Update XCode to latest version with App Store
- Agree to Xcode license in Terminal: ```sudo xcodebuild -license```
- Install [Home Brew](https://brew.sh)
- Install dependencies: ```sudo port install boost log4cpp cmake ndpi```

Run installer script for stable branch:
```bash
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl
```

Run installer script for master branch:
```bash
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl
sudo perl fastnetmon_install.pl --use-git-master
```
