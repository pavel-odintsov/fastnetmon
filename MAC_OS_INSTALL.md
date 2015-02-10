Build on Mac OS 10.10 Yosemite.

- Install XCode https://itunes.apple.com/us/app/xcode/id497799835 with Mac App Store
- Update XCode to latest version with App Store
- Agree to Xcode license in Terminal: ```sudo xcodebuild -license```
- Install Mac Ports: https://www.macports.org/install.php
- Install dependencies: ```sudo port install boost log4cpp cmake```

Build fastnetmon:
```bash
cd ~
git clone https://github.com/FastVPSEestiOu/fastnetmon.git
cd fastnetmon
mkdir build
cd build
cmake ..
make
```

