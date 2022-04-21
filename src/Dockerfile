FROM ubuntu:20.04

RUN apt-get update && apt-get upgrade -y && apt-get install -y wget && wget https://install.fastnetmon.com/installer -Oinstaller && chmod +x installer && ./installer -install_community_edition

LABEL org.opencontainers.image.source https://github.com/pavel-odintsov/fastnetmon

CMD /opt/fastnetmon/fastnetmon
