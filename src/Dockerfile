FROM ubuntu:24.04

ENV CI=true
ARG TARGETPLATFORM

RUN apt-get update && apt-get upgrade -y && apt-get install -y wget

RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
  wget https://install.fastnetmon.com/installer -O installer; \
  elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
  wget https://install.fastnetmon.com/installer_arm64 -O installer; \
  fi && \
  chmod +x installer && \
  ./installer -install_community_edition

LABEL org.opencontainers.image.source=https://github.com/pavel-odintsov/fastnetmon

CMD ["/opt/fastnetmon-community/app/bin/fastnetmon"]
