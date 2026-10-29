FROM ubuntu:24.04

ARG TARGETARCH
ARG FASTNETMON_VERSION

RUN apt-get update && apt-get upgrade -y && \
  apt-get install -y wget libncurses6 iproute2 tcpdump mtr-tiny bsd-mailx msmtp ca-certificates && \
  wget --no-verbose  -O /tmp/fastnetmon.deb  https://storage.googleapis.com/community_packages/${FASTNETMON_VERSION}/ubuntu/24.04/fastnetmon_${FASTNETMON_VERSION}_${TARGETARCH}.deb && \
  dpkg -i /tmp/fastnetmon.deb && \
  apt-get clean && rm -rf /var/lib/apt/lists/* && rm /tmp/fastnetmon.deb


CMD ["/opt/fastnetmon-community/app/bin/fastnetmon"]

LABEL org.opencontainers.image.source=https://github.com/pavel-odintsov/fastnetmon
LABEL org.opencontainers.image.description="FastNetMon is a very high performance DDoS detector built on top of multiple packet capture engines: NetFlow, IPFIX, sFlow and SPAN/port mirror."

