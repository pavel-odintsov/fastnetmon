FROM ubuntu
MAINTAINER robertoberto

RUN apt-get update && apt-get install -y \
  bison \
  build-essential \
  cmake \
  flex \
  g++ \
  gcc \
  git \
  libboost-all-dev \
  libgeoip-dev \
  libgpm-dev \
  libhiredis-dev \
  liblog4cpp5-dev \
  libncurses5-dev \
  libnuma-dev \
  libpcap-dev \
  linux-headers-$(uname -r) \
  make \
  mongodb-dev \
  python-pip \
  socat \
  vim



RUN pip install exabgp

RUN cd /usr/src; git clone https://github.com/FastVPSEestiOu/fastnetmon.git

#COPY exabgp_blackhole.conf /etc/exabgp_blackhole.conf

RUN cd /usr/src/fastnetmon/src; mkdir build; cd build; cmake .. -DDISABLE_PF_RING_SUPPORT=ON; make

RUN cp /usr/src/fastnetmon/src/fastnetmon.conf /etc/
RUN cp /usr/src/fastnetmon/src/build/fastnetmon /usr/bin/
RUN cp /usr/src/fastnetmon/src/build/fastnetmon_client /usr/bin/
RUN touch /etc/networks_list




