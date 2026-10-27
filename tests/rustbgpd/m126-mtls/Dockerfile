# Build dependencies follow tests/Dockerfile.ubuntu-24.04.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git ca-certificates cmake libssl-dev libelf-dev libbpf-dev libpcap-dev \
    libgrpc-dev libgrpc++-dev libprotobuf-dev protobuf-compiler libprotoc-dev protobuf-compiler-grpc \
    libboost-dev libboost-serialization-dev libboost-thread-dev libboost-regex-dev \
    libboost-program-options-dev liblog4cpp5-dev libncurses5-dev libabsl-dev libhiredis-dev \
    tcpreplay iproute2 procps && rm -rf /var/lib/apt/lists/*
COPY src/ /fnm/src/
ARG BUILD_CPUS=0
RUN cmake -S /fnm/src -B /fnm/build -DLINK_WITH_ABSL=ON -DENABLE_RUSTBGPD_SUPPORT=ON \
    -DENABLE_CAPNP_SUPPORT=OFF -DENABLE_MONGODB_SUPPORT=OFF \
    && taskset -c "$BUILD_CPUS" cmake --build /fnm/build --target fastnetmon -j6 \
    && install -m755 /fnm/build/fastnetmon /usr/local/bin/fastnetmon
COPY tests/rustbgpd/m126-mtls/fastnetmon.conf /etc/fastnetmon.conf
COPY tests/rustbgpd/m126-mtls/networks_list /etc/networks_list
RUN touch /etc/networks_whitelist && mkdir -p /var/log/fastnetmon_attacks
CMD ["sleep", "infinity"]
