#!/usr/bin/env bash
# Native FastNetMon -> separate rustbgpd over mTLS -> FRR, using M126 traffic.
set -euo pipefail
lab=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$lab/../../.." && pwd)
for tool in docker containerlab jq python3 openssl flock; do
    command -v "$tool" >/dev/null || { echo "ERROR: required tool not found: $tool" >&2; exit 1; }
done
# Keep the canonical host lock through deployment and the EXIT cleanup.
host_lock=${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}
mkdir -p "$(dirname "$host_lock")"
exec 9>"$host_lock"
if ! flock -n 9; then
    echo "ERROR: $host_lock is held by another process; wait for it, do not unlink the lock file" >&2
    exit 75
fi
echo "acquired host lock: $host_lock"
work=$(mktemp -d)
export MTLS_CERT_DIR="$work/certs"
export FNM_MTLS_IMAGE=${FNM_MTLS_IMAGE:-fastnetmon-rustbgpd:mtls}
export RUSTBGPD_IMAGE=${RUSTBGPD_IMAGE:-rustbgpd:dev}
name="fnm-mtls-$$"
detector="clab-$name-detector"
daemon="clab-$name-rustbgpd"
frr="clab-$name-frr"
# A unique name prevents this run from deleting another lab's containers.
topology="$work/topology.clab.yml"
sed -e "s/^name: fnm-mtls$/name: $name/" -e "s|\./|$lab/|g" "$lab/topology.clab.yml" > "$topology"
results=${RESULTS_DIR:-$work/results}
mkdir -p "$results"
results=$(cd "$results" && pwd)
deployed=0
cleanup() {
    local rc=$?
    if [ "$deployed" = 1 ]; then
        docker exec "$detector" cat /var/log/fastnetmon.log > "$results/fastnetmon.log" 2>/dev/null || true
        docker exec "$daemon" cat /var/log/rustbgpd.log > "$results/rustbgpd.log" 2>/dev/null || true
        docker exec "$frr" cat /tmp/bgpd.log > "$results/frr.log" 2>/dev/null || true
        containerlab destroy -t "$topology" --cleanup > "$results/destroy.log" 2>&1 || true
    fi
    echo "Lab exit $rc; results: $results"
    # Keep the run directory, including failed deploys, for diagnosis.
}
trap cleanup EXIT
bash "$lab/../make-test-certificates.sh" "$MTLS_CERT_DIR" rustbgpd > "$results/certificates.log" 2>&1
if [ "${SKIP_BUILD:-0}" != 1 ]; then
    docker build -f "$lab/Dockerfile" --build-arg "BUILD_CPUS=${BUILD_CPUS:-0}" \
        -t "$FNM_MTLS_IMAGE" "$repo" > "$results/build.log" 2>&1
fi
docker image inspect "$FNM_MTLS_IMAGE" "$RUSTBGPD_IMAGE" > "$results/images.json"
git -C "$repo" rev-parse HEAD > "$results/fastnetmon-commit.txt"
git -C "$repo" diff --binary HEAD > "$results/fastnetmon-diff.patch"
deployed=1
containerlab deploy -t "$topology" > "$results/deploy.log" 2>&1
docker exec "$frr" touch /etc/frr/vtysh.conf
# Bind mounts retain the host UID; FastNetMon requires its TLS files to belong to its runtime user or root.
docker exec "$detector" sh -c 'mkdir -p /certs && cp /certs-source/ca.pem /certs-source/client.pem /certs-source/client.key /certs/ &&
    chmod 644 /certs/ca.pem /certs/client.pem && chmod 600 /certs/client.key'
docker exec "$daemon" sh -c 'cp /certs-source/server.key /certs/server.key && chmod 600 /certs/server.key'
docker exec "$daemon" rustbgpd --version | tee "$results/rustbgpd-version.txt"
docker exec "$detector" fastnetmon --version | tee "$results/fastnetmon-version.txt"
docker exec "$daemon" rustbgpd --check /etc/rustbgpd/config.toml
docker exec -d "$daemon" sh -c 'exec rustbgpd /etc/rustbgpd/config.toml > /var/log/rustbgpd.log 2>&1'
session_up() {
    docker exec "$frr" vtysh -c 'show bgp neighbors 10.0.0.1 json' |
        jq -e '.["10.0.0.1"].bgpState == "Established"' >/dev/null
}
wait_until() {
    local limit=$1; shift
    local deadline=$((SECONDS + limit))
    until "$@"; do
        if [ "$SECONDS" -ge "$deadline" ]; then echo "FAIL: $*" >&2; return 1; fi
        sleep 1
    done
}
route_matches() {
    local family=$1 prefix=$2 expected=$3
    session_up || return 1
    docker exec "$frr" vtysh -c "show bgp $family unicast $prefix json" |
        jq -e --arg expected "$expected" '
            if $expected == "absent" then (.paths // [] | length) == 0
            else any(.paths[]?; any(.community.list[]?; . == "blackhole") and
                any(.nexthops[]?; .ip == $expected) and (.stale != true)) end' >/dev/null
}
wait_until 90 session_up
wait_until 5 route_matches ipv4 203.0.113.7/32 absent
wait_until 5 route_matches ipv6 2001:db8:66::7/128 absent
docker exec -d "$detector" sh -c 'exec fastnetmon --configuration_file /etc/fastnetmon.conf --log_to_console > /var/log/fastnetmon.log 2>&1'
wait_until 15 docker exec "$detector" grep -q 'rustbgpd action will use' /var/log/fastnetmon.log
python3 -I "$lab/make_attack_pcap.py" "$work/attack.pcap"
docker cp -q "$work/attack.pcap" "$detector:/tmp/attack.pcap"
docker exec -d "$detector" sh -c 'echo $$ > /tmp/replay.pid; exec tcpreplay -q -i fnmmirror0 --pps 10000 --loop 0 /tmp/attack.pcap > /var/log/replay.log 2>&1'
wait_until 60 route_matches ipv4 203.0.113.7/32 10.0.0.1
wait_until 60 route_matches ipv6 2001:db8:66::7/128 2001:db8:126::1
for family in ipv4 ipv6; do
    docker exec "$frr" vtysh -c "show bgp $family unicast json" > "$results/banned-$family.json"
done
for expected in 'rustbgpd announced 203.0.113.7/32' 'rustbgpd announced 2001:db8:66::7/128'; do
    docker exec "$detector" grep -F "$expected" /var/log/fastnetmon.log
done
echo 'PASS: IPv4 and IPv6 BLACKHOLE bans reached FRR over mTLS'
docker exec "$detector" sh -c 'kill -TERM "$(cat /tmp/replay.pid)"'
wait_until 90 route_matches ipv4 203.0.113.7/32 absent
wait_until 90 route_matches ipv6 2001:db8:66::7/128 absent
for expected in 'rustbgpd withdrew 203.0.113.7/32' 'rustbgpd withdrew 2001:db8:66::7/128'; do
    docker exec "$detector" grep -F "$expected" /var/log/fastnetmon.log
done
echo 'PASS: IPv4 and IPv6 withdrawals reached FRR over mTLS'
