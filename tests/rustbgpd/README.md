# rustbgpd action TLS tests

Build with `-DBUILD_TESTS=ON -DENABLE_RUSTBGPD_SUPPORT=ON` and run
`rustbgpd_action_tests`. The test build uses Bash and OpenSSL to generate
disposable certificates once in its build directory, and again only when
`make-test-certificates.sh` changes. The mock requires a trusted client
certificate. Tests cover hostname and IP address SAN verification, optional
tokens, wrong CA, SAN mismatch, refusal to fall back to plaintext, hosts named
like gRPC resolver schemes, reconnect backoff, partial TLS settings, key file
permissions, symlinks, FIFOs and size limits, and CA and certificate file
owner and write permissions. Existing plaintext tests keep
covering the Unix socket and literal-loopback restrictions.

## M126 mTLS variant

This adapts the [rustbgpd M126 lab](https://github.com/lance0/rustbgpd/tree/main/tests/interop/m126-fastnetmon-rtbh)
traffic and FRR configuration (the imported fixtures retain the [MIT license](m126-mtls/LICENSE-MIT)). Three containers run FastNetMon, rustbgpd and FRR.
The detector reaches `rustbgpd:50051` over a separate link and verifies its DNS
SAN. rustbgpd requires the client certificate and maps its URI principal to the
operator role; no bearer token is configured. Actual traffic crosses FastNetMon's
threshold, and the lab asserts IPv4/IPv6 BLACKHOLE announcements with next-hop
self and subsequent withdrawals at FRR over an established BGP session.

Requirements: Docker, containerlab, jq, Python 3, OpenSSL, `flock` and a rustbgpd image
containing `rustbgpd`, `ip` and `sleep` (for example rustbgpd's development image).
Use a known image built from the daemon revision being qualified:

```sh
RUSTBGPD_IMAGE=rustbgpd:dev BUILD_CPUS=0-3 \
  RESULTS_DIR=/tmp/fastnetmon-mtls-results \
  bash tests/rustbgpd/m126-mtls/run.sh
```

Before building or deploying, the script acquires
`~/.local/state/rustbgpd-host.lock` and holds it through container cleanup.
`RUSTBGPD_HOST_LOCK` can override the path; all concurrent host workloads must
use the same path. A held lock stops the run with exit status 75. Wait for its
holder to finish; do not unlink a held lock file.

The script builds the FastNetMon image from this checkout, generates disposable
certificates, deploys a unique lab, and destroys only that lab on exit. It retains
logs, image metadata and the checkout diff. `BUILD_CPUS` controls C++ build CPU
affinity (default CPU 0, six jobs); choose CPUs available on the build host.
`FNM_MTLS_IMAGE` chooses the detector image tag. `SKIP_BUILD=1` reuses that image;
when doing so, verify it contains the source under test. The temporary run
directory is retained for diagnosis and may be removed after reviewing results.

This lab covers ban/unban transport and authorization, not scale, restart
convergence or certificate rotation. The unit mock covers negative TLS cases.
