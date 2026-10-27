# rustbgpd integration

FastNetMon can announce blackhole routes through [rustbgpd](https://github.com/lance0/rustbgpd), a BGP daemon with a gRPC API. The `rustbgpd` action calls rustbgpd's `InjectionService` directly: `AddPath` on ban and `DeletePath` on unban. Unlike the GoBGP action, it sends typed fields (prefix, next hop, communities) instead of encoded BGP attributes, and it needs no GoBGP daemon.

The action handles IPv4 hosts, IPv4 customer subnets and IPv6 hosts, each with one community and next hop, like the GoBGP action. It can run at the same time as the GoBGP or ExaBGP actions.

The local transport was tested with rustbgpd 0.79.0; the mTLS ban/unban lab uses rustbgpd 0.80.1. Earlier rustbgpd releases reject the `0.0.0.0` and `::` next hops this action uses by default.

## Build

The action is not built by default. Enable it with `-DENABLE_RUSTBGPD_SUPPORT=ON`; it needs gRPC support (`ENABLE_GOBGP_SUPPORT`, on by default), and CMake reports when it is requested without it. It was built and tested on Linux only. Windows builds leave it out because it uses POSIX signal and file APIs; the GoBGP action stays available there.

With `-DBUILD_TESTS=ON` the build also produces `rustbgpd_action_tests`, which runs the action against a mock of rustbgpd's gRPC API.

The action uses a reduced copy of rustbgpd's API definition, `src/rustbgpd_client/rustbgpd_injection.proto`. Its header names the rustbgpd release it was copied from and that file's SHA-256.

## FastNetMon configuration

```
rustbgpd = on

# rustbgpd's default owner-only Unix socket
rustbgpd_target = unix:///var/lib/rustbgpd/grpc.sock

# 0.0.0.0 and :: mean next hop self: rustbgpd uses its own address on each BGP session
rustbgpd_next_hop_host_ipv4 = 0.0.0.0
rustbgpd_next_hop_subnet_ipv4 = 0.0.0.0
rustbgpd_next_hop_host_ipv6 = ::

rustbgpd_announce_host = on
rustbgpd_announce_whole_subnet = off
rustbgpd_announce_host_ipv6 = on

rustbgpd_community_host = 65535:666
rustbgpd_community_subnet = 65535:666
rustbgpd_community_host_ipv6 = 65535:666
```

| Option | Default | Meaning |
|---|---|---|
| `rustbgpd` | `off` | Enable the action |
| `rustbgpd_target` | `unix:///var/lib/rustbgpd/grpc.sock` | rustbgpd gRPC endpoint: `unix:///absolute/path`, or a literal loopback address and port: `127.0.0.1:50051` (any address in 127.0.0.0/8) or `[::1]:50051`. With mTLS, also accepts a host name or remote IP address and port |
| `rustbgpd_token_file` | empty | File with the bearer token; sent as `authorization: Bearer <token>` on every call. Required for plaintext TCP; with mTLS, required only when the rustbgpd listener sets `token_file`. It must be a regular file (not a symbolic link) owned by the user who runs FastNetMon or by root, with no group or other permissions (`chmod 600`), at most 4096 bytes, one token of printable ASCII characters |
| `rustbgpd_tls_ca_file` | empty | PEM CA bundle used to verify the server certificate; set together with the client certificate and key. Same owner and no-symbolic-link requirements as the token file; must not be writable by group or others |
| `rustbgpd_tls_cert_file` | empty | PEM client certificate chain; its principal must have the `operator` role in rustbgpd. Same file requirements as the CA file |
| `rustbgpd_tls_key_file` | empty | PEM client private key; same owner, mode and no-symbolic-link requirements as the token file |
| `rustbgpd_next_hop_host_ipv4` | `0.0.0.0` | Next hop for IPv4 host announces; `0.0.0.0` means next hop self |
| `rustbgpd_next_hop_subnet_ipv4` | `0.0.0.0` | Next hop for IPv4 subnet announces |
| `rustbgpd_next_hop_host_ipv6` | `::` | Next hop for IPv6 host announces; `::` means next hop self |
| `rustbgpd_announce_host` | `on` | Announce the attacked IPv4 address as /32 |
| `rustbgpd_announce_whole_subnet` | `off` | Announce the customer network of the attacked IPv4 address |
| `rustbgpd_announce_host_ipv6` | `on` | Announce the attacked IPv6 address as /128 |
| `rustbgpd_community_host`, `rustbgpd_community_subnet`, `rustbgpd_community_host_ipv6` | `65535:666` | Community in `ASN:value` form; `65535:666` is BLACKHOLE (RFC 7999) |
| `rustbgpd_reconcile_interval` | `30` | Seconds between passes which announce all active bans again |
| `rustbgpd_lease` | `off` | Announce under an injection lease, see below |
| `rustbgpd_lease_owner` | `fastnetmon` | Lease owner name, 1-64 characters of `A-Z a-z 0-9 . _ -`, checked on start when leases are on |
| `rustbgpd_lease_time` | `30` | Lease time in seconds, 5-3600 |

FastNetMon does not start the action when an option is invalid, and logs which one. It never logs the token or private key. TLS files must be nonempty regular files, not symbolic links, at most 1 MiB each. Credentials are read on startup; restart FastNetMon after replacing them.

### Connecting to rustbgpd

rustbgpd accepts plaintext gRPC only on its owner-only Unix socket or on a TCP listener with a bearer token. Without TLS, the action allows only a Unix socket or a literal loopback address, so the token never leaves the host, and it refuses a TCP target without a token. It ignores `grpc_proxy`, `https_proxy` and `http_proxy`, which gRPC would otherwise use even for a loopback address.

- **Unix socket** (default). rustbgpd authorizes clients of its owner-only socket as its local operator; no token is needed. FastNetMon must be able to open the socket: run it as rustbgpd's user, or as root.
- **Loopback TCP with token.** Configure the listener in rustbgpd and map its principal to the `operator` role, which route injection requires:

  ```toml
  [global.telemetry.grpc_tcp]
  address = "127.0.0.1:50051"
  token_file = "/etc/rustbgpd/grpc.token"
  principal = "fastnetmon"

  [security.grpc.roles]
  "fastnetmon" = "operator"
  ```

  Then in FastNetMon:

  ```
  rustbgpd_target = 127.0.0.1:50051
  rustbgpd_token_file = /etc/rustbgpd/grpc.token
  ```

- **Remote TCP with mutual TLS.** Issue a server certificate whose DNS or IP SAN matches `rustbgpd_target`, and a client certificate signed by the CA rustbgpd trusts. For this example the client's URI SAN is `rustbgpd://operator/fastnetmon`:

  ```toml
  [global.telemetry.grpc_tcp]
  address = "0.0.0.0:50051"
  tls_cert_file = "/etc/rustbgpd/server.pem"
  tls_key_file = "/etc/rustbgpd/server.key"
  tls_client_ca_file = "/etc/rustbgpd/client-ca.pem"

  [security.grpc.roles]
  "rustbgpd://operator/fastnetmon" = "operator"
  ```

  Then in FastNetMon:

  ```
  rustbgpd_target = announcer.example.net:50051
  rustbgpd_tls_ca_file = /etc/fastnetmon/server-ca.pem
  rustbgpd_tls_cert_file = /etc/fastnetmon/client.pem
  rustbgpd_tls_key_file = /etc/fastnetmon/client.key
  ```

  Set all three TLS files or none. All three must be owned by the user running FastNetMon or root. The client key must have no group or other permissions (`chmod 600`); the CA and certificate may be readable by anyone but writable only by their owner (`chmod 644`).

  The bearer token is optional only when the rustbgpd listener has no `token_file`. If the listener sets `token_file`, rustbgpd checks the token in addition to the client certificate, so also set `rustbgpd_token_file`. When configured, the token is sent on each call. The role always comes from the certificate principal: the token only authenticates and never selects a role, and an mTLS listener cannot set `principal`.

  gRPC verifies the server certificate and target name. There is no name override, verification bypass, or plaintext fallback. Invalid certificates, an untrusted CA or a SAN mismatch prevent RPCs from reaching rustbgpd; the worker logs connection failures and retries with the same TLS credentials, waiting up to about 5 seconds between attempts. Startup success alone does not prove a successful TLS handshake.

  rustbgpd derives the client principal from its `rustbgpd:` URI SAN, then email SAN, then Subject CN. Map the exact resulting value to `operator`; an unmapped principal can complete TLS but receives `PERMISSION_DENIED` on RPCs. Several collectors can use separately issued client certificates and role mappings. The [mTLS lab](../tests/rustbgpd/README.md) exercises IPv4 and IPv6 bans and withdrawals against a separate rustbgpd container and FRR.

## rustbgpd configuration

rustbgpd advertises injected routes like locally originated routes, subject to each neighbor's export policy. This policy sends only injected /32 and /128 routes which carry BLACKHOLE:

```toml
[policy.definitions.rtbh-only]
default_action = "deny"
[[policy.definitions.rtbh-only.statements]]
action = "permit"
match_route_type = "local"
prefix = "0.0.0.0/0"
ge = 32
match_community = ["BLACKHOLE"]
[[policy.definitions.rtbh-only.statements]]
action = "permit"
match_route_type = "local"
prefix = "::/0"
ge = 128
match_community = ["BLACKHOLE"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast"]
# Needed for IPv6 next hop self on an IPv4 session
local_ipv6_nexthop = "2001:db8:126::1"
export_policy_chain = ["rtbh-only"]
```

If you enable `rustbgpd_announce_whole_subnet`, add a statement for your customer networks, for example:

```toml
[[policy.definitions.rtbh-only.statements]]
action = "permit"
match_route_type = "local"
prefix = "203.0.113.0/24"
match_community = ["BLACKHOLE"]
```

Change `match_community` too if you use another community.

## Behaviour

- Ban and unban only update the list of routes FastNetMon wants, in the order they happen. One worker thread makes all calls to rustbgpd and brings rustbgpd to that list, so a slow or failed call never delays detection, and an unban that arrives while the announce is still in flight is applied after it.
- With `rustbgpd_announce_whole_subnet = on`, the subnet route stays announced while any banned host from that subnet needs it, and is withdrawn after the last one is unbanned. An attack without customer network (0.0.0.0/0) gets no subnet announce, only an error in the log. When the customer network is the host itself (a /32), only the host announce is sent, with the host next hop and community.
- FastNetMon's ban lists are the source of truth. A ban for a host which is no longer in the ban list is ignored at once: its unban came first. FastNetMon's core does not order ban and unban events across its threads, so ban and unban calls can still reach the action in another order than FastNetMon changed its ban lists. As a backstop, every full pass compares the action's routes with the IPv4 and IPv6 ban lists in both directions, and corrects a disagreement (logged as WARN) when the previous full pass saw the same disagreement for the same host and no ban or unban of that host came in between. A single pass can fall between a ban list change and its action call, so one pass alone never changes routes, and a pass does not use its copy for a host whose ban or unban call arrived while it copied the ban lists; the rest of the copy is used, so calls for other hosts do not delay the backstop. Any ordering race is corrected within two full passes, normally two `rustbgpd_reconcile_interval`s; a full pass starts only after the current round of calls, so after a large burst of bans against a slow rustbgpd this time grows by the length of that round. The action reads FastNetMon's ban lists because they are FastNetMon's own record of current bans; they do not order everything either, as unban of expired bans removes hosts from them only after it calls actions.
- Changed withdrawals are sent first, then changed announces, then unchanged routes are resent; within each group the route which waited longest goes first. If a withdrawal stalled, announces go first in the next round, so neither kind can hold up the other. A round of calls ends at the first call which fails because rustbgpd is unreachable or too slow, and when a new ban or unban arrives, so one slow prefix does not hold up the others. A route whose calls always time out costs up to one 5 second call in each round in which it is due for retry.
- Each call is checked. Changes in rustbgpd (`PATH_INJECT_OUTCOME_CREATED` or `REPLACED`, `PATH_DELETE_OUTCOME_DELETED`) are logged at INFO; `UNCHANGED` and `NOT_PRESENT`, which full passes mostly produce, at DEBUG, with one INFO summary line per full pass. Failures are logged at ERROR with the gRPC status name; when the same failure repeats for a route, the repeats go to DEBUG. An answer without one of these outcomes (rustbgpd older than 0.79.0, for example) counts as a failure.
- Withdrawals set `allow_missing`, so withdrawing a route rustbgpd no longer has succeeds.
- A call rustbgpd rejects is retried after `rustbgpd_reconcile_interval` seconds, but at most 10 seconds later the first time; the same rejection again is retried every `rustbgpd_reconcile_interval` seconds. A call that fails because rustbgpd is unreachable is retried after 0.5, 1, 2, 4 and 8 seconds, then every 10 seconds (and never later than `rustbgpd_reconcile_interval`), and at once when rustbgpd answers again after a failed liveness probe. A result for a ban state that changed while the call was in progress is ignored, so the newer state is sent without delay.
- rustbgpd keeps injected routes in memory only. The action announces all wanted routes again:
  - as soon as rustbgpd answers after a restart: the action checks its connection before each liveness probe (every 0.5 seconds) and treats a lost connection, or a failed probe, as a restart; it logs the status of a failed probe;
  - when rustbgpd starts a new lease generation, if leases are on;
  - every `rustbgpd_reconcile_interval` seconds.

  Each of these full passes also compares routes with FastNetMon's ban lists, as above.
- On a planned rustbgpd restart, BGP peers with Graceful Restart keep the blackholes as stale routes. rustbgpd sends End-of-RIB soon after the session comes back, and the action announces the bans again shortly after rustbgpd's API answers. A short gap between the two is possible, so a peer may drop a blackhole for a moment. A restart which keeps the gRPC connection is not possible, so even a restart faster than one probe interval is noticed at the next probe.
- On SIGINT, after its own shutdown steps, FastNetMon's signal handler asks the worker to stop and waits up to 6 seconds (the 5 second call deadline plus one second) for it to finish its current call. This part of the handler does not lock, join or write anything. If the worker has finished, FastNetMon exits as usual with status 1. If it has not, FastNetMon exits at once with status 2, without running exit handlers or destructors, which the worker might still use. The worker thread, named `rustbgpd` where the platform supports thread names, blocks SIGINT, so the handler never runs on it; gRPC threads created for its channel block SIGINT too, but gRPC threads that existed before may still receive it. These guarantees cover the rustbgpd steps only. Before them FastNetMon's handler logs, stops its API server and joins its own threads, which is not async-signal-safe and is outside this action.
- Ban lists are not persistent in FastNetMon either. If FastNetMon stops, its bans stay in rustbgpd until they are withdrawn by hand (`rbgp rib delete <prefix>`) or until rustbgpd restarts, unless leases are on.

## Leases (experimental)

With `rustbgpd_lease = on` the action uses `AddLeasedPath` instead of `AddPath`, all under one owner (`rustbgpd_lease_owner`), and renews the lease every third of `rustbgpd_lease_time`, checking before every call. Each call ends at least one second before the lease would expire. If FastNetMon stops renewing, rustbgpd withdraws all of the owner's bans when the lease expires. When rustbgpd refuses a renewal, or answers an announce with a new lease generation, the action announces all wanted routes again under the new lease.

The lease calls (`AddLeasedPath`, `RenewLease`) are not part of rustbgpd's stable v1 API in rustbgpd 0.79.0 and may change in later releases.

Limitations:

- A restarted FastNetMon uses the same owner and joins the existing lease. Bans the previous process held and the new one does not know about stay announced while the lease is renewed. Remove them with `rbgp rib delete <prefix> --override-owner`.
- A route added without a lease cannot be taken over by a leased add, and the other way round: rustbgpd answers `FAILED_PRECONDITION` and the action logs the prefix. Delete such routes once when you switch leases on or off.
