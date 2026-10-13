# VORTEX

Experimental Linux TCP forwarding proxy with TLS ClientHello telemetry and an optional
IPv4 XDP blacklist. **This is not a production DDoS protection service, an Anycast
network, a WAF, or a replacement for Nginx/HAProxy/CDN protection.**

## What is implemented

- Bounded async TCP forwarding with global/per-IP connection caps, connect and idle timeouts.
- A per-IP token bucket for **new TCP connections**, with a 60-second violation window and bounded memory.
- Reassembly of fragmented TLS ClientHello messages for JA3/JA4-format telemetry.
- Optional generic XDP IPv4 blacklist; bans expire in both userspace and the kernel.
- Basic malformed TCP flag checks. IPv6 bypasses the current XDP filter.
- A terminal dashboard; displayed traffic counters are userspace stream events, **not NIC packet/PPS measurements**.

No zero-copy forwarding, upstream connection pool, TLS termination, HTTP-request rate
limiting, Anycast routing, or verified 10M PPS performance is claimed. TLS fingerprints
are heuristic and can be spoofed or shared by legitimate clients; never treat them as identity.
JA4 telemetry has regression coverage, but independent conformance validation is still recommended.

## Install on Ubuntu / Debian

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
vortex run --port 8080 --upstream 127.0.0.1:80 --interface eth0
```

Use the actual ingress interface name; `lo` only observes loopback traffic. On shared
hosting or an unprivileged user, the proxy runs in **userspace-only** mode and does not
provide kernel-level/volumetric protection. Ensure the chosen listening port is permitted.
For HTTPS forwarding, the upstream itself must accept TLS; VORTEX does not terminate TLS.

Optional XDP mode requires Linux, root/network administration capabilities, and tools:

```bash
sudo apt-get install clang llvm libbpf-dev gcc-multilib iproute2 bpftool
```

Only use XDP on interfaces you administer. The loader refuses to replace an existing
XDP program. Source is included in wheels under `share/vortex/kernel`; a fresh object
is built in `~/.cache/vortex` instead of trusting a committed binary. Architecture support
is currently x86-64 and ARM64; other environments fall back explicitly to userspace.

## Test

```bash
pip install '.[dev]'
python -m pytest tests -q
```

Unit/integration tests do not attach XDP or modify host interfaces. CI separately compiles
the C source. Runtime verifier/attachment, real kernel ban expiry, and production performance
must be validated on a disposable Linux test host before deployment.

`vortex test-attack` is a loopback-only synthetic test helper, not a real DDoS benchmark.

MIT license.
