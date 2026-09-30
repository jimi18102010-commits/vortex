# ⚡ VORTEX

<div align="center">

[![GitHub](https://img.shields.io/badge/GitHub-jimi18102010--commits-181717?logo=github)](https://github.com/jimi18102010-commits/vortex)
[![Kernel: eBPF/XDP](https://img.shields.io/badge/Kernel-eBPF%20%2F%20XDP-red.svg)](kernel/xdp_filter.c)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-6%2F6%20Passing-brightgreen.svg)]()

**High-Performance Edge L4/L7 Reverse-Proxy, Anti-DDoS Shield & TLS Fingerprint Radar.**  
*Zero-copy packet drops in the Linux network driver via eBPF/XDP, JA3/JA4 wire sniffing, and asynchronous TCP streaming.*

</div>

---

```text
╭─────────────────────────────────────────────────────────────────────────────╮
│ ⚡ VORTEX SHIELD :: Edge Anycast L4/L7 Reverse-Proxy & Threat Radar        │
│ • Uptime: 42s  • Engine: 0.0.0.0:8080 ➔ 127.0.0.1:80  • L4 Mode: [XDP_GENERIC]│
╰─────────────────────────────────────────────────────────────────────────────╯
│ Packets/Sec (PPS):   1,240,580    │ Live TLS ClientHello & JA4 Stream       │
│ Wire Dropped:        412,900 pkts │ 127.0.0.1  Python / Requests Tool  [SUS]│
│ Active Banned IPs:   14           │ 10.0.4.12  ZGrab Mass Scanner      [CRIT]│
```

---

## 🚀 Why VORTEX?

Modern cloud reverse proxies like Nginx or HAProxy operate in user-space. When an adversary launches a multi-gigabit SYN or UDP flood, the Linux kernel spends critical CPU cycles allocating socket buffers (`sk_buff`) before user-space code even inspects the packet.

**VORTEX solves this with a dual-layer defensive architecture:**

1. **L4 eBPF / XDP Kernel Shield (`kernel/xdp_filter.c`):**  
   Drops volumetric floods directly at the network interface card (NIC) driver level using `XDP_DROP`. BPF hash tables (`BPF_MAP_TYPE_LRU_HASH`) allow O(1) wire-speed IP drops exceeding **10,000,000 packets/second** on a single CPU core.
2. **L7 TLS Wire Sniffer & JA3/JA4 Fingerprinting (`vortex/security`):**  
   Inspects raw TCP stream headers before full SSL handshake termination. Computes MD5 **JA3** and alphanumeric **JA4** client signatures to identify automated vulnerability scanners (ZGrab, Nikto, sqlmap, custom botnets) regardless of spoofed HTTP `User-Agent` headers.
3. **Async Zero-Copy Reverse Proxy (`vortex/proxy`):**  
   Bi-directional streaming proxy with connection pooling, keep-alive pipelining, and Sliding-Window Token-Bucket rate limiting with automatic L4 ban escalation.
4. **Cyberpunk Terminal Radar TUI (`vortex/ui`):**  
   Real-time observability console showing live PPS rates, dropped packet metrics, and streaming TLS client detections.

---

## 📦 Installation

```bash
git clone https://github.com/jimi18102010-commits/vortex.git
cd vortex

# Install editable package
pip install -e .
```

---

## 💻 Usage

### 1. Launch Proxy & Live Terminal Radar
```bash
# Run reverse-proxy forwarding port 8080 to upstream localhost:80
vortex run --port 8080 --upstream 127.0.0.1:80 --interface lo
```

### 2. Built-in Synthetic Attack Benchmark
Stress-test your local setup to observe real-time L4/L7 rate limiting and mitigation:
```bash
vortex test-attack --port 8080 --concurrency 50 --requests 500
```

---

## 🛠 Architecture Overview

```
                      [ Incoming Traffic ]
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ Normal Traffic ]               [ Flood / Attack ]
               │                               │
               ▼                               ▼
      XDP Kernel Filter                 eBPF Map Lookup
      (xdp_vortex_shield)               (BPF_MAP_TYPE_LRU_HASH)
               │                               │
               ▼ (XDP_PASS)                    ▼ (XDP_DROP)
      Linux Network Stack               INSTANT WIRE DROP
               │                         (Zero CPU/RAM overhead)
               ▼
     TLS ClientHello Sniffer
       (JA3 / JA4 Extraction)
               │
               ▼
     Sliding-Window Limiter
               │
               ▼
    Async Stream Forwarding ────► [ Upstream Server ]
```

---

## 📄 License

MIT License. Designed & engineered by **Jimmiy** (2026).
