# Serai

A multipath reverse tunnel for panel-based proxies — 3x-ui, Marzban, bare Xray.

**English** · [فارسی](README.fa.md)

The host that owns the panel dials the relay, not the other way round. The relay
holds one key and one open port, and from the outside it looks like an ordinary
web server.

```
         users                         ┌─ edge (relay) ─┐        ┌─ origin ────────┐
  ─── end-to-end TLS ─────────────────►│  443 tcp+udp   │        │                  │
      (terminates at Xray, not here)   │  SNI router    │        │   3x-ui / Xray   │
                                       │                │◄───────┤   127.0.0.1:*    │
                                       │  decoy site    │ tunnel │                  │
                                       └────────────────┘        └──────────────────┘
                                                     ▲ the origin dials out
```

The origin needs no inbound firewall rule, no public port and no certificate.
The relay knows no backend addresses: it quotes a rule *name* back, and the
origin resolves the real target from its own config, so a seized relay cannot
be told to connect anywhere it was not already allowed.

---

## Why relay addresses get blocked, and what this does about it

Blocking almost never comes from breaking the encryption. It comes from these:

| Detection vector | What actually happens | What Serai does |
|---|---|---|
| **TLS fingerprint (JA3/JA4)** | Go's `crypto/tls` emits a ClientHello no browser produces: different cipher order, no GREASE, no ALPS. frp, chisel, rathole and most forks all carry this tell. | **uTLS** with a Chrome or Firefox ClientHello on the WebSocket path |
| **Custom ALPN** | `mtnl/1` in a Chrome-shaped hello is a *stronger* signal than a plain Go one | when mimicry is on, only `h2, http/1.1` is offered and the tunnel rides a WebSocket |
| **Self-signed cert on 443** | a signal all by itself | a real domain with a real certificate; pinning is for private CAs only |
| **Active probing** | a relay that answers with a reset, a TLS alert or a synthetic page has identified itself | a **decoy** reverse proxy serving a real site; a failed MAC gets total silence, never an error |
| **Traffic shape** | fixed-size heartbeats at a fixed interval, perfectly silent idle, long runs of identically sized records | an **obfs** layer: randomised chunking, random padding, jittered cover traffic |
| **Scannable ports** | a host with fifty odd open ports is found long before any connection is analysed | **one port** (443 tcp+udp), with **SNI routing** that never opens the user's TLS |
| **Reconnect storms** | a one-second retry loop after a cut confirms a tunnel | per-path exponential backoff with jitter |

### Without a CDN

All of the above works with no CDN. The practical recipe:

- a domain pointed at the relay's IP, **DNS-only** (grey cloud on Cloudflare or
  ArvanCloud) — you get the name and the certificate, and pay nothing for CDN
  bandwidth because traffic goes straight there
- a Let's Encrypt certificate
- profile `balanced` or `stealth`
- only 80 and 443 reachable

If you do want a CDN in the mix, the `role` field lets the **control channel
only** go through it — a few kilobytes an hour — while bulk traffic stays
direct:

```json
{ "transport": "websocket", "url": "wss://link.example.com/ws",
  "edge_addr": "cdn-edge-ip:443", "role": "bootstrap", "weight": 1 }
```

---

## Install

On the **relay** (the host users will connect to):

```bash
curl -fsSL https://raw.githubusercontent.com/Mohammad858m/serai/main/deploy/install.sh -o install.sh && sudo bash install.sh edge
```

It prints a key and a certificate pin. Then on the **origin** (the host running
the panel):

```bash
sudo bash install.sh origin
```

Run `sudo bash install.sh` with no argument for the full menu: status, logs,
pairing details, diagnostics, config editing, updates and key rotation.

The installer fetches Go if needed, builds, obtains a certificate, writes a
hardened systemd unit, narrows the firewall to 80 and 443, and tunes the kernel
(BBR, fq, socket buffers, descriptor limits).

Building by hand:

```bash
go mod tidy && go build -trimpath -ldflags "-s -w" -o serai ./cmd/serai
```

### DNS

Two names, both pointed at the **relay's** IP, both DNS-only:

| Name | Purpose |
|---|---|
| `tun.example.com` | the tunnel itself, its certificate, and the decoy site |
| `vpn.example.com` | user traffic, routed by SNI on the same 443 |

They are separate on purpose: TLS for `tun` terminates on the relay, while
`vpn` is forwarded untouched to Xray on the origin, so the relay never sees
user content.

---

## Using it with 3x-ui

Forwarding rules live in the **origin** config, on the host that already runs
the panel:

```json
"forwards": [
  {
    "name": "main",
    "proto": "tcp",
    "edge_ports": "443",
    "sni": ["vpn.example.com"],
    "target": "127.0.0.1:443",
    "proxy_protocol": 2
  },
  {
    "name": "inbounds",
    "proto": "tcp+udp",
    "edge_ports": "8000-9000,20000-20100",
    "target_host": "127.0.0.1",
    "proxy_protocol": 2
  }
]
```

- `edge_ports` takes ranges. Add an inbound on 20001 in the panel and it is
  already reachable, with no change on either server.
- `target_host` keeps the port: edge:20001 → 127.0.0.1:20001.
- `sni` lets a rule share 443 with the tunnel, which is what keeps the relay
  down to a single open port.
- `proxy_protocol: 2` plus `acceptProxyProtocol: true` on the inbound means the
  panel logs the **real client IP** instead of 127.0.0.1. Without it, per-IP
  limits and GeoIP routing are meaningless.

Use `proto: "udp"` or `"tcp+udp"` for Hysteria2 and TUIC.

---

## Performance

### Why several carriers

| Problem | One connection | N carriers |
|---|---|---|
| Head-of-line blocking | one lost segment stalls every user flow | only the flows on that carrier |
| Per-flow ISP shaping | you hit the ceiling | ceiling × N |
| Losing QUIC to a UDP block | the whole tunnel | only the flows already on it |

New flows are assigned by shortest queue, weighted, and scaled by each
carrier's EWMA open latency — so a degrading path drains itself instead of
having to be declared dead.

### Latency

**Optimistic open**: the open request and the user's first bytes go out
together, and the reply is never waited for. The tunnel adds **zero round
trips** — a user's TLS handshake completes in the one round trip it needs, not
two.

### Memory — read this

`stream_window` is a memory ceiling as much as a speed knob:

```
worst-case buffered ≈ stream_window × max_streams × carriers
```

16 MiB × 256 × 3 would be twelve gigabytes. VPN traffic is many concurrent
small flows, where aggregate throughput comes from concurrency and from running
several carriers, not from a large window.

| Profile | Window | Carriers | Ceiling | obfs |
|---|---|---|---|---|
| `speed` | 4 MiB | 4 | ~3 GiB | off |
| `balanced` | 2 MiB | 3 | ~1.5 GiB | control only |
| `stealth` | 1 MiB | 2 | ~768 MiB | everywhere |

The ceiling is theoretical worst case. In practice the relay reads and
immediately writes, so buffers stay near empty and real usage is tens of
megabytes. `serai check -c config.json` computes the ceiling for your settings.

`GOMEMLIMIT` is set to 70% of RAM in the systemd unit — without it a memory
spike is an OOM kill rather than a collection.

### CPU

TLS dominates. The relay prefers AES-GCM suites: on a CPU with AES-NI that is
several times cheaper per gigabyte than ChaCha20. The obfs layer adds one
memcpy per record — at 1 Gbit/s with 4 KiB records that is about 30k records a
second, which is noise.

---

## Comparison

| | frp / rathole | Backhaul | chisel | Serai |
|---|---|---|---|---|
| Several transports at once | ✗ | ✗ | ✗ | ✓ QUIC + TLS + WSS |
| Multi-carrier aggregation | ✗ | pool, single transport | ✗ | ✓ scheduled per flow |
| Browser TLS fingerprint | ✗ | ✗ | ✗ | ✓ uTLS |
| Traffic shaping | ✗ | ✗ | ✗ | ✓ |
| Single port with SNI routing | ✗ | ✗ | ✗ | ✓ |
| Decoy for active probes | ✗ | ✗ | ✗ | ✓ real reverse proxy |
| UDP | weak | partial | ✗ | ✓ flow table with a cap |
| PROXY protocol | partial | ✗ | ✗ | ✓ v1/v2 |
| Zero added RTT per connection | ✗ | ✓ | ✗ | ✓ |
| Prometheus metrics | ✗ | ✗ | ✗ | ✓ |

Verify this table yourself rather than taking my word for it:

```bash
# throughput
iperf3 -s                                   # on the origin, behind a forward
iperf3 -c <edge-ip> -p <port> -P 8 -t 60

# per-connection latency, which matters more than throughput for how it feels
for i in $(seq 50); do
  curl -so /dev/null -w "%{time_connect}\n" https://<edge>:<port>/
done | sort -n | awk '{a[NR]=$1} END {print "p50",a[int(NR*0.5)],"p95",a[int(NR*0.95)]}'

# look at your own TLS fingerprint, with and without the mimicry
curl https://tls.peet.ws/api/clean
```

If JA3 does not change when you set `fingerprint`, uTLS is not engaged and you
do not have the biggest advantage here.

---

## Configuration

`//` line comments are accepted.

### Shared

| Key | Meaning |
|---|---|
| `role` | `edge` or `origin` |
| `profile` | `speed` \| `balanced` \| `stealth` — a starting point; explicit fields win |
| `psk_file` | path to the key file, preferred over inline `psk` |
| `obfs.scope` | `none` \| `control` \| `all` |
| `tuning.*` | `carriers`, `stream_window`, `max_streams`, `copy_buffer`, `keepalive` |
| `admin_addr` | defaults to `127.0.0.1:9900` — **never bind this publicly** |

### edge

| Key | Meaning |
|---|---|
| `server.control_addr` | the single TCP port, normally `:443` |
| `server.quic_addr` | the UDP port; empty disables QUIC |
| `server.tunnel_sni` | the name that reaches Serai itself; any other SNI is forwarded or sent to the decoy |
| `server.ws_path` | the WebSocket endpoint — pick something unremarkable |
| `server.cert_file`, `server.key_file` | certificate for `tunnel_sni` |
| `server.decoy_upstream` | site mirrored for probers |
| `server.allow_ports` | which ports an origin may open; 443 is served by SNI and needs no entry |

### origin

| Key | Meaning |
|---|---|
| `edge.paths[]` | `transport` (`quic`/`tls`/`websocket`), `addr`/`url`, `fingerprint`, `role`, `weight`, `edge_addr`, `headers` |
| `edge.pinned_spki` | public-key pin; required if `insecure` is set |
| `edge.reconnect` | `min`, `max`, `factor`, `jitter` |
| `forwards[]` | as above |

Path `role`: `both` (default) · `data` (bulk only) · `bootstrap` (control only —
for an expensive or slow path such as a CDN).

---

## Threat model and real limits

What this does **not** do matters more than what it does:

- **Volume-based blocking.** If one address moves terabytes a day, no layer
  here saves it. That is an operational problem, not a protocol one.
- **Hiding that users connect to the relay.** The relay is exposed by design;
  the goal is that it looks like a web server.
- **QUIC plus uTLS.** QUIC carries its own TLS stack, so ClientHello shaping
  does not apply there. Acceptable, because HTTP/3 is ubiquitous — and where
  UDP is blocked the racer falls back to the WebSocket path.
- **obfs is not encryption.** It is a shaping layer; confidentiality comes from
  the TLS beneath it.
- **A seized relay.** It holds the key and sees forwarded traffic, but user TLS
  is end-to-end to Xray so it cannot read content, and it cannot make the
  origin connect to a host the origin did not already configure.
- **Timing analysis.** Cover traffic breaks simple patterns, not a classifier
  trained on long-run volume.

---

## Operating it

```bash
serai check -c /etc/serai/origin.json     # validate and print what it will do
serai keygen                              # a fresh key
serai pin -cert fullchain.pem              # pin for a private CA
curl -s localhost:9900/status | jq         # live state
curl -s localhost:9900/metrics             # Prometheus
journalctl -u serai-origin -f

sudo bash install.sh diagnose              # dns, ports, certificate, carriers
sudo bash install.sh pairing               # what the other server needs
```
