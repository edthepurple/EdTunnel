<div align="center">

# 🚇 EdTunnel

**A high-performance Go relay/tunnel for forwarding TCP & UDP traffic through one or more relay servers — built for high throughput, low latency, zero-allocation hot paths, and resilient multi-relay failover.**

Ideal for relaying **WireGuard**, **OpenVPN**, and **Ocserv** traffic through a public relay into a private/NAT'd network.

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

</div>

---

## ✨ Overview

**EdTunnel** lets a VPN/application server sitting behind NAT or in a restricted network expose TCP and UDP services to the public internet through one or more **relay** nodes. The relay accepts public connections and ships traffic over a multiplexed, authenticated tunnel to the VPN-side client, which forwards it to local target ports.

It's built around two cooperating processes:

| Mode | Role |
|------|------|
| `relay` | Public-facing node. Accepts TCP/UDP client traffic and tunnels it to the VPN client. |
| `vpn`   | Private-side node. Connects out to one or more relays and forwards traffic to local services. |

---

## 🔑 Key Features

- **⚡ High throughput, low latency** — zero-allocation hot paths, pooled buffers, `TCP_NODELAY`, and `SO_REUSEPORT` listeners keep forwarding overhead minimal even under heavy load.
- **🔒 VPN-friendly forwarding** — works great as a relay in front of **WireGuard**, **OpenVPN**, and **Ocserv**, letting you expose them publicly while the actual server stays behind NAT or in a restricted network.
- **🔀 TCP multiplexing via `smux`** — a single authenticated TCP connection carries many forwarded streams, avoiding per-connection handshake overhead.
- **📡 Raw UDP tunneling** — UDP traffic is encapsulated with a lightweight 14-byte header (auth hash + session ID + target port) and shipped directly over a dedicated UDP socket, with **zero-allocation** read/write loops via `sync.Pool` buffer pooling.
- **🩹 Multi-relay support** — connect to several relay servers at once with two selectable strategies:
  - `multi` — all healthy relays stay active simultaneously.
  - `failover` — only one relay is active at a time, automatically promoting the next healthy relay on disconnect.
- **🔐 Token authentication** — relay connections are authenticated with a shared token; UDP packets are authenticated per-packet via an FNV-1a hash of the token.
- **♻️ Hot-reconnect** — a new VPN connection to a relay immediately tears down and replaces the previous session, freeing bound ports without downtime gaps.
- **⚡ `SO_REUSEPORT` listeners** — TCP and UDP listeners are created with `SO_REUSEADDR`/`SO_REUSEPORT` for fast rebinding.
- **🧹 Automatic UDP session cleanup** — stale relay-side UDP sessions are garbage-collected on a 30-second sweep after 2 minutes of inactivity.
- **💓 NAT keep-alive** — the VPN client periodically sends a session-ID-0 keep-alive packet so the relay always has a fresh public endpoint for the VPN client, even behind NAT.

---

## 🏗️ Architecture

```
                         ┌────────────────────┐
   Public Client  ─TCP──▶│                    │
                         │    relay  mode     │──smux stream──▶  VPN mode  ──TCP──▶ Local Target
   Public Client  ─UDP──▶│  (public-facing)   │──UDP tunnel───▶  (private) ──UDP──▶ Local Target
                         └────────────────────┘
```

- **TCP path:** Relay accepts a raw TCP connection → opens an `smux` stream over the authenticated tunnel → sends a small header (`protocol`, `target-port`) → bidirectional `io.CopyBuffer` relay using pooled 32 KB buffers.
- **UDP path:** Relay assigns each public client a numeric session ID → wraps payloads in a custom 14-byte frame → sends over a dedicated UDP socket to the VPN client's last-known public endpoint → VPN client unwraps, forwards to the local target, and reverses the process for replies.

---

## 🚀 Usage

### Build

```bash
go build -o edtunnel .
```

### Run as a relay (public-facing node)

```bash
./edtunnel -mode=relay \
  -port=27015 \
  -token="your-shared-secret"
```

### Run as a VPN client (private-side node)

```bash
./edtunnel -mode=vpn \
  -host="relay1.example.com:27015,relay2.example.com:27015" \
  -token="your-shared-secret" \
  -forward="943,943" \
  -forwardudp="51820,51820" \
  -strategy=multi
```

> **Example:** forwarding **WireGuard** (UDP `51820`), **OpenVPN** (UDP `1194` or TCP `943`), and **Ocserv** (TCP/UDP `443`) just means adding the matching `srcPort,targetPort` pair to `-forward` / `-forwardudp`.

---

## ⚙️ Flags

| Flag | Used in | Description |
|------|---------|-------------|
| `-mode` | both | `relay` or `vpn` |
| `-port` | relay | Port the relay listens on (TCP **and** UDP tunnel) |
| `-host` | vpn | Comma-separated list of `host:port` relay servers |
| `-token` | both | Shared authentication secret |
| `-forward` | vpn | TCP forwarding rules — `srcPort,targetPort;srcPort,targetPort` |
| `-forwardudp` | vpn | UDP forwarding rules — same format as `-forward` |
| `-strategy` | vpn | `multi` (all relays active) or `failover` (one active at a time) |

> **Note:** `srcPort` is the port opened on the **relay**; `targetPort` is the port on the **local target** the VPN client forwards to.

---

## 🧠 Design Notes

- **Buffer pooling:** Both the 32 KB TCP copy buffers and the 65,550-byte UDP frame buffers (`65535` max UDP payload + `14`-byte header) are recycled through `sync.Pool` to keep the hot path allocation-free.
- **Session bookkeeping:** Relay-side UDP sessions are tracked in two maps — `clientAddr → sessionID` and `sessionID → *RelayUDPSession` — protected by an `RWMutex`, allowing concurrent reads on the hot path.
- **Graceful relay handover:** When a VPN client reconnects to a relay, `closeCurrentSession()` tears down all previously bound listeners and the prior `smux` session before the new one is established, so ports are released immediately rather than waiting on a timeout.

---

## 📋 Requirements

- Go **1.21+**
- Linux (uses `SO_REUSEPORT` via `syscall`)
- [`github.com/xtaci/smux`](https://github.com/xtaci/smux)

---

## 📄 License

MIT — feel free to fork, adapt, and build on it.

---

<div align="center">

*Built for fast, resilient, multiplexed tunneling.*

</div>
