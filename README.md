<div align="center">

# 🚇 EdTunnel

**A high-performance Go relay/tunnel for forwarding TCP & UDP traffic through one or more relay servers — built for resilient multi-relay failover and low-overhead hot paths.**

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

- **🔀 TCP multiplexing via `smux`** — a single authenticated TCP connection carries many forwarded streams, avoiding per-connection handshake overhead. The smux session is tuned for high throughput: `MaxReceiveBuffer` is set to 16 MiB and `MaxStreamBuffer` to 4 MiB, sized to fill large bandwidth-delay products without stalling.
- **📡 Raw UDP tunneling** — UDP traffic is encapsulated with a lightweight 14-byte header (8-byte FNV-1a token hash + 4-byte session ID + 2-byte target port) and shipped directly over a dedicated UDP socket, bypassing the smux layer entirely to avoid head-of-line blocking on lossy paths.
- **🩹 Multi-relay support** — connect to several relay servers at once with two selectable strategies:
  - `multi` — all healthy relays stay active simultaneously; every connected relay forwards independently.
  - `failover` — only one relay is active at a time; on disconnect the monitor goroutine automatically promotes the next healthy relay without manual intervention.
- **🔐 Token authentication** — TCP relay connections are authenticated at handshake time with a plaintext shared token. UDP packets carry per-packet authentication via an FNV-1a hash of the token prepended to every frame, so spoofed or replayed packets from unknown senders are dropped at the top of the read loop before any session lookup.
- **♻️ Hot-reconnect** — when a VPN client reconnects, `closeCurrentSession()` immediately tears down all previously bound listeners and the prior `smux` session before establishing the new one, so relay ports are freed at once rather than waiting on OS timeout.
- **⚡ `SO_REUSEPORT` / `SO_REUSEADDR` listeners** — both TCP and UDP listeners are created with these socket options, enabling fast rebinding to the same port immediately after a session teardown.
- **🧹 Automatic UDP session cleanup** — both relay-side and VPN-side UDP sessions are garbage-collected on a 30-second sweep after 2 minutes of inactivity. The relay-side cleaner double-checks under a write lock to prevent races between the sweep and an arriving packet re-activating a session.
- **💓 NAT keep-alive** — the VPN client sends a session-ID-0 UDP keep-alive packet at connection time and then every 5 seconds so the relay always has a fresh public endpoint for the VPN client, keeping NAT mappings alive even on restrictive firewalls.
- **🔒 VPN-friendly forwarding** — works as a relay in front of **WireGuard**, **OpenVPN**, and **Ocserv**, letting you expose them publicly while the actual server stays behind NAT or in a restricted network.

---

## ⚡ Why It Stays Fast Under Load

EdTunnel is structured so that the work done per packet or per byte in the steady-state forwarding loops is as small and allocation-free as possible. The specific mechanisms:

**Buffer pooling eliminates GC pressure on hot paths.**
Two `sync.Pool` instances are maintained: one for 65,549-byte UDP frame buffers (14-byte header + maximum 65,535-byte UDP payload) and one for 32 KiB TCP copy buffers used by `io.CopyBuffer`. Under sustained traffic both buffer sizes are hit on every iteration of their respective read loops, so without pooling the GC would be collecting a large slab on every packet or copy chunk. With pooling, once the pool is warm those allocations disappear entirely from the profile.

**UDP reads land directly into the pooled frame buffer.**
Both the relay-side `startUDPForwarderWithConn` and the VPN-side `handleVPNUDPLocal` call `ReadFromUDP` / `Read` into `(*framep)[14:]` — the payload region of the pooled buffer — so the 14-byte header can be filled in-place and the frame sent without any intermediate copy. The header bytes are overwritten on each loop iteration; no allocation or `append` is needed.

**Read/write lock sharding on UDP session maps keeps concurrent goroutines from serializing.**
The relay-side session map is protected by an `RWMutex` with a deliberate two-phase lookup: a cheap read-lock fast path for the common case where the session already exists, and a write-lock slow path only when a genuinely new client address is seen. This means that once sessions are established, thousands of concurrent goroutines reading from different clients can look up their session ID in parallel without blocking each other.

**`TCP_NODELAY` is set on every TCP connection.**
`setTCPNoDelay` is called on every accepted and dialed TCP connection, disabling Nagle's algorithm. For interactive or low-latency traffic like VPN control messages this eliminates the up-to-40 ms artificial delay that Nagle would otherwise impose waiting to coalesce small writes.

**The smux keepalive and buffer tuning prevents idle-timeout stalls.**
`KeepAliveInterval` is 10 seconds and `KeepAliveTimeout` is 30 seconds. Without keepalives, a long-lived smux session over an idle TCP connection can be silently killed by a NAT device or stateful firewall mid-stream. The keepalives ensure the underlying TCP connection stays alive and smux detects a dead peer within 30 seconds rather than hanging indefinitely.

**Relay monitor uses a channel to react to reconnects immediately.**
`monitorRelays` selects on both a 5-second ticker and a `reconnectChan`. When `connectOnce` detects a connection establishment or loss it sends to `reconnectChan`, so the monitor evaluates relay health immediately rather than waiting up to 5 seconds for the next tick. This minimises the window during which a newly connected relay is not yet marked active.

---

## 🏗️ Architecture

```
                         ┌────────────────────┐
   Public Client  ─TCP──▶│                    │──smux stream──▶  vpn mode  ──TCP──▶ Local Target
                         │    relay  mode     │
   Public Client  ─UDP──▶│  (public-facing)   │──UDP tunnel───▶  vpn mode  ──UDP──▶ Local Target
                         └────────────────────┘
```

**TCP path:** The relay accepts a raw TCP connection → opens an `smux` stream over the authenticated tunnel → writes a small stream header (`[proto byte] [port-len byte] [port bytes]`) → runs bidirectional `io.CopyBuffer` using a pooled 32 KiB buffer. The VPN side reads the stream header, dispatches by protocol byte, and dials the local target.

**UDP path:** The relay assigns each public client a numeric session ID (allocated with `atomic.AddUint32` to avoid lock contention on the counter itself) → wraps payloads in a 14-byte frame (`tokenHash[8] | sessionID[4] | targetPort[2]`) → sends over a dedicated UDP socket to the VPN client's last-known public endpoint stored in an `atomic.Value`. The VPN client unwraps, looks up or creates a per-session local `UDPConn` dialed to `127.0.0.1:targetPort`, writes the payload, and reverses the process for replies.

**Session ID allocation:** On the relay, `relayNextSessionID` is incremented via `atomic.AddUint32`, so concurrent goroutines receiving packets from new clients never contend on a mutex just to claim a session ID.

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

Multiple relay hosts are supplied as a comma-separated list to `-host`. Each host is connected to independently by its own goroutine; `strategy` controls which connected relays actually forward traffic.

---

## ⚙️ Flags

| Flag | Used in | Description |
|------|---------|-------------|
| `-mode` | both | `relay` or `vpn` |
| `-port` | relay | Port the relay listens on — used for both the TCP smux listener and the UDP tunnel socket |
| `-host` | vpn | Comma-separated list of `host:port` relay servers |
| `-token` | both | Shared authentication secret |
| `-forward` | vpn | TCP forwarding rules — `srcPort,targetPort;srcPort,targetPort` |
| `-forwardudp` | vpn | UDP forwarding rules — same format as `-forward` |
| `-strategy` | vpn | `multi` (all healthy relays active simultaneously) or `failover` (one active relay at a time, auto-promoted on disconnect) |

> **Note:** `srcPort` is the port opened on the **relay**; `targetPort` is the port on the local machine the VPN client forwards to (always `127.0.0.1:targetPort`).

---

## 🧠 Design Notes

**Relay TCP and UDP share a single port.** The relay opens both a TCP listener and a UDP socket on `-port`. The TCP listener carries the smux control/data tunnel; the UDP socket carries the raw UDP forwarding tunnel and keep-alive packets. This simplifies firewall rules — one port to open, one port to forward.

**Forward rules are negotiated at handshake time.** The VPN client encodes its `-forward` and `-forwardudp` rules into a length-prefixed, pipe-separated string (`tcpRules|udpRules`) sent immediately after authentication. The relay parses this and opens listeners only for the ports the VPN client requests, rather than having ports configured statically on both sides.

**Hot-reconnect with immediate port release.** `closeCurrentSession()` is called inside the authentication handler, under `currentRelaySessionMu`, before acknowledging the new connection. This means the old listeners are torn down synchronously — before the new session sends its `OK` — so the new session's `launchRelayForwarders` call always finds its ports free.

**VPN-side stream dispatch is protocol-extensible.** `dispatchStream` reads a protocol byte from the stream header and switches on it. Currently only `TCP_FORWARD (1)` is handled; unknown protocol bytes are logged and the stream is dropped cleanly, leaving the door open for additional protocol types without breaking existing sessions.

**Stale VPN-side UDP sessions are closed, not just evicted.** `cleanStaleVPNSessions` calls `sess.conn.Close()` under `sess.mu` before deleting the map entry, ensuring the `handleVPNUDPLocal` goroutine unblocks from its `Read` call and exits rather than leaking. The closed flag prevents a double-close if the goroutine races to close the connection itself.

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
