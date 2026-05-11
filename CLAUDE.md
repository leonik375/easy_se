# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`easy_se` is a standalone C++17 static library (`libeasy_se.a`) that implements a SoftEther VPN client from scratch. It speaks the SoftEther Cedar wire protocol over TLS, assigns itself an IP via DHCP over the virtual Ethernet tunnel, then forwards packets between an OS TUN device and the VPN server. The public surface is a plain C API (`include/easy_se.h`) so it can be consumed from C, JNI, or Swift.

## Build

```bash
# Native (Linux) — also builds the easy_se_cli tool
cmake -B build && cmake --build build

# Cross-compile for Android (used by the Flutter app)
# SE_PREBUILT_DIR must point to a directory with include/ and lib/{libssl,libcrypto}.a
cmake -B build-android \
  -DCMAKE_TOOLCHAIN_FILE=... \
  -DSE_PREBUILT_DIR=/path/to/android-openssl-arm64 \
  && cmake --build build-android
```

System OpenSSL is used when `SE_PREBUILT_DIR` is not set; prebuilt static libs are required for Android cross-compilation.

## Run the CLI (requires CAP_NET_ADMIN / root)

```bash
sudo ./build/easy_se_cli <host> <port> <hub> <user> <pass> [--radius] [--debug] [--default-gw] [--proxy [port]]
```

`--radius` selects `SE_AUTH_PLAIN_PASSWORD` (plaintext sent to server, which does local+RADIUS fallback). Default is `SE_AUTH_PASSWORD` (SHA-0–based hashed auth, local only).

There are no automated tests — `easy_se_cli` is the only test harness.

## Architecture

### Source layout

| File | Role |
|---|---|
| `include/easy_se.h` | Public C API |
| `src/easy_se.cpp` | API implementation: connect/run/disconnect, ARP cache, TUN↔tunnel forwarding loop, reconnect logic |
| `src/tunnel.hpp/.cpp` | SoftEther Cedar protocol: TLS, HTTP PACK exchange, handshake, auth, DHCP probe, frame I/O (TCP + UDP acceleration) |
| `src/pack.hpp/.cpp` | PACK: SoftEther's binary key-value serialization |
| `src/proxy.hpp/.cpp` | HTTP CONNECT + SOCKS5 proxy server (standalone or alongside TUN VPN) |
| `src/sha0.hpp` | SHA-0 (used by the hashed-password auth path) |
| `easy_se_cli.cpp` | Linux CLI: opens TUN device, configures routes, calls `se_connect` + `se_run` |

### Connection lifecycle

```
se_connect()
  └─ Tunnel::connect()      — TCP + TLS (cert not validated)
  └─ Tunnel::handshake()    — POST watermark to /vpnsvc/connect.cgi, receive server_random[20]
  └─ Tunnel::authenticate() — POST auth PACK to /vpnsvc/vpn.cgi, negotiate UDP acceleration
  └─ Tunnel::dhcp_probe()   — DHCP DISCOVER→OFFER→REQUEST→ACK over Ethernet tunnel; ARP for gateway MAC

se_run(tun_fd)              — blocks; two threads:
  main thread:  recv_frame_any() → strip Ethernet header → write(tun_fd)
  tun_reader:   read(tun_fd)   → resolve_dst_mac() → wrap in Ethernet frame → send_frame/send_udp_frame
```

`se_run()` auto-reconnects on error with exponential backoff (1 s → 2 → 4 → 8 → 16 → 30 → 30 s cap). `se_disconnect()` stops both the session and the reconnect loop atomically; it is safe to call from a signal handler.

### Protocol details worth knowing

- **SoftEther wire format**: each data batch is `uint32_BE(num_blocks)` followed by `num_blocks × [uint32_BE(size) + bytes]`. A keepalive is `uint32_BE(0xFFFFFFFF) + uint32_BE(payload_size) + payload`.
- **HTTP tunnel**: all Cedar control messages are POST to `/vpnsvc/vpn.cgi` (`application/octet-stream`) on the same persistent TLS connection. Data frames are sent inline on the same connection (no separate channel).
- **UDP acceleration (V1)**: RC4 with a per-packet key derived as `SHA1(common_key[20] || IV[20])`. Outbound packets fall back to TCP until the first UDP packet is received from the server (`udp_ready_` flag).
- **Fixed MAC**: the virtual NIC always uses `02:AA:BB:CC:DD:EE` (locally administered, so no conflict with real NICs).
- **ARP cache**: maintained in `easy_se.cpp` (`g_arp_cache`). On a same-subnet ARP miss the packet is sent as Ethernet broadcast and an ARP request is injected into the tunnel; requests are rate-limited to once per second per IP.
- **Global singleton**: `g_tunnel` is a single static `Tunnel`. The library does not support multiple simultaneous VPN sessions in one process.

### Proxy server

`se_proxy_start(port)` starts a local HTTP CONNECT + SOCKS5 server. One `pthread` per accepted connection. Outgoing connections can be bound to a specific interface via `SO_BINDTODEVICE` (`se_proxy_set_iface`), which forces routing through the VPN without requiring a default-gateway route.
