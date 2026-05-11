# easy_se

A self-contained C++17 static library that implements a SoftEther VPN client from scratch. Speaks the SoftEther Cedar wire protocol over TLS, obtains an IP via DHCP through the virtual Ethernet tunnel, then forwards packets between an OS TUN device and the VPN server.

The public surface is a plain C API so it can be linked from C, C++, JNI (Android), or Swift (iOS).

## Features

- Full SoftEther Cedar handshake and authentication (hashed password or plaintext/RADIUS)
- DHCP probe over the virtual Ethernet layer for automatic IP assignment
- UDP acceleration with RC4/SHA-1 per-packet key derivation (falls back to TCP/TLS)
- ARP cache with automatic gateway resolution
- Auto-reconnect with exponential backoff (1 → 2 → 4 → 8 → 16 → 30 s cap)
- Built-in HTTP CONNECT + SOCKS5 proxy server (works standalone or alongside TUN)
- No dependencies beyond OpenSSL

## Build

**Native (Linux):**
```bash
cmake -B build && cmake --build build
# produces: build/libeasy_se.a  build/easy_se_cli
```

**Android cross-compile:**
```bash
# SE_PREBUILT_DIR must contain include/ and lib/{libssl,libcrypto}.a
cmake -B build-android \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/android-ndk/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DSE_PREBUILT_DIR=/path/to/android-openssl-arm64 \
  && cmake --build build-android
# produces: build-android/libeasy_se.a
```

System OpenSSL is used automatically when `SE_PREBUILT_DIR` is not set.

## CLI usage

Requires `CAP_NET_ADMIN` (or root):

```bash
sudo ./build/easy_se_cli <host> <port> <hub> <user> <pass> [options]

Options:
  --radius       plaintext auth (local + RADIUS fallback)
  --debug        verbose logging to stderr
  --default-gw   install a default route through the VPN
  --proxy [port] start HTTP/SOCKS5 proxy (default 1080, 0 = OS-assigned)
```

## API

Include `easy_se.h` and link against `libeasy_se.a` and OpenSSL.

### Connect

```c
se_ip_info_t ip;
int rc = se_connect("vpn.example.com", 443, "HUB", "user", "pass",
                    SE_AUTH_PASSWORD, &ip);
// rc == 0 on success; ip.ip / ip.gw / ip.dns / ip.prefix are filled in
```

`SE_AUTH_PASSWORD` — SHA-0-based hashed auth (local accounts only).  
`SE_AUTH_PLAIN_PASSWORD` — plaintext sent to server; supports local + RADIUS.

### Run

```c
// Open your TUN fd first (platform-specific), then:
int rc = se_run(tun_fd);  // blocks until disconnected
```

`se_run()` auto-reconnects on error. Call `se_disconnect()` from any thread or signal handler to stop it cleanly.

### Optional configuration (call before `se_connect`)

```c
se_set_debug(1);                          // verbose stderr logging
se_set_keepalive(15);                     // TCP keepalive interval (seconds)
se_set_static_ip("10.0.0.5", 24,
                 "10.0.0.1", "8.8.8.8"); // override DHCP-assigned addresses
se_set_skip_default_gw(1);               // don't route 0.0.0.0/0 through VPN
```

### Android VpnService socket protection

```c
int tcp_fd = se_get_tcp_fd();
int udp_fd = se_get_udp_fd();
// call VpnService.protect(tcp_fd) and VpnService.protect(udp_fd) here
// before se_run()
```

### Proxy server

```c
se_proxy_set_iface("sevpn0");  // optional: bind to VPN interface
int port = se_proxy_start(1080);
// HTTP CONNECT and SOCKS5 now available on 127.0.0.1:1080
se_proxy_stop();
```

## Source layout

| File | Role |
|---|---|
| `include/easy_se.h` | Public C API |
| `src/easy_se.cpp` | API implementation: connect/run/disconnect, ARP, TUN forwarding, reconnect |
| `src/tunnel.hpp/.cpp` | Cedar protocol: TLS, PACK exchange, handshake, auth, DHCP, frame I/O |
| `src/pack.hpp/.cpp` | PACK serialization (SoftEther binary key-value format) |
| `src/proxy.hpp/.cpp` | HTTP CONNECT + SOCKS5 proxy server |
| `src/sha0.hpp` | SHA-0 (hashed-password auth path) |
| `easy_se_cli.cpp` | Linux CLI: TUN setup, routing, calls `se_connect` + `se_run` |
