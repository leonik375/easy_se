#include "../include/easy_se.h"
#include "tunnel.hpp"
#include "proxy.hpp"
#include "tcp_conn.hpp"
#include "vpn_internal.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <array>
#include <cerrno>
#include <cstring>
#include <cstdio>

static Tunnel             g_tunnel;
static IpInfo             g_ip;
static std::atomic<bool>  g_stop{false};
static std::atomic<bool>  g_user_stop{false}; /* set only by se_disconnect() */
static bool               g_debug{false};

/* Stored connection params — used by se_run's reconnect loop. */
static std::string g_host, g_hub, g_user_str, g_pass;
static int         g_port = 443, g_authtype = 1;

/* Optional overrides (set before se_connect). */
static int              g_keepalive_sec     = 60;
static std::string      g_static_ip, g_static_gw, g_static_dns;
static int              g_static_prefix     = 24;
static std::atomic<int> g_skip_default_gw{0};
static std::atomic<int> g_verify_cert{1};   /* default ON: secure by default */
static std::mutex       g_ca_path_mutex;
static std::string      g_ca_path;
static std::atomic<int> g_use_udp_accel{1}; /* default ON; toggle off for lossy paths */

#define DBG(...) do { if (g_debug) fprintf(stderr, __VA_ARGS__); } while(0)

static constexpr int    ETH_HDR = 14;
static constexpr size_t MAX_PKT = 2048;

static std::mutex              g_stop_mutex;
static std::condition_variable g_stop_cv;

struct ArpEntry {
    std::array<uint8_t,6>                 mac;
    std::chrono::steady_clock::time_point learned_at;
    std::chrono::steady_clock::time_point probed_at;
    bool                                  probing{false};
};
static constexpr int ARP_STALE_SEC        = 60; /* start NUD probe after this many seconds */
static constexpr int ARP_PROBE_TIMEOUT_SEC = 3; /* evict if no reply within this window    */

/* ARP cache: IPv4 (network byte order) → ArpEntry.
   Stale entries (age ≥ ARP_STALE_SEC) trigger a background NUD probe while the
   cached MAC is still used. If no reply arrives within ARP_PROBE_TIMEOUT_SEC the
   entry is evicted; the next miss re-ARPs from scratch. */
static std::mutex g_arp_mutex;
static std::unordered_map<uint32_t, ArpEntry> g_arp_cache;
/* Rate-limit outbound ARP requests on cache misses: ip → time of last request. */
static std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> g_arp_requested;

/* TCP demux: local port → VpnTcpConn for userspace proxy connections. */
static std::mutex g_tcp_demux_mutex;
static std::unordered_map<uint16_t, VpnTcpConn*> g_tcp_demux;

static void arp_cache_put(uint32_t ip_net, const uint8_t *mac) {
    DBG("[arp-learn] ip=%08x mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
        ip_net, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    std::lock_guard<std::mutex> lk(g_arp_mutex);
    auto &e      = g_arp_cache[ip_net];
    memcpy(e.mac.data(), mac, 6);
    e.learned_at = std::chrono::steady_clock::now();
    e.probing    = false;
    g_arp_requested.erase(ip_net);
}

static void arp_cache_clear() {
    {
        std::lock_guard<std::mutex> lk(g_arp_mutex);
        g_arp_cache.clear();
        g_arp_requested.clear();
    }
    {
        std::lock_guard<std::mutex> lk(g_tcp_demux_mutex);
        g_tcp_demux.clear();
    }
}

/* Return subnet mask in network byte order from prefix length. */
static uint32_t prefix_mask(int prefix) {
    return prefix > 0 ? htonl(~0u << (32 - prefix)) : 0u;
}

/* Send an ARP request ("who has target_ip_net?") through the tunnel.
   Called from the tun_reader thread when a same-subnet MAC is unknown. */
static void send_arp_request(uint32_t target_ip_net) {
    uint8_t req[ETH_HDR + 28]{};
    memset(req, 0xff, 6);                    /* Ethernet dst = broadcast */
    memcpy(req + 6, g_ip.our_mac, 6);
    req[12]=0x08; req[13]=0x06;              /* ARP ethertype */
    uint8_t *a = req + ETH_HDR;
    a[0]=0; a[1]=1; a[2]=8; a[3]=0; a[4]=6; a[5]=4; /* Ethernet/IPv4 */
    a[6]=0; a[7]=1;                          /* op = request */
    memcpy(a + 8,  g_ip.our_mac,     6);
    memcpy(a + 14, &g_ip.our_ip_net, 4);
    memcpy(a + 24, &target_ip_net,   4); /* target IP at ARP offset 24 */
    DBG("[arp-req] who-has %08x\n", target_ip_net);
    g_tunnel.udp_active()
        ? g_tunnel.send_udp_frame(req, sizeof(req))
        : g_tunnel.send_frame(req, sizeof(req));
}

/* Fill dst_mac for an outbound IPv4 packet (ip_pkt, n bytes).
   For both in-subnet and off-subnet (gateway) destinations, look up the ARP
   cache and send an ARP request on a miss.  Using a fixed gw_mac would pin
   whichever DHCP server answered first (e.g. SecureNAT), so we let ARP
   discover the real gateway MAC dynamically instead. */
static void resolve_dst_mac(const uint8_t *ip_pkt, ssize_t n, uint8_t *dst_mac) {
    if (n < 20) { memset(dst_mac, 0xff, 6); return; }

    uint32_t dst_net   = *reinterpret_cast<const uint32_t*>(ip_pkt + 16);
    uint32_t mask      = prefix_mask(g_ip.prefix);
    uint32_t gw_net    = (uint32_t)inet_addr(g_ip.gw.c_str());
    uint32_t lookup_ip = ((dst_net & mask) == (g_ip.our_ip_net & mask))
                          ? dst_net : gw_net;

    using Clock  = std::chrono::steady_clock;
    using Sec    = std::chrono::seconds;
    auto now     = Clock::now();
    bool need_arp = false;

    {
        std::lock_guard<std::mutex> lk(g_arp_mutex);
        auto it = g_arp_cache.find(lookup_ip);
        if (it != g_arp_cache.end()) {
            ArpEntry &e = it->second;
            if (!e.probing) {
                /* Entry is current (or first-seen stale) — give caller the MAC */
                memcpy(dst_mac, e.mac.data(), 6);
                auto age = std::chrono::duration_cast<Sec>(now - e.learned_at).count();
                if (age >= ARP_STALE_SEC) {
                    /* Gone stale: fire a background NUD probe, keep using cached MAC */
                    DBG("[resolve] stale ip=%08x age=%llds, NUD probe\n",
                        lookup_ip, (long long)age);
                    e.probing   = true;
                    e.probed_at = now;
                    need_arp    = true; /* send probe after lock release */
                } else {
                    DBG("[resolve] arp-hit ip=%08x\n", lookup_ip);
                }
                if (!need_arp) return; /* fresh hit — nothing more to do */
            } else {
                /* NUD probe already in flight */
                auto probe_age = std::chrono::duration_cast<Sec>(
                                     now - e.probed_at).count();
                if (probe_age < ARP_PROBE_TIMEOUT_SEC) {
                    /* Still waiting for the reply — use cached MAC */
                    memcpy(dst_mac, e.mac.data(), 6);
                    DBG("[resolve] probing ip=%08x probe_age=%llds\n",
                        lookup_ip, (long long)probe_age);
                    return;
                }
                /* Probe timed out — MAC is stale, evict and re-ARP */
                DBG("[resolve] NUD timeout ip=%08x, evicting\n", lookup_ip);
                g_arp_cache.erase(it);
                memset(dst_mac, 0xff, 6);
                g_arp_requested[lookup_ip] = now;
                need_arp = true;
            }
        } else {
            /* Cache miss — broadcast for this packet, rate-limited ARP request */
            memset(dst_mac, 0xff, 6);
            auto pit = g_arp_requested.find(lookup_ip);
            if (pit == g_arp_requested.end() ||
                now - pit->second > Sec(1)) {
                g_arp_requested[lookup_ip] = now;
                need_arp = true;
            }
        }
    }
    if (need_arp) send_arp_request(lookup_ip);
}

/* ---- private helpers ---- */

/* Block until an ARP reply for gw_n arrives (or timeout_ms elapses).
   Uses recv_frame_any() so poll-timeout (r==0) and keepalives are handled
   correctly without touching SO_RCVTIMEO (which breaks ssl_readn on timeout).
   Resends the ARP request every 500 ms in case the first packet is lost. */
static void probe_gateway_arp(uint32_t gw_n, int timeout_ms) {
    {
        std::lock_guard<std::mutex> lk(g_arp_mutex);
        if (g_arp_cache.count(gw_n)) {
            struct in_addr a; a.s_addr = gw_n;
            fprintf(stderr, "[arp-probe] %s already in cache\n", inet_ntoa(a));
            return;
        }
    }

    struct in_addr a; a.s_addr = gw_n;
    fprintf(stderr, "[arp-probe] probing %s (timeout %d ms)\n", inet_ntoa(a), timeout_ms);
    send_arp_request(gw_n);

    using Clock = std::chrono::steady_clock;
    auto deadline  = Clock::now() + std::chrono::milliseconds(timeout_ms);
    auto last_send = Clock::now();
    uint8_t eth[ETH_HDR + MAX_PKT];

    while (Clock::now() < deadline) {
        int r = g_tunnel.recv_frame_any(eth, sizeof(eth));
        if (r < 0) { fprintf(stderr, "[arp-probe] tunnel error, aborting\n"); break; }

        /* Resend every 500 ms in case the first request was lost */
        if (Clock::now() - last_send >= std::chrono::milliseconds(500)) {
            send_arp_request(gw_n);
            last_send = Clock::now();
        }

        if (r < (int)(ETH_HDR + 28)) continue; /* 0 = poll timeout / keepalive */
        uint16_t etype = static_cast<uint16_t>((eth[12] << 8) | eth[13]);
        if (etype != 0x0806) {
            DBG("[arp-probe] skip etype=0x%04x len=%d\n", etype, r);
            continue;
        }

        uint8_t *arp = eth + ETH_HDR;
        uint32_t sender_ip;
        memcpy(&sender_ip, arp + 14, sizeof(sender_ip));   /* unaligned-safe */
        struct in_addr sa; sa.s_addr = sender_ip;
        DBG("[arp-probe] ARP from %s op=%d\n", inet_ntoa(sa), (arp[6]<<8|arp[7]));
        arp_cache_put(sender_ip, arp + 8);
        if (sender_ip == gw_n) {
            fprintf(stderr, "[arp-probe] gateway MAC resolved\n");
            break;
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_arp_mutex);
        if (!g_arp_cache.count(gw_n))
            fprintf(stderr, "[arp-probe] WARNING: timed out, cache miss for %s\n", inet_ntoa(a));
    }
}

/* ── vpn_internal.hpp implementations ───────────────────────────────────── */

uint32_t vpn_our_ip_net()       { return g_ip.our_ip_net; }
const uint8_t *vpn_our_mac()    { return g_ip.our_mac; }
uint32_t vpn_gateway_ip_net()   { return static_cast<uint32_t>(inet_addr(g_ip.gw.c_str())); }

bool vpn_lookup_mac(uint32_t ip_net, uint8_t *mac_out) {
    std::lock_guard<std::mutex> lk(g_arp_mutex);
    auto it = g_arp_cache.find(ip_net);
    if (it == g_arp_cache.end()) return false;
    memcpy(mac_out, it->second.mac.data(), 6);
    return true;
}

bool vpn_send_frame(const uint8_t *eth, size_t len) {
    return g_tunnel.udp_active()
           ? g_tunnel.send_udp_frame(eth, len)
           : g_tunnel.send_frame(eth, len);
}

void vpn_tcp_register(uint16_t port, VpnTcpConn *conn) {
    std::lock_guard<std::mutex> lk(g_tcp_demux_mutex);
    g_tcp_demux[port] = conn;
}

void vpn_tcp_unregister(uint16_t port) {
    std::lock_guard<std::mutex> lk(g_tcp_demux_mutex);
    g_tcp_demux.erase(port);
}

bool vpn_probe_arp(uint32_t ip_net, int timeout_ms) {
    {
        std::lock_guard<std::mutex> lk(g_arp_mutex);
        if (g_arp_cache.count(ip_net)) return true;
    }
    send_arp_request(ip_net);
    if (timeout_ms <= 0) return false; /* fire-and-forget */

    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        usleep(10000); /* 10 ms */
        std::lock_guard<std::mutex> lk(g_arp_mutex);
        if (g_arp_cache.count(ip_net)) return true;
    }
    fprintf(stderr, "[arp-probe] vpn_probe_arp timeout for %08x\n", ip_net);
    return false;
}

/* Deliver an inbound TCP segment to a registered VpnTcpConn.
   Returns true if consumed, false if no registered connection (→ goes to TUN). */
static bool tcp_demux_deliver(const uint8_t *frame, size_t len) {
    static constexpr size_t TCP_MIN = 20;
    if (len < ETH_HDR + 20 + TCP_MIN) return false;

    const uint8_t *ip = frame + ETH_HDR;
    size_t ip_hdr_len = (ip[0] & 0x0fu) * 4u;
    if (ip_hdr_len < 20 || len < ETH_HDR + ip_hdr_len + TCP_MIN) return false;
    const uint8_t *tcp = ip + ip_hdr_len;

    uint16_t ip_total = (static_cast<uint16_t>(ip[2]) << 8) | ip[3];
    if (ip_total < ip_hdr_len || ETH_HDR + ip_total > len) return false;
    size_t tcp_seg_len = ip_total - ip_hdr_len;
    if (tcp_seg_len < TCP_MIN) return false;

    uint16_t dst_port = (static_cast<uint16_t>(tcp[2]) << 8) | tcp[3];
    uint32_t src_ip_net;
    memcpy(&src_ip_net, ip + 12, 4);

    /* Hold the mutex through deliver() to prevent use-after-free and to
       reject frames whose src_ip doesn't match the registered connection
       (port reuse between TUN connections and proxy VpnTcpConn). */
    {
        std::lock_guard<std::mutex> lk(g_tcp_demux_mutex);
        auto it = g_tcp_demux.find(dst_port);
        if (it == g_tcp_demux.end()) return false;
        VpnTcpConn *conn = it->second;
        if (conn->remote_ip_net() != src_ip_net) return false;
        conn->deliver(tcp, tcp_seg_len, src_ip_net);
    }
    return true;
}

/* ── connect / run ───────────────────────────────────────────────────────── */

/* Run one connect attempt (no side effects on g_user_stop or stored params). */
static int do_connect(se_ip_info_t *ip_out) {
    arp_cache_clear();

    std::string ca_path;
    {
        std::lock_guard<std::mutex> lk(g_ca_path_mutex);
        ca_path = g_ca_path;
    }
    if (!g_tunnel.connect(g_host.c_str(), g_port,
                          g_verify_cert.load() != 0, ca_path))                  return -1;
    if (!g_tunnel.handshake())                                                   return -2;
    if (!g_tunnel.authenticate(g_hub.c_str(), g_user_str.c_str(),
                               g_pass.c_str(), g_authtype))                      return -3;

    auto ip = g_tunnel.dhcp_probe(30);
    if (!ip) return -4;

    g_ip = *ip;

    /* Apply static IP/GW/DNS overrides if set. */
    if (!g_static_ip.empty()) {
        g_ip.ip         = g_static_ip;
        g_ip.our_ip_net = (uint32_t)inet_addr(g_static_ip.c_str());
        g_ip.prefix     = g_static_prefix;
        if (!g_static_gw.empty())  g_ip.gw  = g_static_gw;
        if (!g_static_dns.empty()) g_ip.dns = g_static_dns;
    }

    DBG("[connect] ip=%s/%d gw=%s our_ip_net=0x%08x gw_net=0x%08x\n",
            g_ip.ip.c_str(), g_ip.prefix, g_ip.gw.c_str(),
            g_ip.our_ip_net, (uint32_t)inet_addr(g_ip.gw.c_str()));

    if (ip_out) {
        strncpy(ip_out->ip,  g_ip.ip.c_str(),  15);
        strncpy(ip_out->gw,  g_ip.gw.c_str(),  15);
        strncpy(ip_out->dns, g_ip.dns.c_str(), 15);
        ip_out->ip[15] = ip_out->gw[15] = ip_out->dns[15] = '\0';
        ip_out->prefix = g_ip.prefix;
    }

    /* ARP for the gateway now, while the tunnel is idle, so the cache is warm
       before se_run() starts.  dhcp_probe() already did this for the DHCP
       router; we repeat it here in case a static GW override changed the IP. */
    probe_gateway_arp((uint32_t)inet_addr(g_ip.gw.c_str()), 2000);

    return 0;
}

/* Run one forwarding session (blocks until the tunnel drops or g_stop is set).
   Returns true if exit was caused by g_user_stop (clean), false on error. */
static bool run_once(int tun_fd) {
    g_stop.store(false);

    std::thread tun_reader([&]() {
        uint8_t ip_pkt[MAX_PKT];
        uint8_t eth_frame[ETH_HDR + MAX_PKT];

        memcpy(eth_frame + 6, g_ip.our_mac, 6);
        eth_frame[12] = 0x08; eth_frame[13] = 0x00;

        DBG("[run] our_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
            g_ip.our_mac[0], g_ip.our_mac[1], g_ip.our_mac[2],
            g_ip.our_mac[3], g_ip.our_mac[4], g_ip.our_mac[5]);
        DBG("[run] gw_mac =%02x:%02x:%02x:%02x:%02x:%02x\n",
            g_ip.gw_mac[0],  g_ip.gw_mac[1],  g_ip.gw_mac[2],
            g_ip.gw_mac[3],  g_ip.gw_mac[4],  g_ip.gw_mac[5]);

        while (!g_stop) {
            /* Poll with timeout so we can notice g_stop without waiting for
               the next packet — avoids blocking indefinitely on disconnect. */
            struct pollfd pfd = {tun_fd, POLLIN, 0};
            if (poll(&pfd, 1, 400) <= 0) continue;
            ssize_t n = read(tun_fd, ip_pkt, sizeof(ip_pkt));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;

            if (n < 1 || (ip_pkt[0] >> 4) != 4) {
                DBG("[run] skip non-IPv4 ver=%d len=%zd\n", ip_pkt[0] >> 4, n);
                continue;
            }

            resolve_dst_mac(ip_pkt, n, eth_frame);
            memcpy(eth_frame + ETH_HDR, ip_pkt, static_cast<size_t>(n));

            DBG("[run] tun→vpn %zd bytes proto=0x%02x dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                n, ip_pkt[9],
                eth_frame[0],eth_frame[1],eth_frame[2],
                eth_frame[3],eth_frame[4],eth_frame[5]);

            bool ok = g_tunnel.udp_active()
                      ? g_tunnel.send_udp_frame(eth_frame, ETH_HDR + static_cast<size_t>(n))
                      : g_tunnel.send_frame(eth_frame,     ETH_HDR + static_cast<size_t>(n));
            if (!ok) break;
        }
        g_stop = true;
        g_tunnel.interrupt();
    });

    uint8_t eth[ETH_HDR + MAX_PKT];
    auto    last_ka = std::chrono::steady_clock::now();

    while (!g_stop) {
        int r = g_tunnel.recv_frame_any(eth, sizeof(eth));
        if (r < 0) break;

        /* Keepalive runs on every iteration — including poll timeouts (r==0) and
           server-sent keepalives — so idle connections stay alive in TCP mode. */
        auto now = std::chrono::steady_clock::now();
        if (now - last_ka > std::chrono::seconds(g_keepalive_sec)) {
            g_tunnel.send_keepalive();
            last_ka = now;
        }

        if (r == 0) continue;

        size_t frame_len = static_cast<size_t>(r);
        if (frame_len < ETH_HDR) continue;

        uint16_t etype = static_cast<uint16_t>((eth[12] << 8) | eth[13]);

        if (etype == 0x0806 && frame_len >= ETH_HDR + 28) {
            uint8_t *arp = eth + ETH_HDR;
            uint32_t sender_ip;
            memcpy(&sender_ip, arp + 14, sizeof(sender_ip)); /* unaligned-safe */
            arp_cache_put(sender_ip, arp + 8);

            if ((arp[6]<<8|arp[7]) == 1 &&
                memcmp(arp + 24, &g_ip.our_ip_net, 4) == 0) {
                /* Only reply when someone is asking for OUR IP */
                uint8_t reply[ETH_HDR + 28]{};
                memcpy(reply,     eth + 6,        6);
                memcpy(reply + 6, g_ip.our_mac,   6);
                reply[12]=0x08; reply[13]=0x06;
                uint8_t *a = reply + ETH_HDR;
                a[0]=0;a[1]=1;a[2]=8;a[3]=0;a[4]=6;a[5]=4;
                a[6]=0;a[7]=2;
                memcpy(a + 8,  g_ip.our_mac,    6); /* sender MAC = our MAC */
                memcpy(a + 14, &g_ip.our_ip_net, 4); /* sender IP  = our IP  */
                memcpy(a + 18, arp + 8,          6); /* target MAC = requester MAC */
                memcpy(a + 24, arp + 14,         4); /* target IP  = requester IP */
                g_tunnel.udp_active()
                    ? g_tunnel.send_udp_frame(reply, sizeof(reply))
                    : g_tunnel.send_frame(reply, sizeof(reply));
            }
            continue;
        }

        if (etype != 0x0800) continue;

        /* TCP segment addressed to our VPN IP → try proxy demux first */
        if (frame_len >= (size_t)(ETH_HDR + 20 + 20)) {
            const uint8_t *ip_hdr = eth + ETH_HDR;
            uint32_t dst_ip; memcpy(&dst_ip, ip_hdr + 16, 4);
            if (ip_hdr[9] == 6 && dst_ip == g_ip.our_ip_net &&
                tcp_demux_deliver(eth, frame_len))
                continue;
        }

        DBG("[run] vpn→tun %zu bytes proto=0x%02x\n",
            frame_len - ETH_HDR, eth[ETH_HDR + 9]);
        ssize_t written;
        do { written = write(tun_fd, eth + ETH_HDR, frame_len - ETH_HDR); }
        while (written < 0 && errno == EINTR);
        if (written < 0)
            DBG("[run] write(tun) failed: %s\n", strerror(errno));
    }

    g_stop = true;
    tun_reader.join();
    g_tunnel.close();
    return g_user_stop.load();
}

/* Interruptible sleep: blocks until timeout or se_disconnect() signals g_stop_cv. */
static void backoff_sleep(int seconds) {
    std::unique_lock<std::mutex> lk(g_stop_mutex);
    g_stop_cv.wait_for(lk, std::chrono::seconds(seconds),
                       [] { return g_user_stop.load(); });
}

/* ---- public API ---- */

int se_connect(const char *host, int port,
               const char *hub, const char *user, const char *pass,
               int authtype,
               se_ip_info_t *ip_out)
{
    g_stop      = false;
    g_user_stop = false;

    g_host     = host;
    g_port     = port;
    g_hub      = hub;
    g_user_str = user;
    g_pass     = pass;
    g_authtype = authtype;

    return do_connect(ip_out);
}

int se_run(int tun_fd) {
    while (!g_user_stop.load()) {
        bool clean = run_once(tun_fd);
        if (clean) break;

        /* Error exit — reconnect with exponential backoff (1 2 4 8 16 30 30 …) */
        int delay = 1;
        while (!g_user_stop.load()) {
            fprintf(stderr, "[run] reconnect in %ds\n", delay);
            backoff_sleep(delay);
            if (g_user_stop.load()) break;

            if (do_connect(nullptr) == 0) {
                fprintf(stderr, "[run] reconnected %s/%d\n",
                        g_ip.ip.c_str(), g_ip.prefix);
                delay = 1;
                break;
            }
            fprintf(stderr, "[run] reconnect failed, next in %ds\n",
                    std::min(delay * 2, 30));
            delay = std::min(delay * 2, 30);
        }
    }
    return 0;
}

void se_disconnect() {
    g_user_stop = true;
    g_stop      = true;
    g_stop_cv.notify_all();
    g_tunnel.interrupt();
}

void se_force_reconnect(void) {
    /* Don't touch g_user_stop — that would prevent the reconnect loop from
       running.  Just interrupt the current tunnel so the recv loop returns
       and the backoff retry path kicks in. */
    g_tunnel.interrupt();
}

void se_set_debug(int enable) {
    g_debug = (enable != 0);
}

bool vpn_debug() { return g_debug;
}

bool vpn_use_udp_accel() { return g_use_udp_accel.load() != 0; }

void se_set_keepalive(int seconds) {
    g_keepalive_sec = (seconds > 0) ? seconds : 15;
}

void se_set_static_ip(const char *ip, int prefix, const char *gw, const char *dns) {
    if (!ip || !*ip) {
        g_static_ip.clear(); g_static_gw.clear(); g_static_dns.clear();
        return;
    }
    g_static_ip     = ip;
    g_static_prefix = prefix;
    g_static_gw     = gw  ? gw  : "";
    g_static_dns    = dns ? dns : "";
}

void se_set_skip_default_gw(int skip) { g_skip_default_gw.store(skip != 0 ? 1 : 0); }
int  se_get_skip_default_gw(void)    { return g_skip_default_gw.load(); }

void se_set_verify_cert(int enable) { g_verify_cert.store(enable != 0 ? 1 : 0); }

void se_set_use_udp_accel(int enable) { g_use_udp_accel.store(enable != 0 ? 1 : 0); }

void se_set_ca_path(const char *path) {
    std::lock_guard<std::mutex> lk(g_ca_path_mutex);
    g_ca_path = path ? path : "";
}

static ProxyServer g_proxy;
int  se_proxy_start(int port) {
    return g_proxy.start(port);
}
void se_proxy_stop(void)  { g_proxy.stop(); }
int  se_proxy_port(void)  { return g_proxy.port(); }
void se_proxy_set_iface(const char *ifname) { (void)ifname; /* no-op: proxy routes via VPN tunnel directly */ }

int se_get_tcp_fd(void) { return g_tunnel.tcp_fd(); }
int se_get_udp_fd(void) { return g_tunnel.udp_fd(); }
