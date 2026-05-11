#include "tcp_conn.hpp"
#include "vpn_internal.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <chrono>

#define DBG(...) do { if (vpn_debug()) fprintf(stderr, __VA_ARGS__); } while(0)

static constexpr size_t ETH_HDR = 14;
static constexpr size_t IP_HDR  = 20;
static constexpr size_t TCP_HDR = 20;

/* ── checksum helpers ────────────────────────────────────────────────────── */

static uint16_t ones_complement(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    while (n >= 2) { s += (static_cast<uint32_t>(p[0]) << 8) | p[1]; p += 2; n -= 2; }
    if (n)          s +=  static_cast<uint32_t>(p[0]) << 8;
    while (s >> 16) s  = (s & 0xffff) + (s >> 16);
    return static_cast<uint16_t>(~s);
}

static uint16_t ip_cksum(const uint8_t *hdr) {
    return ones_complement(hdr, IP_HDR);
}

static uint16_t tcp_cksum(uint32_t src_net, uint32_t dst_net,
                           const uint8_t *tcp, size_t tcp_len) {
    /* RFC 793 pseudo-header */
    uint8_t pseudo[12];
    memcpy(pseudo,     &src_net, 4);
    memcpy(pseudo + 4, &dst_net, 4);
    pseudo[8]  = 0;
    pseudo[9]  = 6; /* TCP */
    pseudo[10] = static_cast<uint8_t>(tcp_len >> 8);
    pseudo[11] = static_cast<uint8_t>(tcp_len);

    uint32_t s = 0;
    for (int i = 0; i < 12; i += 2)
        s += (static_cast<uint32_t>(pseudo[i]) << 8) | pseudo[i + 1];
    for (size_t i = 0; i < tcp_len; i += 2)
        s += (i + 1 < tcp_len)
             ? (static_cast<uint32_t>(tcp[i]) << 8) | tcp[i + 1]
             :  static_cast<uint32_t>(tcp[i]) << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return static_cast<uint16_t>(~s);
}

/* ── port allocation ─────────────────────────────────────────────────────── */

static std::atomic<uint16_t> g_next_port{49152};

uint16_t VpnTcpConn::alloc_local_port() {
    uint16_t p = g_next_port.fetch_add(1, std::memory_order_relaxed);
    if (p == 0) p = 49152;
    return p;
}

/* ── send_segment ────────────────────────────────────────────────────────── */

void VpnTcpConn::send_segment(uint8_t flags, const void *data, size_t dlen) {
    static std::atomic<uint16_t> ip_id{1};

    size_t frame_sz = ETH_HDR + IP_HDR + TCP_HDR + dlen;
    uint8_t f[ETH_HDR + IP_HDR + TCP_HDR + MSS] = {};
    if (frame_sz > sizeof(f)) return;

    uint8_t *eth = f;
    uint8_t *ip  = eth + ETH_HDR;
    uint8_t *tcp = ip  + IP_HDR;

    /* Ethernet header */
    uint8_t  gw_mac[6];
    uint32_t gw_ip = vpn_gateway_ip_net();
    if (!vpn_lookup_mac(gw_ip, gw_mac))
        memset(gw_mac, 0xff, 6);               /* broadcast on ARP miss */
    memcpy(eth,     gw_mac,        6);
    memcpy(eth + 6, vpn_our_mac(), 6);
    eth[12] = 0x08; eth[13] = 0x00;            /* IPv4 */

    /* IP header */
    ip[0] = 0x45;                              /* version=4, IHL=5 */
    auto tot = static_cast<uint16_t>(IP_HDR + TCP_HDR + dlen);
    ip[2]  = tot >> 8;  ip[3] = tot & 0xff;
    uint16_t id = ip_id.fetch_add(1, std::memory_order_relaxed);
    ip[4]  = id >> 8;   ip[5] = id & 0xff;
    ip[6]  = 0x40;                             /* DF, no fragment */
    ip[8]  = 64;                               /* TTL */
    ip[9]  = 6;                                /* TCP */
    memcpy(ip + 12, &local_ip_net_,  4);
    memcpy(ip + 16, &remote_ip_net_, 4);
    uint16_t ick = ip_cksum(ip);
    ip[10] = ick >> 8; ip[11] = ick & 0xff;

    /* TCP header */
    tcp[0] = local_port_  >> 8; tcp[1] = local_port_  & 0xff;
    tcp[2] = remote_port_ >> 8; tcp[3] = remote_port_ & 0xff;

    tcp[4] = snd_nxt_ >> 24; tcp[5] = (snd_nxt_ >> 16) & 0xff;
    tcp[6] = (snd_nxt_ >>  8) & 0xff; tcp[7] = snd_nxt_ & 0xff;

    uint32_t ack_val = (flags & 0x10) ? rcv_nxt_ : 0;
    tcp[8]  = ack_val >> 24; tcp[9]  = (ack_val >> 16) & 0xff;
    tcp[10] = (ack_val >>  8) & 0xff; tcp[11] = ack_val & 0xff;

    tcp[12] = 0x50;                            /* data offset = 5 (20 bytes) */
    tcp[13] = flags;
    tcp[14] = 0xff; tcp[15] = 0xff;            /* window = 65535 */

    if (dlen) memcpy(tcp + TCP_HDR, data, dlen);

    size_t tcp_seg_len = TCP_HDR + dlen;
    uint16_t tck = tcp_cksum(local_ip_net_, remote_ip_net_, tcp, tcp_seg_len);
    tcp[16] = tck >> 8; tcp[17] = tck & 0xff;

    vpn_send_frame(f, frame_sz);
}

/* ── connect ─────────────────────────────────────────────────────────────── */

bool VpnTcpConn::connect(uint32_t dst_ip_net, uint16_t dst_port, int timeout_ms) {
    local_ip_net_  = vpn_our_ip_net();
    remote_ip_net_ = dst_ip_net;
    local_port_    = alloc_local_port();
    remote_port_   = dst_port;

    /* Random-ish ISN derived from monotonic clock */
    snd_nxt_ = static_cast<uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());

    struct in_addr da; da.s_addr = dst_ip_net;
    DBG("[tcp] connect %s:%u src_ip=%08x local_port=%u\n",
        inet_ntoa(da), dst_port, local_ip_net_, local_port_);

    /* Trigger ARP for the gateway so the recv loop can process the reply and
       populate the cache while we wait for SYN-ACK.  We re-send the SYN every
       2 s; by the second attempt the ARP reply will have been processed and the
       SYN will reach SecureNAT as a unicast frame (broadcast is ignored). */
    uint32_t gw = vpn_gateway_ip_net();
    vpn_probe_arp(gw, 0); /* fire-and-forget: kick the ARP request, don't block */

    state_ = State::SYN_SENT;
    vpn_tcp_register(local_port_, this); /* register before sending SYN */

    send_segment(0x02);  /* SYN — counts as one sequence byte */
    snd_nxt_++;
    uint32_t isn = snd_nxt_ - 1; /* save ISN for retransmits */

    std::unique_lock<std::mutex> lk(mtx_);
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    while (!connect_done_) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        auto wait = std::min(std::chrono::milliseconds(2000),
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 deadline - now));
        cv_.wait_for(lk, wait, [this] { return connect_done_; });
        if (connect_done_ || std::chrono::steady_clock::now() >= deadline) break;
        if (state_ != State::SYN_SENT) break;
        /* Retransmit SYN — ARP should be resolved by now */
        DBG("[tcp] retransmit SYN → %s:%u\n", inet_ntoa(da), dst_port);
        snd_nxt_ = isn;
        lk.unlock();
        send_segment(0x02);
        lk.lock();
        snd_nxt_ = isn + 1;
    }

    bool ok = connect_done_;
    if (!ok || !connect_ok_) {
        DBG("[tcp] connect %s:%u failed (ok=%d connect_ok=%d)\n",
            inet_ntoa(da), dst_port, ok, connect_ok_);
        state_ = State::CLOSED;
        lk.unlock();
        vpn_tcp_unregister(local_port_);
        return false;
    }
    DBG("[tcp] connect %s:%u established\n", inet_ntoa(da), dst_port);
    return true;
}

/* ── send ────────────────────────────────────────────────────────────────── */

bool VpnTcpConn::send(const void *buf, size_t len) {
    const auto *p = static_cast<const uint8_t *>(buf);
    while (len > 0) {
        if (state_ != State::ESTABLISHED) return false;
        size_t chunk = std::min(len, MSS);
        send_segment(0x18, p, chunk);          /* PSH + ACK */
        snd_nxt_ += static_cast<uint32_t>(chunk);
        p   += chunk;
        len -= chunk;
    }
    return true;
}

/* ── recv ────────────────────────────────────────────────────────────────── */

ssize_t VpnTcpConn::recv(void *buf, size_t len) {
    std::unique_lock<std::mutex> lk(mtx_);
    cv_.wait(lk, [this] { return !rx_buf_.empty() || rx_eof_; });
    if (rx_buf_.empty()) return 0;             /* EOF */
    size_t n = std::min(len, rx_buf_.size());
    memcpy(buf, rx_buf_.data(), n);
    rx_buf_.erase(rx_buf_.begin(), rx_buf_.begin() + static_cast<ptrdiff_t>(n));
    return static_cast<ssize_t>(n);
}

/* ── close ───────────────────────────────────────────────────────────────── */

void VpnTcpConn::close() {
    bool should_fin = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == State::CLOSED) return;
        if (state_ == State::ESTABLISHED || state_ == State::CLOSE_WAIT)
            should_fin = true;
        state_  = State::CLOSED;
        rx_eof_ = true;
        cv_.notify_all();
    }
    if (should_fin) send_segment(0x11);        /* FIN + ACK */
    vpn_tcp_unregister(local_port_);
}

/* ── deliver (called from recv loop, no locks held by caller) ────────────── */

void VpnTcpConn::deliver(const uint8_t *tcp, size_t tcp_len, uint32_t src_ip_net) {
    if (src_ip_net != remote_ip_net_) return;

    uint16_t src_port = (static_cast<uint16_t>(tcp[0]) << 8) | tcp[1];
    if (src_port != remote_port_) return;

    if (tcp_len < TCP_HDR) return;

    uint32_t seq = (static_cast<uint32_t>(tcp[4]) << 24)
                 | (static_cast<uint32_t>(tcp[5]) << 16)
                 | (static_cast<uint32_t>(tcp[6]) <<  8)
                 |  static_cast<uint32_t>(tcp[7]);

    size_t hdr_len = (tcp[12] >> 4) * 4u;
    if (hdr_len < TCP_HDR || hdr_len > tcp_len) return;

    const uint8_t *data     = tcp + hdr_len;
    size_t         data_len = tcp_len - hdr_len;

    uint8_t flags   = tcp[13];
    bool rst      = flags & 0x04;
    bool syn      = flags & 0x02;
    bool fin      = flags & 0x01;
    bool ack_flag = flags & 0x10;

    bool send_ack = false;

    {
        std::lock_guard<std::mutex> lk(mtx_);

        if (rst) {
            state_        = State::CLOSED;
            rx_eof_       = true;
            connect_done_ = true;
            connect_ok_   = false;
            cv_.notify_all();
            return;
        }

        switch (state_) {
        case State::SYN_SENT:
            if (syn && ack_flag) {
                rcv_nxt_      = seq + 1;      /* SYN counts as one seq byte */
                state_        = State::ESTABLISHED;
                connect_done_ = true;
                connect_ok_   = true;
                send_ack      = true;
                cv_.notify_all();
            }
            break;

        case State::ESTABLISHED:
            if (data_len > 0 && seq == rcv_nxt_) {
                rx_buf_.insert(rx_buf_.end(), data, data + data_len);
                rcv_nxt_ += static_cast<uint32_t>(data_len);
                send_ack  = true;
                cv_.notify_all();
            }
            if (fin) {
                rcv_nxt_++;
                state_   = State::CLOSE_WAIT;
                rx_eof_  = true;
                send_ack = true;
                cv_.notify_all();
            }
            break;

        case State::FIN_WAIT:
            if (fin) {
                rcv_nxt_++;
                state_   = State::CLOSED;
                send_ack = true;
                cv_.notify_all();
            }
            break;

        default:
            break;
        }
    }

    if (send_ack) send_segment(0x10);          /* ACK (called outside lock) */
}
