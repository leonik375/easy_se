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

void VpnTcpConn::send_segment_seq(uint8_t flags, uint32_t seq,
                                  const void *data, size_t dlen) {
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

    tcp[4] = seq >> 24; tcp[5] = (seq >> 16) & 0xff;
    tcp[6] = (seq >>  8) & 0xff; tcp[7] = seq & 0xff;

    uint32_t ack_val = (flags & 0x10) ? rcv_nxt_ : 0;
    tcp[8]  = ack_val >> 24; tcp[9]  = (ack_val >> 16) & 0xff;
    tcp[10] = (ack_val >>  8) & 0xff; tcp[11] = ack_val & 0xff;

    tcp[12] = 0x50;                            /* data offset = 5 (20 bytes) */
    tcp[13] = flags;
    /* Advertise our remaining receive-buffer capacity (no window scaling). */
    tcp[14] = static_cast<uint8_t>(rcv_wnd_ >> 8);
    tcp[15] = static_cast<uint8_t>(rcv_wnd_ & 0xff);

    if (dlen) memcpy(tcp + TCP_HDR, data, dlen);

    size_t tcp_seg_len = TCP_HDR + dlen;
    uint16_t tck = tcp_cksum(local_ip_net_, remote_ip_net_, tcp, tcp_seg_len);
    tcp[16] = tck >> 8; tcp[17] = tck & 0xff;

    vpn_send_frame(f, frame_sz);
}

void VpnTcpConn::send_segment(uint8_t flags, const void *data, size_t dlen) {
    send_segment_seq(flags, snd_nxt_, data, dlen);
}

/* Drain reorder buffer entries that are now contiguous with rcv_nxt_.
   Caller holds mtx_. */
void VpnTcpConn::drain_reorder_() {
    auto it = oo_buf_.find(rcv_nxt_);
    while (it != oo_buf_.end()) {
        rx_buf_.insert(rx_buf_.end(), it->second.begin(), it->second.end());
        rcv_nxt_  += static_cast<uint32_t>(it->second.size());
        oo_total_ -= it->second.size();
        oo_buf_.erase(it);
        it = oo_buf_.find(rcv_nxt_);
    }
}

/* Recompute the advertised receive window from current rx_buf_ usage.
   Caller holds mtx_. */
static inline uint16_t calc_rcv_wnd(size_t buffered) {
    constexpr size_t MAX = VpnTcpConn::RX_MAX_BUF;
    if (buffered >= MAX) return 0;
    size_t free_bytes = MAX - buffered;
    return static_cast<uint16_t>(std::min<size_t>(65535, free_bytes));
}

/* Retransmit loop.  Sleeps until either the head retx segment's RTO expires
   or someone notifies (new send, ACK received, or shutdown). */
void VpnTcpConn::retx_loop_() {
    std::unique_lock<std::mutex> lk(mtx_);
    while (!stop_retx_) {
        if (retx_q_.empty() || state_ != State::ESTABLISHED) {
            cv_.wait(lk, [this] {
                return stop_retx_ ||
                       (!retx_q_.empty() && state_ == State::ESTABLISHED);
            });
            continue;
        }

        auto deadline = retx_q_.front().sent_at +
                        std::chrono::milliseconds(rto_ms_);
        auto status   = cv_.wait_until(lk, deadline);

        if (stop_retx_) break;
        if (status != std::cv_status::timeout) continue;   /* spurious / ACK */
        if (retx_q_.empty()) continue;
        if (state_ != State::ESTABLISHED) continue;

        auto now = std::chrono::steady_clock::now();
        if (now < retx_q_.front().sent_at +
                  std::chrono::milliseconds(rto_ms_))
            continue;

        /* RTO fired — retransmit head segment.  Give up after RETX_MAX_TRIES. */
        auto &head = retx_q_.front();
        if (head.retx_count >= RETX_MAX_TRIES) {
            DBG("[tcp] retx give-up after %d tries; closing\n", head.retx_count);
            state_  = State::CLOSED;
            rx_eof_ = true;
            cv_.notify_all();
            break;
        }
        head.sent_at = now;
        head.retx_count++;
        rto_ms_ = std::min(rto_ms_ * 2, RTO_MAX_MS);   /* exponential backoff */
        uint32_t seq    = head.seq;
        size_t   dlen   = head.data.size();
        std::vector<uint8_t> data = head.data;          /* copy under lock */
        lk.unlock();
        send_segment_seq(0x18, seq, data.data(), dlen); /* PSH+ACK */
        lk.lock();
    }
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
    snd_una_ = snd_nxt_;

    struct in_addr da; da.s_addr = dst_ip_net;
    DBG("[tcp] connect %s:%u src_ip=%08x local_port=%u\n",
        inet_ntoa(da), dst_port, local_ip_net_, local_port_);

    /* Trigger ARP for the gateway so the recv loop can process the reply and
       populate the cache while we wait for SYN-ACK.  We re-send the SYN every
       200 ms; by the second attempt the ARP reply will have been processed and
       the SYN will reach SecureNAT as a unicast frame (broadcast is ignored). */
    uint32_t gw = vpn_gateway_ip_net();
    vpn_probe_arp(gw, 0); /* fire-and-forget: kick the ARP request, don't block */

    state_ = State::SYN_SENT;
    /* Register a weak_ptr so the recv loop can hold the conn alive
       during deliver() without keeping the demux mutex. */
    vpn_tcp_register(local_port_, shared_from_this());

    send_segment(0x02);  /* SYN — counts as one sequence byte */
    snd_nxt_++;
    uint32_t isn = snd_nxt_ - 1; /* save ISN for retransmits */

    std::unique_lock<std::mutex> lk(mtx_);
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);
    int syn_rto = RTO_INITIAL_MS;
    while (!connect_done_) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        auto wait = std::min(std::chrono::milliseconds(syn_rto),
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 deadline - now));
        cv_.wait_for(lk, wait, [this] { return connect_done_; });
        if (connect_done_ || std::chrono::steady_clock::now() >= deadline) break;
        if (state_ != State::SYN_SENT) break;
        /* Retransmit SYN with exponential backoff. */
        DBG("[tcp] retransmit SYN → %s:%u (rto=%dms)\n",
            inet_ntoa(da), dst_port, syn_rto);
        lk.unlock();
        send_segment_seq(0x02, isn, nullptr, 0);
        lk.lock();
        syn_rto = std::min(syn_rto * 2, RTO_MAX_MS);
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
    snd_una_  = snd_nxt_;
    last_ack_ = snd_nxt_;
    lk.unlock();
    /* Start retransmit timer thread now that the connection is established.
       Spawned outside the lock to avoid retx_loop_() racing onto a held mtx_. */
    stop_retx_ = false;
    retx_thread_ = std::thread([this] { retx_loop_(); });
    DBG("[tcp] connect %s:%u established\n", inet_ntoa(da), dst_port);
    return true;
}

/* ── send ────────────────────────────────────────────────────────────────── */

bool VpnTcpConn::send(const void *buf, size_t len) {
    const auto *p = static_cast<const uint8_t *>(buf);
    while (len > 0) {
        std::unique_lock<std::mutex> lk(mtx_);
        if (state_ != State::ESTABLISHED) return false;

        /* Wait until the peer's advertised window has room for at least
           one byte.  Without this we kept stuffing packets through a
           full peer buffer → server drops → we retransmit → loop;
           catastrophic upload throughput and unbounded retx_q_ growth
           (the source of the 360 MB resident memory). */
        cv_.wait(lk, [this] {
            return state_ != State::ESTABLISHED ||
                   (snd_nxt_ - snd_una_) < snd_wnd_;
        });
        if (state_ != State::ESTABLISHED) return false;

        uint32_t in_flight = snd_nxt_ - snd_una_;
        uint32_t avail     = (snd_wnd_ > in_flight) ? snd_wnd_ - in_flight : 0;
        size_t   chunk     = std::min(len, MSS);
        if (chunk > avail) chunk = avail;

        uint32_t seq = snd_nxt_;
        std::vector<uint8_t> data(p, p + chunk);

        send_segment_seq(0x18, seq, data.data(), chunk); /* PSH+ACK */
        snd_nxt_ += static_cast<uint32_t>(chunk);

        bool was_empty = retx_q_.empty();
        retx_q_.push_back({seq, std::move(data),
                          std::chrono::steady_clock::now(), 0});
        if (was_empty) cv_.notify_one();

        lk.unlock();
        p   += chunk;
        len -= chunk;
    }
    return true;
}

/* ── recv ────────────────────────────────────────────────────────────────── */

ssize_t VpnTcpConn::recv(void *buf, size_t len) {
    bool send_window_update = false;
    ssize_t out;
    {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait(lk, [this] {
            return rx_read_pos_ < rx_buf_.size() || rx_eof_;
        });
        size_t avail = rx_buf_.size() - rx_read_pos_;
        if (avail == 0) return 0;              /* EOF */
        size_t n = std::min(len, avail);
        memcpy(buf, rx_buf_.data() + rx_read_pos_, n);
        rx_read_pos_ += n;
        /* Compact when more than half the buffer is consumed — keeps memory
           bounded without doing it on every read (O(amortised 1)). */
        if (rx_read_pos_ > 0 && rx_read_pos_ >= rx_buf_.size() / 2) {
            rx_buf_.erase(rx_buf_.begin(),
                          rx_buf_.begin() + static_cast<ptrdiff_t>(rx_read_pos_));
            rx_read_pos_ = 0;
        }
        uint16_t old_wnd = rcv_wnd_;
        rcv_wnd_ = calc_rcv_wnd(rx_buf_.size() - rx_read_pos_ + oo_total_);
        /* If the peer was stalled at our zero-window, send an explicit
           window-update ACK so it doesn't sit on a persist timer. */
        if (old_wnd == 0 && rcv_wnd_ > 0) send_window_update = true;
        out = static_cast<ssize_t>(n);
    }
    if (send_window_update) send_segment(0x10);   /* ACK with new window */
    return out;
}

/* ── close ───────────────────────────────────────────────────────────────── */

/* Idempotent and safe under concurrent callers (proxy bridge_rx and
   bridge_tx both call close() when their side of the conn drains).
   Critical: we MUST always join the retx thread before VpnTcpConn is
   destroyed, even if state_ is already CLOSED — otherwise the std::thread
   member destructor finds it joinable and calls std::terminate(). */
void VpnTcpConn::close() {
    bool should_fin = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == State::ESTABLISHED || state_ == State::CLOSE_WAIT)
            should_fin = true;
        state_     = State::CLOSED;
        rx_eof_    = true;
        stop_retx_ = true;
        cv_.notify_all();
    }
    if (should_fin) send_segment(0x11);            /* FIN + ACK */
    /* Join exactly once across all close() callers.  call_once parks any
       second caller until the first finishes, so neither winds up with a
       half-joined std::thread. */
    std::call_once(retx_join_once_, [this] {
        if (retx_thread_.joinable()) retx_thread_.join();
    });
    /* Unregister exactly once.  Critical: retx_loop_'s give-up branch and
       deliver()'s RST handler set state_=CLOSED without going through this
       path; if we conditionally skipped the unregister "because state_ is
       already CLOSED", g_tcp_demux would keep a dangling pointer after
       the VpnTcpConn is freed → UAF when the recv loop dereferences it. */
    std::call_once(unregister_once_, [this] {
        if (local_port_) vpn_tcp_unregister(local_port_);
    });
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
    uint32_t ack = (static_cast<uint32_t>(tcp[8])  << 24)
                 | (static_cast<uint32_t>(tcp[9])  << 16)
                 | (static_cast<uint32_t>(tcp[10]) <<  8)
                 |  static_cast<uint32_t>(tcp[11]);

    size_t hdr_len = (tcp[12] >> 4) * 4u;
    if (hdr_len < TCP_HDR || hdr_len > tcp_len) return;

    const uint8_t *data     = tcp + hdr_len;
    size_t         data_len = tcp_len - hdr_len;

    uint8_t flags   = tcp[13];
    bool rst      = flags & 0x04;
    bool syn      = flags & 0x02;
    bool fin      = flags & 0x01;
    bool ack_flag = flags & 0x10;

    /* Peer's advertised receive window (no window-scaling option). */
    uint16_t peer_wnd = (static_cast<uint16_t>(tcp[14]) << 8) | tcp[15];

    bool send_ack             = false;
    bool fast_retx            = false;
    uint32_t fast_retx_seq    = 0;
    std::vector<uint8_t> fast_retx_data;

    {
        std::lock_guard<std::mutex> lk(mtx_);

        if (rst) {
            state_        = State::CLOSED;
            rx_eof_       = true;
            connect_done_ = true;
            connect_ok_   = false;
            stop_retx_    = true;
            cv_.notify_all();
            return;
        }

        /* Update send window from every inbound segment (ACK or not).
           Wakes any send() blocked on a previously-full window. */
        {
            uint32_t old_wnd = snd_wnd_;
            snd_wnd_ = peer_wnd;
            if (snd_wnd_ > old_wnd) cv_.notify_all();
        }

        /* Process ACK: drop ACKed segments from retx_q_, detect dup ACKs
           for fast retransmit, reset RTO when forward progress made. */
        if (ack_flag && state_ == State::ESTABLISHED) {
            if (static_cast<int32_t>(ack - snd_una_) > 0) {
                /* New ACK — advance snd_una_, drop fully-ACKed segments. */
                snd_una_ = ack;
                while (!retx_q_.empty() &&
                       static_cast<int32_t>(
                           ack - (retx_q_.front().seq +
                                  retx_q_.front().data.size())) >= 0) {
                    retx_q_.pop_front();
                }
                rto_ms_     = RTO_INITIAL_MS;     /* reset on progress */
                dup_ack_n_  = 0;
                last_ack_   = ack;
                cv_.notify_all();
            } else if (ack == last_ack_ && !retx_q_.empty()) {
                /* Duplicate ACK — peer is stuck waiting for missing seq.
                   On the 3rd dup ACK, fast-retransmit the head segment
                   without waiting for the RTO. */
                dup_ack_n_++;
                if (dup_ack_n_ == FAST_RETX_DUP) {
                    fast_retx       = true;
                    fast_retx_seq   = retx_q_.front().seq;
                    fast_retx_data  = retx_q_.front().data;
                    retx_q_.front().sent_at = std::chrono::steady_clock::now();
                    DBG("[tcp] fast-retransmit seq=%u after %d dup ACKs\n",
                        fast_retx_seq, dup_ack_n_);
                }
            }
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
            if (data_len > 0) {
                int32_t off = static_cast<int32_t>(seq - rcv_nxt_);
                size_t  buffered = rx_buf_.size() - rx_read_pos_;
                if (off == 0) {
                    /* In-order: refuse if it would exceed RX_MAX_BUF
                       (caps unbounded rx_buf_ growth → 1.5 GB RES leak).
                       Peer will retransmit when our window re-opens. */
                    if (buffered + data_len <= RX_MAX_BUF) {
                        rx_buf_.insert(rx_buf_.end(), data, data + data_len);
                        rcv_nxt_ += static_cast<uint32_t>(data_len);
                        drain_reorder_();
                        cv_.notify_all();
                    }
                    rcv_wnd_ = calc_rcv_wnd(rx_buf_.size() - rx_read_pos_);
                    send_ack = true;
                } else if (off > 0 && oo_total_ + data_len <= OO_MAX &&
                           buffered + oo_total_ + data_len <= RX_MAX_BUF) {
                    /* Out-of-order: buffer it.  Send a dup ACK on rcv_nxt_
                       so the sender knows about the gap. */
                    if (oo_buf_.find(seq) == oo_buf_.end()) {
                        oo_buf_.emplace(seq,
                            std::vector<uint8_t>(data, data + data_len));
                        oo_total_ += data_len;
                    }
                    rcv_wnd_ = calc_rcv_wnd(buffered + oo_total_);
                    send_ack = true;
                } else if (off < 0) {
                    /* Duplicate (already received) — re-ACK to advance peer. */
                    send_ack = true;
                }
                /* else: gap too large for our reorder buffer; drop & dup-ACK */
            }
            if (fin) {
                /* Only honour FIN if it's at the current rcv_nxt_ (no gaps). */
                if (seq + data_len == rcv_nxt_) {
                    rcv_nxt_++;
                    state_   = State::CLOSE_WAIT;
                    rx_eof_  = true;
                    send_ack = true;
                    cv_.notify_all();
                }
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

    if (fast_retx)
        send_segment_seq(0x18, fast_retx_seq,
                         fast_retx_data.data(), fast_retx_data.size());
    if (send_ack) send_segment(0x10);          /* ACK (called outside lock) */
}
