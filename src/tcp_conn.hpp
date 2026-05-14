#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/types.h>
#include <vector>
#include <deque>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

/* Minimal userspace TCP connection sent/received via the VPN tunnel's
   send_frame() / deliver() path.

   Implements the bits of TCP we actually need for a proxy bridge:
     - 3-way handshake / FIN teardown
     - Retransmit on RTO (exponential backoff, cap 32 s, give up after 6 tries)
     - Out-of-order receive buffer (drops reordered tunnel deliveries gracefully)
     - Amortised-O(1) rx_buf_ read using a read offset + periodic compaction

   Not implemented (still good enough for SOCKS5/HTTP proxy traffic):
     - Window/flow control (advertised window is fixed at 64 KB)
     - Congestion control (cwnd / slow start)
     - TIME_WAIT (closed ports are reused immediately)
     - Selective ACK

   Typical use:
     VpnTcpConn c;
     if (!c.connect(dst_ip_net, port)) ...error...;
     c.send(data, len);
     ssize_t n = c.recv(buf, sizeof(buf));
     c.close();
*/
class VpnTcpConn {
public:
    VpnTcpConn()  = default;
    ~VpnTcpConn() { close(); }

    VpnTcpConn(const VpnTcpConn &)            = delete;
    VpnTcpConn &operator=(const VpnTcpConn &) = delete;

    /* 3-way handshake through VPN tunnel.  Returns true on ESTABLISHED. */
    bool connect(uint32_t dst_ip_net, uint16_t dst_port,
                 int timeout_ms = 10000);

    /* Send data.  Returns false if connection is closed/broken. */
    bool send(const void *buf, size_t len);

    /* Receive data (blocks until available or EOF).
       Returns bytes written into buf, 0 on clean EOF, -1 on error. */
    ssize_t recv(void *buf, size_t len);

    /* Send FIN and mark connection closed (idempotent). */
    void close();

    uint16_t local_port()    const { return local_port_;    }
    uint32_t remote_ip_net() const { return remote_ip_net_; }

    /* Called by se_client's recv loop to deliver an inbound TCP segment.
       tcp_seg points to the TCP header; tcp_len = header + data length. */
    void deliver(const uint8_t *tcp_seg, size_t tcp_len, uint32_t src_ip_net);

private:
    enum class State { CLOSED, SYN_SENT, ESTABLISHED, CLOSE_WAIT, FIN_WAIT };

    /* Lower-level send: uses an explicit sequence number (used for retx). */
    void send_segment_seq(uint8_t flags, uint32_t seq,
                          const void *data, size_t len);
    /* Convenience: send_segment_seq(flags, snd_nxt_, data, len) */
    void send_segment(uint8_t flags,
                      const void *data = nullptr, size_t len = 0);

    /* Drain contiguous segments from oo_buf_ into rx_buf_. Caller holds mtx_. */
    void drain_reorder_();
    /* Background retransmit timer.  Loops until stop_retx_ is set. */
    void retx_loop_();

    static uint16_t alloc_local_port();

    uint32_t local_ip_net_  = 0;
    uint32_t remote_ip_net_ = 0;
    uint16_t local_port_    = 0;
    uint16_t remote_port_   = 0;
    uint32_t snd_nxt_       = 0;   /* next seq byte to send     */
    uint32_t snd_una_       = 0;   /* oldest unacked seq        */
    uint32_t rcv_nxt_       = 0;   /* next expected from remote */

    State state_ = State::CLOSED;

    std::mutex              mtx_;
    std::condition_variable cv_;

    /* RX buffer: amortised-O(1) reads via a read offset; compacted when
       half-empty so memory doesn't grow unbounded under steady use. */
    std::vector<uint8_t> rx_buf_;
    size_t               rx_read_pos_ = 0;

    /* Out-of-order RX: seq → segment payload.  Drained into rx_buf_ when
       the gap before them gets filled. */
    std::map<uint32_t, std::vector<uint8_t>> oo_buf_;
    size_t                                   oo_total_ = 0;
    static constexpr size_t OO_MAX = 256 * 1024;   /* bound memory */

    bool rx_eof_       = false;
    bool connect_done_ = false;
    bool connect_ok_   = false;

    /* Retransmit queue: segments sent but not yet ACKed. */
    struct RetxSeg {
        uint32_t                              seq;
        std::vector<uint8_t>                  data;
        std::chrono::steady_clock::time_point sent_at;
        int                                   retx_count = 0;
    };
    std::deque<RetxSeg> retx_q_;
    int                 rto_ms_     = 500;          /* RTO; doubles on loss */
    int                 dup_ack_n_  = 0;            /* fast-retransmit counter */
    uint32_t            last_ack_   = 0;            /* most recent ACK seen   */
    std::thread         retx_thread_;
    bool                stop_retx_  = false;
    /* Guards retx_thread_.join() so concurrent close() calls from
       bridge_rx and bridge_tx (and the destructor) can't all race onto
       join() simultaneously (UB on the same std::thread). */
    std::once_flag      retx_join_once_;
    /* Same idea for vpn_tcp_unregister(local_port_): must run exactly once
       across all the paths that mark a connection dead (close(), the retx-
       give-up branch, RST in deliver(), and the destructor).  Without this
       the entry in g_tcp_demux outlives the VpnTcpConn → UAF in the recv
       loop's tcp_demux_deliver. */
    std::once_flag      unregister_once_;

    static constexpr int RTO_INITIAL_MS = 500;      /* matches typical VPN RTT; avoids spurious retx */
    static constexpr int RTO_MAX_MS     = 32000;
    static constexpr int RETX_MAX_TRIES = 6;        /* ~ RTO * (1+2+4+8+16+32) */
    static constexpr int FAST_RETX_DUP  = 3;

    static constexpr size_t MSS = 1400;
};
