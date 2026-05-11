#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/types.h>
#include <vector>
#include <mutex>
#include <condition_variable>

/* Minimal userspace TCP connection sent/received via the VPN tunnel's
   send_frame() / deliver() path.  The tunnel runs over TLS (reliable,
   ordered) so we skip retransmission and congestion control.

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

    void             send_segment(uint8_t flags,
                                  const void *data = nullptr, size_t len = 0);
    static uint16_t  alloc_local_port();

    uint32_t local_ip_net_  = 0;
    uint32_t remote_ip_net_ = 0;
    uint16_t local_port_    = 0;
    uint16_t remote_port_   = 0;
    uint32_t snd_nxt_       = 0;   /* next seq byte to send     */
    uint32_t rcv_nxt_       = 0;   /* next expected from remote */

    State state_ = State::CLOSED;

    std::mutex              mtx_;
    std::condition_variable cv_;
    std::vector<uint8_t>    rx_buf_;
    bool rx_eof_       = false;
    bool connect_done_ = false;
    bool connect_ok_   = false;

    static constexpr size_t MSS = 1400;
};
