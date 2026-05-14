#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <atomic>

struct IpInfo {
    std::string ip, gw, dns;
    int         prefix = 0;
    uint8_t     our_mac[6]{};
    uint8_t     gw_mac[6]{};
    uint32_t    our_ip_net = 0; /* our_ip in network byte order */
};

class Tunnel {
public:
    Tunnel()  = default;
    ~Tunnel() { close(); }

    Tunnel(const Tunnel &)            = delete;
    Tunnel &operator=(const Tunnel &) = delete;

    /* Phase 1: TLS connect.
       verify_cert: when true, validate the peer cert against ca_path (a dir
       of hash-named PEMs, a PEM bundle file, or empty → OpenSSL defaults)
       and match the cert's hostname against `host`. */
    bool connect(const std::string &host, int port,
                 bool verify_cert = true,
                 const std::string &ca_path = "");

    /* Phase 2: send watermark, receive server random[20] */
    bool handshake();

    /* Phase 3: send auth PACK, receive welcome PACK.
       authtype: 1=SE_AUTH_PASSWORD (hashed, local only)
                 2=SE_AUTH_PLAIN_PASSWORD (plaintext, local + RADIUS) */
    bool authenticate(const std::string &hub,
                      const std::string &user,
                      const std::string &pass,
                      int authtype = 1);

    /* Phase 4: DHCP probe — discover IP assignment through SE tunnel.
       Runs after authenticate(); blocks up to timeout_sec. */
    std::optional<IpInfo> dhcp_probe(int timeout_sec = 30);

    /* Tunnel packet I/O (after dhcp_probe succeeds).
       send_frame: eth is a full Ethernet frame (14-byte header + IP payload).
       recv_frame: fills buf with a full Ethernet frame; returns bytes read,
                   0 for keepalive/zero-size block, -1 on error. */
    bool send_frame(const uint8_t *eth, size_t len);
    int  recv_frame(uint8_t *buf, size_t buflen);

    /* Send a zero-size keepalive block. */
    bool send_keepalive();

    /* UDP acceleration — sends frame via UDP if active and server has replied at
       least once (udp_ready); otherwise falls back to the TCP/SSL path. */
    bool send_udp_frame(const uint8_t *eth, size_t len);

    /* Receive next data frame from UDP (preferred when active) or TCP.
       Returns frame byte count, 0 for keepalive/timeout, -1 on fatal error. */
    int  recv_frame_any(uint8_t *buf, size_t buflen);

    bool udp_active() const { return udp_active_; }

    /* Interrupt all blocking I/O (shutdown TCP socket, close UDP socket)
       without freeing SSL objects.  Safe to call from any thread or signal
       handler.  Must be followed by close() once all threads have exited. */
    void interrupt();

    void close();

    const uint8_t *our_mac() const { return our_mac_; }
    const uint8_t *gw_mac()  const { return gw_mac_;  }
    uint32_t       our_ip()   const { return our_ip_;  } /* network byte order */
    int            tcp_fd()   const { return fd_;      }
    int            udp_fd()   const { return udp_fd_;  }

private:
    SSL_CTX *ctx_  = nullptr;
    SSL     *ssl_  = nullptr;
    int      fd_   = -1;

    std::string host_;
    uint8_t  server_random_[20]{};
    uint8_t  our_mac_[6]{};
    uint8_t  gw_mac_[6]{};
    uint32_t our_ip_ = 0;

    /* UDP acceleration (V1: RC4 + SHA-1 per-packet key derivation) */
    int      udp_fd_             = -1;
    bool     udp_active_         = false;
    std::atomic<bool> udp_ready_{false}; /* true after first UDP pkt received */
    bool     udp_plain_text_     = false;
    uint32_t udp_my_cookie_      = 0;
    uint32_t udp_your_cookie_    = 0;
    uint8_t  udp_my_key_[20]     {};  /* encrypts our outbound packets */
    uint8_t  udp_your_key_[20]   {};  /* decrypts server's inbound packets */
    uint8_t  udp_next_iv_[20]    {};  /* rolling IV for outbound */
    uint64_t udp_now_ms_         = 0;
    uint64_t udp_last_peer_tick_ = 0;
    struct   sockaddr_in udp_peer_{};

    /* Returns frame size, 0 on timeout/keepalive, -1 on error.
       timeout_ms == 0 → non-blocking. */
    int recv_udp_frame_(uint8_t *buf, size_t buflen, int timeout_ms);

    /* Serialises all SSL writes: concurrent send_frame / send_keepalive calls
       from tun_reader, proxy handler, and main recv-loop threads are safe. */
    std::mutex send_mutex_;

    /* Remaining frames in the current Cedar batch (may be > 1). */
    uint32_t pending_blocks_ = 0;

    /* ── Batched TX path ────────────────────────────────────────────────
       send_frame() enqueues an Ethernet frame and returns immediately.
       A single tx_thread_ drains the queue, packs up to MAX_BATCH frames
       into one Cedar block (num_blocks > 1) and writes them with one
       SSL_write — amortising TLS-record/MAC overhead across many small
       VPN packets.  Without batching, each small frame (84-200 B) was
       its own SSL_write → throughput cliff on bulk proxy traffic. */
    std::mutex                       tx_mutex_;
    std::condition_variable          tx_cv_;
    std::deque<std::vector<uint8_t>> tx_queue_;
    std::thread                      tx_thread_;
    bool                             tx_stop_  = false;
    std::atomic<bool>                tx_dead_{false};
    static constexpr size_t          TX_MAX_BATCH      = 32;
    static constexpr size_t          TX_MAX_BATCH_BYTES = 16 * 1024;
    void tx_loop_();

    /* Low-level SSL I/O */
    bool ssl_writen(const void *buf, size_t n);
    bool ssl_readn (void *buf, size_t n);

    /* HTTP helpers: both use the same persistent TLS connection */
    bool http_post(const char *url, const char *content_type,
                   const uint8_t *body, size_t body_len);
    /* Returns body bytes; empty on error. */
    std::vector<uint8_t> http_recv_body();

    /* PACK over HTTP (the SE "HttpClientSend/HttpClientRecv" pattern) */
    bool pack_send(const class Pack &p);
    std::optional<class Pack> pack_recv();

    /* DHCP probe internals */
    void dhcp_send_discover();
    void dhcp_send_request(uint32_t offered_ip_host, uint32_t server_ip_host);
    void dhcp_send_arp_reply(const uint8_t *request, size_t len);
};
