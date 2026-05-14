#include "proxy.hpp"
#include "tcp_conn.hpp"

#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

/* ── low-level I/O ───────────────────────────────────────────────────────── */

static bool recvn(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, static_cast<char *>(buf) + got, n - got, 0);
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

static bool sendn(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t s = send(fd, static_cast<const char *>(buf) + sent, n - sent,
                         MSG_NOSIGNAL);
        if (s <= 0) return false;
        sent += static_cast<size_t>(s);
    }
    return true;
}

/* ── connect to remote host through VPN tunnel ───────────────────────────── */

/* Each VpnTcpConn is bridged to a socketpair so that the rest of the proxy
   (handle_http, handle_socks5, relay) works unchanged with plain fds.

   Bridge threads:
     rx: conn.recv() → write(sv[1])   — VPN data arriving for the caller
     tx: read(sv[1]) → conn.send()    — caller data going out through VPN  */

struct BridgeCtx {
    std::shared_ptr<VpnTcpConn> conn;
    int sv1;
};

static void *bridge_rx(void *arg) {
    auto *b = static_cast<BridgeCtx *>(arg);
    char buf[4096];
    for (;;) {
        ssize_t n = b->conn->recv(buf, sizeof(buf));
        if (n <= 0) break;
        if (::write(b->sv1, buf, static_cast<size_t>(n)) <= 0) break;
    }
    b->conn->close();
    ::shutdown(b->sv1, SHUT_WR);
    delete b;
    return nullptr;
}

static void *bridge_tx(void *arg) {
    auto *b = static_cast<BridgeCtx *>(arg);
    char buf[4096];
    for (;;) {
        ssize_t n = ::read(b->sv1, buf, sizeof(buf));
        if (n <= 0) break;
        if (!b->conn->send(buf, static_cast<size_t>(n))) break;
    }
    b->conn->close();
    ::close(b->sv1);
    delete b;
    return nullptr;
}

static int dial(const char *host, int port) {
    /* Resolve hostname to IPv4 */
    char svc[8];
    snprintf(svc, sizeof(svc), "%d", port);
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, svc, &hints, &res) != 0) return -1;
    uint32_t dst_ip = reinterpret_cast<struct sockaddr_in *>(res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    /* Open userspace TCP connection through the VPN tunnel */
    auto conn = std::make_shared<VpnTcpConn>();
    if (!conn->connect(dst_ip, static_cast<uint16_t>(port))) return -1;

    /* Bridge conn to a socketpair so callers use normal fd I/O */
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        conn->close(); return -1;
    }

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, bridge_rx, new BridgeCtx{conn, sv[1]});
    pthread_create(&t, &attr, bridge_tx, new BridgeCtx{conn, sv[1]});
    pthread_attr_destroy(&attr);

    return sv[0];
}

/* ── bidirectional relay ─────────────────────────────────────────────────── */

static void relay(int a, int b) {
    char buf[8192];
    struct pollfd fds[2] = {
        {a, POLLIN | POLLHUP, 0},
        {b, POLLIN | POLLHUP, 0},
    };
    for (;;) {
        if (poll(fds, 2, -1) < 0) break;
        for (int i = 0; i < 2; ++i) {
            if (fds[i].revents & (POLLHUP | POLLERR)) goto done;
            if (!(fds[i].revents & POLLIN)) continue;
            ssize_t n = recv(fds[i].fd, buf, sizeof(buf), 0);
            if (n <= 0) goto done;
            if (!sendn(fds[1 - i].fd, buf, static_cast<size_t>(n))) goto done;
        }
    }
done:;
}

/* ── HTTP proxy (CONNECT tunnel + plain GET/POST forwarding) ─────────────── */

/* Parse "scheme://host[:port]/path" → host, port, path.
   Returns false if the URL isn't absolute (caller falls back to Host header). */
static bool parse_abs_url(const std::string &url,
                           std::string &host, int &port, std::string &path)
{
    size_t scheme = url.find("://");
    if (scheme == std::string::npos) return false;
    std::string rest = url.substr(scheme + 3);
    size_t slash = rest.find('/');
    std::string authority = (slash != std::string::npos) ? rest.substr(0, slash) : rest;
    path = (slash != std::string::npos) ? rest.substr(slash) : "/";
    size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        try { port = std::stoi(authority.substr(colon + 1)); } catch (...) { return false; }
    } else {
        host = authority;
        port = 80;
    }
    return true;
}

/* Strip hop-by-hop proxy headers from the accumulated header block. */
static std::string strip_proxy_headers(const std::string &hdrs) {
    std::string out;
    out.reserve(hdrs.size());
    size_t pos = 0;
    while (pos < hdrs.size()) {
        size_t eol = hdrs.find("\r\n", pos);
        if (eol == std::string::npos) { out += hdrs.substr(pos); break; }
        std::string line = hdrs.substr(pos, eol - pos);
        pos = eol + 2;
        // drop proxy-specific headers
        auto lc = line;
        for (char &c : lc) c = static_cast<char>(tolower(c));
        if (lc.compare(0, 17, "proxy-connection:") == 0) continue;
        if (lc.compare(0, 19, "proxy-authorization:") == 0) continue;
        out += line; out += "\r\n";
    }
    return out;
}

static void handle_http(int fd, const char *initial, int initial_len) {
    // Accumulate headers until \r\n\r\n
    std::string hdrs(initial, initial_len);
    char tmp[4096];
    while (hdrs.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) return;
        hdrs.append(tmp, static_cast<size_t>(n));
        if (hdrs.size() > 65536) return;
    }

    // Parse request line: METHOD SP target SP HTTP/x.y CRLF
    size_t sp1 = hdrs.find(' ');
    if (sp1 == std::string::npos) return;
    size_t sp2 = hdrs.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return;

    std::string method = hdrs.substr(0, sp1);
    std::string target = hdrs.substr(sp1 + 1, sp2 - sp1 - 1);
    // everything from sp2 to end of headers (includes " HTTP/1.1\r\n…\r\n\r\n")
    std::string tail   = hdrs.substr(sp2);

    /* ── CONNECT tunnel ── */
    if (method == "CONNECT") {
        size_t colon = target.rfind(':');
        if (colon == std::string::npos) return;
        std::string host = target.substr(0, colon);
        int port = 0;
        try { port = std::stoi(target.substr(colon + 1)); } catch (...) { return; }

        int dst = dial(host.c_str(), port);
        if (dst < 0) {
            const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            sendn(fd, err, strlen(err));
            return;
        }
        const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
        sendn(fd, ok, strlen(ok));
        relay(fd, dst);
        ::close(dst);
        return;
    }

    /* ── Plain HTTP forwarding (GET, POST, …) ── */
    std::string host, path;
    int port = 80;
    if (!parse_abs_url(target, host, port, path)) {
        // Relative URL — extract host from Host header
        auto hpos = hdrs.find("\r\nHost:");
        if (hpos == std::string::npos) hpos = hdrs.find("\r\nhost:");
        if (hpos == std::string::npos) return;
        hpos += 7;
        // skip optional space
        while (hpos < hdrs.size() && hdrs[hpos] == ' ') ++hpos;
        size_t hend = hdrs.find("\r\n", hpos);
        std::string authority = hdrs.substr(hpos, hend - hpos);
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            host = authority.substr(0, colon);
            try { port = std::stoi(authority.substr(colon + 1)); } catch (...) { return; }
        } else {
            host = authority;
        }
        path = target;
    }

    int dst = dial(host.c_str(), port);
    if (dst < 0) {
        const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        sendn(fd, err, strlen(err));
        return;
    }

    // Rewrite request: use relative path, strip proxy headers
    std::string req = method + " " + path + strip_proxy_headers(tail);
    sendn(dst, req.c_str(), req.size());
    relay(fd, dst);
    ::close(dst);
}

/* ── SOCKS5 ───────────────────────────────────────────────────────────────── */

static void handle_socks5(int fd) {
    uint8_t buf[512];

    // Greeting: VER(1) NMETHODS(1) METHODS(n)
    if (!recvn(fd, buf, 2) || buf[0] != 5) return;
    uint8_t nmethods = buf[1];
    if (!recvn(fd, buf, nmethods)) return;

    // Pick no-auth (0) if offered; accept user/pass (2) as fallback and skip auth
    uint8_t chosen = 0xFF;
    for (int i = 0; i < nmethods; ++i) {
        if (buf[i] == 0) { chosen = 0; break; }
        if (buf[i] == 2) chosen = 2;
    }
    const uint8_t sel[2] = {5, chosen};
    if (!sendn(fd, sel, 2)) return;
    if (chosen == 0xFF) return;

    if (chosen == 2) {
        // Sub-negotiation: VER(1) ULEN(1) UNAME(n) PLEN(1) PASSWD(m)
        if (!recvn(fd, buf, 2) || buf[0] != 1) return;
        uint8_t ulen = buf[1];
        if (!recvn(fd, buf, ulen)) return;
        if (!recvn(fd, buf, 1)) return;
        uint8_t plen = buf[0];
        if (!recvn(fd, buf, plen)) return;
        const uint8_t auth_ok[2] = {1, 0};
        if (!sendn(fd, auth_ok, 2)) return;
    }

    // Request: VER(1) CMD(1) RSV(1) ATYP(1)
    if (!recvn(fd, buf, 4) || buf[0] != 5) return;
    uint8_t cmd  = buf[1];
    uint8_t atyp = buf[3];
    if (cmd != 1) return;   // only CONNECT supported

    char host[256]; int port = 0;
    if (atyp == 0x01) {                 // IPv4
        uint8_t ip4[4];
        if (!recvn(fd, ip4, 4)) return;
        snprintf(host, sizeof(host), "%d.%d.%d.%d",
                 ip4[0], ip4[1], ip4[2], ip4[3]);
    } else if (atyp == 0x03) {          // DOMAINNAME
        uint8_t len;
        if (!recvn(fd, &len, 1)) return;
        if (!recvn(fd, host, len)) return;
        host[len] = '\0';
    } else if (atyp == 0x04) {          // IPv6
        uint8_t ip6[16];
        if (!recvn(fd, ip6, 16)) return;
        inet_ntop(AF_INET6, ip6, host, sizeof(host));
    } else return;

    uint8_t portbuf[2];
    if (!recvn(fd, portbuf, 2)) return;
    port = (portbuf[0] << 8) | portbuf[1];

    int dst = dial(host, port);

    // Reply: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    uint8_t rep[10] = {5, static_cast<uint8_t>(dst < 0 ? 5 : 0),
                       0, 1, 0, 0, 0, 0, 0, 0};
    sendn(fd, rep, 10);
    if (dst < 0) return;

    relay(fd, dst);
    ::close(dst);
}

/* ── per-connection handler thread ─────────────────────────────────────────── */

void *ProxyServer::handler_thread(void *arg) {
    int fd = static_cast<int>(reinterpret_cast<intptr_t>(arg));

    uint8_t first;
    if (recv(fd, &first, 1, MSG_PEEK) == 1) {
        if (first == 0x05) {
            handle_socks5(fd);
        } else {
            char buf[2048];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n > 0) handle_http(fd, buf, static_cast<int>(n));
        }
    }

    ::close(fd);
    return nullptr;
}

/* ── listener thread ─────────────────────────────────────────────────────── */

void *ProxyServer::listener_thread(void *arg) {
    auto *self = static_cast<ProxyServer *>(arg);
    struct pollfd fds[2] = {
        {self->lfd_,     POLLIN, 0},
        {self->pipe_[0], POLLIN, 0},
    };
    for (;;) {
        if (poll(fds, 2, -1) < 0) break;
        if (fds[1].revents & POLLIN) break;             // stop signal
        if (!(fds[0].revents & POLLIN)) continue;
        int cfd = ::accept(self->lfd_, nullptr, nullptr);
        if (cfd < 0) break;
        pthread_t t;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&t, &attr, handler_thread,
                       reinterpret_cast<void *>(static_cast<intptr_t>(cfd)));
        pthread_attr_destroy(&attr);
    }
    return nullptr;
}

/* ── public API ──────────────────────────────────────────────────────────── */

int ProxyServer::start(int port) {
    if (running_) return port_;

    /* Defensive: ignore SIGPIPE for callers (CLI / JNI / library users)
       that forgot.  The bridge threads do plain ::write(socketpair, …)
       which delivers SIGPIPE on a closed peer — default disposition is
       process termination with exit code 141 and no output. */
    struct sigaction sigact{};
    sigaction(SIGPIPE, nullptr, &sigact);
    if (sigact.sa_handler != SIG_IGN) {
        sigact.sa_handler = SIG_IGN;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction(SIGPIPE, &sigact, nullptr);
    }

    if (::pipe(pipe_) != 0) return -1;

    lfd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (lfd_ < 0) { ::close(pipe_[0]); ::close(pipe_[1]); return -1; }

    int one = 1;
    setsockopt(lfd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa{};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = htons(static_cast<uint16_t>(port));

    if (::bind(lfd_, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) != 0 ||
        ::listen(lfd_, 32) != 0) {
        ::close(lfd_); lfd_ = -1;
        ::close(pipe_[0]); ::close(pipe_[1]);
        return -1;
    }

    socklen_t slen = sizeof(sa);
    ::getsockname(lfd_, reinterpret_cast<struct sockaddr *>(&sa), &slen);
    port_ = ntohs(sa.sin_port);

    if (pthread_create(&tid_, nullptr, listener_thread, this) != 0) {
        ::close(lfd_); lfd_ = -1;
        ::close(pipe_[0]); ::close(pipe_[1]);
        port_ = 0; return -1;
    }
    running_ = true;
    return port_;
}

void ProxyServer::stop() {
    if (!running_) return;
    char b = 1; ::write(pipe_[1], &b, 1);
    pthread_join(tid_, nullptr);
    ::close(lfd_);     lfd_     = -1;
    ::close(pipe_[0]); ::close(pipe_[1]);
    pipe_[0] = pipe_[1] = -1;
    running_ = false;
    port_    = 0;
}
