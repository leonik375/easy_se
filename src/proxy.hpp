#pragma once
#include <pthread.h>

/* Minimal HTTP-CONNECT + SOCKS5 TCP proxy.
   One detached thread per accepted connection; a stop-pipe wakes the listener.
   Outgoing connections are made through the VPN tunnel via VpnTcpConn —
   no kernel routing or SO_BINDTODEVICE required. */
class ProxyServer {
public:
    int  start(int port);   /* 0 → OS picks; returns actual port or -1 */
    void stop();
    int  port() const { return port_; }

private:
    int       port_      = 0;
    int       lfd_       = -1;
    int       pipe_[2]   = {-1, -1};
    bool      running_   = false;
    pthread_t tid_{};

    static void *listener_thread(void *);
    static void *handler_thread(void *);
};
