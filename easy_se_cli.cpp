/* easy_se_cli.cpp — Linux CLI for the easy_se library.
 *
 * Usage (as root or with CAP_NET_ADMIN):
 *   ./easy_se <host> <port> <hub> <user> <pass> [options]
 *
 * Options:
 *   --radius        use plaintext auth (local + RADIUS)
 *   --debug         verbose easy_se logging
 *   --default-gw    add default route through VPN (+ protect server route)
 *   --proxy [port]  start HTTP/SOCKS5 proxy (default port 1080, 0=auto)
 *
 * What it does:
 *   1. se_connect() — TLS, handshake, auth, DHCP probe
 *   2. Prints the assigned IP info
 *   3. Opens a Linux TUN device (sevpn0)
 *   4. Configures the interface; optionally sets default route
 *   5. Optionally starts the built-in proxy
 *   6. se_run() — forwards packets until Ctrl-C
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include "easy_se.h"

static int g_tun_fd = -1;

static void on_signal(int) {
    printf("\nDisconnecting…\n");
    se_disconnect();
}

static int tun_open(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    printf("TUN device: %s\n", ifr.ifr_name);
    return fd;
}

/* ── interface helpers (ioctl) ───────────────────────────────────────── */

static bool net_if_up(const char *ifname, const char *ip4, int prefix) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return false; }

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    auto *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;

    inet_pton(AF_INET, ip4, &sin->sin_addr);
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0)    { perror("SIOCSIFADDR");    close(s); return false; }

    sin->sin_addr.s_addr = htonl(prefix ? (~0u << (32 - prefix)) : 0u);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) { perror("SIOCSIFNETMASK"); close(s); return false; }

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)   { perror("SIOCGIFFLAGS");   close(s); return false; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)   { perror("SIOCSIFFLAGS");   close(s); return false; }

    close(s);
    return true;
}

static void net_if_down(const char *ifname) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags &= static_cast<short>(~IFF_UP);
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
}

/* ── rtnetlink route helpers ─────────────────────────────────────────── */

static void rta_add(struct nlmsghdr *nlh, int type, const void *data, int dlen) {
    auto *rta = reinterpret_cast<struct rtattr *>(
        reinterpret_cast<char *>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = RTA_LENGTH(dlen);
    if (dlen) memcpy(RTA_DATA(rta), data, dlen);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static bool nl_transact(struct nlmsghdr *nlh) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) { perror("netlink socket"); return false; }
    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    bind(s, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_flags |= NLM_F_ACK;
    send(s, nlh, nlh->nlmsg_len, 0);
    char buf[4096];
    ssize_t n = recv(s, buf, sizeof(buf), 0);
    close(s);
    if (n <= 0) return false;
    for (auto *r = reinterpret_cast<struct nlmsghdr *>(buf);
         NLMSG_OK(r, static_cast<int>(n)); r = NLMSG_NEXT(r, n)) {
        if (r->nlmsg_type == NLMSG_ERROR) {
            int e = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(r))->error;
            if (e == 0) return true;
            errno = -e;
            return false;
        }
        if (r->nlmsg_type == NLMSG_DONE) return true;
    }
    return true;
}

/* Add (or replace) an IPv4 route.  dst_net=0/prefix=0 → default route. */
static bool net_route_add(uint32_t dst_net, int prefix, uint32_t gw_net, int oif) {
    struct { struct nlmsghdr nlh; struct rtmsg rtm; char buf[256]; } req{};
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.rtm));
    req.nlh.nlmsg_type  = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    req.rtm.rtm_family   = AF_INET;
    req.rtm.rtm_dst_len  = static_cast<uint8_t>(prefix);
    req.rtm.rtm_table    = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope    = gw_net ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    req.rtm.rtm_type     = RTN_UNICAST;
    if (dst_net) rta_add(&req.nlh, RTA_DST,     &dst_net, 4);
    if (gw_net)  rta_add(&req.nlh, RTA_GATEWAY, &gw_net,  4);
    if (oif > 0) rta_add(&req.nlh, RTA_OIF,     &oif,     4);
    bool ok = nl_transact(&req.nlh);
    if (!ok) fprintf(stderr, "net_route_add %d.%d.%d.%d/%d failed: %s\n",
                     (dst_net)&0xff, (dst_net>>8)&0xff, (dst_net>>16)&0xff, (dst_net>>24)&0xff,
                     prefix, strerror(errno));
    return ok;
}

static bool net_route_del(uint32_t dst_net, int prefix) {
    struct { struct nlmsghdr nlh; struct rtmsg rtm; char buf[128]; } req{};
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.rtm));
    req.nlh.nlmsg_type  = RTM_DELROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.rtm.rtm_family  = AF_INET;
    req.rtm.rtm_dst_len = static_cast<uint8_t>(prefix);
    req.rtm.rtm_table   = RT_TABLE_MAIN;
    req.rtm.rtm_scope   = RT_SCOPE_NOWHERE;
    if (dst_net) rta_add(&req.nlh, RTA_DST, &dst_net, 4);
    return nl_transact(&req.nlh);
}

/* Query the current IPv4 default route → gateway IP and output iface index. */
static bool net_get_default_route(uint32_t *gw_out, int *oif_out) {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) return false;
    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    bind(s, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa));

    struct { struct nlmsghdr nlh; struct rtmsg rtm; } req{};
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.rtm));
    req.nlh.nlmsg_type  = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.rtm.rtm_family  = AF_INET;
    send(s, &req.nlh, req.nlh.nlmsg_len, 0);

    char buf[32768];
    ssize_t n = recv(s, buf, sizeof(buf), 0);
    close(s);
    if (n <= 0) return false;

    for (auto *nh = reinterpret_cast<struct nlmsghdr *>(buf);
         NLMSG_OK(nh, static_cast<int>(n)); nh = NLMSG_NEXT(nh, n)) {
        if (nh->nlmsg_type == NLMSG_DONE) break;
        if (nh->nlmsg_type != RTM_NEWROUTE) continue;
        auto *rtm = reinterpret_cast<struct rtmsg *>(NLMSG_DATA(nh));
        if (rtm->rtm_dst_len != 0 || rtm->rtm_family != AF_INET) continue;
        int rlen = static_cast<int>(RTM_PAYLOAD(nh));
        for (auto *rta = RTM_RTA(rtm); RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
            if (rta->rta_type == RTA_GATEWAY && gw_out)  memcpy(gw_out,  RTA_DATA(rta), 4);
            if (rta->rta_type == RTA_OIF     && oif_out) memcpy(oif_out, RTA_DATA(rta), 4);
        }
        return true;
    }
    return false;
}

/* Resolve hostname → IPv4 in network byte order. */
static bool resolve_host(const char *host, uint32_t *ip_net) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return false;
    *ip_net = reinterpret_cast<struct sockaddr_in *>(res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return true;
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <host> <port> <hub> <user> <pass> [--radius] [--debug] [--default-gw] [--proxy [port]]\n", argv[0]);
        return 1;
    }

    const char *host     = argv[1];
    int         port     = atoi(argv[2]);
    const char *hub      = argv[3];
    const char *user     = argv[4];
    const char *pass     = argv[5];
    int         authtype = SE_AUTH_PASSWORD;

    bool want_default_gw = false;
    bool want_proxy      = false;
    int  proxy_port      = 1080;

    for (int i = 6; i < argc; ++i) {
        if (strcmp(argv[i], "--radius")     == 0) authtype = SE_AUTH_PLAIN_PASSWORD;
        if (strcmp(argv[i], "--debug")      == 0) se_set_debug(1);
        if (strcmp(argv[i], "--default-gw") == 0) want_default_gw = true;
        if (strcmp(argv[i], "--proxy")      == 0) {
            want_proxy = true;
            if (i + 1 < argc && argv[i+1][0] != '-')
                proxy_port = atoi(argv[++i]);
        }
    }

    printf("Connecting to %s:%d hub=%s user=%s authtype=%d …\n",
           host, port, hub, user, authtype);

    se_ip_info_t ip{};
    int rc = se_connect(host, port, hub, user, pass, authtype, &ip);
    if (rc != 0) { fprintf(stderr, "se_connect failed: %d\n", rc); return 1; }

    printf("IP    : %s/%d\n", ip.ip, ip.prefix);
    printf("GW    : %s\n",    ip.gw);
    printf("DNS   : %s\n",    ip.dns);

    g_tun_fd = tun_open("sevpn0");
    if (g_tun_fd < 0) return 1;

    if (!net_if_up("sevpn0", ip.ip, ip.prefix)) {
        fprintf(stderr, "Failed to configure sevpn0\n");
        close(g_tun_fd);
        return 1;
    }
    printf("Interface sevpn0 up: %s/%d\n", ip.ip, ip.prefix);

    uint32_t srv_ip_net = 0;
    uint32_t orig_gw    = 0;
    int      orig_oif   = 0;

    if (want_default_gw) {
        if (!net_get_default_route(&orig_gw, &orig_oif))
            fprintf(stderr, "Warning: could not read existing default route\n");

        if (!resolve_host(host, &srv_ip_net))
            fprintf(stderr, "Warning: could not resolve %s; VPN server route not protected\n", host);

        if (srv_ip_net && orig_gw) {
            net_route_add(srv_ip_net, 32, orig_gw, orig_oif);
            struct in_addr a; a.s_addr = srv_ip_net;
            printf("Server route: %s/32 via original gw\n", inet_ntoa(a));
        }

        uint32_t vpn_gw = 0;
        inet_pton(AF_INET, ip.gw, &vpn_gw);
        int vpn_oif = static_cast<int>(if_nametoindex("sevpn0"));
        net_route_add(0, 0, vpn_gw, vpn_oif);
        printf("Default route via VPN (%s)\n", ip.gw);

        /* Best-effort DNS (systemd-resolved; silent if absent) */
        if (*ip.dns) {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "resolvectl dns sevpn0 %s 2>/dev/null", ip.dns);
            system(cmd);
        }
    }

    if (want_proxy) {
        int actual = se_proxy_start(proxy_port);
        if (actual < 0) {
            fprintf(stderr, "se_proxy_start failed\n");
        } else {
            printf("Proxy  : 127.0.0.1:%d  (HTTP CONNECT + SOCKS5)\n", actual);
            printf("Test   : curl -x socks5h://127.0.0.1:%d https://ifconfig.me\n", actual);
        }
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    printf("Forwarding. Press Ctrl-C to disconnect.\n");
    rc = se_run(g_tun_fd);

    se_proxy_stop();

    if (want_default_gw) {
        uint32_t vpn_gw = 0;
        inet_pton(AF_INET, ip.gw, &vpn_gw);
        net_route_del(0, 0);                        /* remove default */
        if (srv_ip_net) net_route_del(srv_ip_net, 32);
        if (orig_gw)    net_route_add(0, 0, orig_gw, orig_oif); /* restore */
    }

    net_if_down("sevpn0");
    close(g_tun_fd);

    printf("Done (rc=%d).\n", rc);
    return rc < 0 ? 1 : 0;
}
