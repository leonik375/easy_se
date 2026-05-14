/* easy_se_cli.cpp — Linux CLI for the easy_se library.
 *
 * Usage (as root or with CAP_NET_ADMIN):
 *   ./easy_se_cli <host> <port> <hub> <user> <pass> [options]
 *   ./easy_se_cli --config /etc/easy-se/myvpn.conf [options]
 *   ./easy_se_cli                                  # all settings via env
 *
 * Options:
 *   --config <path> KEY=VALUE config file (same format as systemd EnvironmentFile)
 *   --radius        use plaintext auth (local + RADIUS)
 *   --debug         verbose easy_se logging
 *   --default-gw    add default route through VPN (+ protect server route)
 *   --proxy [port]  start HTTP/SOCKS5 proxy (default port 1080, 0=auto)
 *   --no-verify     disable TLS server-cert validation (insecure)
 *   --ca <path>     CA bundle/dir for cert validation (default: system store)
 *
 * Configuration precedence (later overrides earlier):
 *   1. --config file (if given)
 *   2. SE_* environment variables
 *   3. command-line arguments
 *
 * Environment variables / config keys (SE_ prefix):
 *   SE_HOST, SE_PORT (443), SE_HUB (DEFAULT), SE_USER,
 *   SE_PASS               — password literal
 *   SE_PASS_FILE          — read password from file (preferred for secrets;
 *                           works with systemd's LoadCredential=)
 *   SE_AUTH               — "password" (default) | "radius"
 *   SE_DEBUG              — 0/1
 *   SE_DEFAULT_GW         — 0/1, install default route via VPN
 *   SE_PROXY              — 0/1, start HTTP/SOCKS5 proxy
 *   SE_PROXY_PORT         — default 1080
 *   SE_VERIFY_CERT        — 0/1, default 1 (validate TLS server cert)
 *   SE_CA_PATH            — dir of hash-named PEMs or single PEM bundle
 *   SE_UDP_ACCEL          — 0/1, default 1 (use RC4-over-UDP fast path)
 *   SE_TUN_NAME           — default sevpn0
 *   SE_KEEPALIVE          — seconds, default library setting
 *
 * What it does:
 *   1. se_connect() — TLS, handshake, auth, DHCP probe
 *   2. Prints the assigned IP info
 *   3. Opens a Linux TUN device (sevpn0 by default)
 *   4. Configures the interface; optionally sets default route
 *   5. Optionally starts the built-in proxy
 *   6. se_run() — forwards packets until SIGINT/SIGTERM
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <string>
#include <fstream>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include "easy_se.h"

static int g_tun_fd = -1;

static void on_signal(int sig) {
    /* printf is NOT async-signal-safe; write(2, …) is.  Use a fixed-size
       buffer + manual int formatting so we can identify which signal is
       responsible for the otherwise-silent clean exits we keep seeing. */
    char  buf[64];
    char *p = buf;
    const char *prefix = "\n[signal] received ";
    while (*prefix) *p++ = *prefix++;
    int v = sig, d = 100;
    if (v >= 100) { *p++ = '0' + v / 100; v %= 100; d = 10; }
    if (v >=  10 || d == 10) { *p++ = '0' + v / 10;  v %= 10; }
    *p++ = '0' + v;
    *p++ = '\n';
    (void)write(2, buf, p - buf);
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

/* ── config / env loader ────────────────────────────────────────────── */

/* Trim whitespace and optional surrounding "..."/'...' quotes. */
static std::string cfg_trim(std::string s) {
    auto issp = [](unsigned char c){ return std::isspace(c) != 0; };
    while (!s.empty() && issp(s.front())) s.erase(s.begin());
    while (!s.empty() && issp(s.back()))  s.pop_back();
    if (s.size() >= 2 &&
        ((s.front() == '"'  && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\'')))
        s = s.substr(1, s.size() - 2);
    return s;
}

/* Read a systemd-EnvironmentFile-style KEY=VALUE config and setenv() each
   entry.  Existing env values are NOT overridden — env wins, so a user can
   override a config-file value by exporting the same variable. */
static bool load_config_into_env(const char *path) {
    std::ifstream f(path);
    if (!f) {
        fprintf(stderr, "config: cannot open %s: %s\n", path, strerror(errno));
        return false;
    }
    std::string line; int n = 0;
    while (std::getline(f, line)) {
        ++n;
        std::string s = cfg_trim(line);
        if (s.empty() || s[0] == '#' || s[0] == ';') continue;
        auto eq = s.find('=');
        if (eq == std::string::npos) {
            fprintf(stderr, "config %s:%d: no '=' — ignored\n", path, n);
            continue;
        }
        std::string k = cfg_trim(s.substr(0, eq));
        std::string v = cfg_trim(s.substr(eq + 1));
        setenv(k.c_str(), v.c_str(), 0);   /* 0 = don't override existing */
    }
    return true;
}

/* Refuses world/group-readable secret files to catch mistakes early. */
static std::string read_pass_file(const char *path) {
    struct stat st{};
    if (::stat(path, &st) != 0) {
        fprintf(stderr, "SE_PASS_FILE %s: %s\n", path, strerror(errno));
        return "";
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr, "SE_PASS_FILE %s: refusing — group/other-readable (mode %o)\n",
                path, st.st_mode & 0777);
        return "";
    }
    std::ifstream f(path);
    std::string p; std::getline(f, p);
    return p;
}

static bool env_bool(const char *k, bool def) {
    const char *v = getenv(k);
    if (!v || !*v) return def;
    return std::strcmp(v, "1") == 0 || std::strcmp(v, "true") == 0 ||
           std::strcmp(v, "yes") == 0 || std::strcmp(v, "on")   == 0;
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* Line-buffer stdout so journalctl flushes per-line under systemd. */
    setvbuf(stdout, nullptr, _IOLBF, 0);

    /* Pass 1: --config (lowest precedence; populates env without overriding
       anything the caller already exported). */
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            if (!load_config_into_env(argv[++i])) return 1;
        } else if (std::strcmp(argv[i], "-h") == 0 ||
                   std::strcmp(argv[i], "--help") == 0) {
            fprintf(stderr,
                "Usage: %s <host> <port> <hub> <user> <pass> [options]\n"
                "       %s --config /path/to/easy-se.conf [options]\n"
                "       %s         # all settings via SE_* env vars\n"
                "Options: --radius --debug --default-gw --proxy [port]\n"
                "         --no-verify --ca <path> --tun <name> --keepalive <s>\n"
                "         --config <path>\n"
                "See easy_se_cli.cpp header for SE_* env var names.\n",
                argv[0], argv[0], argv[0]);
            return 0;
        }
    }

    /* Seed positional values from env (overridden by argv positionals below). */
    std::string s_host = getenv("SE_HOST") ? getenv("SE_HOST") : "";
    std::string s_hub  = getenv("SE_HUB")  ? getenv("SE_HUB")  : "DEFAULT";
    std::string s_user = getenv("SE_USER") ? getenv("SE_USER") : "";
    std::string s_pass = getenv("SE_PASS") ? getenv("SE_PASS") : "";
    if (s_pass.empty() && getenv("SE_PASS_FILE"))
        s_pass = read_pass_file(getenv("SE_PASS_FILE"));
    int port = getenv("SE_PORT") ? std::atoi(getenv("SE_PORT")) : 443;

    int  authtype = (getenv("SE_AUTH") &&
                     (std::strcmp(getenv("SE_AUTH"), "radius") == 0 ||
                      std::strcmp(getenv("SE_AUTH"), "plain")  == 0))
                  ? SE_AUTH_PLAIN_PASSWORD : SE_AUTH_PASSWORD;
    bool want_default_gw = env_bool("SE_DEFAULT_GW", false);
    bool want_proxy      = env_bool("SE_PROXY",      false);
    int  proxy_port      = getenv("SE_PROXY_PORT") ? std::atoi(getenv("SE_PROXY_PORT")) : 1080;
    bool verify_cert     = env_bool("SE_VERIFY_CERT", true);
    bool use_udp_accel   = env_bool("SE_UDP_ACCEL", true);
    std::string ca_path  = getenv("SE_CA_PATH")  ? getenv("SE_CA_PATH")  : "";
    std::string tun_name = getenv("SE_TUN_NAME") ? getenv("SE_TUN_NAME") : "sevpn0";
    int  keepalive       = getenv("SE_KEEPALIVE") ? std::atoi(getenv("SE_KEEPALIVE")) : 0;
    if (env_bool("SE_DEBUG", false)) se_set_debug(1);

    /* Pass 2: positional args + flags.  Positional fill in any of the five
       core fields that env didn't supply; explicit argv values always win. */
    int pos = 0;
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] == '-') {
            if      (std::strcmp(a, "--config")     == 0) ++i;
            else if (std::strcmp(a, "--radius")     == 0) authtype = SE_AUTH_PLAIN_PASSWORD;
            else if (std::strcmp(a, "--debug")      == 0) se_set_debug(1);
            else if (std::strcmp(a, "--default-gw") == 0) want_default_gw = true;
            else if (std::strcmp(a, "--no-verify")  == 0) verify_cert = false;
            else if (std::strcmp(a, "--no-udp")     == 0) use_udp_accel = false;
            else if (std::strcmp(a, "--ca")         == 0 && i + 1 < argc) ca_path  = argv[++i];
            else if (std::strcmp(a, "--tun")        == 0 && i + 1 < argc) tun_name = argv[++i];
            else if (std::strcmp(a, "--keepalive")  == 0 && i + 1 < argc) keepalive = std::atoi(argv[++i]);
            else if (std::strcmp(a, "--proxy")      == 0) {
                want_proxy = true;
                if (i + 1 < argc && argv[i+1][0] != '-')
                    proxy_port = std::atoi(argv[++i]);
            } else {
                fprintf(stderr, "Unknown option: %s\n", a); return 1;
            }
        } else {
            switch (pos++) {
                case 0: s_host = a; break;
                case 1: port   = std::atoi(a); break;
                case 2: s_hub  = a; break;
                case 3: s_user = a; break;
                case 4: s_pass = a; break;
                default:
                    fprintf(stderr, "Extra positional argument: %s\n", a);
                    return 1;
            }
        }
    }

    if (s_host.empty() || s_user.empty()) {
        fprintf(stderr, "error: host and user are required (positional, env, or --config)\n");
        return 1;
    }

    const char *host = s_host.c_str();
    const char *hub  = s_hub.c_str();
    const char *user = s_user.c_str();
    const char *pass = s_pass.c_str();

    /* Apply runtime config to the library. */
    se_set_verify_cert(verify_cert ? 1 : 0);
    se_set_use_udp_accel(use_udp_accel ? 1 : 0);
    if (!ca_path.empty()) se_set_ca_path(ca_path.c_str());
    if (keepalive > 0)    se_set_keepalive(keepalive);

    printf("Connecting to %s:%d hub=%s user=%s authtype=%d …\n",
           host, port, hub, user, authtype);

    se_ip_info_t ip{};
    int rc = se_connect(host, port, hub, user, pass, authtype, &ip);
    if (rc != 0) { fprintf(stderr, "se_connect failed: %d\n", rc); return 1; }

    printf("IP    : %s/%d\n", ip.ip, ip.prefix);
    printf("GW    : %s\n",    ip.gw);
    printf("DNS   : %s\n",    ip.dns);

    g_tun_fd = tun_open(tun_name.c_str());
    if (g_tun_fd < 0) return 1;

    if (!net_if_up(tun_name.c_str(), ip.ip, ip.prefix)) {
        fprintf(stderr, "Failed to configure %s\n", tun_name.c_str());
        close(g_tun_fd);
        return 1;
    }
    printf("Interface %s up: %s/%d\n", tun_name.c_str(), ip.ip, ip.prefix);

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
        int vpn_oif = static_cast<int>(if_nametoindex(tun_name.c_str()));
        net_route_add(0, 0, vpn_gw, vpn_oif);
        printf("Default route via VPN (%s)\n", ip.gw);

        /* Best-effort DNS (systemd-resolved; silent if absent) */
        if (*ip.dns) {
            char cmd[160];
            snprintf(cmd, sizeof(cmd), "resolvectl dns %s %s 2>/dev/null",
                     tun_name.c_str(), ip.dns);
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
    signal(SIGHUP,  on_signal);
    /* SIGPIPE is the most common cause of silent-clean-exit: the proxy
       bridges write to socketpairs whose other end may have closed.
       Ignore it process-wide — affected sends will just return EPIPE
       and the bridge thread handles that locally. */
    signal(SIGPIPE, SIG_IGN);

    printf("Forwarding. SIGINT/SIGTERM to disconnect.\n");
    rc = se_run(g_tun_fd);

    se_proxy_stop();

    if (want_default_gw) {
        uint32_t vpn_gw = 0;
        inet_pton(AF_INET, ip.gw, &vpn_gw);
        net_route_del(0, 0);                        /* remove default */
        if (srv_ip_net) net_route_del(srv_ip_net, 32);
        if (orig_gw)    net_route_add(0, 0, orig_gw, orig_oif); /* restore */
    }

    net_if_down(tun_name.c_str());
    close(g_tun_fd);

    printf("Done (rc=%d).\n", rc);
    return rc < 0 ? 1 : 0;
}
