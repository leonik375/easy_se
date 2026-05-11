#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char ip[16];   /* dotted-decimal IPv4 */
    char gw[16];
    char dns[16];
    int  prefix;   /* e.g. 24 */
} se_ip_info_t;

/* authtype values for se_connect */
#define SE_AUTH_PASSWORD        1  /* local hashed password only */
#define SE_AUTH_PLAIN_PASSWORD  2  /* plaintext → local + RADIUS fallback */

/* Connect to SoftEther server, authenticate, run DHCP probe, fill ip_out.
   Returns 0 on success, negative errno-style on failure. */
int se_connect(const char *host, int port,
               const char *hub, const char *user, const char *pass,
               int authtype,
               se_ip_info_t *ip_out);

/* Start packet forwarding loop (blocks until disconnected or error).
   Caller must have called se_connect() first.
   tun_fd: file descriptor opened by VpnService / NEPacketTunnelProvider.
   Returns 0 on clean disconnect, negative on error. */
int se_run(int tun_fd);

/* Signal disconnect from any thread. Safe to call from signal handler. */
void se_disconnect(void);

/* Enable/disable verbose debug logging to stderr (default: off). */
void se_set_debug(int enable);

/* Set keepalive interval on the TCP channel (default: 15 s).
   Call before se_run(). */
void se_set_keepalive(int seconds);

/* Override DHCP-assigned IP/GW/DNS.  The DHCP probe still runs to set up
   the Ethernet layer (MAC, ARP), but ip/prefix/gw/dns are replaced in the
   result before se_connect() returns.  Pass NULL/empty ip to clear. */
void se_set_static_ip(const char *ip, int prefix, const char *gw, const char *dns);

/* When skip != 0, the platform layer should NOT install a default (0.0.0.0/0)
   route through the VPN — only the assigned subnet is routed.
   Call before se_connect(); query with se_get_skip_default_gw() in the
   onIPAssigned / NEPacketTunnelProvider callback. */
void se_set_skip_default_gw(int skip);
int  se_get_skip_default_gw(void);

/* Built-in HTTP CONNECT + SOCKS5 proxy server.
   Listens on 127.0.0.1.  Works standalone or alongside a TUN-based VPN —
   when the TUN is up, outgoing proxy connections are routed through it
   automatically.
   port = 0 → OS assigns a free port; query the result with se_proxy_port().
   Returns the actual listening port, or -1 on error. */
int  se_proxy_start(int port);
void se_proxy_stop(void);
int  se_proxy_port(void);

/* Bind outgoing proxy connections to a specific network interface (e.g. "sevpn0").
   Uses SO_BINDTODEVICE — forces routing through that interface regardless of the
   routing table, so the proxy works without a default gateway via VPN.
   Call before se_proxy_start().  Pass NULL or "" to clear. */
void se_proxy_set_iface(const char *ifname);

/* Return the raw TCP / UDP socket fds used by the tunnel (-1 if not open).
   Call after se_connect() and before establish()-ing the TUN device so that
   Android VpnService.protect() can exclude them from VPN routing. */
int se_get_tcp_fd(void);
int se_get_udp_fd(void);

#ifdef __cplusplus
}
#endif
