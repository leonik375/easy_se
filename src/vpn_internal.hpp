#pragma once
#include <cstdint>
#include <cstddef>

class VpnTcpConn;

/* Internal interface exposed by se_client.cpp for use by tcp_conn.cpp.
   Not part of the public API. */

bool vpn_debug();
bool vpn_use_udp_accel();

uint32_t       vpn_our_ip_net();
const uint8_t *vpn_our_mac();
uint32_t       vpn_gateway_ip_net();

/* ARP cache lookup. Returns true and fills mac_out[6] if found. */
bool vpn_lookup_mac(uint32_t ip_net, uint8_t *mac_out);

/* Send an Ethernet frame through the VPN tunnel (TCP or UDP path). */
bool vpn_send_frame(const uint8_t *eth, size_t len);

/* TCP demux: register/unregister a VpnTcpConn by its local port.
   The recv loop calls deliver() on registered connections when a matching
   TCP segment arrives addressed to our VPN IP. */
void vpn_tcp_register  (uint16_t port, VpnTcpConn *conn);
void vpn_tcp_unregister(uint16_t port);

/* Send an ARP request for ip_net and poll until the recv loop processes the
   reply (or timeout_ms elapses).  Returns true if MAC is now in cache.
   Requires se_run() to be active so that ARP replies are processed. */
bool vpn_probe_arp(uint32_t ip_net, int timeout_ms);
