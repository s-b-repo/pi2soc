"""
VPN status detection for the on-wall indicator — pure + privilege-free.

`vpn_state(vpn)` returns one of:
  "not_configured"  the vpn section is absent/disabled
  "online"          the tunnel looks up
  "offline"         configured but no evidence of a live tunnel

Detection, in order of reliability:
  1. vpn.ready_probe (a host:port reachable only once the VPN is up) — a TCP
     connect. This is the accurate, type-agnostic signal; set it.
  2. otherwise, the presence of the expected tunnel interface in
     /sys/class/net (wg<n> / tun0 / ppp0) — best-effort, no privileges.
"""
from __future__ import annotations

import os
import socket

from . import config as cfg

STATE_NOT_CONFIGURED = "not_configured"
STATE_ONLINE = "online"
STATE_OFFLINE = "offline"
STATE_CONNECTING = "connecting"      # probe timed out (slow / mid-handshake)


def _tcp_probe(hostport: str, timeout: float = 1.5) -> str:
    """Three-way probe used by the top-bar traffic-light:
      'ok'         — TCP connect succeeded
      'timeout'    — the connect did not complete in `timeout`s (slow / not yet
                     routed) — shown as amber 'connecting' rather than red
      'refused'    — the host actively rejected the connect, or the address is
                     malformed — shown as red 'offline'
    """
    host, _, port = hostport.rpartition(":")
    if not host or not port.isdigit():
        return "refused"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return "ok"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "refused"


def _tcp_ok(hostport: str, timeout: float = 2.0) -> bool:
    """Back-compat boolean probe. New code should use _tcp_probe() to
    distinguish timeouts (amber) from refusals (red)."""
    return _tcp_probe(hostport, timeout) == "ok"


def _expected_iface(vpn: dict) -> str:
    kind = cfg.vpn_kind(vpn)
    if kind == "wireguard":
        from . import vpndrivers
        return vpndrivers.WireGuardDriver().iface(vpn) or "wg0"
    if kind == "openvpn":
        return "tun0"
    return "ppp0"


def _iface_up(iface: str) -> bool:
    return bool(iface) and os.path.isdir(f"/sys/class/net/{iface}")


def vpn_state(vpn: dict) -> str:
    """Four-state status used by the top-bar pill (green/amber/red/grey):
      online        — probe ok OR iface up        (green)
      connecting    — probe timed out             (amber — mid-handshake or slow)
      offline       — probe refused / iface gone  (red)
      not_configured — vpn disabled or absent     (grey / hidden)
    """
    if not vpn or not vpn.get("enabled"):
        return STATE_NOT_CONFIGURED
    probe = (vpn.get("ready_probe") or "").strip()
    if probe:
        r = _tcp_probe(probe)
        if r == "ok":
            return STATE_ONLINE
        if r == "timeout":
            return STATE_CONNECTING
        return STATE_OFFLINE
    return STATE_ONLINE if _iface_up(_expected_iface(vpn)) else STATE_OFFLINE


def vpn_name(vpn: dict, idx: int = 0) -> str:
    """Display name for a vpn entry. The operator can set `name:`; falls back
    to type-or-gateway so the pill reads 'fortinet:vpn.acme.com' instead of
    a bare 'VPN' the operator has to mouse-over to identify."""
    if vpn.get("name"):
        return str(vpn["name"])
    kind = (vpn.get("type") or "").lower()
    gw = (vpn.get("gateway") or "").split(":", 1)[0]
    if gw and kind:
        return f"{kind}:{gw}"
    if kind:
        return f"{kind}-{idx+1}"
    return f"vpn-{idx+1}"


LABELS = {
    STATE_NOT_CONFIGURED: "VPN: not configured",
    STATE_ONLINE: "VPN: online",
    STATE_CONNECTING: "VPN: connecting",
    STATE_OFFLINE: "VPN: offline",
}
