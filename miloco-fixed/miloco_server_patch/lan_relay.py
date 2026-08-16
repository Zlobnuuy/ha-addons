#!/usr/bin/env python3
"""Multi-segment LanSearch relay for miloco.

C-SDK (libmiot_camera_lite) discovers cameras via cs2p2p LanSearch broadcast
on UDP 54321. The broadcast does NOT cross Keenetic router segments, so
cameras in other subnets (IOT2 192.168.2.x, WirelessK 192.168.0.x) never
answer. Python miot.lan already finds them via unicast probes, but the SDK
is a black box that only trusts its own LanSearch replies.

This relay listens on 0.0.0.0:54321 (SO_REUSEADDR, so it coexists with the
SDK socket), and for every broadcast packet it receives from the SDK
(dst 255.255.255.255:54321) it re-sends a copy unicast to every IP in the
configured extra subnets. Cameras answer unicast back to the SDK's source
port — the SDK sees the reply exactly as if the camera were in its own L2
segment, and connects over LAN.

Env: MILOCO_LAN_SUBNETS="192.168.0.0/24,192.168.2.0/24" (same as miot.lan scan)
"""
import logging
import os
import socket

OT_PORT = 54321

_LOGGER = logging.getLogger(__name__)


def iter_hosts(subnets):
    for subnet in subnets:
        parts = subnet.split(".")
        if len(parts) != 4:
            continue
        base = ".".join(parts[:3])
        for host in range(1, 255):
            yield f"{base}.{host}"


def main():
    subnets = [s.strip() for s in os.getenv("MILOCO_LAN_SUBNETS", "").split(",") if s.strip()]
    if not subnets:
        _LOGGER.info("lan_relay: no MILOCO_LAN_SUBNETS, disabled")
        return
    targets = list(iter_hosts(subnets))
    _LOGGER.info("lan_relay: relaying LanSearch to %d hosts across %s", len(targets), subnets)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", OT_PORT))
    except OSError as err:
        _LOGGER.error("lan_relay: bind 0.0.0.0:%s failed: %s (SDK may hold it without REUSEADDR)", OT_PORT, err)
        return
    sock.settimeout(1.0)

    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    fwd.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Only forward packets ORIGINATING from this host (SDK LanSearch probes).
    # Camera replies come from camera IPs -> never re-forwarded (no loop).
    local_ips = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            local_ips.add(info[4][0])
    except OSError:
        pass
    for ifname_ip in ("127.0.0.1",):
        local_ips.add(ifname_ip)
    _LOGGER.info("lan_relay: local sources: %s", sorted(local_ips))

    _LOGGER.info("lan_relay: listening for LanSearch broadcasts on %s", OT_PORT)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            continue
        src_ip = addr[0]
        if src_ip not in local_ips:
            continue  # camera reply / anything not from us -> skip (no loop)
        if len(data) > 512:
            continue
        for target in targets:
            try:
                fwd.sendto(data, (target, OT_PORT))
            except OSError:
                pass


if __name__ == "__main__":
    main()
