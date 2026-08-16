#!/usr/bin/env python3
"""Multi-segment LanSearch relay for miloco (two-way).

C-SDK (libmiot_camera_lite) discovers cameras via cs2p2p LanSearch broadcast
on UDP 54321. The broadcast does NOT cross Keenetic router segments, so
cameras in other subnets (IOT2 192.168.2.x, WirelessK 192.168.0.x) never
answer.

How the SDK works (observed):
  - SDK sends LanSearch broadcast FROM its own UDP socket (ephemeral port,
    e.g. 34526) TO 255.255.255.255:54321.
  - Cameras in the same L2 segment answer unicast to 192.168.1.214:34526
    (the SDK socket) -> SDK sees them.
  - Cameras in other segments never receive the broadcast.

Two-way relay on 0.0.0.0:54321 (SO_REUSEADDR, coexists with SDK socket):
  1. SDK broadcast arrives here (src = 192.168.1.214:SDK_PORT).
     Remember SDK_PORT, re-send the probe unicast to every IP in the extra
     subnets, USING OUR OWN 54321 socket (so replies come back to 54321).
  2. Camera replies from extra subnets (src = 192.168.2.x:cam_port) arrive
     on our 54321 socket -> forward them to 192.168.1.214:SDK_PORT so the
     SDK sees the reply exactly as if the camera were in its own segment.

Env: MILOCO_LAN_SUBNETS="192.168.0.0/24,192.168.2.0/24" (same as miot.lan scan)
"""
import logging
import os
import re
import socket
import time

OT_PORT = 54321

# Use the miloco_server.main logger — it is guaranteed to hit the log file
# that the supervisor shows (other loggers may not be configured).
_LOGGER = logging.getLogger("miloco_server.main")


def iter_hosts(subnets):
    for subnet in subnets:
        parts = subnet.split(".")
        if len(parts) != 4:
            continue
        base = ".".join(parts[:3])
        for host in range(1, 255):
            yield f"{base}.{host}"


def get_local_ips():
    """Find this host's own IPv4 addresses (reliable in containers where
    gethostname()/getaddrinfo() does not resolve the real interface IP)."""
    ips = {"127.0.0.1"}
    for probe in ("192.168.1.1", "192.168.0.1", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect((probe, 80))
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    try:
        with open("/proc/net/fib_trie") as fh:
            for m in re.finditer(r"\|-- (\d+\.\d+\.\d+\.\d+)", fh.read()):
                ips.add(m.group(1))
    except OSError:
        pass
    return ips


def main():
    _LOGGER.info("LAN RELAY: main() started")
    subnets = [s.strip() for s in os.getenv("MILOCO_LAN_SUBNETS", "").split(",") if s.strip()]
    if not subnets:
        _LOGGER.info("LAN RELAY: no MILOCO_LAN_SUBNETS, disabled")
        return
    targets = list(iter_hosts(subnets))
    _LOGGER.info("LAN RELAY: relaying LanSearch to %d hosts across %s", len(targets), subnets)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", OT_PORT))
        _LOGGER.info("LAN RELAY: bound 0.0.0.0:%s OK", OT_PORT)
    except OSError as err:
        _LOGGER.error("LAN RELAY: bind 0.0.0.0:%s FAILED: %s (SDK may hold it without REUSEADDR)", OT_PORT, err)
        return
    sock.settimeout(1.0)

    local_ips = get_local_ips()
    _LOGGER.info("LAN RELAY: local sources: %s", sorted(local_ips))
    local_ip = next((ip for ip in local_ips if not ip.startswith("127.")), "127.0.0.1")

    # Camera IPs live in these subnets (their replies are forwarded to SDK).
    extra_ips = set(targets)

    _LOGGER.info("LAN RELAY: listening on %s", OT_PORT)
    stats = {"seen": 0, "fwd": 0, "back": 0, "last_report": time.time()}
    sdk_port = None
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            continue
        src_ip, src_port = addr[0], addr[1]
        stats["seen"] += 1
        now = time.time()
        if now - stats["last_report"] > 30:
            stats["last_report"] = now
            _LOGGER.info("LAN RELAY: stats seen=%d fwd=%d back=%d sdk_port=%s last_src=%s:%s len=%d",
                         stats["seen"], stats["fwd"], stats["back"], sdk_port, src_ip, src_port, len(data))

        if src_ip in local_ips:
            # SDK LanSearch probe (or anything local -> 54321). Re-send unicast
            # to every IP in the extra subnets, from our 54321 socket.
            if len(data) > 512:
                continue
            sdk_port = src_port
            for target in targets:
                try:
                    sock.sendto(data, (target, OT_PORT))
                    stats["fwd"] += 1
                except OSError:
                    pass
        elif src_ip in extra_ips:
            # Camera reply from an extra subnet -> deliver to the SDK socket.
            if sdk_port and len(data) <= 2048:
                try:
                    sock.sendto(data, (local_ip, sdk_port))
                    stats["back"] += 1
                except OSError:
                    pass


if __name__ == "__main__":
    main()
