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
    # Trick: UDP connect to a gateway-ish address picks the outgoing interface
    # without sending anything.
    for probe in ("192.168.1.1", "192.168.0.1", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect((probe, 80))
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    # Also enumerate via /proc/net/fib_trie (cheap, no deps)
    try:
        trie = open("/proc/net/fib_trie").read()
        for m in __import__("re").finditer(r"\|-- (\d+\.\d+\.\d+\.\d+)", trie):
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

    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    fwd.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Only forward packets ORIGINATING from this host (SDK LanSearch probes).
    # Camera replies come from camera IPs -> never re-forwarded (no loop).
    local_ips = get_local_ips()
    _LOGGER.info("LAN RELAY: local sources: %s", sorted(local_ips))

    _LOGGER.info("LAN RELAY: listening on %s", OT_PORT)
    stats = {"seen": 0, "fwd": 0, "last_report": time.time()}
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
            _LOGGER.info("LAN RELAY: stats seen=%d fwd=%d last_src=%s:%s len=%d",
                         stats["seen"], stats["fwd"], src_ip, src_port, len(data))
        if src_ip not in local_ips:
            continue  # camera reply / not from us -> skip (no loop)
        if len(data) > 512:
            continue
        for target in targets:
            try:
                fwd.sendto(data, (target, OT_PORT))
                stats["fwd"] += 1
            except OSError:
                pass


if __name__ == "__main__":
    main()
