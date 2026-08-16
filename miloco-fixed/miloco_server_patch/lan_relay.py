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
import os
import socket
import sys
import time

OT_PORT = 54321


def log(msg):
    print(f"[lan_relay] {msg}", flush=True)


def iter_hosts(subnets):
    for subnet in subnets:
        parts = subnet.split(".")
        if len(parts) != 4:
            continue
        base = ".".join(parts[:3])
        for host in range(1, 255):
            yield f"{base}.{host}"


def main():
    log("relay main() started")
    subnets = [s.strip() for s in os.getenv("MILOCO_LAN_SUBNETS", "").split(",") if s.strip()]
    if not subnets:
        log("no MILOCO_LAN_SUBNETS, disabled")
        return
    targets = list(iter_hosts(subnets))
    log(f"relaying LanSearch to {len(targets)} hosts across {subnets}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", OT_PORT))
        log(f"bound 0.0.0.0:{OT_PORT} OK")
    except OSError as err:
        log(f"bind 0.0.0.0:{OT_PORT} FAILED: {err} (SDK may hold it without REUSEADDR)")
        return
    sock.settimeout(1.0)

    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    fwd.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Only forward packets ORIGINATING from this host (SDK LanSearch probes).
    local_ips = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            local_ips.add(info[4][0])
    except OSError:
        pass
    local_ips.add("127.0.0.1")
    log(f"local sources: {sorted(local_ips)}")

    log(f"listening on {OT_PORT}")
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
            log(f"stats seen={stats['seen']} fwd={stats['fwd']} last_src={src_ip}:{src_port} len={len(data)}")
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
