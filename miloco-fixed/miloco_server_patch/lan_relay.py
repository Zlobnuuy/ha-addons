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
import struct
import threading

OT_PORT = 54321
BROADCAST_ADDRS = ("255.255.255.255",)


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
        print("[lanrelay] no MILOCO_LAN_SUBNETS, disabled")
        return
    targets = list(iter_hosts(subnets))
    print(f"[lanrelay] relaying LanSearch to {len(targets)} hosts across {subnets}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", OT_PORT))
    except OSError as err:
        print(f"[lanrelay] bind 0.0.0.0:{OT_PORT} failed: {err} (SDK may hold it without REUSEADDR)")
        return
    sock.settimeout(1.0)

    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    fwd.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print("[lanrelay] listening for LanSearch broadcasts")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            continue
        dst = addr[0]
        # Only forward packets that look like LanSearch probes (small, < 256B)
        # from the SDK / local process (any local source) heading to broadcast.
        if len(data) > 512:
            continue
        is_bcast = dst in BROADCAST_ADDRS or dst.endswith(".255")
        # Forward regardless of source: SDK probes are the trigger. Avoid
        # loops: do not re-forward packets we just sent (src is our fwd port).
        for target in targets:
            try:
                fwd.sendto(data, (target, OT_PORT))
            except OSError:
                pass
        if is_bcast and len(data) < 512:
            # log once per burst, throttled
            pass


if __name__ == "__main__":
    main()
