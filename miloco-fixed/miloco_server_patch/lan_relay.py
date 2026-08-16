#!/usr/bin/env python3
"""Multi-segment LanSearch relay for miloco (raw-socket source spoofing).

C-SDK (libmiot_camera_lite) discovers cameras via cs2p2p LanSearch broadcast
on UDP 54321. The broadcast does NOT cross Keenetic router segments, so
cameras in other subnets (IOT2 192.168.2.x, WirelessK 192.168.0.x) never
answer.

Observed SDK behaviour:
  - SDK sends LanSearch broadcast FROM its own UDP socket (ephemeral port,
    e.g. 46871) TO 255.255.255.255:54321.
  - Cameras in the same L2 segment answer unicast to 192.168.1.214:46871
    (the SDK socket) -> SDK sees them.
  - Cameras in other segments never receive the broadcast.

Strategy (source-port spoofing with a raw socket):
  - Listen on 0.0.0.0:54321 (SO_REUSEADDR) for SDK LanSearch probes.
  - When a probe arrives from 192.168.1.214:SDK_PORT, re-send its payload
    unicast to every IP in the extra subnets WITH THE SAME SOURCE PORT
    (SDK_PORT). Cameras in extra subnets then reply unicast to
    192.168.1.214:SDK_PORT — straight into the SDK socket, with the
    camera's own source IP. No reply forwarding needed.

Env: MILOCO_LAN_SUBNETS="192.168.0.0/24,192.168.2.0/24" (same as miot.lan scan)
"""
import logging
import os
import re
import socket
import struct
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


def make_udp_packet(src_ip, src_port, dst_ip, dst_port, payload):
    """Build a full IPv4+UDP packet with spoofed source."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)

    # UDP header
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    # Pseudo header for checksum
    pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_len)
    cs = checksum(pseudo + udp + payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, cs)

    ip_len = 20 + udp_len
    iph = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0x1234, 0, 64, 17, 0, src, dst,
    )
    iph = iph[:10] + struct.pack("!H", checksum(iph)) + iph[12:]
    return iph + udp + payload


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def main():
    _LOGGER.info("LAN RELAY: main() started")
    subnets = [s.strip() for s in os.getenv("MILOCO_LAN_SUBNETS", "").split(",") if s.strip()]
    if not subnets:
        _LOGGER.info("LAN RELAY: no MILOCO_LAN_SUBNETS, disabled")
        return
    targets = list(iter_hosts(subnets))
    _LOGGER.info("LAN RELAY: relaying LanSearch to %d hosts across %s", len(targets), subnets)

    # Listener for SDK probes.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("0.0.0.0", OT_PORT))
        _LOGGER.info("LAN RELAY: bound 0.0.0.0:%s OK", OT_PORT)
    except OSError as err:
        _LOGGER.error("LAN RELAY: bind 0.0.0.0:%s FAILED: %s", OT_PORT, err)
        return
    sock.settimeout(1.0)

    local_ips = get_local_ips()
    _LOGGER.info("LAN RELAY: local sources: %s", sorted(local_ips))
    local_ip = next((ip for ip in local_ips if not ip.startswith("127.")), "127.0.0.1")

    # Raw socket to spoof the SDK source port.
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_mode = True
        _LOGGER.info("LAN RELAY: raw socket OK (source spoofing enabled)")
    except OSError as err:
        raw = None
        raw_mode = False
        _LOGGER.error("LAN RELAY: raw socket FAILED (%s) — falling back to normal sendto", err)

    _LOGGER.info("LAN RELAY: listening on %s (raw=%s)", OT_PORT, raw_mode)
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
            continue  # camera reply / not from us -> skip
        if len(data) > 512:
            continue
        for target in targets:
            try:
                if raw_mode:
                    raw.sendto(make_udp_packet(local_ip, src_port, target, OT_PORT, data), (target, 0))
                else:
                    sock.sendto(data, (target, OT_PORT))
                stats["fwd"] += 1
            except OSError:
                pass


if __name__ == "__main__":
    main()
