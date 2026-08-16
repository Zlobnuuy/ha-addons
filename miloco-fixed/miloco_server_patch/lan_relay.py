#!/usr/bin/env python3
"""Multi-segment LanSearch relay for miloco (raw-socket spoofing + AF_PACKET monitor).

Strategy (source-port spoofing with a raw socket):
  - Listen on 0.0.0.0:54321 (SO_REUSEADDR) for SDK LanSearch probes.
  - When a probe arrives from 192.168.1.214:SDK_PORT, re-send its payload
    unicast to every IP in the extra subnets WITH THE SAME SOURCE PORT
    (SDK_PORT). Cameras in extra subnets then reply unicast to
    192.168.1.214:SDK_PORT — straight into the SDK socket.

AF_PACKET monitor:
  - Sits on the default interface, captures ALL UDP packets, logs a summary
    of traffic involving cameras in the extra subnets (src/dst IPs and ports)
    every 30s. This is an in-container tcpdump to verify that cameras DO
    answer the relayed LanSearch and that replies reach the SDK port.

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


# Known camera IPs in extra subnets (from Keenetic hotspot + miot.lan scan).
# Relay sends ONLY to these — instant delivery, SDK socket stays alive.
# Env: MILOCO_LAN_TARGETS="192.168.2.164,192.168.2.70,..." (optional override)
KNOWN_TARGETS = [
    # IOT2 (192.168.2.x) — xiaovv + Mi360 + chuangmi
    "192.168.2.55", "192.168.2.68", "192.168.2.70", "192.168.2.94",
    "192.168.2.112", "192.168.2.147", "192.168.2.152", "192.168.2.164",
    "192.168.2.199", "192.168.2.202", "192.168.2.252",
    # WirelessK (192.168.0.x) — if any
]


def resolve_targets(subnets):
    env = os.getenv("MILOCO_LAN_TARGETS", "").strip()
    if env:
        return [ip.strip() for ip in env.split(",") if ip.strip()]
    return [ip for ip in KNOWN_TARGETS]


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


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def make_udp_packet(src_ip, src_port, dst_ip, dst_port, payload):
    """Build a full IPv4+UDP packet with spoofed source."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
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


def parse_udp(frame):
    """Parse an Ethernet+IPv4+UDP frame -> (src_ip, src_port, dst_ip, dst_port, len) or None."""
    try:
        if len(frame) < 34:
            return None
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type == 0x8100:  # VLAN
            eth_type = struct.unpack("!H", frame[16:18])[0]
            ip_off = 18
        else:
            ip_off = 14
        if eth_type != 0x0800:
            return None
        if len(frame) < ip_off + 20:
            return None
        ver_ihl = frame[ip_off]
        if ver_ihl >> 4 != 4:
            return None
        ihl = (ver_ihl & 0x0F) * 4
        proto = frame[ip_off + 9]
        if proto != 17:  # UDP
            return None
        src_ip = socket.inet_ntoa(frame[ip_off + 12:ip_off + 16])
        dst_ip = socket.inet_ntoa(frame[ip_off + 16:ip_off + 20])
        udp_off = ip_off + ihl
        if len(frame) < udp_off + 8:
            return None
        src_port, dst_port, ulen = struct.unpack("!HHH", frame[udp_off:udp_off + 6])
        return (src_ip, src_port, dst_ip, dst_port, ulen)
    except Exception:
        return None


def packet_monitor(extra_prefixes, stop):
    """AF_PACKET monitor: log UDP traffic involving extra-subnet cameras.

    Special attention: replies FROM 192.168.2.x TO port 54321 (or the SDK
    ephemeral port) prove that IOT2 cameras answer the relayed LanSearch.
    """
    try:
        pkt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except OSError as err:
        _LOGGER.error("LAN RELAY: AF_PACKET monitor FAILED: %s", err)
        return
    pkt.settimeout(1.0)
    _LOGGER.info("LAN RELAY: AF_PACKET monitor started")
    stats = {"total": 0, "iot2_reply": 0, "iot2_any": 0, "last_report": time.time(), "last_portdump": 0}
    last = None
    while not stop.is_set():
        try:
            frame = pkt.recv(65535)
        except socket.timeout:
            # Periodic UDP port table dump (who listens on what) — every 30s,
            # independent of traffic counters.
            try:
                if time.time() - stats["last_portdump"] >= 30:
                    stats["last_portdump"] = time.time()
                    with open("/proc/net/udp") as fh:
                        lines = fh.read().splitlines()[1:]
                    ports = []
                    for line in lines:
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        local = parts[1]
                        st = parts[3]
                        if st == "07":  # UDP_LISTEN
                            addr, port = local.rsplit(":", 1)
                            ip = ".".join(str(int(addr[i:i + 2], 16)) for i in (6, 4, 2, 0))
                            ports.append(f"{ip}:{int(port, 16)}")
                    _LOGGER.info("LAN RELAY: PORTDUMP udp_listen=%s", sorted(ports))
            except OSError:
                pass
            continue
        except OSError:
            continue
        udp = parse_udp(frame)
        if not udp:
            continue
        src_ip, src_port, dst_ip, dst_port, ulen = udp
        stats["total"] += 1
        # "extra" here = ONLY the non-local subnets (IOT2 192.168.2.x etc.),
        # excluding the local 192.168.1.x segment (IOT cameras streaming).
        src_extra = src_ip.startswith("192.168.2.") or src_ip.startswith("192.168.0.") or src_ip.startswith("192.168.8.")
        if src_extra:
            stats["iot2_any"] += 1
            # A reply from IOT2 camera to our host on ANY local port
            # (SDK ephemeral port after source spoofing, or 54321).
            if dst_ip == "192.168.1.214":
                stats["iot2_reply"] += 1
            now = time.time()
            if now - stats["last_report"] > 30:
                stats["last_report"] = now
                _LOGGER.info("LAN RELAY: MONITOR total=%d iot2_any=%d iot2_reply=%d last=%s:%d->%s:%d len=%d",
                             stats["total"], stats["iot2_any"], stats["iot2_reply"],
                             src_ip, src_port, dst_ip, dst_port, ulen)


def main():
    _LOGGER.info("LAN RELAY: main() started")
    subnets = [s.strip() for s in os.getenv("MILOCO_LAN_SUBNETS", "").split(",") if s.strip()]
    targets = resolve_targets(subnets)
    extra_prefixes = [".".join(s.split(".")[:3]) + "." for s in subnets]
    _LOGGER.info("LAN RELAY: relaying LanSearch to %d known targets: %s", len(targets), targets)

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

    # AF_PACKET monitor thread.
    import threading
    stop = threading.Event()
    mon = threading.Thread(target=packet_monitor, args=(extra_prefixes, stop), daemon=True)
    mon.start()

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
            try:
                with open("/proc/net/udp") as fh:
                    lines = fh.read().splitlines()[1:]
                ports = []
                for line in lines:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    local = parts[1]
                    st = parts[3]
                    if st == "07":  # UDP_LISTEN
                        addr_h, port_h = local.rsplit(":", 1)
                        ip = ".".join(str(int(addr_h[i:i + 2], 16)) for i in (6, 4, 2, 0))
                        ports.append(f"{ip}:{int(port_h, 16)}")
                port_str = ",".join(sorted(ports))
            except OSError:
                port_str = "?"
            _LOGGER.info("LAN RELAY: stats seen=%d fwd=%d last_src=%s:%s len=%d udp_listen=%s",
                         stats["seen"], stats["fwd"], src_ip, src_port, len(data), port_str)
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
