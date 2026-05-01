#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scapy.all import ICMP, ICMPv6EchoRequest, IP, IPv6, TCP, UDP, conf, get_if_addr, get_if_list, in6_getifaddr, sniff
from scapy.error import Scapy_Exception


@dataclass(slots=True)
class IDSConfig:
    iface: str | None
    log_file: Path
    port_scan_threshold: int
    port_scan_window: int
    frequency_threshold: int
    frequency_window: int
    alert_cooldown: int
    preview_packets: int
    status_interval: int


@dataclass(slots=True, frozen=True)
class RequestInfo:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    ip_version: int


@dataclass(slots=True, frozen=True)
class PacketInfo:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    ip_version: int


class IntrusionDetector:
    def __init__(self, config: IDSConfig) -> None:
        self.config = config
        self.active_iface = config.iface or str(conf.iface)
        self.local_ipv4s, self.local_ipv6s = get_local_addresses(self.active_iface)
        self.local_ips = self.local_ipv4s | self.local_ipv6s
        self.request_history: dict[str, deque[float]] = defaultdict(deque)
        self.port_history: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self.last_alert_time: dict[tuple[str, str], float] = {}
        self.start_time = time.time()
        self.last_status_time = self.start_time
        self.total_local_packets = 0
        self.total_relevant_packets = 0
        self.alert_count = 0
        self.previewed_packets = 0
        self.ip_version_counts: dict[int, int] = defaultdict(int)
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.config.log_file.touch(exist_ok=True)

    def process_packet(self, packet) -> None:
        if not packet.haslayer(IP) and not packet.haslayer(IPv6):
            return

        packet_info = self._extract_packet_info(packet)
        if packet_info is not None and self._is_local_traffic(packet_info):
            now = time.time()
            self._record_packet_observation(packet_info, now)
            if packet_info.protocol in {"tcp", "udp", "icmp"}:
                self._track_high_frequency(
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    now=now,
                )

        request = self._extract_request(packet)
        if request is None:
            return

        if not self._should_analyze(request):
            return

        now = time.time()
        self._record_request_capture(request, now)

        if request.dst_port is not None:
            self._track_port_scan(
                src_ip=request.src_ip,
                dst_ip=request.dst_ip,
                dst_port=request.dst_port,
                now=now,
            )

    def _extract_request(self, packet) -> RequestInfo | None:
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        src_ip = normalize_ip(str(ip_layer.src))
        dst_ip = normalize_ip(str(ip_layer.dst))
        ip_version = 4 if packet.haslayer(IP) else 6

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = int(tcp_layer.flags)
            syn_set = bool(flags & 0x02)
            ack_set = bool(flags & 0x10)

            if syn_set and not ack_set:
                return RequestInfo(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(tcp_layer.sport),
                    dst_port=int(tcp_layer.dport),
                    protocol="tcp",
                    ip_version=ip_version,
                )
            return None

        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            return RequestInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(udp_layer.sport),
                dst_port=int(udp_layer.dport),
                protocol="udp",
                ip_version=ip_version,
            )

        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            if int(icmp_layer.type) == 8:
                return RequestInfo(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=None,
                    dst_port=None,
                    protocol="icmp",
                    ip_version=ip_version,
                )

        if packet.haslayer(ICMPv6EchoRequest):
            return RequestInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=None,
                dst_port=None,
                protocol="icmp",
                ip_version=ip_version,
            )

        return None

    def _extract_packet_info(self, packet) -> PacketInfo | None:
        ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        src_ip = normalize_ip(str(ip_layer.src))
        dst_ip = normalize_ip(str(ip_layer.dst))
        ip_version = 4 if packet.haslayer(IP) else 6

        if packet.haslayer(TCP):
            return PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(packet[TCP].sport),
                dst_port=int(packet[TCP].dport),
                protocol="tcp",
                ip_version=ip_version,
            )

        if packet.haslayer(UDP):
            return PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(packet[UDP].sport),
                dst_port=int(packet[UDP].dport),
                protocol="udp",
                ip_version=ip_version,
            )

        if packet.haslayer(ICMP) or packet.haslayer(ICMPv6EchoRequest):
            return PacketInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=None,
                dst_port=None,
                protocol="icmp",
                ip_version=ip_version,
            )

        return PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=None,
            protocol="ip",
            ip_version=ip_version,
        )

    def _should_analyze(self, request: RequestInfo) -> bool:
        try:
            src_addr = ipaddress.ip_address(request.src_ip)
            dst_addr = ipaddress.ip_address(request.dst_ip)
        except ValueError:
            return True

        if src_addr.is_multicast or dst_addr.is_multicast:
            return False

        if src_addr.is_unspecified or dst_addr.is_unspecified:
            return False

        if src_addr.is_loopback or dst_addr.is_loopback:
            return False

        if src_addr.is_link_local and dst_addr.is_link_local:
            return False

        if self.local_ips and request.src_ip not in self.local_ips and request.dst_ip not in self.local_ips:
            return False

        return True

    def _is_local_traffic(self, packet_info: PacketInfo) -> bool:
        if self.local_ips and packet_info.src_ip not in self.local_ips and packet_info.dst_ip not in self.local_ips:
            return False

        try:
            src_addr = ipaddress.ip_address(packet_info.src_ip)
            dst_addr = ipaddress.ip_address(packet_info.dst_ip)
        except ValueError:
            return True

        if src_addr.is_multicast or dst_addr.is_multicast:
            return False
        if src_addr.is_unspecified or dst_addr.is_unspecified:
            return False
        if src_addr.is_loopback or dst_addr.is_loopback:
            return False
        return True

    def _record_packet_observation(self, packet_info: PacketInfo, now: float) -> None:
        self.total_local_packets += 1
        self.ip_version_counts[packet_info.ip_version] += 1
        self.protocol_counts[packet_info.protocol] += 1

        if self.previewed_packets < self.config.preview_packets:
            timestamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            direction = self._direction_from_endpoints(packet_info.src_ip, packet_info.dst_ip)
            flow = format_flow(
                src_ip=packet_info.src_ip,
                src_port=packet_info.src_port,
                dst_ip=packet_info.dst_ip,
                dst_port=packet_info.dst_port,
            )
            print(
                f"[{timestamp}] CAPTURE | {direction} | IPv{packet_info.ip_version} | "
                f"{packet_info.protocol.upper()} | {flow}",
                flush=True,
            )
            self.previewed_packets += 1

        self._maybe_print_status(now)

    def _record_request_capture(self, request: RequestInfo, now: float) -> None:
        self.total_relevant_packets += 1

    def _maybe_print_status(self, now: float) -> None:
        if self.config.status_interval <= 0:
            return

        if (now - self.last_status_time) < self.config.status_interval:
            return

        timestamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        runtime = max(1, int(now - self.start_time))
        print(
            f"[{timestamp}] STATUS | local_packets={self.total_local_packets} | "
            f"relevant_requests={self.total_relevant_packets} | "
            f"alerts={self.alert_count} | ipv4={self.ip_version_counts.get(4, 0)} | "
            f"ipv6={self.ip_version_counts.get(6, 0)} | tcp={self.protocol_counts.get('tcp', 0)} | "
            f"udp={self.protocol_counts.get('udp', 0)} | icmp={self.protocol_counts.get('icmp', 0)} | "
            f"uptime={runtime}s",
            flush=True,
        )
        self.last_status_time = now

    def _direction_from_endpoints(self, src_ip: str, dst_ip: str) -> str:
        src_local = src_ip in self.local_ips
        dst_local = dst_ip in self.local_ips
        if src_local and not dst_local:
            return "OUTBOUND"
        if dst_local and not src_local:
            return "INBOUND"
        if src_local and dst_local:
            return "LOCAL"
        return "TRANSIT"

    def _track_high_frequency(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int | None,
        dst_port: int | None,
        now: float,
    ) -> None:
        if dst_port == 443 or src_port == 443:
            return
        if src_ip in self.local_ips:
            return
        history = self.request_history[src_ip]
        history.append(now)
        self._prune_timestamps(history, now, self.config.frequency_window)

        if len(history) < self.config.frequency_threshold:
            return

        if not self._cooldown_passed(src_ip, "HIGH_FREQUENCY", now):
            return

        details = (
            f"{len(history)} packets seen in {self.config.frequency_window}s "
            f"(latest flow: {format_flow(src_ip, src_port, dst_ip, dst_port)})"
        )
        self._alert(
            src_ip=src_ip,
            alert_type="HIGH_FREQUENCY",
            details=details,
            now=now,
            dst_ip=dst_ip,
        )

    def _track_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, now: float) -> None:
        key = (src_ip, dst_ip)
        history = self.port_history[key]
        history.append((now, dst_port))
        self._prune_port_history(history, now, self.config.port_scan_window)

        unique_ports = sorted({port for _, port in history})
        if len(unique_ports) < self.config.port_scan_threshold:
            return

        if not self._cooldown_passed(src_ip, "PORT_SCAN", now):
            return

        preview = ", ".join(str(port) for port in unique_ports[:10])
        details = (
            f"contacted {len(unique_ports)} unique ports on {dst_ip} in "
            f"{self.config.port_scan_window}s (ports: {preview})"
        )
        self._alert(
            src_ip=src_ip,
            alert_type="PORT_SCAN",
            details=details,
            now=now,
            dst_ip=dst_ip,
        )

    @staticmethod
    def _prune_timestamps(history: deque[float], now: float, window: int) -> None:
        while history and (now - history[0]) > window:
            history.popleft()

    @staticmethod
    def _prune_port_history(history: deque[tuple[float, int]], now: float, window: int) -> None:
        while history and (now - history[0][0]) > window:
            history.popleft()

    def _cooldown_passed(self, src_ip: str, alert_type: str, now: float) -> bool:
        key = (src_ip, alert_type)
        last_time = self.last_alert_time.get(key)
        if last_time is not None and (now - last_time) < self.config.alert_cooldown:
            return False

        self.last_alert_time[key] = now
        return True

    def _alert(
        self,
        src_ip: str,
        alert_type: str,
        details: str,
        now: float,
        dst_ip: str | None = None,
    ) -> None:
        timestamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        self.alert_count += 1
        direction_text = ""
        if dst_ip is not None:
            direction = self._direction_from_endpoints(src_ip, dst_ip)
            direction_text = f" | Direction: {direction}"
        message = (
            f"[{timestamp}] ALERT | {alert_type}{direction_text} | Source IP: {src_ip} | {details}"
        )
        print(message, flush=True)

        with self.config.log_file.open("a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")

    def print_final_summary(self) -> None:
        runtime = max(1, int(time.time() - self.start_time))
        print(
            "Final summary: "
            f"local_packets={self.total_local_packets}, relevant_requests={self.total_relevant_packets}, "
            f"alerts={self.alert_count}, "
            f"ipv4={self.ip_version_counts.get(4, 0)}, ipv6={self.ip_version_counts.get(6, 0)}, "
            f"tcp={self.protocol_counts.get('tcp', 0)}, udp={self.protocol_counts.get('udp', 0)}, "
            f"icmp={self.protocol_counts.get('icmp', 0)}, uptime={runtime}s"
        )


def parse_args() -> IDSConfig:
    parser = argparse.ArgumentParser(
        description="Live Intrusion Detection System using Python and Scapy."
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Show available network interfaces and exit.",
    )
    parser.add_argument(
        "--iface",
        help="Network interface to sniff on. Use your active device interface such as en0, eth0, wlan0, or Wi-Fi.",
    )
    parser.add_argument(
        "--log-file",
        default="suspicious_activity.log",
        help="Path to the log file used for suspicious IP alerts.",
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=6,
        help="Number of unique destination ports that triggers a port scan alert.",
    )
    parser.add_argument(
        "--port-scan-window",
        type=int,
        default=15,
        help="Time window in seconds for port scan detection.",
    )
    parser.add_argument(
        "--frequency-threshold",
        type=int,
        default=15,
        help="Number of packets within the window that triggers a high-frequency alert.",
    )
    parser.add_argument(
        "--frequency-window",
        type=int,
        default=10,
        help="Time window in seconds for high-frequency detection.",
    )
    parser.add_argument(
        "--alert-cooldown",
        type=int,
        default=15,
        help="Cooldown in seconds before the same IP can trigger the same alert again.",
    )
    parser.add_argument(
        "--preview-packets",
        type=int,
        default=20,
        help="Number of captured packets to preview on screen before switching to status-only output.",
    )
    parser.add_argument(
        "--status-interval",
        type=int,
        default=5,
        help="Seconds between live capture status updates. Use 0 to disable.",
    )
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in get_if_list():
            print(f"- {iface}")
        raise SystemExit(0)

    return IDSConfig(
        iface=args.iface,
        log_file=Path(args.log_file),
        port_scan_threshold=args.port_scan_threshold,
        port_scan_window=args.port_scan_window,
        frequency_threshold=args.frequency_threshold,
        frequency_window=args.frequency_window,
        alert_cooldown=args.alert_cooldown,
        preview_packets=max(0, args.preview_packets),
        status_interval=max(0, args.status_interval),
    )


def get_local_addresses(iface_name: str) -> tuple[set[str], set[str]]:
    ipv4_addresses: set[str] = set()
    ipv6_addresses: set[str] = set()

    try:
        ipv4_address = get_if_addr(iface_name)
        if ipv4_address and ipv4_address != "0.0.0.0":
            ipv4_addresses.add(normalize_ip(ipv4_address))
    except OSError:
        pass

    try:
        for ipv6_address, _, iface in in6_getifaddr():
            if iface == iface_name:
                ipv6_addresses.add(normalize_ip(ipv6_address))
    except OSError:
        pass

    return ipv4_addresses, ipv6_addresses


def normalize_ip(address: str) -> str:
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return address


def format_endpoint(ip_address_text: str, port: int | None) -> str:
    return f"{ip_address_text}:{port}" if port is not None else ip_address_text


def format_flow(src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None) -> str:
    return f"{format_endpoint(src_ip, src_port)} -> {format_endpoint(dst_ip, dst_port)}"


def print_startup(config: IDSConfig, detector: IntrusionDetector) -> None:
    print("Intrusion Detection System started.")
    print(f"Interface: {detector.active_iface}")
    print(
        "Local IPv4: "
        + (", ".join(sorted(detector.local_ipv4s)) if detector.local_ipv4s else "None detected")
    )
    print(
        "Local IPv6: "
        + (", ".join(sorted(detector.local_ipv6s)) if detector.local_ipv6s else "None detected")
    )
    print(f"Log file: {config.log_file}")
    print(
        "Port scan rule: "
        f"{config.port_scan_threshold} unique ports in {config.port_scan_window}s"
    )
    print(
        "High-frequency rule: "
        f"{config.frequency_threshold} packets in {config.frequency_window}s"
    )
    print(f"Packet preview count: {config.preview_packets}")
    print(f"Status interval: {config.status_interval}s")
    print("Press Ctrl+C to stop monitoring.\n")


def build_permission_hint(script_name: str, iface_name: str) -> str:
    system_name = platform.system()
    if system_name == "Windows":
        return (
            "Run the terminal as Administrator, make sure Npcap is installed, "
            f"and start the IDS using:\n  {sys.executable} {script_name} --iface \"{iface_name}\""
        )

    return (
        "Run the IDS with administrator/root privileges using:\n"
        f"  sudo {sys.executable} {script_name} --iface {iface_name}"
    )


def handle_capture_error(exc: Exception) -> int:
    message = str(exc)
    if "/dev/bpf" in message or "Permission denied" in message:
        script_name = Path(sys.argv[0]).name
        iface_name = "your-interface"
        if "--iface" in sys.argv:
            try:
                iface_name = sys.argv[sys.argv.index("--iface") + 1]
            except IndexError:
                pass
        print(
            "Live packet capture needs administrator/root privileges.\n"
            f"{build_permission_hint(script_name, iface_name)}",
            file=sys.stderr,
        )
        return 1

    print(f"Packet capture failed: {message}", file=sys.stderr)
    return 1


def main() -> int:
    config = parse_args()
    detector = IntrusionDetector(config)

    if platform.system() != "Windows" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Warning: Scapy live sniffing usually needs sudo/root privileges.\n")

    print_startup(config, detector)

    try:
        sniff(
            iface=config.iface,
            filter="ip or ip6",
            prn=detector.process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nIDS stopped.")
        detector.print_final_summary()
        return 0
    except (PermissionError, Scapy_Exception) as exc:
        return handle_capture_error(exc)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
