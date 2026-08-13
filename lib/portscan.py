"""High-speed TCP + UDP port scanner with service fingerprinting."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from rich.progress import Progress

from lib.config import SERVICE_NAMES, SERVICE_PROBES


def _grab_banner(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """Attempt to connect and grab service banner with probes."""
    banner = ""
    is_open = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            is_open = True
            # Send service-specific probe if available
            probe = SERVICE_PROBES.get(port)
            if probe:
                try:
                    sock.sendall(probe)
                except OSError:
                    pass
            try:
                sock.settimeout(timeout)
                data = sock.recv(2048)
                if data:
                    decoded = data.decode("utf-8", errors="ignore").strip()
                    if decoded:
                        banner = decoded.replace("\r", " ").replace("\n", " | ")[:300]
            except (socket.timeout, UnicodeDecodeError):
                pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return is_open, banner


def _scan_tcp_port(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Scan a single TCP port."""
    is_open, banner = _grab_banner(host, port, timeout)
    if not is_open:
        return None
    service = SERVICE_NAMES.get(port, "Unknown")
    # Try to infer service from banner if unknown
    if service == "Unknown" and banner:
        bl = banner.lower()
        if "ssh" in bl:
            service = "SSH"
        elif "ftp" in bl:
            service = "FTP"
        elif "smtp" in bl:
            service = "SMTP"
        elif "http" in bl or "html" in bl:
            service = "HTTP"
        elif "pop3" in bl:
            service = "POP3"
        elif "imap" in bl:
            service = "IMAP"
        elif "mysql" in bl:
            service = "MySQL"
        elif "microsoft-iis" in bl:
            service = "IIS"
        elif "nginx" in bl:
            service = "nginx"
        elif "apache" in bl:
            service = "Apache"
        elif "rdp" in bl or "remote desktop" in bl:
            service = "RDP"
        elif "sip" in bl:
            service = "SIP"
    return {
        "port": port,
        "protocol": "tcp",
        "service": service,
        "open": True,
        "banner": banner,
    }


def _scan_udp_port(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    """Scan a single UDP port."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Send a small payload depending on port
        payload = b"\x00" * 8
        if port == 53:
            payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        elif port == 123:
            payload = b"\x1b" + b"\x00" * 47
        elif port == 161:
            payload = (
                b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"
                b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02"
                b"\x01\x01\x01\x00\x05\x00"
            )
        elif port == 69:
            payload = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        elif port == 137:
            payload = (
                b"\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b"
                b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                b"\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
            )
        elif port == 1434:
            payload = b"\x02"
        elif port == 1900:
            payload = (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b'MAN: "ssdp:discover"\r\n'
                b"MX: 1\r\n"
                b"ST: ssdp:all\r\n\r\n"
            )
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(2048)
        banner = (
            data.decode("utf-8", errors="ignore")
            .strip()
            .replace("\r", " ")
            .replace("\n", " | ")[:300]
        )
        service = SERVICE_NAMES.get(port, "Unknown")
        return {
            "port": port,
            "protocol": "udp",
            "service": service,
            "open": True,
            "banner": banner,
        }
    except socket.timeout:
        # For UDP, no response doesn't mean closed - some services are stealthy
        return None
    except OSError:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def scan_ports(
    host: str,
    tcp_ports: list[int] | None = None,
    udp_ports: list[int] | None = None,
    max_workers: int = 150,
    timeout: float = 1.5,
) -> list[dict[str, Any]]:
    """Scan TCP and UDP ports using multi-threading."""
    open_ports: list[dict[str, Any]] = []
    tcp_ports = tcp_ports or []
    udp_ports = udp_ports or []
    total = len(tcp_ports) + len(udp_ports)

    if total == 0:
        return open_ports

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=total)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for p in tcp_ports:
                futures[executor.submit(_scan_tcp_port, host, p, timeout)] = p
            for p in udp_ports:
                futures[executor.submit(_scan_udp_port, host, p, timeout)] = p

            for future in as_completed(futures):
                progress.advance(task)
                res = future.result()
                if res:
                    open_ports.append(res)

    open_ports.sort(key=lambda x: (x["protocol"], x["port"]))
    return open_ports
