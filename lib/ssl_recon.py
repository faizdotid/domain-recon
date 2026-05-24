"""SSL/TLS deep analysis utilities."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any


def ssl_info(domain: str, port: int = 443) -> dict[str, Any]:
    """Fetch SSL/TLS certificate details with fallback."""
    data: dict[str, Any] = {}

    def _fetch(verify: bool = True) -> None:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(
                sock, server_hostname=domain if verify else None
            ) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                data["subject"] = _parse_field(cert.get("subject"))
                data["issuer"] = _parse_field(cert.get("issuer"))
                data["not_before"] = cert.get("notBefore")
                data["not_after"] = cert.get("notAfter")
                data["serial"] = cert.get("serialNumber")
                data["version"] = version
                data["cipher"] = cipher[0] if cipher else "N/A"
                data["san"] = cert.get("subjectAltName", [])
                data["expired"] = _is_expired(cert.get("notAfter"))
                data["tls_version"] = version
                if not verify:
                    data["warning"] = (
                        "Certificate verification disabled (self-signed/invalid)"
                    )

    try:
        _fetch(verify=True)
    except ssl.SSLError:
        try:
            _fetch(verify=False)
        except Exception as exc:
            data["error"] = f"SSL Error: {exc}"
    except socket.error as exc:
        data["error"] = f"Connection Error: {exc}"
    except Exception as exc:
        data["error"] = f"Error: {exc}"
    return data


def test_ssl_versions(domain: str, port: int = 443) -> dict[str, Any]:
    """Test supported TLS/SSL versions."""
    versions = {
        "TLS 1.3": ssl.TLSVersion.TLSv1_3
        if hasattr(ssl.TLSVersion, "TLSv1_3")
        else None,
        "TLS 1.2": ssl.TLSVersion.TLSv1_2
        if hasattr(ssl.TLSVersion, "TLSv1_2")
        else None,
        "TLS 1.1": ssl.TLSVersion.TLSv1_1
        if hasattr(ssl.TLSVersion, "TLSv1_1")
        else None,
        "TLS 1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
    }
    supported: dict[str, str] = {}
    for name, ver in versions.items():
        if ver is None:
            supported[name] = "N/A"
            continue
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ver
        ctx.maximum_version = ver
        try:
            with socket.create_connection((domain, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    supported[name] = "Supported"
        except Exception:
            supported[name] = "Not Supported"
    return supported


def _parse_field(field: Any) -> str:
    if not field:
        return "N/A"
    parts = []
    if isinstance(field, list):
        for item in field:
            if isinstance(item, tuple) and len(item) >= 2:
                parts.append(f"{item[0]}={item[1]}")
            elif isinstance(item, list):
                for sub in item:
                    if isinstance(sub, tuple) and len(sub) >= 2:
                        parts.append(f"{sub[0]}={sub[1]}")
    elif isinstance(field, tuple):
        parts.append(str(field))
    return ", ".join(parts) if parts else str(field)


def _is_expired(not_after: str | None) -> bool:
    if not not_after:
        return False
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return dt < datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    except ValueError:
        return False
