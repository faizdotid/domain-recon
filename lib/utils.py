"""Utility helpers for DomainRecon."""

from __future__ import annotations

import hashlib
import re
import socket
import urllib.parse
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_banner():
    """Print the application banner using Rich."""
    banner_text = Text()
    banner_text.append(
        "╔═══════════════════════════════════════════════════════════╗\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║  ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗      ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║  ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║      ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║  ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║      ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║  ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║      ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║      ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝      ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "║           R E C O N N A I S S A N C E   T O O L          ║\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "╚═══════════════════════════════════════════════════════════╝\n",
        style="bold bright_cyan",
    )
    banner_text.append(
        "                 Advanced Domain Scanner                    ",
        style="dim italic",
    )
    console.print(Panel(banner_text, border_style="bright_cyan", padding=(0, 2)))


def clean_url(url: str) -> str:
    """Normalize and clean a URL/domain string."""
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or parsed.netloc or parsed.path
    return host[4:] if host.startswith("www.") else host


def get_ip(domain: str) -> str:
    """Resolve domain to IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"


def is_valid_domain(domain: str) -> bool:
    """Basic domain validation."""
    pattern = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$"
    )
    return bool(pattern.match(domain))


def favicon_hash(data: bytes) -> str:
    """Compute MD5 hash of favicon data (commonly used in OSINT/Shodan-like tools)."""
    return hashlib.md5(data).hexdigest()


def get_headers(
    agent: str | None = None, extra: dict[str, str] | None = None
) -> dict[str, str]:
    """Build a standard request header dict."""
    headers: dict[str, str] = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if agent:
        headers["User-Agent"] = agent
    if extra:
        headers.update(extra)
    return headers


_RICH_TAGS = re.compile(r"\[/?[^\[\]]*\]")


def strip_markup(text: str) -> str:
    """Remove Rich markup tags from a string."""
    return _RICH_TAGS.sub("", text)


def make_table(title: str, columns: list[tuple[str, str]]) -> Any:
    """Helper to create a styled Rich Table."""
    from rich import box
    from rich.table import Table

    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_black",
        padding=(0, 1),
        expand=False,
    )
    for name, style in columns:
        table.add_column(name, style=style, overflow="fold")
    return table
