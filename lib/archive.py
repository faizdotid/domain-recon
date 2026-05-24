"""Archive and content discovery utilities."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

import requests

from lib.utils import get_headers


def fetch_robots_txt(base_url: str) -> dict[str, Any]:
    """Fetch and parse robots.txt."""
    result: dict[str, Any] = {
        "url": f"{base_url}/robots.txt",
        "found": False,
        "content": [],
        "sitemaps": [],
    }
    try:
        resp = requests.get(result["url"], headers=get_headers(), timeout=10)
        if resp.status_code == 200:
            result["found"] = True
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    result["content"].append(line)
                    if line.lower().startswith("sitemap:"):
                        result["sitemaps"].append(line.split(":", 1)[1].strip())
    except requests.RequestException:
        pass
    return result


def fetch_sitemap(base_url: str, sitemap_url: str | None = None) -> dict[str, Any]:
    """Fetch and parse sitemap.xml."""
    url = sitemap_url or f"{base_url}/sitemap.xml"
    result: dict[str, Any] = {"url": url, "found": False, "urls": [], "error": None}
    try:
        resp = requests.get(url, headers=get_headers(), timeout=15)
        if resp.status_code == 200:
            result["found"] = True
            try:
                root = ET.fromstring(resp.content)
                # Handle both sitemapindex and urlset
                for elem in root.iter():
                    if elem.tag.endswith("loc"):
                        result["urls"].append(elem.text)
            except ET.ParseError as exc:
                result["error"] = f"XML parse error: {exc}"
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def fetch_wayback_urls(domain: str) -> list[str]:
    """Fetch known URLs from Wayback Machine."""
    urls: list[str] = []
    try:
        resp = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey",
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                # First row is header
                for row in data[1:]:
                    if len(row) > 2:
                        urls.append(row[2])
    except Exception:
        pass
    return urls[:50]  # Limit to first 50
