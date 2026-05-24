"""Subdomain and reverse IP enumeration via external APIs."""

from __future__ import annotations

import requests

from lib.config import USER_AGENTS
from lib.utils import clean_url, console, get_headers


class DomainEnumerator:
    """Enumerate subdomains or reverse IP using HackerTarget APIs."""

    API_REVERSE = "https://api.hackertarget.com/reverseiplookup/?q={}"
    API_SUBDOMAIN = "https://api.hackertarget.com/hostsearch/?q={}"

    def __init__(self, domain: str):
        self.domain = clean_url(domain)
        self.results: list[str] = []

    def _fetch(self, api_url: str) -> str | None:
        try:
            resp = requests.get(
                api_url, headers=get_headers(agent=USER_AGENTS[0]), timeout=70
            )
            text = resp.text
            if "error" in text.lower() or "api count exceeded" in text.lower():
                return None
            return text
        except requests.RequestException:
            console.print("[red]Network error while fetching API data.[/red]")
            return None

    def reverse_ip(self, ip: str) -> list[str]:
        text = self._fetch(self.API_REVERSE.format(ip))
        if text:
            self.results = [line.strip() for line in text.splitlines() if line.strip()]
        return self.results

    def subdomain(self) -> list[str]:
        text = self._fetch(self.API_SUBDOMAIN.format(self.domain))
        if text:
            self.results = []
            for line in text.splitlines():
                if "," in line:
                    self.results.append(line.split(",")[0].strip())
                else:
                    self.results.append(line.strip())
        return self.results
