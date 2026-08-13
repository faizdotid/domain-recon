"""Advanced path probing with smart filtering and response analysis."""

from __future__ import annotations

import hashlib
from typing import Any

import requests

from lib.config import WORDLIST_PATHS
from lib.utils import get_headers


class PathProbe:
    """Probe common and sensitive paths with intelligent filtering."""

    def __init__(self, base_url: str, timeout: int = 12, threads: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self._404_signature: str | None = None
        self._404_length: int = 0

    def _get_404_signature(self) -> tuple[int, str]:
        """Fetch a known 404 page to establish baseline."""
        try:
            resp = requests.get(
                f"{self.base_url}/this-should-not-exist-404-test-{hashlib.md5(b'probe').hexdigest()}",
                headers=get_headers(),
                timeout=self.timeout,
                allow_redirects=False,
            )
            body = resp.text[:500]
            sig = hashlib.md5(body.encode()).hexdigest()
            return len(resp.content), sig
        except requests.RequestException:
            return 0, ""

    def _check(self, path: str) -> dict[str, Any] | None:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.get(
                url, headers=get_headers(), timeout=self.timeout, allow_redirects=False
            )
            length = len(resp.content)
            body_sample = resp.text[:500]
            body_sig = hashlib.md5(body_sample.encode()).hexdigest()
            content_type = resp.headers.get("Content-Type", "")

            # Skip if looks exactly like 404 page
            if self._404_signature and body_sig == self._404_signature:
                return None
            if (
                self._404_length
                and abs(length - self._404_length) < 10
                and resp.status_code == 200
            ):
                # Likely custom 404 masquerading as 200
                return None

            return {
                "path": path,
                "status": resp.status_code,
                "length": length,
                "content_type": content_type.split(";")[0],
                "location": resp.headers.get("Location", ""),
                "server": resp.headers.get("Server", ""),
                "title": self._extract_title(resp.text),
                "body_sig": body_sig,
            }
        except requests.RequestException:
            return None

    def _extract_title(self, text: str) -> str:
        import re

        m = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        return (m.group(1).strip()[:60] if m else "").replace("\n", " ")

    def probe_all(self) -> dict[str, Any]:
        """Probe all paths with smart filtering."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from rich.progress import Progress

        # Establish 404 baseline first
        self._404_length, self._404_signature = self._get_404_signature()

        found: dict[str, list[dict[str, Any]]] = {
            "accessible": [],
            "redirects": [],
            "forbidden": [],
            "auth_required": [],
            "server_error": [],
            "interesting": [],
        }

        with Progress() as progress:
            task = progress.add_task(
                "[cyan]Probing paths...", total=len(WORDLIST_PATHS)
            )
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._check, path): path for path in WORDLIST_PATHS
                }
                for future in as_completed(futures):
                    progress.advance(task)
                    res = future.result()
                    if not res:
                        continue
                    s = res["status"]
                    if s == 200:
                        found["accessible"].append(res)
                    elif 300 <= s < 400:
                        found["redirects"].append(res)
                    elif s == 401 or s == 407:
                        found["auth_required"].append(res)
                    elif s == 403:
                        found["forbidden"].append(res)
                    elif 500 <= s < 600:
                        found["server_error"].append(res)
                    elif s in (405, 406, 409, 410, 418, 429):
                        found["interesting"].append(res)

        return found
