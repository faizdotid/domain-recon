"""Web reconnaissance: tech detection, WAF, headers, cookies with confidence scoring."""

from __future__ import annotations

import re
from typing import Any

import requests

from lib.config import TECH_FINGERPRINTS, USER_AGENTS, WAF_SIGNATURES
from lib.utils import clean_url, favicon_hash, get_headers


class WebRecon:
    """Comprehensive web reconnaissance scanner."""

    def __init__(self, domain: str, timeout: int = 15, follow_redirects: bool = True):
        self.domain = clean_url(domain)
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.url = f"http://{self.domain}"
        self.https_url = f"https://{self.domain}"
        self.response: requests.Response | None = None
        self.https_response: requests.Response | None = None
        self.error: str | None = None
        self.https_error: str | None = None

    def fetch(self, target_url: str | None = None, use_https: bool = False) -> bool:
        """Perform HTTP GET request."""
        url = target_url or (self.https_url if use_https else self.url)
        try:
            resp = requests.get(
                url,
                headers=get_headers(agent=USER_AGENTS[0]),
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
            )
            if use_https:
                self.https_response = resp
            else:
                self.response = resp
            return True
        except requests.RequestException as exc:
            if use_https:
                self.https_error = str(exc)
                self.https_response = None
            else:
                self.error = str(exc)
                self.response = None
            return False

    def get_status_code(self, use_https: bool = False) -> str:
        resp = self.https_response if use_https else self.response
        return str(resp.status_code) if resp else "N/A"

    def get_server(self, use_https: bool = False) -> str:
        resp = self.https_response if use_https else self.response
        return resp.headers.get("Server", "Unknown") if resp else "Unknown"

    def get_title(self, use_https: bool = False) -> str:
        resp = self.https_response if use_https else self.response
        if not resp:
            return "N/A"
        match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        title = match.group(1).strip() if match else "N/A"
        return title[:80]

    def get_meta(self, use_https: bool = False) -> dict[str, str]:
        """Extract meta description, keywords, generator, viewport."""
        resp = self.https_response if use_https else self.response
        meta: dict[str, str] = {}
        if not resp:
            return meta
        text = resp.text
        for name in [
            "description",
            "keywords",
            "generator",
            "viewport",
            "author",
            "theme-color",
        ]:
            pattern = re.compile(
                rf'<meta[^>]+name=["\']{name}["\'][^>]+content=["\']([^"\']+)',
                re.IGNORECASE,
            )
            m = pattern.search(text)
            if m:
                meta[name] = m.group(1).strip()[:200]
        og_pattern = re.compile(
            r'<meta[^>]+property=["\']og:([^"\']+)["\'][^>]+content=["\']([^"\']+)',
            re.IGNORECASE,
        )
        for m in og_pattern.findall(text):
            meta[f"og:{m[0]}"] = m[1].strip()[:200]
        twitter_pattern = re.compile(
            r'<meta[^>]+name=["\']twitter:([^"\']+)["\'][^>]+content=["\']([^"\']+)',
            re.IGNORECASE,
        )
        for m in twitter_pattern.findall(text):
            meta[f"twitter:{m[0]}"] = m[1].strip()[:200]
        return meta

    def get_content_length(self, use_https: bool = False) -> str:
        resp = self.https_response if use_https else self.response
        if not resp:
            return "N/A"
        length = resp.headers.get("Content-Length")
        if length is None:
            length = len(resp.content)
        return f"{int(length):,}"

    def detect_tech(self, use_https: bool = False) -> dict[str, float]:
        """Detect CMS/framework/technologies with confidence scores."""
        resp = self.https_response if use_https else self.response
        if not resp:
            return {}
        text = resp.text
        headers_str = str(resp.headers)
        cookies_dict = resp.cookies.get_dict()
        cookies_str = str(cookies_dict)

        scores: dict[str, float] = {}
        for name, indicators in TECH_FINGERPRINTS.items():
            score = 0.0
            # Body matches (weight 1.0 each)
            for sign in indicators["body"]:
                if sign.lower() in text.lower():
                    score += 1.0
            # Header matches (weight 1.5 each)
            for sign in indicators["headers"]:
                if sign.lower() in headers_str.lower():
                    score += 1.5
            # Cookie matches (weight 2.0 each)
            for sign in indicators["cookies"]:
                if sign.lower() in cookies_str.lower():
                    score += 2.0
            if score > 0:
                scores[name] = round(score, 1)
        # Normalize by sorting descending
        return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    def detect_waf(self, use_https: bool = False) -> list[str]:
        """Detect Web Application Firewall."""
        resp = self.https_response if use_https else self.response
        if not resp:
            return []
        combined = str(resp.headers) + str(resp.cookies.get_dict())
        detected = []
        for name, signs in WAF_SIGNATURES.items():
            if any(sign.lower() in combined.lower() for sign in signs):
                detected.append(name)
        return detected

    def check_security_headers(self, use_https: bool = False) -> dict[str, str]:
        """Evaluate security-related HTTP headers."""
        result: dict[str, str] = {}
        resp = self.https_response if use_https else self.response
        if not resp:
            return result
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = {
            "Strict-Transport-Security": "HSTS",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy",
            "Content-Security-Policy": "CSP",
            "X-XSS-Protection": "XSS Filter",
            "X-Permitted-Cross-Domain-Policies": "Cross-Domain Policy",
            "Expect-CT": "Expect-CT",
            "Feature-Policy": "Feature Policy",
        }

        for header, friendly in checks.items():
            value = headers.get(header.lower())
            if value:
                result[friendly] = f"[green]✔ {value[:80]}[/green]"
            else:
                result[friendly] = "[red]✘ Missing[/red]"
        return result

    def check_cors(self, use_https: bool = False) -> dict[str, Any]:
        """Check CORS configuration."""
        result: dict[str, Any] = {
            "enabled": False,
            "misconfigured": False,
            "details": [],
        }
        resp = self.https_response if use_https else self.response
        if not resp:
            return result

        headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        acah = headers.get("access-control-allow-headers")
        acam = headers.get("access-control-allow-methods")
        acaoe = headers.get("access-control-allow-origin-echo")

        if acao:
            result["enabled"] = True
            result["details"].append(f"Allow-Origin: {acao}")
            if acac:
                result["details"].append(f"Allow-Credentials: {acac}")
            if acah:
                result["details"].append(f"Allow-Headers: {acah[:80]}")
            if acam:
                result["details"].append(f"Allow-Methods: {acam}")
            if acaoe:
                result["details"].append(f"Allow-Origin-Echo: {acaoe}")
            if acao == "*" and acac:
                result["misconfigured"] = True
                result["details"].append(
                    "[red]Misconfiguration: wildcard + credentials[/red]"
                )
            if "null" in acao.lower():
                result["misconfigured"] = True
                result["details"].append(
                    "[red]Misconfiguration: null origin allowed[/red]"
                )
        return result

    def check_cookies(self, use_https: bool = False) -> list[dict[str, Any]]:
        """Analyze cookie security flags."""
        resp = self.https_response if use_https else self.response
        if not resp:
            return []
        cookies: list[dict[str, Any]] = []
        header_cookies = [
            v for k, v in resp.headers.items() if k.lower() == "set-cookie"
        ]

        for cookie in resp.cookies:
            flags = []
            if cookie.secure:
                flags.append("Secure")
            cookie_header = ""
            for h in header_cookies:
                if h.startswith(cookie.name + "="):
                    cookie_header = h
                    break
            if "httponly" in cookie_header.lower():
                flags.append("HttpOnly")
            if "samesite" in cookie_header.lower():
                ss_match = re.search(r"samesite=([^;]+)", cookie_header, re.IGNORECASE)
                if ss_match:
                    flags.append(f"SameSite={ss_match.group(1)}")
            cookies.append(
                {
                    "name": cookie.name,
                    "value": (cookie.value[:30] + "...")
                    if len(cookie.value) > 30
                    else cookie.value,
                    "flags": ", ".join(flags)
                    if flags
                    else "[red]No security flags[/red]",
                }
            )
        return cookies

    def get_favicon(self) -> dict[str, Any]:
        """Fetch and hash favicon.ico from both HTTP and HTTPS."""
        result: dict[str, Any] = {
            "url": f"{self.https_url}/favicon.ico",
            "hash": None,
            "size": 0,
            "status": "N/A",
        }
        for url in [f"{self.https_url}/favicon.ico", f"{self.url}/favicon.ico"]:
            try:
                resp = requests.get(
                    url,
                    headers=get_headers(),
                    timeout=10,
                    allow_redirects=True,
                )
                result["status"] = resp.status_code
                if resp.status_code == 200:
                    result["size"] = len(resp.content)
                    result["hash"] = favicon_hash(resp.content)
                    result["url"] = url
                    break
            except requests.RequestException:
                pass
        return result

    def test_http_methods(self) -> dict[str, Any]:
        """Test allowed HTTP methods."""
        from lib.config import HTTP_METHODS

        result: dict[str, Any] = {"allowed": [], "denied": [], "errors": []}
        for method in HTTP_METHODS:
            try:
                resp = requests.request(
                    method,
                    self.url,
                    headers=get_headers(),
                    timeout=10,
                    allow_redirects=False,
                )
                if resp.status_code < 400:
                    result["allowed"].append((method, resp.status_code))
                else:
                    result["denied"].append((method, resp.status_code))
            except Exception:
                result["errors"].append(method)
        return result

    def check_redirect_chain(self) -> list[str]:
        """Analyze redirect chain."""
        if not self.response:
            return []
        chain = []
        if self.response.history:
            for r in self.response.history:
                chain.append(f"{r.status_code} → {r.url}")
        chain.append(f"{self.response.status_code} → {self.response.url}")
        return chain

    def grab_banner(self, use_https: bool = False) -> str:
        """Grab server banner from headers."""
        resp = self.https_response if use_https else self.response
        if not resp:
            return "N/A"
        banner = resp.headers.get("Server", "")
        via = resp.headers.get("Via", "")
        xpowered = resp.headers.get("X-Powered-By", "")
        xhandler = resp.headers.get("X-Handler", "")
        parts = [p for p in [banner, via, xpowered, xhandler] if p]
        return " | ".join(parts) if parts else "N/A"

    def check_wappalyzer_style(self) -> dict[str, list[tuple[str, float]]]:
        """Return categorized tech stack with confidence scores."""
        techs = self.detect_tech()
        cats: dict[str, list[tuple[str, float]]] = {
            "CMS / Platform": [],
            "Framework": [],
            "Frontend": [],
            "Server / CDN": [],
            "Language / Runtime": [],
            "Other": [],
        }
        cms = {
            "WordPress",
            "Joomla",
            "Drupal",
            "Magento",
            "Shopify",
            "PrestaShop",
            "Ghost",
            "phpBB",
            "vBulletin",
            "MediaWiki",
        }
        frameworks = {
            "Laravel",
            "Symfony",
            "CodeIgniter",
            "Django",
            "Flask",
            "Ruby on Rails",
            "Express.js",
            "Next.js",
            "Nuxt.js",
            "Gatsby",
            "Spring Boot",
        }
        frontend = {"React", "Vue.js", "Angular", "Bootstrap", "Tailwind CSS", "jQuery"}
        server = {
            "nginx",
            "Apache",
            "IIS",
            "Cloudflare",
            "Akamai",
            "Fastly",
            "CDN77",
            "Tomcat",
            "Jetty",
        }
        lang = {"Node.js", "phpinfo", "ASP.NET", "PHP"}

        for t, score in techs.items():
            item = (t, score)
            if t in cms:
                cats["CMS / Platform"].append(item)
            elif t in frameworks:
                cats["Framework"].append(item)
            elif t in frontend:
                cats["Frontend"].append(item)
            elif t in server:
                cats["Server / CDN"].append(item)
            elif t in lang:
                cats["Language / Runtime"].append(item)
            else:
                cats["Other"].append(item)
        return cats
