"""DNS, WHOIS, and network recon utilities."""

from __future__ import annotations

import socket
import subprocess
from datetime import datetime
from typing import Any

import dns.resolver
import dns.zone
import whois

from lib.utils import console

DNS_RESOLVER = "8.8.8.8"

# Services commonly vulnerable to subdomain takeover
TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages",
    "github.com": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku",
    "azurewebsites.net": "Azure",
    "cloudapp.net": "Azure",
    "cloudapp.azure.com": "Azure",
    "blob.core.windows.net": "Azure Blob",
    "cloudfront.net": "CloudFront",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "teamwork.com": "Teamwork",
    "helpjuice.com": "Helpjuice",
    "helpscoutdocs.com": "Help Scout",
    "pingdom.com": "Pingdom",
    "tictail.com": "Tictail",
    "campaign-monitor.com": "Campaign Monitor",
    "digitalocean.com": "DigitalOcean",
    "pageserve.co": "PageServe",
    "sendgrid.net": "SendGrid",
    "statuspage.io": "Statuspage",
    "amazonaws.com": "AWS",
    "wordpress.com": "WordPress.com",
    "wpengine.com": "WP Engine",
    "unbouncepages.com": "Unbounce",
    "tumblr.com": "Tumblr",
    "datadoghq.com": "Datadog",
    "pagerduty.com": "PagerDuty",
    "domain.buy": "BuyDomains",
}


def dns_lookup(domain: str) -> dict[str, Any]:
    """Perform comprehensive DNS lookups."""
    records: dict[str, Any] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

    for rtype in record_types:
        try:
            if rtype == "PTR":
                ip = socket.gethostbyname(domain)
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                    records[rtype] = [ptr]
                except socket.herror:
                    records[rtype] = None
                continue

            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            if rtype == "MX":
                mx_records = []
                for r in answers:
                    ex = str(r.exchange).rstrip(".")
                    if not ex or ex == ".":
                        ex = "root"
                    mx_records.append(f"{ex} (priority {r.preference})")
                records[rtype] = mx_records if mx_records else None
            elif rtype == "SOA":
                r = answers[0]
                records[rtype] = f"{r.mname} serial:{r.serial}"
            else:
                records[rtype] = [str(r) for r in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.Timeout,
            dns.exception.DNSException,
        ):
            records[rtype] = None
    return records


def check_zone_transfer(domain: str) -> dict[str, Any]:
    """Check for DNS zone transfer vulnerability (AXFR)."""
    result: dict[str, Any] = {"vulnerable": False, "records": [], "error": None}
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        for ns in ns_answers:
            ns_name = str(ns).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain, timeout=5))
                result["vulnerable"] = True
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        result["records"].append(f"{name} {rdataset}")
            except Exception as exc:
                if result["error"] is None:
                    result["error"] = f"{ns_name}: {exc}"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_subdomain_takeover(domain: str) -> list[dict[str, Any]]:
    """Check for potential subdomain takeover vulnerabilities."""
    findings: list[dict[str, Any]] = []
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
        for rdata in answers:
            cname = str(rdata.target).rstrip(".").lower()
            for svc_domain, svc_name in TAKEOVER_SERVICES.items():
                if svc_domain in cname:
                    # Check if the CNAME target resolves
                    try:
                        socket.gethostbyname(cname)
                    except socket.gaierror:
                        findings.append(
                            {
                                "type": "CNAME dangling",
                                "cname": cname,
                                "service": svc_name,
                                "risk": "Potential subdomain takeover",
                            }
                        )
                    break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        pass

    # Also check NS records for dangling delegations
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        for ns in ns_answers:
            ns_name = str(ns).rstrip(".").lower()
            for svc_domain, svc_name in TAKEOVER_SERVICES.items():
                if svc_domain in ns_name:
                    try:
                        socket.gethostbyname(ns_name)
                    except socket.gaierror:
                        findings.append(
                            {
                                "type": "NS dangling",
                                "ns": ns_name,
                                "service": svc_name,
                                "risk": "Potential NS takeover",
                            }
                        )
                    break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        pass

    return findings


def check_dnssec(domain: str) -> dict[str, Any]:
    """Check DNSSEC status."""
    result: dict[str, Any] = {"enabled": False, "validated": False, "details": []}
    try:
        request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(request, DNS_RESOLVER, timeout=5)
        if response.flags & dns.flags.DO:
            result["enabled"] = True
        # Check for RRSIG
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                result["validated"] = True
                result["details"].append(f"RRSIG found for {rrset.name}")
        if not result["validated"] and result["enabled"]:
            result["details"].append("DNSSEC enabled but no RRSIG in response")
    except Exception as exc:
        result["details"].append(f"DNSSEC check error: {exc}")
    return result


def whois_lookup(domain: str) -> dict[str, Any]:
    """Fetch WHOIS information for a domain."""
    data: dict[str, Any] = {}
    try:
        w = whois.whois(domain)
        data["registrar"] = w.registrar or "N/A"
        data["creation_date"] = _fmt_date(w.creation_date)
        data["expiration_date"] = _fmt_date(w.expiration_date)
        data["updated_date"] = _fmt_date(w.updated_date)
        data["name_servers"] = (
            w.name_servers
            if isinstance(w.name_servers, list)
            else [w.name_servers]
            if w.name_servers
            else []
        )
        data["status"] = (
            w.status if isinstance(w.status, list) else [w.status] if w.status else []
        )
        data["emails"] = (
            w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
        )
        data["org"] = w.org or w.registrant_organization or "N/A"
        data["country"] = w.country or "N/A"
        data["state"] = w.state or "N/A"
        data["city"] = w.city or "N/A"
        data["dnssec"] = w.dnssec or "N/A"
    except Exception as exc:
        data["error"] = str(exc)
    return data


def traceroute(domain: str, max_hops: int = 20) -> list[dict[str, Any]]:
    """Perform traceroute and return parsed hops."""
    hops: list[dict[str, Any]] = []
    system = subprocess.run(["uname"], capture_output=True, text=True).stdout.strip()
    cmd = ["traceroute", "-m", str(max_hops), "-q", "1", domain]
    if system == "Linux":
        cmd = ["traceroute", "-m", str(max_hops), "-q", "1", "-n", domain]
    elif system == "Darwin":
        cmd = ["traceroute", "-m", str(max_hops), "-q", "1", domain]
    else:
        cmd = ["tracert", "-h", str(max_hops), domain]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("traceroute") or line.startswith("Tracing"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                hop_num = int(parts[0])
                host = parts[1] if not parts[1].startswith("*") else "*"
                time_ms = ""
                for p in parts:
                    if "ms" in p.lower() or (
                        p.replace(".", "", 1).isdigit() and float(p) < 10000
                    ):
                        time_ms = p
                        break
                hops.append({"hop": hop_num, "host": host, "time_ms": time_ms or "N/A"})
    except Exception as exc:
        console.print(f"[yellow]Traceroute failed: {exc}[/yellow]")
    return hops


def _fmt_date(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)
