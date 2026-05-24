#!/usr/bin/env python3
"""DomainRecon - Advanced Domain Reconnaissance Tool."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from lib.archive import fetch_robots_txt, fetch_sitemap, fetch_wayback_urls
from lib.config import TOP_PORTS_TCP, TOP_PORTS_UDP
from lib.dns_recon import (
    check_dnssec,
    check_subdomain_takeover,
    check_zone_transfer,
    dns_lookup,
    traceroute,
    whois_lookup,
)
from lib.enumerator import DomainEnumerator
from lib.portscan import scan_ports
from lib.probe import PathProbe
from lib.ssl_recon import ssl_info, test_ssl_versions
from lib.utils import clean_url, get_ip, is_valid_domain, make_table, print_banner
from lib.web_recon import WebRecon

console = Console()


def run_dns(domain: str):
    console.print(f"\n[bold yellow]► DNS Lookup for {domain}[/bold yellow]")
    records = dns_lookup(domain)
    table = make_table("DNS Records", [("Type", "bright_green"), ("Value", "white")])
    for rtype, values in records.items():
        if values is None:
            continue
        if isinstance(values, list):
            for v in values:
                table.add_row(rtype, v)
        else:
            table.add_row(rtype, str(values))
    console.print(table)

    # Zone Transfer
    console.print("\n[bold yellow]► Zone Transfer Check (AXFR)[/bold yellow]")
    axfr = check_zone_transfer(domain)
    if axfr["vulnerable"]:
        console.print("[red bold]⚠ VULNERABLE![/red bold] Zone transfer succeeded!")
        for rec in axfr["records"][:20]:
            console.print(f"  {rec}")
    else:
        console.print("[green]✔ Not vulnerable[/green]")

    # Subdomain Takeover
    console.print("\n[bold yellow]► Subdomain Takeover Check[/bold yellow]")
    takeover = check_subdomain_takeover(domain)
    if takeover:
        t_table = make_table(
            "Takeover Risks",
            [
                ("Type", "red"),
                ("Record", "white"),
                ("Service", "yellow"),
                ("Risk", "red"),
            ],
        )
        for item in takeover:
            t_table.add_row(
                item["type"],
                item.get("cname", item.get("ns", "")),
                item["service"],
                item["risk"],
            )
        console.print(t_table)
    else:
        console.print("[green]✔ No takeover indicators found[/green]")

    # DNSSEC
    console.print("\n[bold yellow]► DNSSEC Validation[/bold yellow]")
    dnssec = check_dnssec(domain)
    if dnssec["enabled"]:
        status = (
            "[green]Enabled[/green]"
            if dnssec["validated"]
            else "[yellow]Enabled but not validated[/yellow]"
        )
        console.print(f"DNSSEC: {status}")
        for d in dnssec["details"]:
            console.print(f"  • {d}")
    else:
        console.print("[red]✘ DNSSEC not enabled[/red]")


def run_whois(domain: str):
    console.print(f"\n[bold yellow]► WHOIS Lookup for {domain}[/bold yellow]")
    data = whois_lookup(domain)
    if "error" in data:
        console.print(f"[red]WHOIS Error: {data['error']}[/red]")
        return
    table = make_table(
        "WHOIS Information", [("Field", "bright_green"), ("Value", "white")]
    )
    table.add_row("Registrar", str(data.get("registrar", "N/A")))
    table.add_row("Organization", str(data.get("org", "N/A")))
    table.add_row("Country", str(data.get("country", "N/A")))
    table.add_row("State", str(data.get("state", "N/A")))
    table.add_row("City", str(data.get("city", "N/A")))
    table.add_row("Creation Date", str(data.get("creation_date", "N/A")))
    table.add_row("Expiration Date", str(data.get("expiration_date", "N/A")))
    table.add_row("Updated Date", str(data.get("updated_date", "N/A")))
    table.add_row("DNSSEC", str(data.get("dnssec", "N/A")))
    ns_list = data.get("name_servers", [])
    table.add_row("Name Servers", "\n".join(ns_list) if ns_list else "N/A")
    status_list = data.get("status", [])
    table.add_row("Status", "\n".join(status_list[:5]) if status_list else "N/A")
    emails = data.get("emails", [])
    table.add_row("Emails", "\n".join(emails[:5]) if emails else "N/A")
    console.print(table)


def run_ssl(domain: str):
    console.print(f"\n[bold yellow]► SSL/TLS Certificate for {domain}[/bold yellow]")
    data = ssl_info(domain)
    if "error" in data:
        console.print(f"[red]SSL Error: {data['error']}[/red]")
        return

    table = make_table(
        "SSL/TLS Details", [("Field", "bright_green"), ("Value", "white")]
    )
    table.add_row("Subject", str(data.get("subject", "N/A")))
    table.add_row("Issuer", str(data.get("issuer", "N/A")))
    table.add_row("Valid From", str(data.get("not_before", "N/A")))
    table.add_row("Valid Until", str(data.get("not_after", "N/A")))
    table.add_row("Serial Number", str(data.get("serial", "N/A")))
    table.add_row("TLS Version", str(data.get("version", "N/A")))
    table.add_row("Cipher", str(data.get("cipher", "N/A")))
    san_list = data.get("san", [])
    san_str = "\n".join(f"{t}: {v}" for t, v in san_list) if san_list else "N/A"
    table.add_row("Subject Alt Names", san_str)
    if data.get("expired"):
        table.add_row("Status", "[red bold]EXPIRED[/red bold]")
    else:
        table.add_row("Status", "[green bold]Valid[/green bold]")
    if data.get("warning"):
        table.add_row("Warning", f"[yellow]{data['warning']}[/yellow]")
    console.print(table)

    console.print("\n[bold yellow]► TLS Version Support[/bold yellow]")
    tls_table = make_table(
        "Supported TLS Versions", [("Version", "bright_green"), ("Status", "white")]
    )
    for ver, status in test_ssl_versions(domain).items():
        color = "green" if "Supported" in status else "red"
        tls_table.add_row(ver, f"[{color}]{status}[/{color}]")
    console.print(tls_table)


def run_portscan(domain: str, tcp_ports: list[int], udp_ports: list[int], threads: int):
    ip = get_ip(domain)
    console.print(f"\n[bold yellow]► Port Scan on {domain} ({ip})[/bold yellow]")
    results = scan_ports(
        ip if ip != "N/A" else domain,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        max_workers=threads,
        timeout=1.5,
    )
    if not results:
        console.print("[red]No open ports found.[/red]")
        return
    table = make_table(
        f"Open Ports ({len(results)} found)",
        [
            ("Port", "bright_green"),
            ("Proto", "cyan"),
            ("Service", "yellow"),
            ("Banner", "white"),
        ],
    )
    for r in results:
        banner = r["banner"] or "—"
        table.add_row(str(r["port"]), r["protocol"], r["service"], banner)
    console.print(table)


def run_web(domain: str, full: bool = False):
    console.print(f"\n[bold yellow]► Web Recon for {domain}[/bold yellow]")
    recon = WebRecon(domain)
    with console.status("[cyan]Fetching HTTP..."):
        recon.fetch(use_https=False)
    with console.status("[cyan]Fetching HTTPS..."):
        recon.fetch(use_https=True)

    # Basic overview
    table = make_table(
        "Web Overview",
        [("Field", "bright_green"), ("HTTP", "white"), ("HTTPS", "white")],
    )
    table.add_row("URL", recon.url, recon.https_url)
    table.add_row("Status", recon.get_status_code(False), recon.get_status_code(True))
    table.add_row("Title", recon.get_title(False), recon.get_title(True))
    table.add_row("Server", recon.get_server(False), recon.get_server(True))
    table.add_row("Banner", recon.grab_banner(False), recon.grab_banner(True))
    table.add_row(
        "Content Length",
        recon.get_content_length(False),
        recon.get_content_length(True),
    )
    console.print(table)

    # Meta
    meta = recon.get_meta(use_https=True) or recon.get_meta(use_https=False)
    if meta:
        meta_table = make_table(
            "Meta / Open Graph / Twitter",
            [("Property", "bright_green"), ("Value", "white")],
        )
        for k, v in meta.items():
            meta_table.add_row(k, v)
        console.print(meta_table)

    # Tech stack with confidence
    techs = recon.check_wappalyzer_style()
    tech_table = make_table(
        "Technology Stack (with confidence)",
        [("Category", "bright_green"), ("Detected", "white")],
    )
    for cat, items in techs.items():
        if items:
            formatted = ", ".join(f"{name}({score})" for name, score in items[:8])
            tech_table.add_row(cat, formatted)
    console.print(tech_table)

    # WAF
    wafs = recon.detect_waf(use_https=True) or recon.detect_waf(use_https=False)
    if wafs:
        console.print(f"\n[bold yellow]► WAF Detected:[/bold yellow] {', '.join(wafs)}")
    else:
        console.print("\n[dim]No WAF detected[/dim]")

    # Security headers
    sec = recon.check_security_headers(use_https=True) or recon.check_security_headers(
        use_https=False
    )
    sec_table = make_table(
        "Security Headers", [("Header", "bright_green"), ("Status", "white")]
    )
    for h, v in sec.items():
        sec_table.add_row(h, v)
    console.print(sec_table)

    # CORS
    cors = recon.check_cors(use_https=True) or recon.check_cors(use_https=False)
    if cors["enabled"]:
        color = "red" if cors["misconfigured"] else "yellow"
        console.print(
            f"\nCORS: [{color}]{'Misconfigured' if cors['misconfigured'] else 'Enabled'}[/{color}]"
        )
        for d in cors["details"]:
            console.print(f"  • {d}")

    # Cookies
    cookies = recon.check_cookies(use_https=True) or recon.check_cookies(
        use_https=False
    )
    if cookies:
        cookie_table = make_table(
            "Cookies",
            [("Name", "bright_green"), ("Value", "white"), ("Flags", "yellow")],
        )
        for c in cookies:
            cookie_table.add_row(c["name"], c["value"], c["flags"])
        console.print(cookie_table)

    # Redirect chain
    chain = recon.check_redirect_chain()
    if len(chain) > 1:
        console.print("\n[bold yellow]► Redirect Chain[/bold yellow]")
        for step in chain:
            console.print(f"  → {step}")

    # Favicon
    fav = recon.get_favicon()
    if fav["status"] == 200:
        console.print("\n[bold yellow]► Favicon[/bold yellow]")
        console.print(f"  URL: {fav['url']}")
        console.print(f"  Size: {fav['size']:,} bytes")
        console.print(f"  MD5: [cyan]{fav['hash']}[/cyan]")

    # HTTP Methods
    console.print("\n[bold yellow]► HTTP Method Testing[/bold yellow]")
    methods = recon.test_http_methods()
    if methods["allowed"]:
        console.print(
            f"[green]Allowed:[/green] {', '.join(f'{m}({s})' for m, s in methods['allowed'])}"
        )
    if methods["denied"]:
        console.print(
            f"[yellow]Denied:[/yellow] {', '.join(f'{m}({s})' for m, s in methods['denied'])}"
        )

    # Path probing (full mode only)
    if full:
        console.print(
            f"\n[bold yellow]► Advanced Path Probing on {recon.url}[/bold yellow]"
        )
        probe = PathProbe(recon.url)
        findings = probe.probe_all()

        if findings["accessible"]:
            pt = make_table(
                f"Accessible Paths ({len(findings['accessible'])})",
                [
                    ("Path", "bright_green"),
                    ("Status", "yellow"),
                    ("Length", "white"),
                    ("Type", "cyan"),
                    ("Title", "magenta"),
                ],
            )
            for item in findings["accessible"][:30]:
                pt.add_row(
                    item["path"],
                    str(item["status"]),
                    f"{item['length']:,}",
                    item.get("content_type", ""),
                    item.get("title", ""),
                )
            console.print(pt)

        if findings["forbidden"]:
            pt = make_table(
                f"Forbidden Paths ({len(findings['forbidden'])})",
                [
                    ("Path", "bright_green"),
                    ("Status", "red"),
                    ("Length", "white"),
                    ("Type", "cyan"),
                ],
            )
            for item in findings["forbidden"][:20]:
                pt.add_row(
                    item["path"],
                    str(item["status"]),
                    f"{item['length']:,}",
                    item.get("content_type", ""),
                )
            console.print(pt)

        if findings["redirects"]:
            pt = make_table(
                f"Redirecting Paths ({len(findings['redirects'])})",
                [("Path", "bright_green"), ("Status", "yellow"), ("Location", "cyan")],
            )
            for item in findings["redirects"][:20]:
                pt.add_row(item["path"], str(item["status"]), item.get("location", ""))
            console.print(pt)

        if findings["auth_required"]:
            pt = make_table(
                f"Auth Required ({len(findings['auth_required'])})",
                [("Path", "bright_green"), ("Status", "yellow"), ("Length", "white")],
            )
            for item in findings["auth_required"][:20]:
                pt.add_row(item["path"], str(item["status"]), f"{item['length']:,}")
            console.print(pt)

        if findings["interesting"]:
            pt = make_table(
                f"Interesting Responses ({len(findings['interesting'])})",
                [("Path", "bright_green"), ("Status", "red"), ("Length", "white")],
            )
            for item in findings["interesting"][:20]:
                pt.add_row(item["path"], str(item["status"]), f"{item['length']:,}")
            console.print(pt)

    # Archives
    console.print("\n[bold yellow]► Archive Discovery[/bold yellow]")
    robots = fetch_robots_txt(recon.url)
    if robots["found"]:
        console.print(
            f"[green]robots.txt found[/green] ({len(robots['content'])} lines)"
        )
        for line in robots["content"][:15]:
            console.print(f"  {line}")
        if robots["sitemaps"]:
            console.print("[cyan]Sitemaps referenced:[/cyan]")
            for sm in robots["sitemaps"]:
                console.print(f"  → {sm}")
    else:
        console.print("[dim]robots.txt not found[/dim]")

    sitemap = fetch_sitemap(recon.url)
    if sitemap["found"]:
        console.print(f"[green]sitemap.xml found[/green] ({len(sitemap['urls'])} URLs)")
        for u in sitemap["urls"][:15]:
            console.print(f"  {u}")
    else:
        console.print("[dim]sitemap.xml not found[/dim]")

    # Wayback
    wb = fetch_wayback_urls(domain)
    if wb:
        console.print(f"\n[green]Wayback Machine:[/green] {len(wb)} URLs found")
        for u in wb[:15]:
            console.print(f"  {u}")

    return {
        "domain": domain,
        "ip": get_ip(domain),
        "title": recon.get_title(True) or recon.get_title(False),
        "status_code": recon.get_status_code(True) or recon.get_status_code(False),
        "server": recon.get_server(True) or recon.get_server(False),
        "tech": techs,
        "waf": wafs,
        "headers": sec,
        "cors": cors,
        "cookies": cookies,
        "favicon": fav,
    }



def run_traceroute(domain: str):
    console.print(f"\n[bold yellow]► Traceroute to {domain}[/bold yellow]")
    hops = traceroute(domain)
    if not hops:
        console.print("[red]No traceroute data.[/red]")
        return
    table = make_table(
        "Traceroute", [("Hop", "bright_green"), ("Host", "white"), ("Time", "yellow")]
    )
    for h in hops:
        table.add_row(str(h["hop"]), h["host"], h["time_ms"])
    console.print(table)


def run_enumeration(domain: str, mode: str, threads: int):
    enumerator = DomainEnumerator(domain)
    ip = get_ip(domain)
    console.print(
        f"\n[bold yellow]► {mode.replace('_', ' ').title()} Enumeration for {domain} ({ip})[/bold yellow]"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching data from API...", total=None)
        if mode == "subdomain":
            results = enumerator.subdomain()
        else:
            results = enumerator.reverse_ip(ip)
        progress.update(task, completed=True)

    if not results:
        console.print("[red]No results found.[/red]")
        return []

    console.print(
        f"[green]Found {len(results)} result(s). Scanning each target...[/green]\n"
    )
    scanned = []
    table = make_table(
        "Enumeration Results",
        [
            ("Domain", "bright_green"),
            ("Title", "white"),
            ("Status", "yellow"),
            ("Tech", "cyan"),
            ("Server", "magenta"),
        ],
    )

    for target in results:
        recon = WebRecon(target)
        ok = recon.fetch(use_https=False)
        if ok and recon.response:
            tech_list = list(recon.detect_tech(False).keys())[:3]
            cms = ", ".join(tech_list) if tech_list else "Unknown"
            status = recon.get_status_code(False)
            title = recon.get_title(False)
            server = recon.get_server(False)
            color = (
                "green"
                if status.startswith("2")
                else "yellow"
                if status.startswith("3")
                else "red"
            )
            table.add_row(
                f"http://{target}", title, f"[{color}]{status}[/{color}]", cms, server
            )
            scanned.append(
                {
                    "domain": target,
                    "status": status,
                    "title": title,
                    "server": server,
                    "tech": tech_list,
                }
            )
        else:
            table.add_row(f"http://{target}", "—", "[red]Unreachable[/red]", "—", "—")
            scanned.append(
                {"domain": target, "status": "unreachable", "error": recon.error}
            )

    console.print(table)
    return scanned


def run_single_target(domain: str, full: bool = False, threads: int = 150):
    domain = clean_url(domain)
    ip = get_ip(domain)
    console.print(
        Panel(
            f"[bold bright_cyan]Target:[/bold bright_cyan] {domain}  |  [bold bright_cyan]IP:[/bold bright_cyan] {ip}",
            border_style="bright_cyan",
        )
    )

    run_dns(domain)
    run_whois(domain)
    run_ssl(domain)
    run_traceroute(domain)

    tcp_ports = TOP_PORTS_TCP if full else [80, 443, 8080, 8443]
    udp_ports = TOP_PORTS_UDP if full else []
    run_portscan(domain, tcp_ports=tcp_ports, udp_ports=udp_ports, threads=threads)

    return run_web(domain, full=full)


def export_results(data: list[dict], fmt: str, out_path: str):
    path = Path(out_path)
    if fmt == "json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    elif fmt == "csv":
        if not data:
            console.print("[red]No data to export.[/red]")
            return
        keys = list(data[0].keys())
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for row in data:
                writer.writerow({k: str(v) for k, v in row.items()})
    elif fmt == "txt":
        with path.open("w", encoding="utf-8") as f:
            for item in data:
                for k, v in item.items():
                    f.write(f"{k}: {v}\n")
                f.write("-" * 40 + "\n")
    console.print(f"[green]Results exported to {path.resolve()}[/green]")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-recon",
        description="DomainRecon - Advanced Domain Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  domain-recon -u example.com                     # Basic recon
  domain-recon -u example.com --full              # Full recon (top 1000 TCP + UDP + path probing)
  domain-recon -u example.com -s subdomain        # Subdomain enumeration
  domain-recon -u example.com -s reverse_ip       # Reverse IP lookup
  domain-recon -u example.com --dns               # DNS only
  domain-recon -u example.com --whois             # WHOIS only
  domain-recon -u example.com --ssl               # SSL only
  domain-recon -u example.com -p 80,443,8080      # Custom TCP port scan
  domain-recon -u example.com -s subdomain -o json -f out.json
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target domain to scan")
    parser.add_argument(
        "-s", "--scan", choices=["subdomain", "reverse_ip"], help="Enumeration mode"
    )
    parser.add_argument("--dns", action="store_true", help="Run DNS lookup")
    parser.add_argument("--whois", action="store_true", help="Run WHOIS lookup")
    parser.add_argument("--ssl", action="store_true", help="Run SSL certificate check")
    parser.add_argument("--trace", action="store_true", help="Run traceroute")
    parser.add_argument(
        "-p", "--ports", help="Comma-separated TCP ports to scan (e.g., 80,443,8080)"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Enable full recon (top 1000 TCP + UDP ports + path probing + archives)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=150,
        help="Threads for port/probe scanning (default: 150)",
    )
    parser.add_argument(
        "-o", "--output", choices=["json", "csv", "txt"], help="Export format"
    )
    parser.add_argument("-f", "--file", help="Output file path for export")
    return parser


def main():
    print_banner()
    parser = build_cli()
    args = parser.parse_args()

    domain = clean_url(args.url)
    if not is_valid_domain(domain):
        console.print(f"[red]Invalid domain: {args.url}[/red]")
        sys.exit(1)

    all_results: list[dict] = []

    try:
        if args.scan:
            scanned = run_enumeration(domain, args.scan, threads=args.threads)
            all_results.extend(scanned)
        else:
            if args.dns:
                run_dns(domain)
            if args.whois:
                run_whois(domain)
            if args.ssl:
                run_ssl(domain)
            if args.trace:
                run_traceroute(domain)
            if args.ports:
                ports = [
                    int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()
                ]
                run_portscan(
                    domain, tcp_ports=ports, udp_ports=[], threads=args.threads
                )
            elif args.full:
                all_results.append(
                    run_single_target(domain, full=True, threads=args.threads)
                )

            if not any([args.dns, args.whois, args.ssl, args.trace, args.ports]):
                all_results.append(
                    run_single_target(domain, full=False, threads=args.threads)
                )

        if args.output and args.file:
            export_results(all_results, args.output, args.file)

    except KeyboardInterrupt:
        console.print("\n[red bold]CTRL+C detected. Exiting...[/red bold]")
        sys.exit(0)


if __name__ == "__main__":
    main()
