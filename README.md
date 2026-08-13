# DomainRecon

Advanced Domain Reconnaissance Tool with beautiful terminal UI powered by [Rich](https://github.com/Textualize/rich).

## Features

### Reconnaissance Modules
- **DNS Lookup** — A, AAAA, MX, NS, TXT, CNAME, SOA, PTR records
- **DNS Zone Transfer (AXFR)** — Check for zone transfer vulnerabilities
- **WHOIS Lookup** — Registrar, dates, name servers, status, emails, location, DNSSEC
- **SSL/TLS Analysis** — Certificate details, supported TLS versions, cipher, expiry
- **Port Scanner** — Top 1000 TCP ports with multi-threading + banner grabbing
- **Traceroute** — Network path mapping

### Web Reconnaissance
- **Technology Detection** — CMS, frameworks, frontend libs, server/CDN (30+ signatures)
- **WAF Detection** — Cloudflare, AWS WAF, Sucuri, Akamai, Imperva, etc
- **Security Headers** — HSTS, CSP, X-Frame-Options, CORS, cookie flags, and more
- **HTTP Method Testing** — Test GET/POST/PUT/DELETE/OPTIONS/TRACE/PATCH/HEAD
- **Redirect Chain** — Full redirect path analysis
- **Favicon Hashing** — MD5 hash for OSINT framework correlation
- **Meta / Open Graph** — Extract page metadata

### Enumeration
- **Subdomain Enumeration** — via HackerTarget API
- **Reverse IP Lookup** — Find co-hosted domains

### Path Probing
- **Sensitive Paths** — 90+ endpoints (admin panels, APIs, configs, backups)
- **Backup Files** — .bak, .zip, .sql, .tar.gz, .old, .swp detection
- **Archive Discovery** — robots.txt, sitemap.xml, Wayback Machine URLs

### Output
- **Export** — JSON, CSV, TXT
- **Rich Terminal UI** — Tables, panels, progress bars, color-coded results

## Installation

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install .
```

After installing, the `domain-recon` command is available on your PATH:

```bash
domain-recon -u example.com
```

## Usage

```bash
# Basic reconnaissance
uv run main.py -u example.com

# Full recon (top 1000 ports + path probing + archives)
uv run main.py -u example.com --full

# Subdomain enumeration
uv run main.py -u example.com -s subdomain

# Reverse IP lookup
uv run main.py -u example.com -s reverse_ip

# Individual modules
uv run main.py -u example.com --dns
uv run main.py -u example.com --whois
uv run main.py -u example.com --ssl
uv run main.py -u example.com --trace
uv run main.py -u example.com -p 80,443,8080,3306

# Export results
uv run main.py -u example.com -s subdomain -o json -f results.json
```

## Requirements

- Python 3.11+
- uv (optional, recommended)
- requests
- rich
- dnspython
- python-whois
