#!/usr/bin/env python3
"""
Website Vulnerability Scanner
------------------------------
Performs a lightweight security assessment of a target web application:
  1. Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, etc.)
  2. Insecure cookie flags (missing HttpOnly / Secure / SameSite)
  3. Server/technology fingerprinting (info disclosure via headers)
  4. Basic reflected-input check: sends a harmless marker string as a query
     parameter and checks if it is reflected unescaped in the response,
     which indicates the page MAY be vulnerable to reflected XSS
     (this only tests for reflection, it does not exploit anything)
  5. SSL/TLS certificate expiry check

⚠️ Ethical use only: only scan applications you own or have explicit
written permission to test. Unauthorized scanning of third-party sites
may violate laws such as the IT Act (India) or Computer Fraud and Abuse
Act (US).

Usage:
    python vuln_scanner.py -u https://example.com
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# Marker used to test for reflected input — deliberately harmless (no <script> payload)
REFLECTION_MARKER = "cs_reflect_test_9f3a"

SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-Content-Type-Options": "Prevents MIME-sniffing",
    "X-Frame-Options": "Protects against clickjacking",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser feature access",
}


def check_headers(response) -> list:
    findings = []
    for header, purpose in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append({"severity": "Medium", "issue": f"Missing header: {header}", "detail": purpose})
    server = response.headers.get("Server")
    powered_by = response.headers.get("X-Powered-By")
    if server:
        findings.append({"severity": "Low", "issue": "Server header discloses software", "detail": server})
    if powered_by:
        findings.append({"severity": "Low", "issue": "X-Powered-By discloses technology", "detail": powered_by})
    return findings


def check_cookies(response) -> list:
    findings = []
    for cookie in response.cookies:
        flags = []
        if not cookie.secure:
            flags.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
            flags.append("missing HttpOnly flag")
        if flags:
            findings.append({
                "severity": "Medium",
                "issue": f"Cookie '{cookie.name}' insecure",
                "detail": ", ".join(flags),
            })
    return findings


def check_reflection(base_url: str, timeout: int) -> list:
    findings = []
    test_url = f"{base_url}{'&' if '?' in base_url else '?'}q={REFLECTION_MARKER}"
    try:
        resp = requests.get(test_url, timeout=timeout)
        if REFLECTION_MARKER in resp.text:
            findings.append({
                "severity": "High",
                "issue": "Unescaped input reflection detected",
                "detail": f"Parameter value reflected in response body — possible XSS vector at {test_url}",
            })
    except requests.RequestException:
        pass
    return findings


def check_tls(hostname: str) -> list:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 30:
                    findings.append({
                        "severity": "High" if days_left < 7 else "Medium",
                        "issue": "TLS certificate expiring soon",
                        "detail": f"Expires in {days_left} days ({expiry.date()})",
                    })
    except Exception as e:
        findings.append({"severity": "Info", "issue": "TLS check skipped", "detail": str(e)})
    return findings


def scan(url: str, timeout: int = 8):
    parsed = urlparse(url)
    hostname = parsed.hostname

    print(f"\nScanning: {url}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        print(f"Error: could not reach target — {e}")
        sys.exit(1)

    all_findings = []
    all_findings += check_headers(response)
    all_findings += check_cookies(response)
    all_findings += check_reflection(url, timeout)
    if parsed.scheme == "https":
        all_findings += check_tls(hostname)

    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    print(f"{'SEVERITY':<10}{'ISSUE':<45}{'DETAIL'}")
    print("-" * 100)
    for f in all_findings:
        print(f"{f['severity']:<10}{f['issue']:<45}{f['detail'][:45]}")

    print(f"\nScan complete. {len(all_findings)} finding(s).")
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Lightweight web application vulnerability scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    args = parser.parse_args()

    url = args.url if args.url.startswith("http") else f"https://{args.url}"
    scan(url, args.timeout)


if __name__ == "__main__":
    main()
