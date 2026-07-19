# Cybersecurity Projects

Two standalone Python security tools built for portfolio/resume use.

## ⚠️ Ethical Use Notice
Only run these against systems you **own** or have **explicit written permission**
to test. Unauthorized scanning of third-party systems can violate laws such as
the IT Act (India) or the Computer Fraud and Abuse Act (US). Use `127.0.0.1`,
your own local network, or dedicated legal practice targets like
`scanme.nmap.org` (Nmap's official test host) for demos.

---

## 1. Port Scanner (`port_scanner.py`)

Multithreaded TCP port scanner that finds open ports and identifies the
likely service (via a common-port lookup table and banner grabbing).

**Setup:**
```bash
python3 port_scanner.py -t <target> -p <ports>
```

**Examples:**
```bash
python3 port_scanner.py -t 127.0.0.1 -p 1-1024
python3 port_scanner.py -t scanme.nmap.org -p 20,21,22,80,443
```

**How it works:**
- Uses Python's `socket` module with `connect_ex()` for fast TCP connect scans
- Runs scans concurrently via `concurrent.futures.ThreadPoolExecutor` (default: 100 threads)
- Attempts to read a service banner from each open port for extra fingerprinting
- Maps well-known ports (22, 80, 443, 3306, etc.) to human-readable service names

---

## 2. Website Vulnerability Scanner (`vuln_scanner.py`)

Lightweight web app security scanner. Checks for common misconfigurations
that show up in real-world security audits.

**Setup:**
```bash
pip install requests
python3 vuln_scanner.py -u <url>
```

**Example:**
```bash
python3 vuln_scanner.py -u https://example.com
```

**Checks performed:**
1. **Missing security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **Insecure cookies** — flags cookies missing `Secure`/`HttpOnly` flags
3. **Information disclosure** — flags `Server` / `X-Powered-By` headers that leak stack details
4. **Reflected input check** — sends a harmless marker string as a query parameter and checks if it's echoed back unescaped (a signal for potential reflected XSS — this only *detects*, it does not exploit)
5. **TLS certificate expiry** — warns if the SSL cert expires within 30 days

---

## For Your Resume / Interviews

**Suggested resume bullets:**
- *Website Vulnerability Scanner:* "Built a Python web security scanner using `requests` that audits HTTP security headers, cookie flags, and TLS certificate validity, and flags potential reflected-XSS vectors via safe input-reflection testing."
- *Python Port Scanner:* "Developed a multithreaded TCP port scanner in Python using `socket` and `concurrent.futures`, capable of scanning 1000+ ports in seconds with automatic service identification via banner grabbing."

**Likely interview questions and how to answer:**
- *"How does your port scanner work?"* → Explain TCP connect scanning (`connect_ex`), why you used threading for speed, and how banner grabbing helps identify services beyond just the port number.
- *"What's a TCP connect scan vs a SYN scan?"* → Your tool does a full connect scan (completes the 3-way handshake); a SYN scan (like Nmap's `-sS`) only sends the SYN packet and never completes the handshake, making it stealthier but requiring raw sockets/root privileges.
- *"How does your vulnerability scanner detect XSS?"* → Be precise: it doesn't confirm exploitability — it checks if unescaped input is *reflected* in the response, which is a strong *indicator* worth manual follow-up, not a guaranteed vulnerability.
- *"What would you add next?"* → Good answers: SQLi detection via error-based payloads, subdomain enumeration, integration with the CVE database, exporting results to JSON/PDF reports.
