#!/usr/bin/env python3
"""
Python Port Scanner
--------------------
A multithreaded TCP port scanner that identifies open ports and attempts to detect the service running on each port.
"""

import socket
import argparse
import concurrent.futures
import sys
import json
import csv
from datetime import datetime

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 902: "VMware-Auth", 912: "VMware-Auth",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

def parse_ports(port_arg: str):
    """Parse a port argument like '1-1024' or '22,80,443' into a list of ints."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def grab_banner(sock: socket.socket) -> str:
    """Attempt to read a service banner from an open socket."""
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else ""
    except Exception:
        return ""

def scan_port(target: str, port: int, timeout: float = 0.5):
    """Scan a single port. Returns a dict with results if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(sock)
                return {"port": port, "service": service, "banner": banner}
    except socket.error:
        pass
    return None

def save_results(results: list, output_file: str):
    """Save scan results to a JSON or CSV file based on the extension."""
    if output_file.endswith(".json"):
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {output_file}")
    elif output_file.endswith(".csv"):
        if not results:
            print("\n[!] No results to write to CSV.")
            return
        fieldnames = ["port", "service", "banner"]
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[+] Results saved to {output_file}")
    else:
        print("\n[!] Unsupported format. Please specify a file ending in .json or .csv")

def scan(target: str, ports: list, max_threads: int = 100, timeout: float = 0.5):
    print(f"\nScanning target: {target}")
    print(f"Ports: {ports[0]}-{ports[-1]} ({len(ports)} total)")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<15}{'BANNER'}")
    print("-" * 60)
    for r in open_ports:
        banner_display = r["banner"][:30] if r["banner"] else "-"
        print(f"{r['port']:<8}{'open':<8}{r['service']:<15}{banner_display}")

    print(f"\nScan complete. {len(open_ports)} open port(s) found.")
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Simple multithreaded TCP port scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range/list, e.g. 1-1024 or 22,80,443")
    parser.add_argument("-o", "--output", help="Output file path (.json or .csv)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: could not resolve hostname '{args.target}'")
        sys.exit(1)

    ports = parse_ports(args.ports)
    results = scan(target_ip, ports, args.threads, args.timeout)

    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    main()
