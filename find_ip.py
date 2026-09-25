#!/usr/bin/env python3
"""
find_ip.py - Find IP addresses of equipment / PCs / laptops on the LAN.
Works on Windows, macOS and Linux (standard library only, nothing to install).

How it works:
  1. Parallel ping sweep of the subnet (also populates the ARP table)
  2. Read the ARP table (arp -a) to map IP <-> MAC
  3. Resolve hostnames (DNS / NetBIOS / mDNS, depending on the OS)

Examples:
  python3 find_ip.py                          # scan the current subnet (/24)
  python3 find_ip.py 192.168.1.0/24           # scan a specific subnet
  python3 find_ip.py --mac AA:BB:CC:DD:EE:FF  # find IP by MAC
  python3 find_ip.py --mac aa-bb-cc           # partial MAC match (e.g. vendor OUI)
  python3 find_ip.py --name laptop            # search by hostname
  python3 find_ip.py --csv result.csv         # export to CSV
"""
import argparse
import csv
import ipaddress
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def normalize_mac(mac: str) -> str:
    """Normalize any MAC format to aa:bb:cc:dd:ee:ff (macOS drops leading zeros, e.g. 0:1a:...)."""
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(p.zfill(2) for p in parts).lower()


def mac_query(q: str) -> str:
    """Reduce a MAC search term to bare hex digits for substring matching."""
    return re.sub(r"[^0-9a-fA-F]", "", q).lower()


def local_ip() -> str:
    """IP of this machine (UDP connect trick, no packet is actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ping(ip: str, timeout_ms: int) -> bool:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout_ms / 1000 + 2)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def read_arp_table() -> dict:
    """Return {ip: mac} from arp -a."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             errors="ignore").stdout
    except FileNotFoundError:
        # Some Linux distros have no arp -> fall back to ip neigh
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
    table = {}
    for line in out.splitlines():
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        table[ip_m.group(1)] = mac
    return table


def resolve_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def main():
    ap = argparse.ArgumentParser(description="Find IP addresses of devices on the LAN")
    ap.add_argument("subnet", nargs="?", help="e.g. 192.168.1.0/24 (default: this host's /24)")
    ap.add_argument("--mac", help="filter by MAC (full or partial)")
    ap.add_argument("--name", help="filter by hostname (partial, case-insensitive)")
    ap.add_argument("--timeout", type=int, default=800, help="ping timeout in ms (default 800)")
    ap.add_argument("--workers", type=int, default=128, help="number of threads (default 128)")
    ap.add_argument("--no-resolve", action="store_true", help="skip hostname lookup (faster)")
    ap.add_argument("--csv", help="save results to a CSV file")
    args = ap.parse_args()

    my_ip = local_ip()
    try:
        net = ipaddress.ip_network(args.subnet or f"{my_ip}/24", strict=False)
    except ValueError as e:
        sys.exit(f"Invalid subnet: {e}")
    if net.num_addresses > 4096:
        sys.exit("Subnet too large (> /20), please narrow it down")

    hosts = [str(h) for h in net.hosts()]
    print(f"[*] This host: {my_ip}   Scanning: {net} ({len(hosts)} hosts) ...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(lambda h: ping(h, args.timeout), hosts)) if ok}

    arp = read_arp_table()
    if not arp and alive:
        print("[!] ARP table came back empty - MAC addresses unavailable."
              + (" On macOS this is usually Local Network privacy blocking this Python build;"
                 " try /usr/bin/python3 or grant access in System Settings > Privacy & Security"
                 " > Local Network." if IS_MAC else ""), file=sys.stderr)
    # Merge ping replies + ARP entries (some hosts block ICMP but still answer ARP)
    found = sorted({ip for ip in alive | set(arp) if ipaddress.ip_address(ip) in net},
                   key=ipaddress.ip_address)

    names = {}
    if not args.no_resolve:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            names = dict(zip(found, ex.map(resolve_name, found)))

    rows = []
    for ip in found:
        mac = arp.get(ip, "(this host)" if ip == my_ip else "")
        name = names.get(ip, "")
        if args.mac and mac_query(args.mac) not in mac.replace(":", ""):
            continue
        if args.name and args.name.lower() not in name.lower():
            continue
        rows.append((ip, mac, name, "yes" if ip in alive else "no (ARP only)"))

    print(f"\n{'IP Address':<16} {'MAC Address':<18} {'Ping':<14} Hostname")
    print("-" * 72)
    for ip, mac, name, p in rows:
        print(f"{ip:<16} {mac:<18} {p:<14} {name}")
    print(f"\nFound {len(rows)} device(s)")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["IP", "MAC", "Hostname", "Ping"])
            w.writerows((ip, mac, name, p) for ip, mac, name, p in rows)
        print(f"Saved: {args.csv}", file=sys.stderr)

    if (args.mac or args.name) and not rows:
        sys.exit(1)


if __name__ == "__main__":
    main()
