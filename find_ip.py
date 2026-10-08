#!/usr/bin/env python3
"""
find_ip.py - Multi-tool for LAN Device & DHCP Discovery.
Works on Windows, macOS, and Linux (Python Standard Library ONLY - zero dependencies).

Key Capabilities:
  1. Subnet Scan: Parallel ping sweep + ARP cache merging (even finds hosts blocking ICMP).
  2. Device Identification: MAC Vendor / OUI lookup + Private Randomized MAC detection.
  3. Multi-Protocol Name Discovery: DNS PTR + mDNS / Bonjour (.local) + NetBIOS (port 137).
  4. DHCP Server Discovery: Broadcast DHCP Discover to find DHCP servers, gateways, DNS,
     lease times, and detect Rogue DHCP servers on the network.
  5. Watch Mode (--watch): Real-time continuous monitoring for new devices or offline alerts.
  6. Quick Port Scan (--ports): Rapid check of common ports (SSH, HTTP, HTTPS, etc.).
  7. Export Formats: Pretty CLI table, CSV (--csv), or JSON (--json).

Examples:
  python3 find_ip.py                             # scan local subnet
  python3 find_ip.py 192.168.1.0/24              # scan specific subnet
  python3 find_ip.py --dhcp                      # find DHCP server(s) then scan
  python3 find_ip.py --dhcp-only                 # inspect DHCP server info only
  python3 find_ip.py --watch                     # live monitor for new devices
  python3 find_ip.py --vendor apple              # filter by device brand
  python3 find_ip.py --mac aa:bb:cc              # search by MAC address / OUI
  python3 find_ip.py --name printer              # search by hostname
  python3 find_ip.py --ports 80,443,22           # check common open ports
  python3 find_ip.py --csv devices.csv           # save output to CSV
  python3 find_ip.py --json                      # output JSON format
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# macOS Local Network Privacy Workaround:
# On macOS Sequoia and newer, Python builds from Homebrew/pyenv without Local Network
# entitlement return an empty ARP cache. /usr/bin/python3 has system entitlements.
# If we detect that arp returns empty on macOS under third-party Python, automatically
# re-execute using /usr/bin/python3 so the user gets full MAC addresses seamlessly.
if (
    IS_MAC
    and sys.executable != "/usr/bin/python3"
    and os.path.exists("/usr/bin/python3")
    and not os.environ.get("_DHCP_FINDER_REEXEC")
):
    try:
        _test_arp = subprocess.run(["/usr/sbin/arp", "-an"], capture_output=True, text=True, errors="ignore").stdout
        if not _test_arp.strip():
            _env = os.environ.copy()
            _env["_DHCP_FINDER_REEXEC"] = "1"
            os.execve("/usr/bin/python3", ["/usr/bin/python3"] + sys.argv, _env)
    except Exception:
        pass

MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

# ---------------------------------------------------------------------------
# MAC OUI Database (Top enterprise, consumer, and IoT manufacturers)
# ---------------------------------------------------------------------------
OUI_MAP = {
    # Apple
    "000393": "Apple", "000502": "Apple", "000A27": "Apple", "000A95": "Apple",
    "000D93": "Apple", "0010FA": "Apple", "001124": "Apple", "001451": "Apple",
    "0016CB": "Apple", "0017F2": "Apple", "0019E3": "Apple", "001B63": "Apple",
    "001CB3": "Apple", "001D4F": "Apple", "001E52": "Apple", "001EC2": "Apple",
    "0021E9": "Apple", "002241": "Apple", "002312": "Apple", "002332": "Apple",
    "00236C": "Apple", "002436": "Apple", "002500": "Apple", "00254B": "Apple",
    "0025BC": "Apple", "002608": "Apple", "00264A": "Apple", "0026B0": "Apple",
    "147DDA": "Apple", "28CFDA": "Apple", "38F9D3": "Apple", "3C15C2": "Apple",
    "406C8F": "Apple", "70EE50": "Apple", "784F43": "Apple", "843835": "Apple",
    "88665A": "Apple", "A483E7": "Apple", "A8667F": "Apple", "ACBC32": "Apple",
    "B8E856": "Apple", "BCD177": "Apple", "C82A14": "Apple", "DCA904": "Apple",
    "E0C767": "Apple", "F01898": "Apple", "F0DBF8": "Apple", "F4F15A": "Apple",
    "F8FFC2": "Apple", "F099BF": "Apple", "600308": "Apple", "68DBCA": "Apple",
    "D0880C": "Apple",
    # Cisco / Linksys
    "00000C": "Cisco", "000142": "Cisco", "000143": "Cisco", "000163": "Cisco",
    "000164": "Cisco", "000196": "Cisco", "000197": "Cisco", "0001C7": "Cisco",
    "0001C9": "Cisco", "000216": "Cisco", "000217": "Cisco", "00024A": "Cisco",
    "00024B": "Cisco", "00027D": "Cisco", "00027E": "Cisco", "0002B9": "Cisco",
    "0002BA": "Cisco", "0002FC": "Cisco", "0002FD": "Cisco", "1C1D86": "Cisco",
    "7864A0": "Cisco", "001C0F": "Cisco", "001DA1": "Cisco", "001E13": "Cisco",
    "001E14": "Cisco", "001E49": "Cisco", "001E4A": "Cisco", "001E79": "Cisco",
    "001E7A": "Cisco", "001EBD": "Cisco", "001EBE": "Cisco", "001F6C": "Cisco",
    "001F6D": "Cisco", "001F9E": "Cisco", "001F9F": "Cisco", "001FCA": "Cisco",
    "001FCB": "Cisco", "002155": "Cisco", "002156": "Cisco", "0021A0": "Cisco",
    "0021A1": "Cisco", "0021D7": "Cisco", "0021D8": "Cisco", "002255": "Cisco",
    "002256": "Cisco", "002290": "Cisco", "002291": "Cisco", "0022BD": "Cisco",
    "0022BE": "Cisco", "002304": "Cisco", "002305": "Cisco", "002333": "Cisco",
    "002334": "Cisco", "00235D": "Cisco", "00235E": "Cisco", "0023AC": "Cisco",
    "0023AD": "Cisco", "0023EB": "Cisco", "0023EC": "Cisco", "002413": "Cisco",
    "002414": "Cisco", "002450": "Cisco", "002451": "Cisco", "002497": "Cisco",
    "002498": "Cisco", "0024C3": "Cisco", "0024C4": "Cisco", "0024F7": "Cisco",
    "0024F8": "Cisco", "002545": "Cisco", "002546": "Cisco", "002583": "Cisco",
    "002584": "Cisco", "0025B4": "Cisco", "0025B5": "Cisco", "00260A": "Cisco",
    "00260B": "Cisco", "002643": "Cisco", "002644": "Cisco", "002698": "Cisco",
    "002699": "Cisco", "0026CB": "Cisco", "0026CC": "Cisco", "68BDAB": "Cisco",
    # Intel
    "0002B3": "Intel", "000347": "Intel", "000423": "Intel", "0007E9": "Intel",
    "000E0C": "Intel", "000E35": "Intel", "001111": "Intel", "0012F0": "Intel",
    "001302": "Intel", "001320": "Intel", "0013E8": "Intel", "001500": "Intel",
    "001517": "Intel", "001676": "Intel", "0018DE": "Intel", "0019D1": "Intel",
    "0019D2": "Intel", "001B21": "Intel", "001B77": "Intel", "001CBF": "Intel",
    "001CC0": "Intel", "001DE0": "Intel", "001E64": "Intel", "001E65": "Intel",
    "001E67": "Intel", "001F3B": "Intel", "001F3C": "Intel", "00215C": "Intel",
    "00216A": "Intel", "00216B": "Intel", "0022FA": "Intel", "0022FB": "Intel",
    "002314": "Intel", "002315": "Intel", "0024D6": "Intel", "0024D7": "Intel",
    "0026C6": "Intel", "0026C7": "Intel", "10F60A": "Intel", "7CB566": "Intel",
    "A44CC8": "Intel", "AC7409": "Intel", "B49691": "Intel", "C85B76": "Intel",
    "E82A44": "Intel", "FC7774": "Intel", "58961D": "Intel", "28D0EA": "Intel",
    "ECED04": "Intel",
    # Espressif (ESP32 / ESP8266)
    "083A2F": "Espressif", "240AC4": "Espressif", "2462AB": "Espressif",
    "246F28": "Espressif", "24DCC3": "Espressif", "30AEA4": "Espressif",
    "3C6105": "Espressif", "3C71BF": "Espressif", "4022D8": "Espressif",
    "404CCA": "Espressif", "409151": "Espressif", "483FDA": "Espressif",
    "485519": "Espressif", "4C7525": "Espressif", "5443B2": "Espressif",
    "545AA6": "Espressif", "5CCF7F": "Espressif", "600194": "Espressif",
    "686725": "Espressif", "68C63A": "Espressif", "70039F": "Espressif",
    "7CDFA1": "Espressif", "807D3A": "Espressif", "840D8E": "Espressif",
    "84CCA8": "Espressif", "84F703": "Espressif", "8CAAB5": "Espressif",
    "9097D5": "Espressif", "94B555": "Espressif", "94B97E": "Espressif",
    "98F4AB": "Espressif", "A020A6": "Espressif", "A4CF12": "Espressif",
    "A4E57C": "Espressif", "AC67B2": "Espressif", "B4E62D": "Espressif",
    "BCDDD2": "Espressif", "C44F33": "Espressif", "C4DD57": "Espressif",
    "CC50E3": "Espressif", "D8A01D": "Espressif", "DC4F22": "Espressif",
    "E09806": "Espressif", "E831CD": "Espressif", "E868E7": "Espressif",
    "E8DB84": "Espressif", "EC6260": "Espressif", "ECFABC": "Espressif",
    "F4CFA2": "Espressif",
    # Raspberry Pi
    "28CDC1": "Raspberry Pi", "B827EB": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    # TP-Link
    "000AEB": "TP-Link", "001478": "TP-Link", "0019E0": "TP-Link", "001D0F": "TP-Link",
    "002127": "TP-Link", "0023CD": "TP-Link", "002586": "TP-Link", "002719": "TP-Link",
    "147590": "TP-Link", "14CC20": "TP-Link", "18A6F7": "TP-Link", "1C3BF3": "TP-Link",
    "20DCE6": "TP-Link", "30B5C2": "TP-Link", "30DE4B": "TP-Link", "388345": "TP-Link",
    "40169F": "TP-Link", "50C7BF": "TP-Link", "50D4F7": "TP-Link", "54AF97": "TP-Link",
    "54E6FC": "TP-Link", "5C63BF": "TP-Link", "6032B1": "TP-Link", "645601": "TP-Link",
    "6466B3": "TP-Link", "647002": "TP-Link", "6C5AB0": "TP-Link", "704F57": "TP-Link",
    "7405A5": "TP-Link", "788B2A": "TP-Link", "8416F9": "TP-Link", "8C210A": "TP-Link",
    "909A4A": "TP-Link", "984827": "TP-Link", "98DAC4": "TP-Link", "A0F3C1": "TP-Link",
    "B04E26": "TP-Link", "B09575": "TP-Link", "C006C3": "TP-Link", "C025E9": "TP-Link",
    "C04A00": "TP-Link", "C46E1F": "TP-Link", "CC32E5": "TP-Link", "CC3429": "TP-Link",
    "D46E0E": "TP-Link", "D80D17": "TP-Link", "D84732": "TP-Link", "DCEE06": "TP-Link",
    "E4C32A": "TP-Link", "E848B8": "TP-Link", "EC086B": "TP-Link", "EC172F": "TP-Link",
    "F4EC38": "TP-Link", "F4F26D": "TP-Link", "FC3497": "TP-Link", "FCD733": "TP-Link",
    # Ubiquiti / UniFi
    "00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti", "18E829": "Ubiquiti",
    "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "687251": "Ubiquiti", "70A741": "Ubiquiti",
    "7483C2": "Ubiquiti", "788A20": "Ubiquiti", "802AA8": "Ubiquiti", "AC8BA9": "Ubiquiti",
    "B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti", "E063DA": "Ubiquiti", "F09FC2": "Ubiquiti",
    "FCECDA": "Ubiquiti",
    # MikroTik
    "000C42": "MikroTik", "488F5A": "MikroTik", "64D154": "MikroTik", "6C3B6B": "MikroTik",
    "744D28": "MikroTik", "CC2DE0": "MikroTik", "D401C3": "MikroTik", "D4CA6D": "MikroTik",
    "E48D8C": "MikroTik", "F41E26": "MikroTik",
    # Samsung
    "0000F0": "Samsung", "000278": "Samsung", "0007AB": "Samsung", "000918": "Samsung",
    "000DAE": "Samsung", "001247": "Samsung", "0012FB": "Samsung", "001599": "Samsung",
    "0015B9": "Samsung", "001632": "Samsung", "00166C": "Samsung", "0017C9": "Samsung",
    "0017D5": "Samsung", "0018AF": "Samsung", "001A8A": "Samsung", "001B98": "Samsung",
    "001C43": "Samsung", "001D25": "Samsung", "001EE1": "Samsung", "001EE2": "Samsung",
    "002119": "Samsung", "00214C": "Samsung", "0021D1": "Samsung", "0021D2": "Samsung",
    "002339": "Samsung", "00233A": "Samsung", "0023C2": "Samsung", "0023C3": "Samsung",
    "0023D6": "Samsung", "0023D7": "Samsung", "002454": "Samsung", "002490": "Samsung",
    "002491": "Samsung", "002566": "Samsung", "002567": "Samsung", "002637": "Samsung",
    "00265D": "Samsung", "00265E": "Samsung", "0808C2": "Samsung", "0C1420": "Samsung",
    "14BB6E": "Samsung", "205531": "Samsung", "244B03": "Samsung", "28987B": "Samsung",
    "34C059": "Samsung", "380195": "Samsung", "400E85": "Samsung", "4844F7": "Samsung",
    "5056BF": "Samsung", "50A4C8": "Samsung", "5440AD": "Samsung", "5CA39D": "Samsung",
    # Xiaomi
    "009EC8": "Xiaomi", "04CF4B": "Xiaomi", "0C9838": "Xiaomi", "14F65A": "Xiaomi",
    "18F0E4": "Xiaomi", "2082C0": "Xiaomi", "286C07": "Xiaomi", "348004": "Xiaomi",
    "3CBD3E": "Xiaomi", "508F4C": "Xiaomi", "584120": "Xiaomi", "584498": "Xiaomi",
    "64CC2E": "Xiaomi", "68DFDD": "Xiaomi", "7451BA": "Xiaomi", "7811DC": "Xiaomi",
    "7C49EB": "Xiaomi", "8CBEBE": "Xiaomi", "98FAE3": "Xiaomi", "A43B35": "Xiaomi",
    # Huawei
    "001882": "Huawei", "001E10": "Huawei", "0022A1": "Huawei", "002568": "Huawei",
    "00259E": "Huawei", "00464B": "Huawei", "0425C5": "Huawei", "04C06F": "Huawei",
    "0819A6": "Huawei", "0C37DC": "Huawei", "101B54": "Huawei", "104780": "Huawei",
    "14A51A": "Huawei", "18C58A": "Huawei", "1C1D67": "Huawei", "200BC7": "Huawei",
    # Google
    "001A11": "Google", "1C56FE": "Google", "20DFB9": "Google", "30FD38": "Google",
    "3C5A37": "Google", "48D6D5": "Google", "546009": "Google", "703EAC": "Google",
    "88366C": "Google", "94EBCD": "Google", "A47733": "Google", "D4F547": "Google",
    "E4F042": "Google", "F40304": "Google", "F4F5E8": "Google",
    # Amazon
    "00FC8B": "Amazon", "0C47C9": "Amazon", "18742E": "Amazon", "244CE3": "Amazon",
    "34D270": "Amazon", "38F73D": "Amazon", "40B4CD": "Amazon", "44650D": "Amazon",
    "50DCE7": "Amazon", "6837E9": "Amazon", "6854FD": "Amazon", "74C246": "Amazon",
    "78E103": "Amazon", "84D6D0": "Amazon", "AC63BE": "Amazon", "B47C9C": "Amazon",
    # Dell
    "00065B": "Dell", "000874": "Dell", "000BDB": "Dell", "000D56": "Dell",
    "001143": "Dell", "00123F": "Dell", "001372": "Dell", "001422": "Dell",
    "0015C5": "Dell", "0016F0": "Dell", "00188B": "Dell", "0019B9": "Dell",
    "141877": "Dell", "180373": "Dell", "1866DA": "Dell", "24B6FD": "Dell",
    "3417EB": "Dell", "44A842": "Dell", "549F35": "Dell", "74867A": "Dell",
    # HP
    "0001E6": "HP", "0002A5": "HP", "000802": "HP", "000BCD": "HP",
    "000E7F": "HP", "00110A": "HP", "001279": "HP", "001321": "HP",
    "10E7C6": "HP", "28924A": "HP", "308D99": "HP", "3CD92B": "HP",
    # ASUS
    "000C6E": "ASUS", "00112F": "ASUS", "0011D8": "ASUS", "0013D4": "ASUS",
    "0015F2": "ASUS", "001731": "ASUS", "0018F3": "ASUS", "001A92": "ASUS",
    "04421A": "ASUS", "08606E": "ASUS", "10BF48": "ASUS", "1C872C": "ASUS",
    # Netgear
    "00095B": "Netgear", "000FB5": "Netgear", "00146C": "Netgear", "00184D": "Netgear",
    "001B2F": "Netgear", "001E2A": "Netgear", "001F33": "Netgear", "00223F": "Netgear",
    "10DA43": "Netgear", "20E52A": "Netgear", "288088": "Netgear", "4494FC": "Netgear",
    # Zyxel
    "0002CF": "Zyxel", "001349": "Zyxel", "0019CB": "Zyxel", "001FA4": "Zyxel",
    "0023F8": "Zyxel", "107B44": "Zyxel", "54833A": "Zyxel", "CC5D4E": "Zyxel",
    # Synology & QNAP
    "001132": "Synology", "9009D0": "Synology", "00089B": "QNAP", "245EBE": "QNAP",
    # Sony & Microsoft
    "00014A": "Sony", "00041F": "Sony", "709E29": "Sony", "A8E3EE": "Sony",
    "0003FF": "Microsoft", "00125A": "Microsoft", "00155D": "Microsoft", "281878": "Microsoft",
    # Tuya / Smart Home
    "105A17": "Tuya", "20F41B": "Tuya", "7CF666": "Tuya", "A4C138": "Tuya", "D81F12": "Tuya",
}


def normalize_mac(mac: str) -> str:
    """Normalize any MAC string to aa:bb:cc:dd:ee:ff."""
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(p.zfill(2) for p in parts).lower()


def mac_query(q: str) -> str:
    """Reduce MAC search term to hex digits for substring search."""
    return re.sub(r"[^0-9a-fA-F]", "", q).lower()


def get_vendor(mac: str) -> str:
    """Identify device manufacturer or recognize Private/Randomized MAC."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(cleaned) < 6:
        return ""
    # IEEE 802 Locally Administered bit (bit 1 of 1st octet):
    # If set, MAC is randomized (used by iOS, Android, macOS private Wi-Fi).
    try:
        first_byte = int(cleaned[:2], 16)
        is_random = bool(first_byte & 0x02)
    except ValueError:
        is_random = False

    oui = cleaned[:6]
    vendor = OUI_MAP.get(oui, "")
    if vendor:
        return f"{vendor} (Private MAC)" if is_random else vendor
    if is_random:
        return "Private / Random MAC"
    return "Unknown"


# ---------------------------------------------------------------------------
# Network Interface & Subnet Discovery
# ---------------------------------------------------------------------------
def local_ip() -> str:
    """Determine the primary IP of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def detect_default_network() -> tuple[str, str]:
    """Detect current IP and actual subnet prefix length from network adapter."""
    my_ip = local_ip()
    detected_cidr = f"{my_ip}/24"

    if IS_MAC:
        try:
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
            m_if = re.search(r"interface:\s*(\S+)", r)
            iface = m_if.group(1) if m_if else "en0"
            out = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
            m_inet = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", out)
            if m_inet:
                my_ip = m_inet.group(1)
                prefix = bin(int(m_inet.group(2), 16)).count("1")
                detected_cidr = f"{my_ip}/{prefix}"
        except Exception:
            pass
    elif IS_LINUX:
        try:
            out = subprocess.run(["ip", "-4", "route", "show", "to", "default"], capture_output=True, text=True).stdout
            m_if = re.search(r"dev\s+(\S+)", out)
            iface = m_if.group(1) if m_if else "eth0"
            out_addr = subprocess.run(["ip", "-4", "addr", "show", "dev", iface], capture_output=True, text=True).stdout
            m_cidr = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out_addr)
            if m_cidr:
                my_ip = m_cidr.group(1)
                detected_cidr = f"{my_ip}/{m_cidr.group(2)}"
        except Exception:
            pass

    return my_ip, detected_cidr


def get_active_mac() -> str:
    """Retrieve MAC address of the active primary interface."""
    if IS_MAC:
        try:
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
            m_if = re.search(r"interface:\s*(\S+)", r)
            iface = m_if.group(1) if m_if else "en0"
            out = subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout
            m_mac = re.search(r"ether\s+([0-9a-fA-F:]{17})", out)
            if m_mac:
                return m_mac.group(1).lower()
        except Exception:
            pass
    elif IS_LINUX:
        try:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
            m = re.search(r"default\s+via\s+\S+\s+dev\s+(\S+)", out)
            iface = m.group(1) if m else "eth0"
            with open(f"/sys/class/net/{iface}/address") as f:
                return f.read().strip().lower()
        except Exception:
            pass
    elif IS_WINDOWS:
        try:
            out = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
            m = re.search(r"\"([0-9A-Fa-f-]{17})\"", out)
            if m:
                return m.group(1).replace("-", ":").lower()
        except Exception:
            pass

    import uuid
    node = uuid.getnode()
    return ":".join(f"{b:02x}" for b in node.to_bytes(6, "big"))


# ---------------------------------------------------------------------------
# DHCP Server Discovery
# ---------------------------------------------------------------------------
def discover_dhcp(timeout: float = 2.5) -> list[dict]:
    """
    Broadcast a standard DHCP Discover request (UDP 67/68) to locate all DHCP servers.
    Useful for identifying network gateways and detecting rogue DHCP servers.
    """
    mac_str = get_active_mac()
    try:
        import binascii
        mac_bytes = binascii.unhexlify(mac_str.replace(":", ""))
    except Exception:
        mac_bytes = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])

    xid = random.randint(1, 0xFFFFFFFF)
    # BOOTREQUEST struct: op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr...
    hdr = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s4s",
        1, 1, 6, 0,
        xid,
        0, 0x8000,  # broadcast flag
        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
        mac_bytes.ljust(16, b"\x00"),
        b"\x00" * 64,
        b"\x00" * 128,
        bytes([99, 130, 83, 99])  # DHCP Magic Cookie
    )
    # DHCP Options: Option 53 (Discover), Option 61 (Client-ID), Option 55 (PRL), Option 255 (End)
    client_id = bytes([61, 7, 1]) + mac_bytes
    prl = bytes([55, 4, 1, 3, 6, 15])  # Request Subnet, Router, DNS, Domain
    opts = bytes([53, 1, 1]) + client_id + prl + bytes([255])
    packet = hdr + opts

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(0.5)

    servers = []
    try:
        s.bind(("0.0.0.0", 68))
        s.sendto(packet, ("255.255.255.255", 67))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
                if len(data) < 240:
                    continue
                resp_xid = struct.unpack("!I", data[4:8])[0]
                if resp_xid != xid:
                    continue

                info = {
                    "server_ip": addr[0],
                    "offered_ip": socket.inet_ntoa(data[16:20]),
                    "netmask": "",
                    "router": "",
                    "dns": [],
                    "lease_sec": 0,
                }
                idx = 240
                while idx < len(data):
                    opt = data[idx]
                    if opt == 255:
                        break
                    if opt == 0:
                        idx += 1
                        continue
                    length = data[idx + 1]
                    val = data[idx + 2 : idx + 2 + length]
                    if opt == 54 and len(val) >= 4:
                        info["server_ip"] = socket.inet_ntoa(val[:4])
                    elif opt == 1 and len(val) >= 4:
                        info["netmask"] = socket.inet_ntoa(val[:4])
                    elif opt == 3 and len(val) >= 4:
                        info["router"] = socket.inet_ntoa(val[:4])
                    elif opt == 6:
                        info["dns"] = [socket.inet_ntoa(val[i : i + 4]) for i in range(0, len(val), 4)]
                    elif opt == 51 and len(val) >= 4:
                        info["lease_sec"] = struct.unpack("!I", val[:4])[0]
                    idx += 2 + length

                if not any(s["server_ip"] == info["server_ip"] for s in servers):
                    servers.append(info)
            except socket.timeout:
                pass
    except PermissionError:
        print("[!] Note: DHCP Discover on port 68 requires administrator/root permissions.", file=sys.stderr)
    except OSError as e:
        print(f"[!] DHCP Discover socket error: {e}", file=sys.stderr)
    finally:
        s.close()

    return servers


# ---------------------------------------------------------------------------
# Ping & ARP Scanning
# ---------------------------------------------------------------------------
def ping(ip: str, timeout_ms: int) -> bool:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_ms / 1000 + 2,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def read_arp_table() -> dict[str, str]:
    """Read system ARP table using arp -an or ip neigh."""
    table = {}
    out = ""
    try:
        out = subprocess.run(["arp", "-an"], capture_output=True, text=True, errors="ignore").stdout
    except FileNotFoundError:
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        except FileNotFoundError:
            pass

    for line in out.splitlines():
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        table[ip_m.group(1)] = mac
    return table


# ---------------------------------------------------------------------------
# Multi-Protocol Name Resolution (DNS + mDNS + NetBIOS)
# ---------------------------------------------------------------------------
def resolve_name_mdns(ip: str, timeout: float = 0.4) -> str:
    """Resolve .local hostname using Multicast DNS (RFC 6762)."""
    parts = ip.split(".")[::-1]
    arpa = ".".join(parts) + ".in-addr.arpa"
    pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in arpa.split("."):
        pkt += struct.pack("!B", len(part)) + part.encode()
    pkt += b"\x00\x00\x0c\x00\x01"  # Type PTR, Class IN

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("224.0.0.251", 5353))
        t0 = time.time()
        while time.time() - t0 < timeout:
            data, addr = s.recvfrom(2048)
            if addr[0] == ip and len(data) > 12:
                # Fast extraction of .local name
                for chunk in data[12:].split(b"\x00"):
                    if b"local" in chunk:
                        cleaned = "".join(chr(c) if (32 <= c < 127) else "." for c in chunk).strip(".")
                        for sub in cleaned.split(".."):
                            sub = sub.strip(".")
                            if "local" in sub:
                                return sub
    except Exception:
        pass
    finally:
        s.close()
    return ""


def resolve_name_netbios(ip: str, timeout: float = 0.3) -> str:
    """Query NetBIOS Node Status on UDP port 137 for Windows / NAS computer names."""
    name = b"*" + b"\x00" * 15
    encoded = b"".join(bytes([(c >> 4) + 0x41, (c & 0x0F) + 0x41]) for c in name)
    pkt = (
        b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + bytes([len(encoded)])
        + encoded
        + b"\x00\x00\x21\x00\x01"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
        if len(data) > 56:
            num = data[56]
            for i in range(num):
                entry = data[57 + i * 18 : 57 + (i + 1) * 18]
                nb = entry[:15].decode("latin-1", errors="ignore").strip()
                if entry[15] == 0x00 and nb:
                    return nb
    except Exception:
        pass
    finally:
        s.close()
    return ""


def resolve_name(ip: str) -> str:
    """Try system DNS, mDNS (.local), and NetBIOS to find device hostname."""
    try:
        h = socket.gethostbyaddr(ip)[0]
        if h and h != ip:
            return h
    except (socket.herror, socket.gaierror, OSError):
        pass

    mdns = resolve_name_mdns(ip)
    if mdns:
        return mdns

    nbns = resolve_name_netbios(ip)
    if nbns:
        return nbns

    return ""


# ---------------------------------------------------------------------------
# Quick Port Scanner
# ---------------------------------------------------------------------------
def check_ports(ip: str, ports: list[int], timeout: float = 0.3) -> list[int]:
    """Check if specific TCP ports are open on the target."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports


# ---------------------------------------------------------------------------
# Scanning Core Logic
# ---------------------------------------------------------------------------
def perform_scan(net: ipaddress.IPv4Network, my_ip: str, timeout_ms: int, workers: int,
                 no_resolve: bool, ports_to_check: list[int] | None = None) -> list[dict]:
    """Execute ping sweep + ARP retrieval + hostname & vendor enrichment."""
    hosts = [str(h) for h in net.hosts()]

    with ThreadPoolExecutor(max_workers=workers) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(lambda h: ping(h, timeout_ms), hosts)) if ok}

    arp = read_arp_table()
    found = sorted({ip for ip in alive | set(arp) if ipaddress.ip_address(ip) in net},
                   key=ipaddress.ip_address)

    names = {}
    if not no_resolve:
        with ThreadPoolExecutor(max_workers=min(workers, 64)) as ex:
            names = dict(zip(found, ex.map(resolve_name, found)))

    port_results = {}
    if ports_to_check:
        with ThreadPoolExecutor(max_workers=min(workers, 32)) as ex:
            port_results = dict(zip(found, ex.map(lambda ip: check_ports(ip, ports_to_check), found)))

    results = []
    for ip in found:
        mac = arp.get(ip, "(this host)" if ip == my_ip else "")
        vendor = get_vendor(mac) if mac and mac != "(this host)" else ("(this host)" if ip == my_ip else "")
        results.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": names.get(ip, ""),
            "ping": "yes" if ip in alive else "no (ARP only)",
            "ports": port_results.get(ip, []) if ports_to_check else None,
        })
    return results


# ---------------------------------------------------------------------------
# Output Formats & Printing
# ---------------------------------------------------------------------------
def print_table(rows: list[dict], has_ports: bool = False):
    """Print results in a clean formatted ASCII table."""
    if has_ports:
        print(f"\n{'IP Address':<16} {'MAC Address':<18} {'Vendor':<16} {'Ping':<13} {'Ports':<12} Hostname")
        print("-" * 92)
        for r in rows:
            ports_str = ",".join(str(p) for p in r["ports"]) if r["ports"] else "-"
            print(f"{r['ip']:<16} {r['mac']:<18} {r['vendor']:<16} {r['ping']:<13} {ports_str:<12} {r['hostname']}")
    else:
        print(f"\n{'IP Address':<16} {'MAC Address':<18} {'Vendor':<18} {'Ping':<14} Hostname")
        print("-" * 80)
        for r in rows:
            print(f"{r['ip']:<16} {r['mac']:<18} {r['vendor']:<18} {r['ping']:<14} {r['hostname']}")
    print(f"\nFound {len(rows)} device(s)")


def print_dhcp_info(servers: list[dict]):
    """Display detected DHCP server details and alert on Rogue DHCP servers."""
    if not servers:
        print("[!] No DHCP servers responded to broadcast Discover request.", file=sys.stderr)
        return

    print("\n" + "=" * 65)
    print("                DHCP SERVER DISCOVERY RESULT")
    print("=" * 65)
    if len(servers) > 1:
        print(f"\n[⚠️ ALERT] {len(servers)} DHCP servers responded! Potential Rogue DHCP Server detected!\n",
              file=sys.stderr)

    for i, s in enumerate(servers, 1):
        vendor = get_vendor(get_active_mac())  # fallback
        lease = s["lease_sec"]
        lease_str = f"{lease}s ({lease // 3600} hours)" if lease else "Unknown"
        dns_str = ", ".join(s["dns"]) if s["dns"] else "None reported"

        print(f"[DHCP Server #{i}]")
        print(f"  Server IP:       {s['server_ip']}")
        print(f"  Offered IP:      {s['offered_ip']}")
        print(f"  Subnet Mask:     {s['netmask']}")
        print(f"  Default Gateway: {s['router']}")
        print(f"  DNS Servers:     {dns_str}")
        print(f"  Lease Time:      {lease_str}")
        print("-" * 65)


# ---------------------------------------------------------------------------
# Watch Mode
# ---------------------------------------------------------------------------
def run_watch_mode(net: ipaddress.IPv4Network, my_ip: str, args: argparse.Namespace):
    """Continuously monitor subnet and display device connect/disconnect events."""
    print(f"[*] Starting watch mode on {net} (interval: {args.interval}s). Press Ctrl+C to stop.\n", file=sys.stderr)
    known = {}

    try:
        while True:
            current_scan = perform_scan(net, my_ip, args.timeout, args.workers, args.no_resolve)
            current_map = {r["ip"]: r for r in current_scan}
            now = time.strftime("%H:%M:%S")

            if not known:
                # Initial baseline
                print(f"[{now}] Baseline scan complete: {len(current_scan)} device(s) online:")
                print_table(current_scan)
                known = current_map
            else:
                # Compare
                new_ips = set(current_map) - set(known)
                offline_ips = set(known) - set(current_map)

                for ip in sorted(new_ips, key=ipaddress.ip_address):
                    item = current_map[ip]
                    name_str = f" ({item['hostname']})" if item["hostname"] else ""
                    print(f"\033[92m[+] [{now}] NEW DEVICE:\033[0m {ip:<15} | {item['mac']:<17} | {item['vendor']:<16}{name_str}")

                for ip in sorted(offline_ips, key=ipaddress.ip_address):
                    item = known[ip]
                    name_str = f" ({item['hostname']})" if item["hostname"] else ""
                    print(f"\033[91m[-] [{now}] OFFLINE:   \033[0m {ip:<15} | {item['mac']:<17} | {item['vendor']:<16}{name_str}")

                known = current_map

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Watch mode stopped.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Find IP addresses, MAC vendors, hostnames, and DHCP servers on the LAN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("subnet", nargs="?", help="e.g. 192.168.1.0/24 (default: auto-detected active subnet)")
    ap.add_argument("--dhcp", "-D", action="store_true", help="discover DHCP server(s) on the network")
    ap.add_argument("--dhcp-only", action="store_true", help="only discover DHCP server(s) and exit")
    ap.add_argument("--mac", help="filter by MAC (full or partial match)")
    ap.add_argument("--name", help="filter by hostname (case-insensitive substring)")
    ap.add_argument("--vendor", help="filter by manufacturer/vendor (e.g. apple, cisco, espressif)")
    ap.add_argument("--watch", "-w", action="store_true", help="continuous watch mode for new devices")
    ap.add_argument("--interval", type=int, default=5, help="watch mode refresh interval in seconds (default 5)")
    ap.add_argument("--ports", help="check common ports, e.g. '80,443,22'")
    ap.add_argument("--timeout", type=int, default=800, help="ping timeout in ms (default 800)")
    ap.add_argument("--workers", type=int, default=128, help="number of concurrent worker threads (default 128)")
    ap.add_argument("--no-resolve", action="store_true", help="skip hostname resolution (faster)")
    ap.add_argument("--csv", help="save results to a CSV file")
    ap.add_argument("--json", nargs="?", const="-", help="output JSON format (optional file path, or '-' for stdout)")
    args = ap.parse_args()

    # DHCP Server Discovery Mode
    if args.dhcp or args.dhcp_only:
        print("[*] Broadcasting DHCP Discover to identify DHCP servers ...", file=sys.stderr)
        dhcp_servers = discover_dhcp()
        print_dhcp_info(dhcp_servers)
        if args.dhcp_only:
            return

    my_ip, default_cidr = detect_default_network()
    subnet_target = args.subnet or default_cidr
    try:
        net = ipaddress.ip_network(subnet_target, strict=False)
    except ValueError as e:
        sys.exit(f"Invalid subnet: {e}")
    if net.num_addresses > 4096:
        sys.exit("Subnet too large (> /20), please narrow it down")

    if args.watch:
        run_watch_mode(net, my_ip, args)
        return

    ports_to_check = None
    if args.ports:
        try:
            ports_to_check = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            sys.exit("Invalid ports format. Example: --ports 80,443,22")

    if not (args.json == "-"):
        hosts_count = len(list(net.hosts()))
        print(f"[*] This host: {my_ip}   Scanning: {net} ({hosts_count} hosts) ...", file=sys.stderr)

    rows = perform_scan(net, my_ip, args.timeout, args.workers, args.no_resolve, ports_to_check)

    # Filtering
    filtered = []
    for r in rows:
        if args.mac and mac_query(args.mac) not in mac_query(r["mac"]):
            continue
        if args.name and args.name.lower() not in r["hostname"].lower():
            continue
        if args.vendor and args.vendor.lower() not in r["vendor"].lower():
            continue
        filtered.append(r)
    rows = filtered

    # Output Rendering
    if args.json:
        json_str = json.dumps(rows, indent=2)
        if args.json == "-":
            print(json_str)
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Saved JSON: {args.json}", file=sys.stderr)
    else:
        print_table(rows, has_ports=bool(ports_to_check))

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            header = ["IP", "MAC", "Vendor", "Hostname", "Ping"]
            if ports_to_check:
                header.append("Ports")
            w.writerow(header)
            for r in rows:
                line = [r["ip"], r["mac"], r["vendor"], r["hostname"], r["ping"]]
                if ports_to_check:
                    line.append(",".join(str(p) for p in r["ports"]) if r["ports"] else "")
                w.writerow(line)
        print(f"Saved CSV: {args.csv}", file=sys.stderr)

    if (args.mac or args.name or args.vendor) and not rows:
        sys.exit(1)


if __name__ == "__main__":
    main()
