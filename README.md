# 🌐 DHCP Finder & LAN Device Scanner

> **Fast network device discovery, MAC vendor identification, hostname resolution, and DHCP server detection for LANs.**  
> Built with **zero external dependencies** (Python standard library only). Works seamlessly across **macOS**, **Linux**, and **Windows**.

---

## ✨ Features

1. **⚡ Fast Parallel Subnet Sweep:**  
   Multi-threaded ping sweep completing in seconds. Automatically merges ping replies with system ARP tables to detect devices even if they block ICMP echo requests.
2. **📡 DHCP Server Discovery & Rogue DHCP Detection:**  
   Broadcasts DHCP Discover packets to locate active DHCP servers, inspect offered configurations (Subnet Mask, Default Gateway, DNS, Lease Time), and alert if multiple DHCP servers are detected (**Rogue DHCP server** detection).
3. **🏷️ MAC Vendor / OUI Identification:**  
   Built-in database identifying top hardware manufacturers (Apple, Cisco, Intel, Espressif/ESP32, Raspberry Pi, TP-Link, Ubiquiti, MikroTik, Samsung, etc.) with automatic recognition of **Private / Randomized MAC Addresses** (iOS, Android, macOS private Wi-Fi).
4. **🌐 Multi-Protocol Hostname Resolution:**  
   Simultaneously resolves device names across three protocols:
   - **DNS PTR Lookup**
   - **mDNS / Bonjour (`.local`)** (Apple, Linux Avahi, ESP32, network printers)
   - **NetBIOS Name Service (UDP 137)** (Windows PCs, Samba file servers, NAS)
5. **⏱️ Watch Mode (`--watch`):**  
   Continuous real-time network monitoring with instant alerts when devices join or leave the network.
6. **🚪 Quick Port Scan (`--ports`):**  
   Rapid TCP connectivity checks for common management ports (e.g., HTTP 80, HTTPS 443, SSH 22).
7. **💾 Flexible Export Options:**  
   Export results directly to structured **CSV** or **JSON** for reporting or automation pipelines.
8. **🍎 macOS Local Network Privacy Auto-Handling:**  
   Detects and gracefully works around macOS Sequoia+ Local Network privacy sandbox restrictions on third-party Python installations.

---

## 🚀 Quick Start

### 1. Python (Recommended - Cross-Platform)
```bash
# Scan current local subnet
python3 find_ip.py

# Discover DHCP server(s) on the network
python3 find_ip.py --dhcp-only

# Discover DHCP server first, then scan the subnet
python3 find_ip.py --dhcp

# Filter devices by manufacturer / vendor
python3 find_ip.py --vendor apple
python3 find_ip.py --vendor espressif

# Filter by MAC address (full or partial match)
python3 find_ip.py --mac 78:64:a0

# Search by hostname
python3 find_ip.py --name laptop

# Live monitor network for joining / leaving devices
python3 find_ip.py --watch

# Check common open ports (e.g., HTTP, HTTPS, SSH)
python3 find_ip.py --ports 80,443,22

# Export results to CSV or JSON
python3 find_ip.py --csv result.csv
python3 find_ip.py --json devices.json
```

---

### 2. Bash Script (macOS / Linux)
```bash
chmod +x find_ip.sh

# Scan current local subnet
./find_ip.sh

# Scan a specific subnet
./find_ip.sh 192.168.1.0/24

# Filter by vendor or MAC address
./find_ip.sh -v cisco
./find_ip.sh -m 78:64:a0

# Export to CSV
./find_ip.sh -o output.csv
```

---

### 3. Windows PowerShell & Batch Launcher
```powershell
# Run using PowerShell
.\find_ip.ps1
.\find_ip.ps1 -Vendor apple
.\find_ip.ps1 -Subnet 192.168.1.0/24 -Csv result.csv
```
Or double-click `find_ip.bat` to launch with bypassed execution policy.

---

## 📋 CLI Options Reference

| Option | Shorthand | Description |
|---|---|---|
| `[subnet]` | - | Target subnet CIDR, e.g. `192.168.1.0/24` (defaults to active interface subnet) |
| `--dhcp` | `-D` | Discover DHCP server(s) before scanning the subnet |
| `--dhcp-only` | - | Discover DHCP server(s) and exit immediately |
| `--vendor <name>` | - | Filter devices by manufacturer name (case-insensitive substring) |
| `--mac <mac>` | - | Filter devices by MAC address (case-insensitive substring) |
| `--name <name>` | - | Filter devices by resolved hostname |
| `--watch` | `-w` | Enable continuous monitoring for device connect / disconnect events |
| `--interval <sec>` | - | Refresh interval in seconds for watch mode (default: 5) |
| `--ports <p1,p2>` | - | Check open TCP ports, e.g. `--ports 80,443,22` |
| `--timeout <ms>` | - | Ping timeout in milliseconds (default: 800ms) |
| `--workers <num>` | - | Number of concurrent worker threads (default: 128) |
| `--no-resolve` | - | Skip hostname resolution for faster scans |
| `--csv <file>` | - | Save results to a CSV file |
| `--json [file]` | - | Output in JSON format (specify file path or `-` for stdout) |

---

## 🖥️ Example Output

### Subnet Scan (`python3 find_ip.py`)
```text
[*] This host: 192.168.168.148   Scanning: 192.168.168.0/24 (254 hosts) ...

IP Address       MAC Address        Vendor             Ping           Hostname
--------------------------------------------------------------------------------
192.168.168.1    78:64:a0:54:8b:27  Cisco              yes            router.local
192.168.168.64   7c:b5:66:24:34:a7  Intel              no (ARP only)  
192.168.168.109  08:3a:2f:30:df:71  Espressif          yes            esp32-sensor.local
192.168.168.148  aa:86:a0:4c:cf:8c  Private / Random MAC yes          Kritsadas-MacBook-Pro.local
192.168.168.178  10:f6:0a:39:de:a6  Intel              no (ARP only)  

Found 5 device(s)
```

### DHCP Server Discovery (`python3 find_ip.py --dhcp-only`)
```text
[*] Broadcasting DHCP Discover to identify DHCP servers ...

=================================================================
                DHCP SERVER DISCOVERY RESULT
=================================================================
[DHCP Server #1]
  Server IP:       192.168.169.1
  Offered IP:      192.168.168.148
  Subnet Mask:     255.255.255.0
  Default Gateway: 192.168.168.1
  DNS Servers:     8.8.8.8, 8.8.4.4
  Lease Time:      430218s (119 hours)
-----------------------------------------------------------------
```

---

## 🔒 macOS Privacy Notes
On macOS Sequoia and newer, Python environments installed via Homebrew or Pyenv without Local Network entitlements may receive an empty ARP cache.  
`find_ip.py` automatically detects this restriction and re-executes seamlessly under `/usr/bin/python3` so MAC addresses and vendor data are always available.

---

## 📄 License
MIT License
