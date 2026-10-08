#!/usr/bin/env bash
# find_ip.sh - Find IP addresses of equipment / PCs / laptops on the LAN (macOS / Linux)
#
# Examples:
#   ./find_ip.sh                          # scan the current subnet
#   ./find_ip.sh 192.168.1.0/24           # scan a specific subnet
#   ./find_ip.sh -m AA:BB:CC:DD:EE:FF     # find IP by MAC (full or partial)
#   ./find_ip.sh -v apple                 # filter by vendor/brand
#   ./find_ip.sh -n laptop                # search by hostname
#   ./find_ip.sh -o result.csv            # export to CSV
#   ./find_ip.sh -r                       # skip hostname lookup (faster)

set -u

MAC_FILTER=""
NAME_FILTER=""
VENDOR_FILTER=""
CSV_OUT=""
RESOLVE=1
PARALLEL=64
OS="$(uname -s)"

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "m:n:v:o:rh" opt; do
  case $opt in
    m) MAC_FILTER="$OPTARG" ;;
    n) NAME_FILTER="$OPTARG" ;;
    v) VENDOR_FILTER="$OPTARG" ;;
    o) CSV_OUT="$OPTARG" ;;
    r) RESOLVE=0 ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))
SUBNET="${1:-}"

ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24) + (b<<16) + (c<<8) + d )); }
int2ip() { echo "$(( ($1>>24)&255 )).$(( ($1>>16)&255 )).$(( ($1>>8)&255 )).$(( $1&255 ))"; }

# normalize MAC -> aa:bb:cc:dd:ee:ff (macOS drops leading zeros, e.g. 0:1a:2:...)
norm_mac() {
  echo "$1" | tr 'A-F-' 'a-f:' | awk -F: '{for(i=1;i<=NF;i++) printf "%s%02s", (i>1?":":""), $i; print ""}' | tr ' ' '0'
}

get_vendor() {
  local m="${1//:/}"
  m="$(echo "$m" | tr 'a-f' 'A-F')"
  local b1="${m:1:1}"
  local is_rand=0
  [[ "$b1" =~ [26AE] ]] && is_rand=1
  local oui="${m:0:6}"
  local v=""
  case "$oui" in
    7864A0|1C1D86|00000C|001C0F|68BDAB) v="Cisco" ;;
    000393|000502|70EE50|D0880C|B8E856|ACBC32) v="Apple" ;;
    10F60A|7CB566|58961D|28D0EA|ECED04|0002B3|A44CC8) v="Intel" ;;
    083A2F|240AC4|30AEA4|84CCA8|A4CF12|EC6260) v="Espressif" ;;
    B827EB|DCA632|E45F01|28CDC1) v="Raspberry Pi" ;;
    50C7BF|000AEB|147590|1C3BF3|704F57) v="TP-Link" ;;
    00156D|24A43C|788A20|AC8BA9) v="Ubiquiti" ;;
    000C42|488F5A|6C3B6B) v="MikroTik" ;;
    54833A|0002CF|107B44) v="Zyxel" ;;
    0000F0|0007AB|0808C2|34C059) v="Samsung" ;;
    009EC8|18F0E4|286C07|7C49EB) v="Xiaomi" ;;
    001882|001E10|0425C5) v="Huawei" ;;
    001A11|3C5A37|546009) v="Google" ;;
    00065B|180373|24B6FD) v="Dell" ;;
    0001E6|000802|28924A) v="HP" ;;
  esac
  if [[ -n "$v" ]]; then
    if (( is_rand )); then echo "$v (Private MAC)"; else echo "$v"; fi
  elif (( is_rand )); then
    echo "Private/Random MAC"
  else
    echo "Unknown"
  fi
}

# ---- IP & Subnet detection ----
DEFAULT_PREFIX=24
if [[ "$OS" == "Darwin" ]]; then
  IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  MY_IP="$(ipconfig getifaddr "${IFACE:-en0}" 2>/dev/null)"
  HEX_MASK="$(ifconfig "${IFACE:-en0}" 2>/dev/null | awk '/netmask/{print $4}' | head -n 1)"
  if [[ -n "$HEX_MASK" && "$HEX_MASK" =~ ^0x ]]; then
    case "$HEX_MASK" in
      0xffffff00) DEFAULT_PREFIX=24 ;;
      0xfffffe00) DEFAULT_PREFIX=23 ;;
      0xfffffc00) DEFAULT_PREFIX=22 ;;
      0xfffff800) DEFAULT_PREFIX=21 ;;
      0xfffff000) DEFAULT_PREFIX=20 ;;
      0xffffff80) DEFAULT_PREFIX=25 ;;
      0xffffffc0) DEFAULT_PREFIX=26 ;;
    esac
  fi
else
  MY_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
  CIDR_PREFIX="$(ip -4 addr show 2>/dev/null | grep -w "$MY_IP" | awk '{print $2}' | cut -d/ -f2)"
  [[ -n "$CIDR_PREFIX" ]] && DEFAULT_PREFIX="$CIDR_PREFIX"
fi
[[ -z "$SUBNET" ]] && SUBNET="${MY_IP}/${DEFAULT_PREFIX}"
[[ "$SUBNET" != */* ]] && SUBNET="${SUBNET}/${DEFAULT_PREFIX}"

BASE="${SUBNET%/*}"; PREFIX="${SUBNET#*/}"
if (( PREFIX < 20 || PREFIX > 30 )); then echo "Only prefixes /20 - /30 are supported" >&2; exit 1; fi
MASK=$(( (0xFFFFFFFF << (32 - PREFIX)) & 0xFFFFFFFF ))
NET=$(( $(ip2int "$BASE") & MASK ))
BCAST=$(( NET | (~MASK & 0xFFFFFFFF) ))
FIRST=$(( NET + 1 )); LAST=$(( BCAST - 1 ))

echo "[*] This host: ${MY_IP:-?}   Scanning: $(int2ip $NET)/$PREFIX ($(( LAST - FIRST + 1 )) hosts) ..." >&2

# ---- Parallel ping sweep ----
ALIVE_FILE="$(mktemp)"
trap 'rm -f "$ALIVE_FILE"' EXIT

do_ping() {
  if [[ "$OS" == "Darwin" ]]; then ping -c 1 -W 800 "$1" >/dev/null 2>&1
  else ping -c 1 -W 1 "$1" >/dev/null 2>&1; fi && echo "$1" >>"$ALIVE_FILE"
}

count=0
for (( i = FIRST; i <= LAST; i++ )); do
  do_ping "$(int2ip $i)" &
  (( ++count % PARALLEL == 0 )) && wait
done
wait

# ---- Read ARP table as "ip mac" ----
if command -v arp >/dev/null 2>&1; then
  ARP="$(arp -an 2>/dev/null | sed -nE 's/.*\(([0-9.]+)\) at ([0-9a-fA-F:]+).*/\1 \2/p')"
else
  ARP="$(ip neigh 2>/dev/null | awk '/lladdr/{print $1, $5}')"
fi

# Merge ping replies + ARP entries, sorted
ALL_IPS="$( { cat "$ALIVE_FILE"; echo "$ARP" | awk '{print $1}'; } | grep -E '^[0-9.]+$' | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n)"

MAC_Q="$(echo "$MAC_FILTER" | tr -cd '0-9a-fA-F' | tr 'A-F' 'a-f')"
NAME_Q="$(echo "$NAME_FILTER" | tr 'A-Z' 'a-z')"
VENDOR_Q="$(echo "$VENDOR_FILTER" | tr 'A-Z' 'a-z')"

[[ -n "$CSV_OUT" ]] && echo "IP,MAC,Vendor,Hostname,Ping" >"$CSV_OUT"
printf "\n%-16s %-18s %-18s %-14s %s\n" "IP Address" "MAC Address" "Vendor" "Ping" "Hostname"
printf '%.0s-' {1..80}; echo

found=0
for ip in $ALL_IPS; do
  n=$(ip2int "$ip")
  (( n < FIRST || n > LAST )) && continue

  raw_mac="$(echo "$ARP" | awk -v ip="$ip" '$1==ip{print $2; exit}')"
  if [[ -n "$raw_mac" ]]; then
    mac="$(norm_mac "$raw_mac")"
    vendor="$(get_vendor "$mac")"
  elif [[ "$ip" == "$MY_IP" ]]; then
    mac="(this host)"
    vendor="(this host)"
  else
    mac=""
    vendor=""
  fi
  [[ "$mac" == "ff:ff:ff:ff:ff:ff" ]] && continue

  if [[ -n "$MAC_Q" && "${mac//:/}" != *"$MAC_Q"* ]]; then continue; fi
  if [[ -n "$VENDOR_Q" && "$(echo "$vendor" | tr 'A-Z' 'a-z')" != *"$VENDOR_Q"* ]]; then continue; fi

  name=""
  if (( RESOLVE )); then
    if [[ "$OS" == "Darwin" ]]; then
      name="$(dscacheutil -q host -a ip_address "$ip" 2>/dev/null | awk '/^name:/{print $2; exit}')"
    else
      name="$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')"
    fi
    [[ -z "$name" ]] && command -v host >/dev/null && \
      name="$(host -W 1 "$ip" 2>/dev/null | awk '/pointer/{sub(/\.$/,"",$NF); print $NF; exit}')"
  fi
  if [[ -n "$NAME_Q" && "$(echo "$name" | tr 'A-Z' 'a-z')" != *"$NAME_Q"* ]]; then continue; fi

  if grep -qx "$ip" "$ALIVE_FILE"; then p="yes"; else p="no (ARP only)"; fi
  printf "%-16s %-18s %-18s %-14s %s\n" "$ip" "$mac" "$vendor" "$p" "$name"
  [[ -n "$CSV_OUT" ]] && echo "$ip,$mac,$vendor,$name,$p" >>"$CSV_OUT"
  (( found++ ))
done

echo -e "\nFound $found device(s)" >&2
[[ -n "$CSV_OUT" ]] && echo "Saved: $CSV_OUT" >&2
[[ ( -n "$MAC_FILTER" || -n "$NAME_FILTER" || -n "$VENDOR_FILTER" ) && $found -eq 0 ]] && exit 1
exit 0
