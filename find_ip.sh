#!/usr/bin/env bash
# find_ip.sh - Find IP addresses of equipment / PCs / laptops on the LAN (macOS / Linux)
#
# Examples:
#   ./find_ip.sh                          # scan the current subnet (/24)
#   ./find_ip.sh 192.168.1.0/24           # scan a specific subnet
#   ./find_ip.sh -m AA:BB:CC:DD:EE:FF     # find IP by MAC (full or partial)
#   ./find_ip.sh -n laptop                # search by hostname
#   ./find_ip.sh -o result.csv            # export to CSV
#   ./find_ip.sh -r                       # skip hostname lookup (faster)

set -u

MAC_FILTER=""
NAME_FILTER=""
CSV_OUT=""
RESOLVE=1
PARALLEL=64
OS="$(uname -s)"

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "m:n:o:rh" opt; do
  case $opt in
    m) MAC_FILTER="$OPTARG" ;;
    n) NAME_FILTER="$OPTARG" ;;
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

# ---- IP of this machine ----
if [[ "$OS" == "Darwin" ]]; then
  IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  MY_IP="$(ipconfig getifaddr "${IFACE:-en0}" 2>/dev/null)"
else
  MY_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
fi
[[ -z "$SUBNET" ]] && SUBNET="${MY_IP}/24"
[[ "$SUBNET" != */* ]] && SUBNET="${SUBNET}/24"

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

[[ -n "$CSV_OUT" ]] && echo "IP,MAC,Hostname,Ping" >"$CSV_OUT"
printf "\n%-16s %-18s %-14s %s\n" "IP Address" "MAC Address" "Ping" "Hostname"
printf '%.0s-' {1..72}; echo

found=0
for ip in $ALL_IPS; do
  n=$(ip2int "$ip")
  (( n < FIRST || n > LAST )) && continue

  raw_mac="$(echo "$ARP" | awk -v ip="$ip" '$1==ip{print $2; exit}')"
  if [[ -n "$raw_mac" ]]; then mac="$(norm_mac "$raw_mac")"
  elif [[ "$ip" == "$MY_IP" ]]; then mac="(this host)"
  else mac=""; fi
  [[ "$mac" == "ff:ff:ff:ff:ff:ff" ]] && continue

  if [[ -n "$MAC_Q" && "${mac//:/}" != *"$MAC_Q"* ]]; then continue; fi

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
  printf "%-16s %-18s %-14s %s\n" "$ip" "$mac" "$p" "$name"
  [[ -n "$CSV_OUT" ]] && echo "$ip,$mac,$name,$p" >>"$CSV_OUT"
  (( found++ ))
done

echo -e "\nFound $found device(s)" >&2
[[ -n "$CSV_OUT" ]] && echo "Saved: $CSV_OUT" >&2
[[ ( -n "$MAC_FILTER" || -n "$NAME_FILTER" ) && $found -eq 0 ]] && exit 1
exit 0
