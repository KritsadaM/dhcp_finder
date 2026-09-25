<#
.SYNOPSIS
  find_ip.ps1 - Find IP addresses of equipment / PCs / laptops on the LAN (Windows PowerShell 5.1+ / PowerShell 7)

.EXAMPLE
  .\find_ip.ps1                               # scan the current subnet
  .\find_ip.ps1 -Subnet 192.168.1.0/24        # scan a specific subnet
  .\find_ip.ps1 -Mac AA-BB-CC-DD-EE-FF        # find IP by MAC (full or partial)
  .\find_ip.ps1 -Name laptop                  # search by hostname
  .\find_ip.ps1 -Csv result.csv               # export to CSV
  .\find_ip.ps1 -NoResolve                    # skip hostname lookup (faster)
#>
param(
    [string]$Subnet,
    [string]$Mac,
    [string]$Name,
    [string]$Csv,
    [int]$Timeout = 800,
    [switch]$NoResolve
)



function ConvertTo-UInt32([string]$ip) {
    $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($b)
    [BitConverter]::ToUInt32($b, 0)
}
function ConvertTo-IP([uint32]$n) {
    $b = [BitConverter]::GetBytes($n)
    [Array]::Reverse($b)
    ([System.Net.IPAddress]$b).ToString()
}

# ---- This host's IP + subnet, taken from the interface with a default gateway ----
$cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$myIP = if ($cfg) { $cfg.IPv4Address[0].IPAddress } else { $null }
if (-not $Subnet) {
    if (-not $cfg) { Write-Error "No active network interface found, please pass -Subnet"; exit 1 }
    $prefixLen = [Math]::Max($cfg.IPv4Address[0].PrefixLength, 20)   # avoid scanning huge ranges
    $Subnet = "$myIP/$prefixLen"
}
if ($Subnet -notmatch '/') { $Subnet = "$Subnet/24" }
$base, $prefix = $Subnet.Split('/'); $prefix = [int]$prefix
if ($prefix -lt 20 -or $prefix -gt 30) { Write-Error "Only prefixes /20 - /30 are supported"; exit 1 }

$mask  = [uint32]([uint64]0xFFFFFFFF -shl (32 - $prefix) -band 0xFFFFFFFF)
$net   = (ConvertTo-UInt32 $base) -band $mask
$bcast = $net -bor (-bnot $mask -band 0xFFFFFFFF)
$first = [uint32]($net + 1); $last = [uint32]($bcast - 1)
# for-loop instead of $first..$last: the PS 5.1 range operator only supports Int32
$targets = for ([uint32]$i = $first; $i -le $last; $i++) { ConvertTo-IP $i }

Write-Host "[*] This host: $myIP   Scanning: $(ConvertTo-IP $net)/$prefix ($($targets.Count) hosts) ..." -ForegroundColor Cyan

# ---- Parallel ping sweep (async) ----
$tasks = @{}
foreach ($ip in $targets) {
    $tasks[$ip] = (New-Object System.Net.NetworkInformation.Ping).SendPingAsync($ip, $Timeout)
}
try { [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks.Values) } catch {}
$alive = @{}
foreach ($kv in $tasks.GetEnumerator()) {
    if ($kv.Value.Status -eq 'RanToCompletion' -and $kv.Value.Result.Status -eq 'Success') { $alive[$kv.Key] = $true }
}

# ---- Read ARP table ----
$arp = @{}
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and $_.State -ne 'Unreachable' } |
    ForEach-Object { $arp[$_.IPAddress] = $_.LinkLayerAddress.Replace('-', ':').ToLower() }

# Merge ping replies + ARP entries (some hosts block ICMP but still answer ARP)
$found = @($alive.Keys) + @($arp.Keys) | Sort-Object -Unique | Where-Object {
    $n = ConvertTo-UInt32 $_; $n -ge $first -and $n -le $last
} | Sort-Object { ConvertTo-UInt32 $_ }

# ---- Parallel hostname lookup ----
$names = @{}
if (-not $NoResolve) {
    $dns = @{}
    foreach ($ip in $found) { $dns[$ip] = [System.Net.Dns]::GetHostEntryAsync($ip) }
    try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$dns.Values, 5000) } catch {}
    foreach ($kv in $dns.GetEnumerator()) {
        if ($kv.Value.Status -eq 'RanToCompletion' -and $kv.Value.Result.HostName -ne $kv.Key) { $names[$kv.Key] = $kv.Value.Result.HostName }
    }
}

$macQ = if ($Mac) { ($Mac -replace '[^0-9a-fA-F]', '').ToLower() } else { '' }

$rows = foreach ($ip in $found) {
    $m = if ($arp[$ip]) { $arp[$ip] } elseif ($ip -eq $myIP) { '(this host)' } else { '' }
    $h = [string]$names[$ip]
    if ($macQ -and ($m -replace ':', '') -notlike "*$macQ*") { continue }
    if ($Name -and $h -notlike "*$Name*") { continue }
    [PSCustomObject]@{
        IP       = $ip
        MAC      = $m
        Ping     = if ($alive[$ip]) { 'yes' } else { 'no (ARP only)' }
        Hostname = $h
    }
}

$rows | Format-Table -AutoSize
Write-Host "Found $(@($rows).Count) device(s)" -ForegroundColor Green

if ($Csv) {
    $rows | Export-Csv -Path $Csv -NoTypeInformation -Encoding UTF8
    Write-Host "Saved: $Csv"
}
if (($Mac -or $Name) -and -not $rows) { exit 1 }
