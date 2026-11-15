<#
.SYNOPSIS
  Windows version of svcwatch (same targets.conf). Use it from DC01/WEB01 if the Linux boxes are busy or down.
  Redraws a status board every cycle; state changes go to C:\bs\svcwatch-*.txt with timestamps.
.EXAMPLE
  powershell -ep bypass -File .\svcwatch.ps1 -Team 7
  .\svcwatch.ps1 -Team 7 -Interval 30 -Conf .\targets.conf -Relearn
#>
param(
    [Parameter(Mandatory = $true)][int]$Team,
    [int]$Interval = 60,
    [string]$Conf = "$PSScriptRoot\targets.conf",
    [int]$TimeoutMs = 3500,
    [switch]$Relearn
)
$ErrorActionPreference = 'SilentlyContinue'
$root = 'C:\bs'; $stateDir = Join-Path $root 'svcwatch-state'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
if ($Relearn) { Remove-Item "$stateDir\*.fp" -Force }
$log = Join-Path $root ("svcwatch-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt")
$Host.UI.RawUI.WindowTitle = "SVCWATCH team $Team"

# accept any TLS cert for internal checks, never use the internet proxy
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls

function Stamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }
function LogLine($lvl, $msg) { Add-Content -Path $log -Value ("[{0}] [{1}] [{2}] {3}" -f (Stamp), $env:COMPUTERNAME, $lvl, $msg) }
function Resolve-Spec($s) {
    if ($s -like 'PUB.*') { return "10.100.$Team." + $s.Substring(4) }
    if ($s -like 'LAN.*') { return '10.42.0.' + $s.Substring(4) }
    return $s
}

$targets = Get-Content $Conf | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_.Trim() } | ForEach-Object {
    $p = ($_.Trim() -split '\s+')
    [pscustomobject]@{ Name = $p[0]; Host = (Resolve-Spec $p[1]); Kind = $p[2]; Arg = $(if ($p.Count -gt 3) { $p[3] } else { '' }) }
}
$status = @{}; $since = @{}; $everUp = @{}
LogLine 'HEAD' "svcwatch started: team $Team, $($targets.Count) checks, every ${Interval}s"

function Get-Banner($h, $port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($h, [int]$port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $null }
        $c.EndConnect($iar)
        $s = $c.GetStream(); $s.ReadTimeout = 2500
        $buf = New-Object byte[] 256
        try { $n = $s.Read($buf, 0, 256) } catch { $n = 0 }
        if ($n -gt 0) { return ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`n")[0].Trim() } else { return '' }
    } catch { return $null } finally { $c.Close() }
}

function Invoke-Check($t) {
    switch ($t.Kind) {
        'ping' {
            $r = (New-Object System.Net.NetworkInformation.Ping).Send($t.Host, 2000)
            if ($r.Status -eq 'Success') { return @('UP', "icmp $($r.RoundtripTime)ms", '') } else { return @('DOWN', 'no icmp reply', '') }
        }
        'tcp' {
            $b = Get-Banner $t.Host $t.Arg
            if ($null -ne $b) { return @('UP', "port $($t.Arg) open", '') } else { return @('DOWN', "port $($t.Arg) closed/filtered", '') }
        }
        'banner' {
            $b = Get-Banner $t.Host $t.Arg
            if ($null -eq $b) { return @('DOWN', "port $($t.Arg) closed/filtered", '') }
            if ($b -eq '') { return @('UP', "port $($t.Arg) open, no banner", '') }
            return @('UP', $b.Substring(0, [Math]::Min(60, $b.Length)), '')
        }
        { $_ -in 'http', 'https' } {
            $path = ($t.Arg -split ',')[0]; $nohash = $t.Arg -like '*,nohash'
            try {
                $req = [System.Net.HttpWebRequest]::Create("$($t.Kind)://$($t.Host)$path")
                $req.Proxy = $null; $req.Timeout = $TimeoutMs; $req.AllowAutoRedirect = $false
                try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
                if (-not $resp) { return @('DOWN', 'no HTTP response', '') }
                $code = [int]$resp.StatusCode
                $body = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd(); $resp.Close()
                $norm = ($body -replace '[0-9a-fA-F]{16,}', '') -replace '[0-9]+', ''
                $sha = [Security.Cryptography.SHA256]::Create()
                $fp = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($norm))) -replace '-', '').Substring(0, 12).ToLower()
                if ($nohash) { $fp = '' }
                if ($code -lt 400 -or $code -eq 401) { return @('UP', "HTTP $code, $($body.Length)B", $fp) } else { return @('DOWN', "HTTP $code", $fp) }
            } catch { return @('DOWN', 'no HTTP response', '') }
        }
        'dns' {
            $a = Resolve-DnsName -Name $t.Arg -Server $t.Host -Type A -DnsOnly -NoHostsFile -QuickTimeout
            $ips = ($a | Where-Object { $_.Type -eq 'A' } | ForEach-Object IPAddress | Sort-Object) -join ' '
            if ($ips) { return @('UP', "$($t.Arg) -> $ips", $ips) } else { return @('DOWN', "$($t.Arg): no answer", '') }
        }
        default { return @('DOWN', "unknown check $($t.Kind)", '') }
    }
}

while ($true) {
    $start = Get-Date
    $rows = foreach ($t in $targets) {
        $r = Invoke-Check $t; $st = $r[0]; $detail = $r[1]; $fp = $r[2]; $shown = $st
        if ($st -eq 'UP' -and $fp) {
            $fpf = Join-Path $stateDir "$($t.Name).fp"
            if (-not (Test-Path $fpf)) { Set-Content $fpf $fp; LogLine 'INFO' "$($t.Name) learned fingerprint $fp" }
            elseif ((Get-Content $fpf) -ne $fp) {
                $shown = 'CHANGED'; $detail = "$detail (was $(Get-Content $fpf))"
                if ($status[$t.Name] -ne 'CHANGED') { LogLine 'ALERT' "$($t.Name) $($t.Host) CONTENT/ANSWER CHANGED: $detail" }
            }
        }
        if ($st -eq 'UP') { $everUp[$t.Name] = $true }
        if ($st -eq 'DOWN' -and -not $everUp[$t.Name]) { $shown = 'NEVER-UP' }
        if ($status[$t.Name] -ne $shown) {
            $since[$t.Name] = Get-Date -Format 'HH:mm:ss'
            $lvl = switch ($shown) { 'DOWN' { 'ALERT' } 'UP' { 'OK' } default { 'INFO' } }
            LogLine $lvl "$($t.Name) $($t.Host) $($t.Kind) $($t.Arg): $($status[$t.Name]) -> $shown ($detail)"
        }
        $status[$t.Name] = $shown
        [pscustomobject]@{ Name = $t.Name; Host = $t.Host; Kind = $t.Kind; Arg = ($t.Arg -split ',')[0]; Status = $shown; Since = $since[$t.Name]; Detail = $detail }
    }
    Clear-Host
    $up = @($rows | Where-Object Status -eq 'UP').Count; $dn = @($rows | Where-Object Status -eq 'DOWN').Count
    Write-Host ("SVCWATCH team {0}  {1}  up:{2} down:{3}  log: {4}" -f $Team, (Stamp), $up, $dn, $log) -ForegroundColor Cyan
    Write-Host ("{0,-16} {1,-15} {2,-7} {3,-6} {4,-9} {5,-8} {6}" -f 'NAME', 'HOST', 'CHECK', 'ARG', 'STATUS', 'SINCE', 'DETAIL')
    foreach ($r in $rows) {
        $c = switch ($r.Status) { 'UP' { 'Green' } 'DOWN' { 'Red' } 'CHANGED' { 'Yellow' } default { 'DarkGray' } }
        $d = "$($r.Detail)"; $d = $d.Substring(0, [Math]::Min(60, $d.Length))
        Write-Host ("{0,-16} {1,-15} {2,-7} {3,-6} {4,-9} {5,-8} {6}" -f $r.Name, $r.Host, $r.Kind, $r.Arg, $r.Status, $r.Since, $d) -ForegroundColor $c
    }
    Write-Host "`nPUB down + LAN up => firewall/NAT. CHANGED => compare with backup. NEVER-UP => maybe not a real service." -ForegroundColor DarkGray
    Get-Content $log | Select-String '\[(ALERT|OK)\]' | Select-Object -Last 6 | ForEach-Object { Write-Host $_.Line -ForegroundColor DarkGray }
    $wait = $Interval - ((Get-Date) - $start).TotalSeconds
    if ($wait -lt 1) { $wait = 1 }
    Start-Sleep -Seconds ([int]$wait)
}
