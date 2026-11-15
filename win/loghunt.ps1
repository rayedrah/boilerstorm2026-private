<#
.SYNOPSIS
  One-shot log analysis for incident reports: "what happened in the last N hours".
  Summaries: failed logons by source IP, successful logons by account/type/IP, account and group
  changes, services and tasks created, log clearing, suspicious PowerShell, and (on WEB01) IIS
  requests that look like webshell use, scanning or injection.
.EXAMPLE
  .\loghunt.ps1                    # last 6 hours
  .\loghunt.ps1 -Hours 1 -Iis      # include IIS log analysis
  .\loghunt.ps1 -User jdoe         # everything about one account
  .\loghunt.ps1 -Ip 10.100.0.66    # everything from one address
#>
param(
    [int]$Hours = 6,
    [switch]$Iis,
    [string]$User,
    [string]$Ip
)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"
$out = Join-Path $BSRoot ("loghunt-" + (Get-FileStamp) + ".txt")
$since = (Get-Date).AddHours(-$Hours)
function Head { param($m) Write-BS "==== $m ====" -Level HEAD -LogFile $out }
function Line { param($m, $lvl = 'INFO') Write-BS $m -Level $lvl -LogFile $out }

Head "Log hunt on $env:COMPUTERNAME since $since"

$sec = Get-WinEvent -FilterHashtable @{ LogName='Security'; StartTime=$since; Id=4624,4625,4648,4720,4722,4724,4726,4728,4732,4756,4738,4740,4697,4698,4688,1102,4769 } |
    ForEach-Object { $f = Get-EventFields $_; $f['_Id'] = $_.Id; $f['_Time'] = $_.TimeCreated; [pscustomobject]$f }
if ($User) { $sec = $sec | Where-Object { $_.TargetUserName -eq $User -or $_.SubjectUserName -eq $User -or $_.MemberName -match $User } }
if ($Ip)   { $sec = $sec | Where-Object { $_.IpAddress -eq $Ip } }
Line ("{0} security events loaded" -f @($sec).Count)

Head 'Failed logons (4625) by source IP'
$sec | Where-Object _Id -eq 4625 | Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
    $users = ($_.Group | Group-Object TargetUserName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' '
    $first = ($_.Group | Sort-Object _Time | Select-Object -First 1)._Time
    $lastT = ($_.Group | Sort-Object _Time | Select-Object -Last 1)._Time
    Line ("{0,-16} {1,5} fails  {2:HH:mm}-{3:HH:mm}  {4}" -f $_.Name, $_.Count, $first, $lastT, $users) $(if ($_.Count -ge 10) { 'ALERT' } else { 'WARN' })
}

Head 'Successful logons (4624) by account, type, source (machine accounts hidden)'
$sec | Where-Object { $_._Id -eq 4624 -and $_.TargetUserName -notmatch '\$$' -and $_.TargetUserName -notin 'SYSTEM','ANONYMOUS LOGON','LOCAL SERVICE','NETWORK SERVICE' -and $_.TargetUserName -notmatch '^(DWM|UMFD)-' } |
    Group-Object TargetUserName, LogonType, IpAddress | Sort-Object Count -Descending | Select-Object -First 40 | ForEach-Object {
        $first = ($_.Group | Sort-Object _Time | Select-Object -First 1)._Time
        Line ("{0,-45} x{1,-4} first {2:HH:mm:ss}" -f $_.Name, $_.Count, $first)
    }

Head 'Successful logon AFTER failures from same IP (password guessed?)'
$failIps = $sec | Where-Object _Id -eq 4625 | Group-Object IpAddress | Where-Object Count -ge 3 | ForEach-Object Name
$sec | Where-Object { $_._Id -eq 4624 -and $failIps -contains $_.IpAddress -and $_.TargetUserName -notmatch '\$$' } | Sort-Object _Time | ForEach-Object {
    Line ("{0:HH:mm:ss} SUCCESS {1} from {2} type {3} after failures" -f $_._Time, $_.TargetUserName, $_.IpAddress, $_.LogonType) 'ALERT'
}

Head 'RDP / interactive logons (type 10, 2)'
$sec | Where-Object { $_._Id -eq 4624 -and $_.LogonType -in '10','2' -and $_.TargetUserName -notmatch '\$$|^(DWM|UMFD)-' } | Sort-Object _Time | ForEach-Object {
    Line ("{0:HH:mm:ss} {1}\{2} type {3} from {4}" -f $_._Time, $_.TargetDomainName, $_.TargetUserName, $_.LogonType, $_.IpAddress) 'WARN'
}

Head 'Account and group changes'
$names = @{ 4720='USER CREATED'; 4722='ENABLED'; 4724='PWD RESET'; 4726='DELETED'; 4728='ADD GLOBAL GRP'; 4732='ADD LOCAL GRP'; 4756='ADD UNIV GRP'; 4738='USER CHANGED'; 4740='LOCKOUT' }
$sec | Where-Object { $names.ContainsKey($_._Id) } | Sort-Object _Time | ForEach-Object {
    Line ("{0:HH:mm:ss} {1,-14} target={2} member={3} group/target={4} by={5}" -f $_._Time, $names[$_._Id], $_.TargetUserName, $_.MemberName, $_.TargetUserName, $_.SubjectUserName) $(if ($_._Id -in 4720,4728,4732,4756) { 'ALERT' } else { 'WARN' })
}

Head 'Services / tasks / log clearing'
$sec | Where-Object { $_._Id -in 4697,4698,1102 } | Sort-Object _Time | ForEach-Object {
    Line ("{0:HH:mm:ss} {1} {2}{3} {4} by {5}" -f $_._Time, $_._Id, $_.ServiceName, $_.TaskName, $_.ServiceFileName, $_.SubjectUserName) 'ALERT'
}
Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045; StartTime=$since } | ForEach-Object {
    $f = Get-EventFields $_
    Line ("{0:HH:mm:ss} 7045 new service {1} -> {2}" -f $_.TimeCreated, $f.ServiceName, $f.ImagePath) 'ALERT'
}

Head 'Suspicious process creation (4688, needs audit-on.ps1)'
$sec | Where-Object { $_._Id -eq 4688 -and ("$($_.CommandLine)" -match $BadCmdRegex -or (Split-Path -Leaf "$($_.ParentProcessName)") -in 'w3wp.exe','sqlservr.exe') } |
    Sort-Object _Time | ForEach-Object {
        Line ("{0:HH:mm:ss} {1} parent={2} : {3}" -f $_._Time, $_.SubjectUserName, (Split-Path -Leaf "$($_.ParentProcessName)"), $_.CommandLine) 'ALERT'
    }

Head 'Kerberoast indicators (4769 with RC4)'
$sec | Where-Object { $_._Id -eq 4769 -and $_.TicketEncryptionType -eq '0x17' -and $_.ServiceName -notmatch '\$$|krbtgt' } | ForEach-Object {
    Line ("{0:HH:mm:ss} RC4 TGS for {1} by {2} from {3}" -f $_._Time, $_.ServiceName, $_.TargetUserName, $_.IpAddress) 'ALERT'
}

Head 'PowerShell script blocks with bad patterns'
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$since } | ForEach-Object {
    $sb = "$($_.Properties[2].Value)"
    if ($sb -match $BadCmdRegex -or $sb -match '(?i)(mimikatz|sekurlsa|amsiInitFailed|Add-MpPreference|DisableRealtimeMonitoring)') {
        Line ("{0:HH:mm:ss} {1}" -f $_.TimeCreated, ($sb.Substring(0, [Math]::Min(200, $sb.Length)) -replace '\s+',' ')) 'ALERT'
    }
}

if ($Iis -or (Test-HasIIS)) {
    Head 'IIS logs'
    $logDirs = @()
    try { Import-Module WebAdministration; foreach ($s in Get-Website) { $logDirs += Join-Path ([Environment]::ExpandEnvironmentVariables($s.logFile.directory)) "W3SVC$($s.id)" } } catch {}
    $logDirs += 'C:\inetpub\logs\LogFiles'
    $files = $logDirs | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem $_ -Recurse -Filter *.log | Where-Object LastWriteTime -gt $since } | Sort-Object FullName -Unique
    $rows = foreach ($file in $files) {
        $fields = $null
        foreach ($l in Get-Content $file.FullName) {
            if ($l -like '#Fields:*') { $fields = ($l -replace '^#Fields:\s*','') -split ' '; continue }
            if ($l -like '#*' -or -not $fields) { continue }
            $v = $l -split ' '; $o = @{}
            for ($i = 0; $i -lt $fields.Count; $i++) { $o[$fields[$i]] = $v[$i] }
            [pscustomobject]$o
        }
    }
    Line ("{0} IIS requests parsed from {1} file(s) (times are UTC)" -f @($rows).Count, @($files).Count)
    $bad = '(?i)(cmd=|exec=|command=|\.\./|%2e%2e|union(\s|%20|\+)+select|<script|%3cscript|/etc/passwd|win\.ini|xp_cmdshell|whoami|powershell|base64|eval\(|shell)'
    Head 'IIS: requests that look like attacks or webshell use'
    $rows | Where-Object { "$($_.'cs-uri-stem')?$($_.'cs-uri-query')" -match $bad } | Select-Object -First 60 | ForEach-Object {
        Line ("{0} {1} {2} {3}?{4} -> {5}" -f $_.date, $_.time, $_.'c-ip', $_.'cs-method', "$($_.'cs-uri-stem')?$($_.'cs-uri-query')".Substring(0,[Math]::Min(150,"$($_.'cs-uri-stem')?$($_.'cs-uri-query')".Length)), $_.'sc-status') 'ALERT'
    }
    Head 'IIS: POSTs to script files (webshells are usually POSTed to)'
    $rows | Where-Object { $_.'cs-method' -eq 'POST' -and $_.'cs-uri-stem' -match '\.(aspx|ashx|asmx|asp|php)$' } | Group-Object 'cs-uri-stem','c-ip' | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        Line ("{0,-60} x{1}" -f $_.Name, $_.Count) 'WARN'
    }
    Head 'IIS: top client IPs and 4xx/5xx bursts'
    $rows | Group-Object 'c-ip' | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { Line ("{0,-16} {1} requests" -f $_.Name, $_.Count) }
    $rows | Where-Object { $_.'sc-status' -match '^(4|5)' } | Group-Object 'c-ip' | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { Line ("{0,-16} {1} error responses (scanner?)" -f $_.Name, $_.Count) 'WARN' }
    Head 'IIS: user agents of attack tools'
    $rows | Where-Object { $_.'cs(User-Agent)' -match '(?i)(sqlmap|nikto|gobuster|dirbuster|ffuf|feroxbuster|wfuzz|nuclei|curl|python-requests|go-http-client|masscan|nmap)' } | Group-Object 'c-ip','cs(User-Agent)' | Select-Object -First 15 | ForEach-Object { Line ("{0} x{1}" -f $_.Name, $_.Count) 'WARN' }
}

Line "Saved: $out" 'HEAD'
Line 'For the report: screenshot the relevant section with the clock visible, note first/last time and source IP.' 'INFO'
