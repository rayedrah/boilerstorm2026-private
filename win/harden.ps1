<#
.SYNOPSIS
  Interactive quick hardening. Every item shows its CURRENT state and asks y/N before changing.
  Only settings that should not break scored services are offered. Each change is logged with
  before/after (C:\bs\harden-*.txt) so you can paste it into an inject memo as evidence.
  After answering, watch the next Quotient check.
.EXAMPLE
  .\harden.ps1
  .\harden.ps1 -ReportOnly       # just show current state of everything
#>
param([switch]$ReportOnly)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"
if (-not (Test-IsAdmin)) { Write-BS 'Run as Administrator.' -Level ALERT; return }
$out = Join-Path $BSRoot ("harden-" + (Get-FileStamp) + ".txt")
$isDC = Test-IsDC

function Ask {
    param([string]$Title, [string]$Current, [scriptblock]$Fix, [string]$Risk = '')
    Write-BS "$Title  | current: $Current" -Level HEAD -LogFile $out
    if ($Risk) { Write-BS "   risk: $Risk" -Level WARN }
    if ($ReportOnly) { return }
    $a = Read-Host '   apply? [y/N]'
    if ($a -match '^(y|yes)$') {
        try { & $Fix; Write-BS "   APPLIED: $Title" -Level OK -LogFile $out } catch { Write-BS "   FAILED: $($_.Exception.Message)" -Level ALERT -LogFile $out }
    } else { Write-BS '   skipped' -LogFile $out }
}

# 1 Guest
$g = Get-LocalUser Guest
if ($g) { Ask 'Disable Guest account' "enabled=$($g.Enabled)" { Disable-LocalUser Guest } }

# 2 SMBv1
$smb = Get-SmbServerConfiguration
Ask 'Disable SMBv1 server' "EnableSMB1Protocol=$($smb.EnableSMB1Protocol)" { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } 'very old clients only'

# 3 WDigest
$wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
Ask 'WDigest: no cleartext passwords in memory' "UseLogonCredential=$wd" {
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -PropertyType DWord -Force | Out-Null }

# 4 RDP NLA
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
Ask 'RDP: require Network Level Authentication' "UserAuthentication=$nla" {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 } 'RDP check "login is attempted": NLA is normal for modern clients, watch the check'

# 5 IFEO debuggers on accessibility tools
$ifeo = @()
foreach ($exe in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe') {
    $k = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
    if ((Get-ItemProperty $k).Debugger) { $ifeo += $k }
}
if ($ifeo) { Ask 'Remove IFEO Debugger backdoors (screenshot first!)' ($ifeo -join ', ') { foreach ($k in $ifeo) { Remove-ItemProperty $k -Name Debugger } } }

# 6 Defender
$mp = Get-MpPreference; $ms = Get-MpComputerStatus
if ($ms) {
    Ask 'Defender: real-time protection ON' "RTP=$($ms.RealTimeProtectionEnabled)" { Set-MpPreference -DisableRealtimeMonitoring $false }
    $ex = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ }
    if ($ex) {
        Ask 'Defender: remove ALL exclusions (screenshot first!)' ($ex -join '; ') {
            foreach ($p in $mp.ExclusionPath) { Remove-MpPreference -ExclusionPath $p }
            foreach ($p in $mp.ExclusionProcess) { Remove-MpPreference -ExclusionProcess $p }
            foreach ($p in $mp.ExclusionExtension) { Remove-MpPreference -ExclusionExtension $p } } 'an exclusion could belong to a real app (e.g. DB folder); check what each path is'
    }
}

# 7 LLMNR / NetBIOS poisoning
$llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient').EnableMulticast
Ask 'Disable LLMNR (Responder-style poisoning)' "EnableMulticast=$llmnr (empty = on)" {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
    New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -PropertyType DWord -Force | Out-Null }

# 8 SMB signing
Ask 'Require SMB signing (server)' "RequireSecuritySignature=$($smb.RequireSecuritySignature)" { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force } 'almost always fine; if SMB check fails right after, revert this'

# 9 Anonymous enumeration
$ra = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RestrictAnonymous
Ask 'Restrict anonymous SAM/share enumeration' "RestrictAnonymous=$ra" {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 1
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Value 1 }

if ($isDC) {
    Import-Module ActiveDirectory; Import-Module DnsServer
    # 10 Spooler
    $sp = Get-Service Spooler
    Ask 'DC: stop + disable Print Spooler' "$($sp.Status)/$($sp.StartType)" { Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled } 'only if no inject/scored service needs printing'
    # 11 AS-REP
    $np = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'
    if ($np) { Ask 'DC: require Kerberos pre-auth on all users' (($np.SamAccountName) -join ', ') { $np | Set-ADAccountControl -DoesNotRequirePreAuth $false } }
    # 12 DNS zone transfers + dynamic update
    foreach ($z in Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' }) {
        if ($z.SecureSecondaries -ne 'NoTransfer') {
            $zn = $z.ZoneName
            Ask "DNS ${zn}: disable zone transfers" $z.SecureSecondaries { Set-DnsServerPrimaryZone -Name $zn -SecureSecondaries NoTransfer } 'if an inject asks for a secondary DNS, re-allow only that IP'
        }
        if ($z.IsDsIntegrated -and $z.DynamicUpdate -ne 'Secure') {
            $zn = $z.ZoneName
            Ask "DNS ${zn}: secure dynamic updates only" $z.DynamicUpdate { Set-DnsServerPrimaryZone -Name $zn -DynamicUpdate Secure }
        }
    }
    # 13 MachineAccountQuota
    $dn = (Get-ADDomain).DistinguishedName
    $maq = (Get-ADObject $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    Ask 'DC: MachineAccountQuota -> 0' "$maq" { Set-ADDomain -Identity $dn -Replace @{'ms-DS-MachineAccountQuota' = 0 } }
}

Write-BS "Log with before/after: $out (attach to the memo, or screenshot this window)" -Level HEAD -LogFile $out
Write-BS 'NOT offered on purpose: enabling Windows Firewall default-deny, LDAP signing enforcement, lockout policy. Each one can break scoring; do them by hand, one at a time, watching Quotient.' -Level INFO
