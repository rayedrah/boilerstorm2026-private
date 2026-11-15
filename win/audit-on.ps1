<#
.SYNOPSIS
  Turns on the logging you need to detect Red Team AND to prove it in incident reports.
  Safe for scoring: changes only audit/log settings, never services or access.
  Saves the old audit policy to C:\bs\auditpol-before.csv first.
  Covers: logon, process creation WITH command line (4688), account and group changes,
  service install (4697), scheduled tasks (4698), Kerberos (DC), directory service changes (DC, 5136),
  PowerShell script block logging (4104), bigger Security log, TaskScheduler operational log.
#>
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\_lib.ps1"
if (-not (Test-IsAdmin)) { Write-BS 'Run as Administrator.' -Level ALERT; return }
$out = Join-Path $BSRoot ("audit-on-" + (Get-FileStamp) + ".txt")

$before = Join-Path $BSRoot 'auditpol-before.csv'
if (-not (Test-Path $before)) { auditpol /backup /file:$before | Out-Null; Write-BS "Old audit policy saved to $before" -Level OK -LogFile $out }

# Force subcategory settings to win over legacy category settings
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -PropertyType DWord -Force | Out-Null

# Subcategory GUIDs are language independent (safer than names)
$subs = [ordered]@{
    'Logon'                               = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Logoff'                              = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'Special Logon'                       = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'Other Logon/Logoff Events'           = '{0CCE921C-69AE-11D9-BED3-505054503030}'
    'Account Lockout'                     = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    'Process Creation'                    = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'User Account Management'             = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management'           = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Computer Account Management'         = '{0CCE9236-69AE-11D9-BED3-505054503030}'
    'Other Account Management Events'     = '{0CCE923A-69AE-11D9-BED3-505054503030}'
    'Security System Extension'           = '{0CCE9211-69AE-11D9-BED3-505054503030}'
    'Security State Change'               = '{0CCE9210-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events'          = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'                 = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'Authentication Policy Change'        = '{0CCE9230-69AE-11D9-BED3-505054503030}'
    'Sensitive Privilege Use'             = '{0CCE9228-69AE-11D9-BED3-505054503030}'
    'Credential Validation'               = '{0CCE923F-69AE-11D9-BED3-505054503030}'
}
if (Test-IsDC) {
    $subs['Kerberos Authentication Service']        = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    $subs['Kerberos Service Ticket Operations']     = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    $subs['Directory Service Changes']              = '{0CCE923C-69AE-11D9-BED3-505054503030}'
    $subs['Directory Service Access']               = '{0CCE923B-69AE-11D9-BED3-505054503030}'
}
foreach ($k in $subs.Keys) {
    auditpol /set /subcategory:"$($subs[$k])" /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-BS "audit on: $k" -Level OK -LogFile $out } else { Write-BS "audit FAILED: $k" -Level WARN -LogFile $out }
}

# Command line in 4688
$p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $p -Force | Out-Null
New-ItemProperty -Path $p -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null
Write-BS 'Process command line logging ON (4688 shows full command)' -Level OK -LogFile $out

# PowerShell script block + module logging
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $ps -Force | Out-Null
New-ItemProperty -Path $ps -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
$pm = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path "$pm\ModuleNames" -Force | Out-Null
New-ItemProperty -Path $pm -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "$pm\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
Write-BS 'PowerShell script block + module logging ON (4104)' -Level OK -LogFile $out

# Bigger logs so Red Team noise does not roll your evidence away (also matters for the legal hold)
wevtutil sl Security /ms:1073741824 | Out-Null
wevtutil sl System /ms:268435456 | Out-Null
wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:268435456 | Out-Null
wevtutil sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true | Out-Null
Write-BS 'Security log 1 GB, System 256 MB, PowerShell 256 MB, TaskScheduler operational enabled' -Level OK -LogFile $out

# Windows Firewall logging (dropped + allowed) for connection evidence
Set-NetFirewallProfile -All -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 32767 -ErrorAction SilentlyContinue
Write-BS 'Firewall logging ON: %windir%\System32\LogFiles\Firewall\pfirewall.log' -Level OK -LogFile $out

auditpol /get /category:* | Out-File (Join-Path $BSRoot 'auditpol-after.txt')
Write-BS "Done. Screenshot this window as evidence of logging hardening (good for a 'logging' or 'legal hold' inject)." -Level HEAD -LogFile $out
