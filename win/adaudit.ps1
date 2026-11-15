<#
.SYNOPSIS
  Active Directory audit for CAI-DC01. Read-only.
  Finds the AD backdoors Red Team likes: rogue admins, roastable accounts, DCSync rights,
  delegation, AdminSDHolder ACEs, GPP passwords, risky GPOs, DNS transfer settings.
.EXAMPLE
  .\adaudit.ps1
#>
param([int]$Days = 7)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"
if (-not (Test-IsDC)) { Write-BS 'Run this on the domain controller (CAI-DC01).' -Level ALERT; return }
Import-Module ActiveDirectory
Import-Module GroupPolicy

$out = Join-Path $BSRoot ("adaudit-" + (Get-FileStamp) + ".txt")
$since = (Get-Date).AddDays(-$Days)
function Head { param($m) Write-BS "==== $m ====" -Level HEAD -LogFile $out }
function Hit  { param($m, $lvl = 'ALERT') Write-BS $m -Level $lvl -LogFile $out }

$dom = Get-ADDomain
$dn  = $dom.DistinguishedName
Write-BS "Domain $($dom.DNSRoot) ($($dom.NetBIOSName))  DN=$dn" -Level HEAD -LogFile $out

# ---------------------------------------------------------------- privileged groups
Head 'Privileged groups (recursive)'
$priv = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators',
        'Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Cert Publishers','Key Admins',
        'Enterprise Key Admins','Remote Desktop Users','Remote Management Users'
foreach ($g in $priv) {
    $members = Get-ADGroupMember $g -Recursive
    $names = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
    $lvl = if ($g -in 'Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Schema Admins' -and $members) { 'ALERT' } else { 'INFO' }
    Write-BS ("{0,-28} [{1}] {2}" -f $g, @($members).Count, $names) -Level $lvl -LogFile $out
}
Get-ADUser -LDAPFilter '(adminCount=1)' | ForEach-Object { Write-BS "adminCount=1: $($_.SamAccountName)" -LogFile $out }

# ---------------------------------------------------------------- recent changes
Head "Accounts created or changed in last $Days days"
Get-ADUser -Filter * -Properties whenCreated,whenChanged,PasswordLastSet,Description |
    Where-Object { $_.whenCreated -gt $since -or $_.whenChanged -gt $since } |
    Sort-Object whenChanged -Descending |
    ForEach-Object { Write-BS ("{0,-22} created {1}  changed {2}  pwdset {3}  {4}" -f $_.SamAccountName, $_.whenCreated, $_.whenChanged, $_.PasswordLastSet, $_.Description) -Level WARN -LogFile $out }

Head 'All enabled users (look for ex-IT staff, test, svc, backup accounts)'
Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate,Description,Title,Department,MemberOf |
    Sort-Object SamAccountName | ForEach-Object {
        $groups = ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ';'
        Write-BS ("{0,-22} last={1,-20} {2} | {3} | {4}" -f $_.SamAccountName, $_.LastLogonDate, $_.Title, $_.Description, $groups) -LogFile $out
    }

# ---------------------------------------------------------------- risky account flags
Head 'Risky account settings'
Get-ADUser -Filter 'Enabled -eq $true' -Properties ServicePrincipalName | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' } |
    ForEach-Object { Hit "Kerberoastable (user with SPN): $($_.SamAccountName) -> $($_.ServicePrincipalName -join ', ')" 'WARN' }
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | ForEach-Object { Hit "AS-REP roastable (no pre-auth): $($_.SamAccountName)" }
Get-ADUser -Filter 'PasswordNotRequired -eq $true' -Properties PasswordNotRequired | Where-Object Enabled | ForEach-Object { Hit "PasswordNotRequired: $($_.SamAccountName)" 'WARN' }
Get-ADUser -Filter 'AllowReversiblePasswordEncryption -eq $true' | ForEach-Object { Hit "Reversible encryption: $($_.SamAccountName)" }
Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' | ForEach-Object { Write-BS "PasswordNeverExpires: $($_.SamAccountName)" -LogFile $out }
Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory } | ForEach-Object { Hit "SIDHistory set on $($_.SamAccountName)" }

Head 'Delegation'
$dcs = (Get-ADDomainController -Filter *).Name
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Where-Object { $dcs -notcontains $_.Name } | ForEach-Object { Hit "Unconstrained delegation (computer): $($_.Name)" }
Get-ADUser -Filter 'TrustedForDelegation -eq $true' | ForEach-Object { Hit "Unconstrained delegation (user): $($_.SamAccountName)" }
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo | ForEach-Object { Hit "Constrained delegation: $($_.Name) -> $($_.'msDS-AllowedToDelegateTo' -join ', ')" 'WARN' }
Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' | ForEach-Object { Hit "RBCD set on: $($_.Name)" }

Head 'krbtgt'
$k = Get-ADUser krbtgt -Properties PasswordLastSet
Write-BS "krbtgt PasswordLastSet: $($k.PasswordLastSet)  (golden ticket risk if Red Team had DA; reset twice, hours apart, only if needed)" -LogFile $out

# ---------------------------------------------------------------- ACL backdoors
Set-Location AD:
Head 'DCSync rights on domain root'
$repl = @{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'='Get-Changes'; '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'='Get-Changes-All'; '89e95b76-444d-4c62-991a-0facbeda640c'='Get-Changes-In-Filtered-Set' }
$okRepl = '(?i)(Domain Controllers|Enterprise Domain Controllers|Enterprise Read-only Domain Controllers|BUILTIN\\Administrators|Read-only Domain Controllers|NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS)'
(Get-Acl "AD:$dn").Access | Where-Object { $repl.ContainsKey("$($_.ObjectType)") -and $_.AccessControlType -eq 'Allow' } | ForEach-Object {
    $who = "$($_.IdentityReference)"
    if ($who -match $okRepl) { Write-BS "ok   $who : $($repl["$($_.ObjectType)"])" -LogFile $out }
    else { Hit "DCSYNC RIGHT for $who : $($repl["$($_.ObjectType)"])" }
}
Head 'Dangerous ACEs on domain root'
(Get-Acl "AD:$dn").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and "$($_.IdentityReference)" -notmatch '(?i)(Domain Admins|Enterprise Admins|Administrators|SYSTEM|Enterprise Domain Controllers|Key Admins|Enterprise Key Admins)' } |
    ForEach-Object { Hit "Domain root: $($_.IdentityReference) has $($_.ActiveDirectoryRights)" }
Head 'AdminSDHolder'
(Get-Acl "AD:CN=AdminSDHolder,CN=System,$dn").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty' -and "$($_.IdentityReference)" -notmatch '(?i)(Domain Admins|Enterprise Admins|Administrators|SYSTEM|Cert Publishers|Self|Windows Authorization Access|Terminal Server License|Key Admins)' } |
    ForEach-Object { Hit "AdminSDHolder: $($_.IdentityReference) has $($_.ActiveDirectoryRights) (persists onto all protected accounts)" }
Head 'Privileged group ACLs'
foreach ($g in 'Domain Admins','Enterprise Admins','Administrators') {
    $gd = (Get-ADGroup $g).DistinguishedName
    (Get-Acl "AD:$gd").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty|Self' -and "$($_.IdentityReference)" -notmatch '(?i)(Domain Admins|Enterprise Admins|Administrators|SYSTEM|Self|Key Admins)' } |
        ForEach-Object { Hit "$g : $($_.IdentityReference) has $($_.ActiveDirectoryRights)" }
}
Set-Location C:\

# ---------------------------------------------------------------- GPO
Head "GPOs (most recently changed first)"
Get-GPO -All | Sort-Object ModificationTime -Descending | ForEach-Object {
    $lvl = if ($_.ModificationTime -gt $since) { 'WARN' } else { 'INFO' }
    Write-BS ("{0,-40} modified {1}  status {2}" -f $_.DisplayName, $_.ModificationTime, $_.GpoStatus) -Level $lvl -LogFile $out
}
$sysvol = "\\$($dom.DNSRoot)\SYSVOL\$($dom.DNSRoot)\Policies"
Head 'SYSVOL: GPP passwords, scripts, scheduled tasks pushed by GPO'
Get-ChildItem $sysvol -Recurse -Include *.xml -File | Select-String -Pattern 'cpassword="[^"]+' | ForEach-Object { Hit "GPP cpassword in $($_.Path)" }
Get-ChildItem $sysvol -Recurse -File -Include ScheduledTasks.xml | ForEach-Object { Hit "GPO-deployed scheduled task: $($_.FullName)" 'WARN' }
Get-ChildItem $sysvol -Recurse -File -Include *.ps1,*.bat,*.cmd,*.vbs,*.exe,scripts.ini,psscripts.ini | ForEach-Object {
    Hit ("GPO script: {0} (modified {1})" -f $_.FullName, $_.LastWriteTime) 'WARN'
}
Get-ChildItem "\\$($dom.DNSRoot)\NETLOGON" -Recurse -File | ForEach-Object { Write-BS "NETLOGON file: $($_.FullName) ($($_.LastWriteTime))" -Level WARN -LogFile $out }

# ---------------------------------------------------------------- policy
Head 'Password and lockout policy'
$pp = Get-ADDefaultDomainPasswordPolicy
Write-BS ("MinLen={0} Complexity={1} MaxAge={2} LockoutThreshold={3} LockoutDuration={4}" -f $pp.MinPasswordLength, $pp.ComplexityEnabled, $pp.MaxPasswordAge, $pp.LockoutThreshold, $pp.LockoutDuration) -LogFile $out
Write-BS 'Careful: a lockout threshold can lock SCORED accounts during a spray and drop service checks.' -Level WARN -LogFile $out
Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object { Write-BS "FGPP $($_.Name) applies to $($_.AppliesTo -join ',')" -LogFile $out }
$maq = (Get-ADObject $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
Write-BS "ms-DS-MachineAccountQuota = $maq (any user can join this many computers)" -Level $(if ($maq -gt 0) { 'WARN' } else { 'INFO' }) -LogFile $out

# ---------------------------------------------------------------- DNS
Head 'DNS server'
Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated } | ForEach-Object {
    $lvl = if ($_.SecureSecondaries -eq 'TransferAnyServer' -or $_.DynamicUpdate -eq 'NonsecureAndSecure') { 'ALERT' } else { 'INFO' }
    Write-BS ("zone {0,-30} type={1} dynUpdate={2} transfers={3}" -f $_.ZoneName, $_.ZoneType, $_.DynamicUpdate, $_.SecureSecondaries) -Level $lvl -LogFile $out
}
$fwd = Get-DnsServerForwarder
Write-BS "Forwarders: $($fwd.IPAddress -join ', ')" -LogFile $out

# ---------------------------------------------------------------- DC hardening quick look
Head 'DC settings'
$ldap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters').LDAPServerIntegrity
Write-BS "LDAPServerIntegrity=$ldap (2 = signing required)" -LogFile $out
$spool = Get-Service Spooler
if ($spool.Status -eq 'Running') { Hit 'Print Spooler running on the DC (coercion / PrintNightmare class). Stop+disable if nothing scored needs it' 'WARN' }
$ca = Get-Service CertSvc
if ($ca) { Hit 'AD CS (CertSvc) is installed. Check templates for ESC1-style misconfig. Do NOT confuse with the competition CA (out of scope).' 'WARN' }

Write-BS "Saved: $out" -Level HEAD -LogFile $out
