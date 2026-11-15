<#
.SYNOPSIS
  On-box backups BEFORE you harden anything. Nothing leaves the machine.
  DC:    DNS zone files + record CSV, all GPOs, AD users/groups CSV, SYSVOL scripts copy
  WEB:   IIS applicationHost.config, appcmd backup, every site/vdir folder (web root), FTP config
  All:   SMB share list + share ACLs + NTFS ACLs, Windows Firewall policy, local users/groups, audit policy
  Output: C:\bs\backup\<timestamp>\
.EXAMPLE
  .\backup.ps1
#>
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"
if (-not (Test-IsAdmin)) { Write-BS 'Run as Administrator.' -Level ALERT; return }
$ts  = Get-FileStamp
$dst = New-BSDir "backup\$ts"
$log = Join-Path $dst '_backup-log.txt'
Write-BS "Backup -> $dst" -Level HEAD -LogFile $log

# ---------------------------------------------------------------- everyone
netsh advfirewall export (Join-Path $dst 'firewall.wfw') | Out-Null
Write-BS 'Windows Firewall policy exported (restore: netsh advfirewall import <file>)' -Level OK -LogFile $log
auditpol /backup /file:(Join-Path $dst 'auditpol.csv') | Out-Null

$shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$)$' }
$shares | Select-Object Name,Path,Description | Export-Csv (Join-Path $dst 'shares.csv') -NoTypeInformation
$shares | ForEach-Object { Get-SmbShareAccess -Name $_.Name } | Select-Object Name,AccountName,AccessControlType,AccessRight | Export-Csv (Join-Path $dst 'share-access.csv') -NoTypeInformation
foreach ($s in $shares) {
    if ($s.Path -and (Test-Path $s.Path)) {
        $safe = $s.Name -replace '[^\w\-]','_'
        icacls $s.Path /save (Join-Path $dst "ntfs-acl-$safe.txt") /t /c /q | Out-Null
        $sizeMB = [math]::Round(((Get-ChildItem $s.Path -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
        if ($sizeMB -lt 500) {
            robocopy $s.Path (Join-Path $dst "share-$safe") /E /COPY:DAT /R:0 /W:0 /NFL /NDL /NJH /NJS | Out-Null
            Write-BS "Share $($s.Name) copied ($sizeMB MB) + NTFS ACLs saved (restore ACL: icacls <parent> /restore <file>)" -Level OK -LogFile $log
        } else {
            Write-BS "Share $($s.Name) is $sizeMB MB, only ACLs saved" -Level WARN -LogFile $log
        }
    }
}

if (-not (Test-IsDC)) {
    Get-LocalUser | Select-Object Name,Enabled,Description,PasswordLastSet | Export-Csv (Join-Path $dst 'local-users.csv') -NoTypeInformation
    Get-LocalGroup | ForEach-Object { $g = $_.Name; Get-LocalGroupMember $g | Select-Object @{n='Group';e={$g}},Name,ObjectClass } | Export-Csv (Join-Path $dst 'local-groups.csv') -NoTypeInformation
}

# ---------------------------------------------------------------- DC
if (Test-IsDC) {
    Import-Module ActiveDirectory; Import-Module GroupPolicy; Import-Module DnsServer
    $dnsDir = New-Item -ItemType Directory -Force -Path (Join-Path $dst 'dns')
    foreach ($z in Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' }) {
        $file = "bs-$ts-$($z.ZoneName).dns"
        Export-DnsServerZone -Name $z.ZoneName -FileName $file
        $src = Join-Path $env:windir "System32\dns\$file"
        if (Test-Path $src) { Copy-Item $src $dnsDir.FullName; Write-BS "DNS zone exported: $($z.ZoneName) (copy also stays in System32\dns\$file)" -Level OK -LogFile $log }
        Get-DnsServerResourceRecord -ZoneName $z.ZoneName | Select-Object HostName,RecordType,TimeToLive,@{n='Data';e={
            switch ($_.RecordType) { 'A' { $_.RecordData.IPv4Address } 'CNAME' { $_.RecordData.HostNameAlias } 'MX' { $_.RecordData.MailExchange } 'NS' { $_.RecordData.NameServer } 'TXT' { $_.RecordData.DescriptiveText } 'SRV' { "$($_.RecordData.DomainName):$($_.RecordData.Port)" } 'PTR' { $_.RecordData.PtrDomainName } default { '' } } }} |
            Export-Csv (Join-Path $dnsDir.FullName "$($z.ZoneName).csv") -NoTypeInformation
    }
    $gpoDir = New-Item -ItemType Directory -Force -Path (Join-Path $dst 'gpo')
    Backup-GPO -All -Path $gpoDir.FullName | Out-Null
    Get-GPOReport -All -ReportType Html -Path (Join-Path $dst 'gpo-report.html')
    Write-BS 'All GPOs backed up (restore one: Restore-GPO -Name <n> -Path <dir>) + HTML report' -Level OK -LogFile $log

    Get-ADUser -Filter * -Properties Enabled,Description,MemberOf,whenCreated,PasswordLastSet,ServicePrincipalName,DoesNotRequirePreAuth |
        Select-Object SamAccountName,Enabled,Description,whenCreated,PasswordLastSet,DoesNotRequirePreAuth,@{n='SPNs';e={$_.ServicePrincipalName -join ';'}},@{n='Groups';e={ ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ';' }} |
        Export-Csv (Join-Path $dst 'ad-users.csv') -NoTypeInformation
    Get-ADGroup -Filter * | ForEach-Object { $g = $_.Name; Get-ADGroupMember $_ | Select-Object @{n='Group';e={$g}},SamAccountName,objectClass } | Export-Csv (Join-Path $dst 'ad-group-members.csv') -NoTypeInformation
    Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName | Export-Csv (Join-Path $dst 'ad-ous.csv') -NoTypeInformation
    $dom = (Get-ADDomain).DNSRoot
    robocopy "\\$dom\SYSVOL\$dom\scripts" (Join-Path $dst 'netlogon') /E /R:0 /W:0 /NFL /NDL /NJH /NJS | Out-Null
    Write-BS 'AD users, groups, OUs, NETLOGON scripts saved' -Level OK -LogFile $log
    Write-BS 'For a full AD restore point consider: wbadmin start systemstatebackup (needs a second volume; slow)' -Level INFO -LogFile $log
}

# ---------------------------------------------------------------- IIS
if (Test-HasIIS) {
    Import-Module WebAdministration
    & "$env:windir\System32\inetsrv\appcmd.exe" add backup "bs-$ts" | Out-Null
    Copy-Item "$env:windir\System32\inetsrv\config\applicationHost.config" $dst
    Copy-Item "$env:windir\System32\inetsrv\config\administration.config" $dst
    Write-BS "IIS config saved + appcmd backup 'bs-$ts' (restore: appcmd restore backup bs-$ts)" -Level OK -LogFile $log
    $webDir = New-Item -ItemType Directory -Force -Path (Join-Path $dst 'web')
    $map = @()
    foreach ($root in Get-WebRoots) {
        $safe = ($root -replace '[:\\]','_').Trim('_')
        robocopy $root (Join-Path $webDir.FullName $safe) /E /COPY:DAT /R:0 /W:0 /NFL /NDL /NJH /NJS | Out-Null
        icacls $root /save (Join-Path $webDir.FullName "$safe.acl") /t /c /q | Out-Null
        $map += [pscustomobject]@{ Source = $root; Backup = (Join-Path $webDir.FullName $safe) }
        Write-BS "Web root copied: $root" -Level OK -LogFile $log
    }
    $map | Export-Csv (Join-Path $webDir.FullName 'map.csv') -NoTypeInformation
    Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject,Thumbprint,NotAfter,HasPrivateKey | Export-Csv (Join-Path $dst 'certs.csv') -NoTypeInformation
    Write-BS 'Web roots + ACLs saved. restore-web.ps1 uses web\map.csv' -Level OK -LogFile $log
}

Write-BS "Backup complete: $dst" -Level HEAD -LogFile $log
Write-BS 'Lock it down so Red Team cannot read or poison it: icacls C:\bs /inheritance:r /grant:r Administrators:F SYSTEM:F' -Level INFO -LogFile $log
