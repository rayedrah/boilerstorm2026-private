<#
.SYNOPSIS
  Snapshot of everything Red Team likes to touch. Run once right at 10:00.
  First run also becomes the baseline (C:\bs\baseline). diff.ps1 compares against it.
.EXAMPLE
  .\baseline.ps1              # snapshot (becomes baseline if none exists)
  .\baseline.ps1 -Promote     # make this snapshot the new baseline (after you cleaned the box)
#>
param(
    [switch]$Promote,
    [switch]$Quiet
)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"

$ts   = Get-FileStamp
$snap = New-BSDir "snap\$ts"
$log  = Join-Path $snap '_log.txt'

function Save-Set {
    # Writes NAME.csv (full detail, for screenshots/evidence) and NAME.sig (one line per item, for diff)
    param([string]$Name, $Objects, [string[]]$SigProps)
    $Objects = @($Objects)
    $Objects | Export-Csv -NoTypeInformation -Path (Join-Path $snap "$Name.csv") -Encoding UTF8
    $lines = foreach ($o in $Objects) { ($SigProps | ForEach-Object { "$($o.$_)" }) -join ' | ' }
    $lines | Sort-Object -Unique | Set-Content -Path (Join-Path $snap "$Name.sig") -Encoding UTF8
    if (-not $Quiet) { Write-BS ("{0,-16} {1} items" -f $Name, $Objects.Count) -LogFile $log }
}

Write-BS "Snapshot -> $snap" -Level HEAD -LogFile $log
$isDC = Test-IsDC

# ---------- accounts ----------
if ($isDC) {
    Import-Module ActiveDirectory
    $users = Get-ADUser -Filter * -Properties whenCreated,whenChanged,PasswordLastSet,adminCount,ServicePrincipalName,Description,LastLogonDate,DoesNotRequirePreAuth,TrustedForDelegation |
        Select-Object SamAccountName,Enabled,whenCreated,whenChanged,PasswordLastSet,LastLogonDate,adminCount,DoesNotRequirePreAuth,TrustedForDelegation,
            @{n='SPNs';e={$_.ServicePrincipalName -join ';'}},Description
    Save-Set 'users' $users @('SamAccountName','Enabled','adminCount','SPNs','DoesNotRequirePreAuth','TrustedForDelegation')
    Save-Set 'users-pwd' $users @('SamAccountName','PasswordLastSet')

    $privGroups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators',
                  'Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners',
                  'Remote Desktop Users','Remote Management Users','Cert Publishers','Key Admins','Enterprise Key Admins'
    $gm = foreach ($g in $privGroups) {
        foreach ($m in (Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Group = $g; Member = $m.SamAccountName; Class = $m.objectClass }
        }
    }
    Save-Set 'priv-groups' $gm @('Group','Member','Class')

    $comps = Get-ADComputer -Filter * -Properties whenCreated,TrustedForDelegation,OperatingSystem |
        Select-Object Name,Enabled,whenCreated,TrustedForDelegation,OperatingSystem
    Save-Set 'computers' $comps @('Name','Enabled','TrustedForDelegation')

    $gpos = Get-GPO -All | Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime
    Save-Set 'gpos' $gpos @('DisplayName','Id','GpoStatus','ModificationTime')

    # DNS records (DNS check is scored, record tampering = service down)
    $rr = foreach ($z in (Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' })) {
        foreach ($r in (Get-DnsServerResourceRecord -ZoneName $z.ZoneName)) {
            $data = switch ($r.RecordType) {
                'A'     { $r.RecordData.IPv4Address.IPAddressToString }
                'AAAA'  { $r.RecordData.IPv6Address.IPAddressToString }
                'CNAME' { $r.RecordData.HostNameAlias }
                'MX'    { "$($r.RecordData.Preference) $($r.RecordData.MailExchange)" }
                'NS'    { $r.RecordData.NameServer }
                'PTR'   { $r.RecordData.PtrDomainName }
                'TXT'   { $r.RecordData.DescriptiveText }
                'SRV'   { "$($r.RecordData.Priority) $($r.RecordData.Weight) $($r.RecordData.Port) $($r.RecordData.DomainName)" }
                default { '' }
            }
            [pscustomobject]@{ Zone = $z.ZoneName; Name = $r.HostName; Type = $r.RecordType; Data = $data; TTL = $r.TimeToLive }
        }
    }
    Save-Set 'dns' ($rr | Where-Object { $_.Type -ne 'SOA' }) @('Zone','Name','Type','Data')
} else {
    $lu = Get-LocalUser | Select-Object Name,Enabled,PasswordLastSet,LastLogon,Description,SID
    Save-Set 'users' $lu @('Name','Enabled')
    Save-Set 'users-pwd' $lu @('Name','PasswordLastSet')
    $lg = foreach ($g in 'Administrators','Remote Desktop Users','Remote Management Users','Backup Operators') {
        foreach ($m in (Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Group = $g; Member = $m.Name; Class = $m.ObjectClass }
        }
    }
    Save-Set 'priv-groups' $lg @('Group','Member','Class')
}

# ---------- network ----------
$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }

$listen = Get-NetTCPConnection -State Listen | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    [pscustomobject]@{ Proto='TCP'; Local="$($_.LocalAddress):$($_.LocalPort)"; Port=$_.LocalPort; PID=$_.OwningProcess; Process=$p.Name; Path=$p.ExecutablePath }
}
$listen += Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    [pscustomobject]@{ Proto='UDP'; Local="$($_.LocalAddress):$($_.LocalPort)"; Port=$_.LocalPort; PID=$_.OwningProcess; Process=$p.Name; Path=$p.ExecutablePath }
}
Save-Set 'listening' $listen @('Proto','Port','Process')

$est = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notin '127.0.0.1','::1' } | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    [pscustomobject]@{ Local="$($_.LocalAddress):$($_.LocalPort)"; Remote="$($_.RemoteAddress):$($_.RemotePort)"; RemoteIP=$_.RemoteAddress; PID=$_.OwningProcess; Process=$p.Name; Path=$p.ExecutablePath }
}
Save-Set 'established' $est @('RemoteIP','Process')

# ---------- processes / services / tasks ----------
$pl = $procs.Values | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,
    @{n='Owner';e={ try { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; "$($o.Domain)\$($o.User)" } catch { '' } }}
Save-Set 'processes' $pl @('Name','ExecutablePath')

$svc = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName
Save-Set 'services' $svc @('Name','StartMode','StartName','PathName')

$tasks = Get-ScheduledTask | ForEach-Object {
    $acts = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ;; '
    [pscustomobject]@{ Path=$_.TaskPath; Name=$_.TaskName; State=$_.State; RunAs=$_.Principal.UserId; Actions=$acts; Author=$_.Author; Date=$_.Date }
}
Save-Set 'tasks' $tasks @('Path','Name','RunAs','Actions')

# ---------- autostart locations ----------
$runKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
$auto = foreach ($k in $runKeys) {
    $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($item) {
        foreach ($prop in $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
            [pscustomobject]@{ Location=$k; Name=$prop.Name; Value="$($prop.Value)" }
        }
    }
}
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$auto += [pscustomobject]@{ Location='Winlogon'; Name='Userinit'; Value="$($wl.Userinit)" }
$auto += [pscustomobject]@{ Location='Winlogon'; Name='Shell';    Value="$($wl.Shell)" }
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$auto += [pscustomobject]@{ Location='Lsa'; Name='Security Packages'; Value=($lsa.'Security Packages' -join ',') }
$auto += [pscustomobject]@{ Location='Lsa'; Name='Notification Packages'; Value=($lsa.'Notification Packages' -join ',') }
foreach ($exe in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe') {
    $d = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe" -ErrorAction SilentlyContinue).Debugger
    if ($d) { $auto += [pscustomobject]@{ Location='IFEO'; Name=$exe; Value=$d } }
}
foreach ($dir in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") {
    Get-ChildItem -Path $dir -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $auto += [pscustomobject]@{ Location='StartupFolder'; Name=$_.FullName; Value=$_.LastWriteTime }
    }
}
Save-Set 'autoruns' $auto @('Location','Name','Value')

# WMI permanent event subscriptions (classic fileless persistence)
$wmi = @()
$wmi += Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | ForEach-Object { [pscustomobject]@{ Kind='Filter'; Name=$_.Name; Detail=$_.Query } }
$wmi += Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object { [pscustomobject]@{ Kind='CmdConsumer'; Name=$_.Name; Detail=$_.CommandLineTemplate } }
$wmi += Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { [pscustomobject]@{ Kind='ScriptConsumer'; Name=$_.Name; Detail=$_.ScriptText } }
$wmi += Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object { [pscustomobject]@{ Kind='Binding'; Name="$($_.Filter)"; Detail="$($_.Consumer)" } }
Save-Set 'wmi-subs' $wmi @('Kind','Name','Detail')

# Accessibility binaries (sticky keys backdoor = replaced with cmd.exe)
$acc = foreach ($f in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','cmd.exe','powershell.exe') {
    $p = Join-Path $env:windir "System32\$f"
    if (Test-Path $p) { [pscustomobject]@{ File=$f; SHA256=(Get-FileHash $p -Algorithm SHA256).Hash; Size=(Get-Item $p).Length } }
}
Save-Set 'access-bins' $acc @('File','SHA256')

# ---------- shares, defender, firewall ----------
$shares = foreach ($s in Get-SmbShare) {
    $acl = (Get-SmbShareAccess -Name $s.Name | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ','
    [pscustomobject]@{ Name=$s.Name; Path=$s.Path; Access=$acl }
}
Save-Set 'shares' $shares @('Name','Path','Access')

$mp = Get-MpPreference
$ms = Get-MpComputerStatus
$def = @(
    [pscustomobject]@{ Setting='RealTimeProtectionEnabled'; Value=$ms.RealTimeProtectionEnabled }
    [pscustomobject]@{ Setting='AntivirusEnabled'; Value=$ms.AntivirusEnabled }
    [pscustomobject]@{ Setting='ExclusionPath'; Value=($mp.ExclusionPath -join ';') }
    [pscustomobject]@{ Setting='ExclusionProcess'; Value=($mp.ExclusionProcess -join ';') }
    [pscustomobject]@{ Setting='ExclusionExtension'; Value=($mp.ExclusionExtension -join ';') }
    [pscustomobject]@{ Setting='DisableRealtimeMonitoring'; Value=$mp.DisableRealtimeMonitoring }
)
Save-Set 'defender' $def @('Setting','Value')

$fw = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked
Save-Set 'fw-profiles' $fw @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction')
$fwr = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Select-Object DisplayName,Profile,
    @{n='Ports';e={ ($_ | Get-NetFirewallPortFilter).LocalPort -join ',' }},
    @{n='Program';e={ ($_ | Get-NetFirewallApplicationFilter).Program }}
Save-Set 'fw-rules' $fwr @('DisplayName','Ports','Program')

$hf = Get-HotFix | Select-Object HotFixID,InstalledOn
Save-Set 'hotfixes' $hf @('HotFixID')

# ---------- web ----------
if (Test-HasIIS) {
    Import-Module WebAdministration
    $sites = Get-Website | Select-Object Name,State,physicalPath,@{n='Bindings';e={ ($_.bindings.Collection | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" }) -join ',' }}
    Save-Set 'iis-sites' $sites @('Name','physicalPath','Bindings')
    $pools = Get-ChildItem IIS:\AppPools | Select-Object Name,State,@{n='Identity';e={ $_.processModel.identityType }},@{n='User';e={ $_.processModel.userName }}
    Save-Set 'iis-pools' $pools @('Name','Identity','User')
    $mods = Get-WebGlobalModule | Select-Object Name,Image
    Save-Set 'iis-modules' $mods @('Name','Image')
}
$wf = foreach ($root in Get-WebRoots) {
    Get-ChildItem -Path $root -Recurse -File -Include $WebExt -Force -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Path=$_.FullName; SHA256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash; Modified=$_.LastWriteTime; Size=$_.Length }
    }
}
Save-Set 'webfiles' $wf @('Path','SHA256')

# ---------- promote ----------
$base = Join-Path $BSRoot 'baseline'
if ($Promote -or -not (Test-Path $base)) {
    if (Test-Path $base) { Rename-Item $base -NewName ("baseline-old-" + $ts) }
    Copy-Item -Path $snap -Destination $base -Recurse
    Write-BS "Baseline set: $base (screenshot this moment, it is your 'before' evidence)" -Level OK -LogFile $log
}
Write-BS "Done. CSVs in $snap (open with: Import-Csv <file> | Out-GridView)" -Level OK -LogFile $log
return $snap
