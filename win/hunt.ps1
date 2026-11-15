<#
.SYNOPSIS
  Persistence and webshell hunt. Read-only: it reports, it never deletes.
  Works without a baseline, so it is the right first thing to run at 10:00
  (Red Team may already be inside when the competition starts).
.EXAMPLE
  .\hunt.ps1
  .\hunt.ps1 -Hours 2        # "recent" = last 2 hours (default 48)
#>
param([int]$Hours = 48)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"

$out   = Join-Path $BSRoot ("hunt-" + (Get-FileStamp) + ".txt")
$since = (Get-Date).AddHours(-$Hours)
$hits  = 0
function Hit { param($m, $lvl = 'ALERT') $script:hits++; Write-BS $m -Level $lvl -LogFile $out }
function Head { param($m) Write-BS "==== $m ====" -Level HEAD -LogFile $out }

Write-BS "Hunt on $env:COMPUTERNAME, recent = since $since" -Level HEAD -LogFile $out

# ---------------------------------------------------------------- accounts
Head 'Accounts'
if (Test-IsDC) {
    Import-Module ActiveDirectory
    Get-ADUser -Filter * -Properties whenCreated,whenChanged | Where-Object { $_.whenCreated -gt $since } |
        ForEach-Object { Hit "New AD user: $($_.SamAccountName) created $($_.whenCreated)" }
    foreach ($g in 'Domain Admins','Enterprise Admins','Administrators','Schema Admins','Backup Operators','Account Operators','Server Operators','DnsAdmins','Group Policy Creator Owners') {
        $m = (Get-ADGroupMember $g -Recursive | ForEach-Object SamAccountName) -join ', '
        Write-BS ("{0,-28} {1}" -f $g, $m) -LogFile $out
    }
} else {
    Get-LocalUser | ForEach-Object { Write-BS ("local user {0,-20} enabled={1} pwdset={2}" -f $_.Name, $_.Enabled, $_.PasswordLastSet) -LogFile $out }
    $adm = (Get-LocalGroupMember Administrators | ForEach-Object Name) -join ', '
    Write-BS "Local Administrators: $adm" -LogFile $out
}
$guest = Get-LocalUser -Name Guest
if ($guest.Enabled) { Hit 'Guest account is ENABLED' }

# ---------------------------------------------------------------- scheduled tasks
Head 'Scheduled tasks'
foreach ($t in Get-ScheduledTask) {
    $acts = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ;; '
    $isMs = $t.TaskPath -like '\Microsoft\*'
    if ($acts -match $BadCmdRegex) { Hit "Suspicious task $($t.TaskPath)$($t.TaskName) [$($t.Principal.UserId)] -> $acts" }
    elseif (-not $isMs) { Write-BS "Non-Microsoft task $($t.TaskPath)$($t.TaskName) [$($t.Principal.UserId)] -> $acts" -Level WARN -LogFile $out }
}

# ---------------------------------------------------------------- services
Head 'Services'
foreach ($s in Get-CimInstance Win32_Service) {
    $p = "$($s.PathName)"
    if ($p -match $BadCmdRegex -or $p -match '(?i)(cmd(\.exe)?\s+/c|powershell|\\temp\\|\\users\\)') {
        Hit "Suspicious service $($s.Name) [$($s.StartName)] -> $p"
    } elseif ($p -and $p -notmatch '(?i)^"?[a-z]:\\(windows|program files|program files \(x86\)|programdata\\microsoft)\\') {
        Write-BS "Service outside Windows/Program Files: $($s.Name) -> $p" -Level WARN -LogFile $out
    }
}
# 7045 = new service installed (System log)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$since} | ForEach-Object {
    $f = Get-EventFields $_
    Hit "Service installed at $($_.TimeCreated): $($f.ServiceName) -> $($f.ImagePath) as $($f.AccountName)"
}

# ---------------------------------------------------------------- autoruns
Head 'Run keys, Winlogon, IFEO, Startup folders'
$runKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
           'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
           'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
foreach ($k in $runKeys) {
    $item = Get-ItemProperty $k
    if (-not $item) { continue }
    foreach ($prop in $item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
        $lvl = if ("$($prop.Value)" -match $BadCmdRegex) { 'ALERT' } else { 'WARN' }
        Hit "$k  $($prop.Name) = $($prop.Value)" $lvl
    }
}
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Userinit -notmatch '(?i)^c:\\windows\\system32\\userinit\.exe,?$') { Hit "Winlogon Userinit modified: $($wl.Userinit)" }
if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { Hit "Winlogon Shell modified: $($wl.Shell)" }
foreach ($exe in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe','atbroker.exe') {
    $d = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe").Debugger
    if ($d) { Hit "IFEO debugger on $exe -> $d (logon-screen backdoor)" }
}
$cmdHash = (Get-FileHash "$env:windir\System32\cmd.exe").Hash
$psHash  = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe").Hash
foreach ($exe in 'sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','displayswitch.exe') {
    $p = "$env:windir\System32\$exe"
    if (Test-Path $p) {
        $h = (Get-FileHash $p).Hash
        if ($h -eq $cmdHash -or $h -eq $psHash) { Hit "$exe has been REPLACED by cmd/powershell (sticky keys backdoor)" }
    }
}
foreach ($dir in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") {
    Get-ChildItem $dir -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { Hit "Startup folder item: $($_.FullName)" 'WARN' }
}

# ---------------------------------------------------------------- WMI
Head 'WMI event subscriptions'
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object { Hit "WMI CommandLine consumer '$($_.Name)': $($_.CommandLineTemplate)" }
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { Hit "WMI ActiveScript consumer '$($_.Name)'" }
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
    if ("$($_.Consumer)" -notmatch 'SCM Event Log Consumer') { Hit "WMI binding: $($_.Filter) -> $($_.Consumer)" 'WARN' }
}

# ---------------------------------------------------------------- defender
Head 'Defender'
$mp = Get-MpPreference; $ms = Get-MpComputerStatus
if ($ms -and -not $ms.RealTimeProtectionEnabled) { Hit 'Defender real-time protection is OFF' }
if ($mp.ExclusionPath)      { Hit "Defender path exclusions: $($mp.ExclusionPath -join '; ')" }
if ($mp.ExclusionProcess)   { Hit "Defender process exclusions: $($mp.ExclusionProcess -join '; ')" }
if ($mp.ExclusionExtension) { Hit "Defender extension exclusions: $($mp.ExclusionExtension -join '; ')" }
Get-MpThreatDetection | Select-Object -First 20 | ForEach-Object {
    Hit "Defender detection $($_.InitialDetectionTime): $($_.Resources -join ', ')" 'WARN'
}

# ---------------------------------------------------------------- remote access settings
Head 'Remote access'
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
if ($rdp.UserAuthentication -eq 0) { Hit 'RDP Network Level Authentication is OFF' 'WARN' }
$smb1 = Get-SmbServerConfiguration
if ($smb1.EnableSMB1Protocol) { Hit 'SMBv1 is enabled' 'WARN' }
if (-not $smb1.RequireSecuritySignature) { Write-BS 'SMB signing not required on this server' -Level WARN -LogFile $out }
$wdig = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
if ($wdig -eq 1) { Hit 'WDigest UseLogonCredential=1 (cleartext passwords in LSASS)' }
$lm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if ($lm.DisableRestrictedAdmin -eq 0) { Write-BS 'RestrictedAdmin enabled (pass-the-hash over RDP possible)' -Level WARN -LogFile $out }

# ---------------------------------------------------------------- network
Head 'Network: listening and outbound'
$procs = @{}; Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    Write-BS ("LISTEN {0,-6} {1,-22} {2}" -f $_.LocalPort, $p.Name, $p.ExecutablePath) -LogFile $out
}
$shellish = 'powershell.exe','pwsh.exe','cmd.exe','rundll32.exe','regsvr32.exe','mshta.exe','wscript.exe','cscript.exe','w3wp.exe','certutil.exe','nc.exe','ncat.exe'
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    $line = "ESTAB {0}:{1} -> {2}:{3}  {4} (pid {5}) {6}" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $p.Name, $_.OwningProcess, $p.CommandLine
    if ($shellish -contains $p.Name) { Hit $line } else { Write-BS $line -LogFile $out }
}

# ---------------------------------------------------------------- processes
Head 'Processes'
foreach ($p in $procs.Values) {
    $parent = $procs[[int]$p.ParentProcessId]
    if ($parent -and $parent.Name -in 'w3wp.exe','sqlservr.exe','php-cgi.exe','httpd.exe','java.exe' -and $p.Name -in 'cmd.exe','powershell.exe','pwsh.exe','whoami.exe','net.exe','net1.exe','certutil.exe','rundll32.exe') {
        Hit "WEBSHELL PATTERN: $($parent.Name) (pid $($parent.ProcessId)) spawned $($p.Name): $($p.CommandLine)"
    }
    if ("$($p.CommandLine)" -match $BadCmdRegex) { Hit "Suspicious process $($p.Name) pid $($p.ProcessId): $($p.CommandLine)" }
    if ($p.ExecutablePath -match '(?i)\\(temp|appdata|users\\public|perflogs)\\') { Hit "Process running from user-writable path: $($p.ExecutablePath)" }
}

# ---------------------------------------------------------------- web roots
Head 'Web roots (webshells, recent changes)'
$shellPattern = '(?i)(eval\s*\(|execute\s*\(|Process\.Start|ProcessStartInfo|cmd\.exe|powershell|System\.Diagnostics|WScript\.Shell|base64_decode|shell_exec|passthru|system\s*\(|Request\.(Form|QueryString|Item)\[[^\]]+\]\s*\)|FromBase64String|Assembly\.Load|xp_cmdshell)'
foreach ($root in Get-WebRoots) {
    Write-BS "Scanning $root" -LogFile $out
    Get-ChildItem $root -Recurse -File -Force -Include $WebExt | ForEach-Object {
        if ($_.LastWriteTime -gt $since) { Hit "Recently modified web file: $($_.FullName) ($($_.LastWriteTime))" 'WARN' }
        if ($_.Extension -in '.aspx','.ashx','.asmx','.asp','.php','.jsp','.cshtml') {
            $m = Select-String -Path $_.FullName -Pattern $shellPattern -List
            if ($m) { Hit "Webshell-like code in $($_.FullName) line $($m.LineNumber): $($m.Line.Trim().Substring(0, [Math]::Min(120, $m.Line.Trim().Length)))" }
        }
    }
    # Upload-style folders that can also execute
    Get-ChildItem $root -Recurse -Directory -Force | Where-Object { $_.Name -match '(?i)upload|files|tmp|temp|images' } | ForEach-Object {
        Write-BS "Writable-looking folder in web root: $($_.FullName) (check NTFS ACL and handler mappings)" -Level WARN -LogFile $out
    }
}
if (Test-HasIIS) {
    Import-Module WebAdministration
    Get-ChildItem IIS:\AppPools | ForEach-Object {
        if ($_.processModel.identityType -in 'LocalSystem','SpecificUser') { Hit "App pool $($_.Name) runs as $($_.processModel.identityType) $($_.processModel.userName)" 'WARN' }
    }
    $defaultMods = 'UriCacheModule','FileCacheModule','TokenCacheModule','HttpCacheModule','DynamicCompressionModule','StaticCompressionModule','DefaultDocumentModule','DirectoryListingModule','ProtocolSupportModule','HttpRedirectionModule','ServerSideIncludeModule','StaticFileModule','AnonymousAuthenticationModule','CertificateMappingAuthenticationModule','UrlAuthorizationModule','BasicAuthenticationModule','WindowsAuthenticationModule','DigestAuthenticationModule','IISCertificateMappingAuthenticationModule','CustomErrorModule','HttpLoggingModule','FailedRequestsTracingModule','RequestFilteringModule','IpRestrictionModule','DynamicIpRestrictionModule','IsapiFilterModule','IsapiModule','CgiModule','FastCgiModule','ManagedEngineV4.0_32bit','ManagedEngineV4.0_64bit','ManagedEngine64','ManagedEngine','ConfigurationValidationModule','WebSocketModule','ApplicationInitializationModule','RewriteModule','ApplicationRequestRouting','WebDAVModule','CustomLoggingModule','TracingModule','RequestMonitorModule','AspNetCoreModuleV2','AspNetCoreModule','WebMatrixSupportModule','iisnode','TokenCacheModule'
    Get-WebGlobalModule | Where-Object { $defaultMods -notcontains $_.Name } | ForEach-Object { Hit "Non-standard IIS native module: $($_.Name) -> $($_.Image)" }
    $db = Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath 'IIS:\' -Name enabled
    if ($db.Value) { Hit 'IIS directory browsing is enabled globally' 'WARN' }
}

# ---------------------------------------------------------------- logs cleared
Head 'Log tampering'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=$since} | ForEach-Object { Hit "Security log CLEARED at $($_.TimeCreated)" }
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104; StartTime=$since} | ForEach-Object { Hit "A log was cleared at $($_.TimeCreated): $($_.Message)" }

Write-BS "$hits finding(s). Saved: $out" -Level HEAD -LogFile $out
Write-BS 'Before deleting anything: screenshot it (clock visible), note it on the incident timeline, then fix the entry point.' -Level INFO
