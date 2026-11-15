<#
.SYNOPSIS
  Live log monitor. Leave it running in its own PowerShell window all day.
  Polls Security, System, PowerShell, Defender, TaskScheduler (and Sysmon if installed)
  and prints one colored, timestamped line per interesting event. Also saved to C:\bs\logwatch-*.txt
  Run audit-on.ps1 first, or you will miss process (4688) and task (4698) events.
.EXAMPLE
  .\logwatch.ps1
  .\logwatch.ps1 -Interval 15 -ShowNetLogons     # also show network logons (noisy: scoring checks log in too)
  .\logwatch.ps1 -Back 60                         # start by replaying the last 60 minutes
#>
param(
    [int]$Interval = 20,
    [int]$Back = 5,
    [int]$SprayThreshold = 8,
    [switch]$ShowNetLogons
)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"
$out = Join-Path $BSRoot ("logwatch-" + (Get-FileStamp) + ".txt")
$Host.UI.RawUI.WindowTitle = "LOGWATCH $env:COMPUTERNAME"

$secIds = 4624,4625,4648,4672,4688,4697,4698,4699,4702,4720,4722,4724,4725,4726,4728,4732,4738,4740,4756,4767,4769,4781,4794,5136,5141,1102
$logonType = @{ '2'='interactive'; '3'='network'; '4'='batch'; '5'='service'; '7'='unlock'; '8'='net-cleartext'; '9'='runas-netonly'; '10'='RDP'; '11'='cached' }
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$last = (Get-Date).AddMinutes(-$Back)
$adminSessionIds = @{}

function Emit { param($lvl, $evt, $msg) Write-BS ("{0:HH:mm:ss} {1}" -f $evt.TimeCreated, $msg) -Level $lvl -LogFile $out }

function Get-New {
    param([hashtable]$Filter)
    $Filter['StartTime'] = $script:last.AddSeconds(-5)
    Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue | Sort-Object TimeCreated | Where-Object {
        $seen.Add("$($_.LogName)|$($_.RecordId)")
    }
}

Write-BS "Logwatch started. Interval ${Interval}s. Output: $out" -Level HEAD -LogFile $out
Write-BS "Reminder: White Team and the scoring engine also log in. Judge by source IP and account, not by the alert alone." -Level INFO

while ($true) {
    $cycleStart = Get-Date
    $fails = @{}

    # ------------------------------------------------ Security
    foreach ($e in Get-New @{ LogName = 'Security'; Id = $secIds }) {
        $f = Get-EventFields $e
        switch ($e.Id) {
            4624 {
                $t = $f.LogonType; $u = "$($f.TargetDomainName)\$($f.TargetUserName)"; $ip = $f.IpAddress
                if ($f.TargetUserName -match '\$$' -or $f.TargetUserName -in 'ANONYMOUS LOGON','SYSTEM','LOCAL SERVICE','NETWORK SERVICE','DWM-1','DWM-2','UMFD-0','UMFD-1') { break }
                if ($t -in '10','2','7','11') { Emit 'WARN' $e "LOGON $($logonType[$t]) $u from $ip ($($f.WorkstationName))" }
                elseif ($t -in '8','9') { Emit 'ALERT' $e "LOGON $($logonType[$t]) $u from $ip (cleartext / runas netonly)" }
                elseif ($t -eq '3' -and $ShowNetLogons) { Emit 'INFO' $e "LOGON network $u from $ip auth=$($f.AuthenticationPackageName)" }
                if ($t -eq '3' -and $f.AuthenticationPackageName -eq 'NTLM' -and $f.LmPackageName -eq 'NTLM V1') { Emit 'ALERT' $e "NTLMv1 logon $u from $ip" }
            }
            4625 {
                $key = "$($f.IpAddress)"
                if (-not $fails.ContainsKey($key)) { $fails[$key] = New-Object System.Collections.ArrayList }
                [void]$fails[$key].Add($f.TargetUserName)
            }
            4648 { if ($f.TargetUserName -notmatch '\$$') { Emit 'WARN' $e "EXPLICIT CREDS $($f.SubjectUserName) used creds of $($f.TargetDomainName)\$($f.TargetUserName) -> $($f.TargetServerName) via $($f.ProcessName)" } }
            4672 { if ($f.SubjectUserName -notmatch '\$$|^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') { $adminSessionIds[$f.SubjectLogonId] = $f.SubjectUserName } }
            4688 {
                $cmd = "$($f.CommandLine)"; $proc = Split-Path -Leaf "$($f.NewProcessName)"; $par = Split-Path -Leaf "$($f.ParentProcessName)"
                if ($par -in 'w3wp.exe','sqlservr.exe','php-cgi.exe','httpd.exe','java.exe' -and $proc -in 'cmd.exe','powershell.exe','pwsh.exe','whoami.exe','net.exe','net1.exe','certutil.exe','rundll32.exe','systeminfo.exe','ipconfig.exe') {
                    Emit 'ALERT' $e "WEBSHELL? $par -> $proc : $cmd"
                } elseif ($cmd -match $BadCmdRegex) {
                    Emit 'ALERT' $e "SUSPICIOUS PROC by $($f.SubjectUserName): $cmd (parent $par)"
                } elseif ($proc -in 'whoami.exe','net.exe','net1.exe','nltest.exe','dsquery.exe','quser.exe','qwinsta.exe','klist.exe','vssadmin.exe','wevtutil.exe','ntdsutil.exe','reg.exe','sc.exe','schtasks.exe','wmic.exe','bcdedit.exe') {
                    Emit 'WARN' $e "RECON/ADMIN TOOL $proc by $($f.SubjectUserName): $cmd"
                }
            }
            4697 { Emit 'ALERT' $e "SERVICE INSTALLED $($f.ServiceName) -> $($f.ServiceFileName) by $($f.SubjectUserName)" }
            4698 { Emit 'ALERT' $e "TASK CREATED $($f.TaskName) by $($f.SubjectUserName)" }
            4699 { Emit 'WARN'  $e "TASK DELETED $($f.TaskName) by $($f.SubjectUserName)" }
            4702 { Emit 'WARN'  $e "TASK UPDATED $($f.TaskName) by $($f.SubjectUserName)" }
            4720 { Emit 'ALERT' $e "USER CREATED $($f.TargetUserName) by $($f.SubjectUserName)" }
            4722 { Emit 'WARN'  $e "USER ENABLED $($f.TargetUserName) by $($f.SubjectUserName)" }
            4724 { Emit 'WARN'  $e "PASSWORD RESET on $($f.TargetUserName) by $($f.SubjectUserName)" }
            4725 { Emit 'WARN'  $e "USER DISABLED $($f.TargetUserName) by $($f.SubjectUserName)" }
            4726 { Emit 'ALERT' $e "USER DELETED $($f.TargetUserName) by $($f.SubjectUserName)" }
            { $_ -in 4728,4732,4756 } { Emit 'ALERT' $e "ADDED TO GROUP $($f.TargetUserName): member $($f.MemberName) by $($f.SubjectUserName)" }
            4738 { if ($f.UserAccountControl -and $f.UserAccountControl -ne '-') { Emit 'WARN' $e "USER CHANGED $($f.TargetUserName) UAC=$($f.UserAccountControl) by $($f.SubjectUserName)" } }
            4740 { Emit 'ALERT' $e "ACCOUNT LOCKED OUT $($f.TargetUserName) (caller $($f.TargetDomainName)). If scored, scoring will fail" }
            4767 { Emit 'INFO'  $e "Account unlocked $($f.TargetUserName)" }
            4769 { if ($f.TicketEncryptionType -eq '0x17' -and $f.ServiceName -notmatch '\$$|krbtgt') { Emit 'ALERT' $e "KERBEROAST? RC4 ticket for $($f.ServiceName) requested by $($f.TargetUserName) from $($f.IpAddress)" } }
            4781 { Emit 'ALERT' $e "ACCOUNT RENAMED $($f.OldTargetUserName) -> $($f.NewTargetUserName)" }
            4794 { Emit 'ALERT' $e "DSRM password set attempt" }
            5136 {
                $attr = $f.AttributeLDAPDisplayName
                if ($attr -in 'nTSecurityDescriptor','member','servicePrincipalName','userAccountControl','msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-AllowedToDelegateTo','gPCFileSysPath','scriptPath','sIDHistory') {
                    Emit 'ALERT' $e "AD CHANGE $attr on $($f.ObjectDN) by $($f.SubjectUserName)"
                }
            }
            5141 { Emit 'ALERT' $e "AD OBJECT DELETED $($f.ObjectDN) by $($f.SubjectUserName)" }
            1102 { Emit 'ALERT' $e "SECURITY LOG CLEARED by $($f.SubjectUserName)" }
        }
    }
    foreach ($ip in $fails.Keys) {
        $n = $fails[$ip].Count
        $users = ($fails[$ip] | Sort-Object -Unique | Select-Object -First 6) -join ','
        $lvl = if ($n -ge $SprayThreshold) { 'ALERT' } else { 'WARN' }
        Write-BS ("FAILED LOGONS x{0} from {1} users: {2}{3}" -f $n, $ip, $users, $(if ($n -ge $SprayThreshold) { '  <- SPRAY/BRUTE' } else { '' })) -Level $lvl -LogFile $out
    }

    # ------------------------------------------------ System
    foreach ($e in Get-New @{ LogName = 'System'; Id = 7045,7040,104 }) {
        $f = Get-EventFields $e
        switch ($e.Id) {
            7045 { Emit 'ALERT' $e "NEW SERVICE $($f.ServiceName) -> $($f.ImagePath) as $($f.AccountName)" }
            7040 { Emit 'WARN'  $e "SERVICE START TYPE CHANGED: $($e.Message -replace '\s+',' ')" }
            104  { Emit 'ALERT' $e "EVENT LOG CLEARED: $($e.Message -replace '\s+',' ')" }
        }
    }
    foreach ($e in Get-New @{ LogName = 'System'; Id = 7036 }) {
        if ($e.Message -match 'stopped' -and $e.Message -match '(?i)(DNS|Netlogon|Active Directory|Kerberos|W3SVC|World Wide Web|FTP|Server|Remote Desktop|Windows Defender|Microsoft Defender|SplunkForwarder|DHCP|IIS|Windows Remote Management)') {
            Emit 'ALERT' $e "SERVICE STOPPED: $($e.Message -replace '\s+',' ')"
        }
    }

    # ------------------------------------------------ PowerShell script blocks
    foreach ($e in Get-New @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 }) {
        $sb = "$($e.Properties[2].Value)"
        if ($sb -match $BadCmdRegex -or $sb -match '(?i)(mimikatz|invoke-mimi|sekurlsa|amsiutils|amsiInitFailed|Add-MpPreference|Set-MpPreference.*Disable|New-LocalUser|Add-ADGroupMember|Add-LocalGroupMember|Register-ScheduledTask|New-Service|Set-ItemProperty.*\\Run)') {
            $snip = $sb.Substring(0, [Math]::Min(160, $sb.Length)) -replace '\s+',' '
            Emit 'ALERT' $e "PS SCRIPTBLOCK: $snip"
        }
    }

    # ------------------------------------------------ Defender
    foreach ($e in Get-New @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116,1117,5001,5004,5007,5010,5012 }) {
        $lvl = if ($e.Id -in 1116,5001,5010,5012) { 'ALERT' } else { 'WARN' }
        Emit $lvl $e ("DEFENDER {0}: {1}" -f $e.Id, (($e.Message -split "`n")[0..3] -join ' ' -replace '\s+',' '))
    }

    # ------------------------------------------------ Task Scheduler (if operational log is enabled)
    foreach ($e in Get-New @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106,140,141 }) {
        Emit 'WARN' $e ("TASKSCHED {0}: {1}" -f $e.Id, ($e.Message -replace '\s+',' '))
    }

    # ------------------------------------------------ Sysmon (only if installed)
    foreach ($e in Get-New @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1,3,8,10,11,13 }) {
        $f = Get-EventFields $e
        switch ($e.Id) {
            1  { if ("$($f.CommandLine)" -match $BadCmdRegex -or (Split-Path -Leaf "$($f.ParentImage)") -in 'w3wp.exe','sqlservr.exe') { Emit 'ALERT' $e "SYSMON PROC $($f.User): $($f.CommandLine) (parent $($f.ParentImage))" } }
            3  { if ((Split-Path -Leaf "$($f.Image)") -in 'powershell.exe','cmd.exe','rundll32.exe','regsvr32.exe','mshta.exe','certutil.exe') { Emit 'ALERT' $e "SYSMON NET $($f.Image) -> $($f.DestinationIp):$($f.DestinationPort)" } }
            8  { Emit 'ALERT' $e "SYSMON REMOTE THREAD $($f.SourceImage) -> $($f.TargetImage)" }
            10 { if ($f.TargetImage -match 'lsass\.exe' -and $f.SourceImage -notmatch '(?i)(MsMpEng|wininit|csrss|svchost|lsm|WmiPrvSE|vmtoolsd)') { Emit 'ALERT' $e "LSASS ACCESS by $($f.SourceImage) (credential dumping?)" } }
            11 { if ($f.TargetFilename -match '(?i)\\(inetpub|wwwroot)\\.*\.(aspx|ashx|asmx|asp|php|config|dll)$') { Emit 'ALERT' $e "SYSMON FILE in web root: $($f.TargetFilename) by $($f.Image)" } }
            13 { if ($f.TargetObject -match '(?i)\\(Run|RunOnce|Winlogon|Image File Execution Options)\\') { Emit 'ALERT' $e "SYSMON REG $($f.TargetObject) = $($f.Details) by $($f.Image)" } }
        }
    }

    $script:last = $cycleStart
    if ($seen.Count -gt 200000) { $seen.Clear() }
    Start-Sleep -Seconds $Interval
}
