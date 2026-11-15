# Shared helpers. Dot-sourced by every script in this folder.
# Output root: C:\bs  (stays on the box, never copy it out)

$Global:BSRoot = 'C:\bs'
if (-not (Test-Path $BSRoot)) { New-Item -ItemType Directory -Force -Path $BSRoot | Out-Null }

function Get-Stamp     { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }
function Get-FileStamp { Get-Date -Format 'yyyyMMdd-HHmmss' }

function New-BSDir {
    param([string]$Name)
    $p = Join-Path $BSRoot $Name
    New-Item -ItemType Directory -Force -Path $p | Out-Null
    return $p
}

function Write-BS {
    param(
        [string]$Msg,
        [ValidateSet('INFO','OK','WARN','ALERT','HEAD')][string]$Level = 'INFO',
        [string]$LogFile
    )
    $line = '[{0}] [{1}] [{2}] {3}' -f (Get-Stamp), $env:COMPUTERNAME, $Level, $Msg
    $color = switch ($Level) {
        'ALERT' { 'Red' } 'WARN' { 'Yellow' } 'OK' { 'Green' } 'HEAD' { 'Cyan' } default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($LogFile) { Add-Content -Path $LogFile -Value $line -Encoding UTF8 }
}

function Test-IsDC {
    try { return ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) } catch { return $false }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-HasIIS {
    return [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)
}

# Event record -> hashtable of EventData fields (Name -> value)
function Get-EventFields {
    param($Evt)
    $h = @{}
    try {
        $x = [xml]$Evt.ToXml()
        foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = $d.'#text' } }
    } catch {}
    return $h
}

# Physical paths of every IIS site and virtual directory
function Get-WebRoots {
    $roots = @()
    if (Test-HasIIS) {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($s in Get-Website) {
                $roots += [Environment]::ExpandEnvironmentVariables($s.physicalPath)
                foreach ($v in (Get-WebVirtualDirectory -Site $s.Name -ErrorAction SilentlyContinue)) {
                    $roots += [Environment]::ExpandEnvironmentVariables($v.physicalPath)
                }
                foreach ($a in (Get-WebApplication -Site $s.Name -ErrorAction SilentlyContinue)) {
                    $roots += [Environment]::ExpandEnvironmentVariables($a.PhysicalPath)
                }
            }
        } catch {}
    }
    if (Test-Path 'C:\inetpub\wwwroot') { $roots += 'C:\inetpub\wwwroot' }
    if (Test-Path 'C:\inetpub\ftproot') { $roots += 'C:\inetpub\ftproot' }
    return ($roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
}

$Global:WebExt = @('*.aspx','*.ashx','*.asmx','*.asp','*.php','*.config','*.cshtml','*.jsp','*.dll','*.exe','*.ps1','*.bat','*.cmd','*.html','*.htm','*.js')

# Words that show up in malicious command lines
$Global:BadCmdRegex = '(?i)(-enc(odedcommand)?\s|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient|certutil.*-urlcache|bitsadmin|mshta|regsvr32.*/i:|rundll32.*javascript|wscript|cscript|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\[^\\]+\.(exe|ps1|bat|vbs)|nc(at)?\.exe|socat|plink|chisel|ngrok|-w\s*hidden|-windowstyle\s+hidden|-nop\s)'
