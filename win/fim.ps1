<#
.SYNOPSIS
  File integrity monitor. Leave it running in its own window on WEB01 (and DC for SYSVOL).
  Hashes the web roots + SYSVOL/NETLOGON + startup folders, then re-checks every N seconds
  and prints ADDED / CHANGED / DELETED files with a timestamp. Read-only.
.EXAMPLE
  .\fim.ps1
  .\fim.ps1 -Interval 15 -Extra 'D:\Shares\Finance'
#>
param([int]$Interval = 30, [string[]]$Extra = @())
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"
$out = Join-Path $BSRoot ("fim-" + (Get-FileStamp) + ".txt")
$Host.UI.RawUI.WindowTitle = "FIM $env:COMPUTERNAME"

$paths = @(Get-WebRoots)
if (Test-IsDC) { $paths += "$env:windir\SYSVOL\domain\Policies"; $paths += "$env:windir\SYSVOL\domain\scripts" }
$paths += "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$paths += "$env:windir\System32\Tasks"
$paths += $Extra
$paths = $paths | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

function Get-State {
    $h = @{}
    foreach ($p in $paths) {
        Get-ChildItem $p -Recurse -File -Force | Where-Object { $_.Length -lt 50MB } | ForEach-Object {
            $h[$_.FullName] = "$($_.Length)|$($_.LastWriteTimeUtc.Ticks)"
        }
    }
    return $h
}
Write-BS ("Watching {0} path(s): {1}" -f $paths.Count, ($paths -join '; ')) -Level HEAD -LogFile $out
$base = Get-State
Write-BS "$($base.Count) files baselined. Checking every ${Interval}s." -Level OK -LogFile $out
while ($true) {
    Start-Sleep -Seconds $Interval
    $now = Get-State
    foreach ($k in $now.Keys) {
        if (-not $base.ContainsKey($k)) {
            $hash = (Get-FileHash $k).Hash.Substring(0,16)
            Write-BS "ADDED   $k  sha256:$hash..." -Level ALERT -LogFile $out
        } elseif ($base[$k] -ne $now[$k]) {
            Write-BS "CHANGED $k" -Level ALERT -LogFile $out
        }
    }
    foreach ($k in $base.Keys) { if (-not $now.ContainsKey($k)) { Write-BS "DELETED $k" -Level WARN -LogFile $out } }
    $base = $now
}
