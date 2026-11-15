<#
.SYNOPSIS
  Takes a fresh snapshot and prints ONLY what changed since the baseline.
  "+ ADDED" lines are what Red Team usually leaves behind. Screenshot them.
.EXAMPLE
  .\diff.ps1
  .\diff.ps1 -Against C:\bs\snap\20261115-101500    # compare against a specific snapshot
  .\diff.ps1 -Loop 120                               # repeat every 120 s, only prints when something changes
#>
param(
    [string]$Against = 'C:\bs\baseline',
    [int]$Loop = 0
)
$ErrorActionPreference = 'SilentlyContinue'
. "$PSScriptRoot\_lib.ps1"

# Categories where a change is almost always worth a look
$hot = 'users','priv-groups','tasks','services','autoruns','wmi-subs','access-bins','webfiles','defender','iis-modules','dns','shares','listening','gpos','fw-rules','fw-profiles','computers','iis-pools'

function Invoke-Diff {
    if (-not (Test-Path $Against)) { Write-BS "No baseline at $Against. Run .\baseline.ps1 first." -Level ALERT; return }
    $snap = & "$PSScriptRoot\baseline.ps1" -Quiet | Select-Object -Last 1
    $out  = Join-Path $BSRoot ("diff-" + (Get-FileStamp) + ".txt")
    Write-BS "Diff: $Against  vs  $snap" -Level HEAD -LogFile $out
    $changes = 0
    foreach ($sig in Get-ChildItem -Path $snap -Filter *.sig) {
        $name = $sig.BaseName
        $old  = Join-Path $Against "$name.sig"
        $a = @(); if (Test-Path $old) { $a = @(Get-Content $old) }
        $b = @(Get-Content $sig.FullName)
        $added   = $b | Where-Object { $_ -and ($a -notcontains $_) }
        $removed = $a | Where-Object { $_ -and ($b -notcontains $_) }
        foreach ($l in $added) {
            $lvl = if ($hot -contains $name) { 'ALERT' } else { 'WARN' }
            Write-BS ("[{0}] + ADDED   {1}" -f $name, $l) -Level $lvl -LogFile $out; $changes++
        }
        foreach ($l in $removed) {
            Write-BS ("[{0}] - REMOVED {1}" -f $name, $l) -Level WARN -LogFile $out; $changes++
        }
    }
    if ($changes -eq 0) { Write-BS "No changes since baseline." -Level OK -LogFile $out }
    else { Write-BS "$changes change(s). Full detail: CSVs in $snap. Report saved: $out" -Level HEAD -LogFile $out }
    Write-BS "Tip: 'processes' and 'established' changes are noisy. Focus on users, tasks, services, autoruns, webfiles, dns." -Level INFO
}

if ($Loop -gt 0) {
    while ($true) { Invoke-Diff; Start-Sleep -Seconds $Loop }
} else { Invoke-Diff }
