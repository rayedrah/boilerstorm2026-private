<#
.SYNOPSIS
  Defacement / webshell recovery for CAI-WEB01.
  1) Moves the CURRENT web root into C:\bs\quarantine\<ts>\ (evidence, nothing is deleted)
  2) Copies the known-good backup back in place
  3) Restarts the site
.EXAMPLE
  .\restore-web.ps1                                   # uses the newest backup
  .\restore-web.ps1 -Backup C:\bs\backup\20261115-101200
  .\restore-web.ps1 -WhatIf                           # show what it would do
#>
param([string]$Backup, [switch]$WhatIf)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_lib.ps1"
if (-not $Backup) { $Backup = (Get-ChildItem "$BSRoot\backup" -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'web\map.csv') } | Sort-Object Name | Select-Object -Last 1).FullName }
$mapFile = Join-Path $Backup 'web\map.csv'
if (-not (Test-Path $mapFile)) { Write-BS "No web\map.csv in $Backup. Run backup.ps1 first." -Level ALERT; return }
$ts = Get-FileStamp
$q  = New-BSDir "quarantine\$ts"
$log = Join-Path $q '_restore-log.txt'

foreach ($m in Import-Csv $mapFile) {
    $safe = ($m.Source -replace '[:\\]','_').Trim('_')
    Write-BS "Restore $($m.Source)  <-  $($m.Backup)   (current copy -> $q\$safe)" -Level HEAD -LogFile $log
    if ($WhatIf) { continue }
    robocopy $m.Source (Join-Path $q $safe) /E /COPY:DAT /R:0 /W:0 /NFL /NDL /NJH /NJS | Out-Null
    # /MIR makes the folder identical to the backup (removes attacker-added files; they are preserved in quarantine)
    robocopy $m.Backup $m.Source /MIR /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    Write-BS "Restored $($m.Source)" -Level OK -LogFile $log
}
if (-not $WhatIf -and (Test-HasIIS)) {
    Import-Module WebAdministration
    Get-Website | ForEach-Object { Stop-Website $_.Name; Start-Website $_.Name }
    Get-ChildItem IIS:\AppPools | ForEach-Object { Restart-WebAppPool $_.Name -ErrorAction SilentlyContinue }
    Write-BS 'Sites and app pools restarted. Check the HTTP/HTTPS checks in Quotient now.' -Level OK -LogFile $log
}
Write-BS "Evidence of the bad state is in $q. Compare with: Compare-Object (gci -r $q) (gci -r <webroot>) -Property Name" -Level INFO -LogFile $log
Write-BS 'The restore fixes the symptom. Find the upload/FTP/share path they used, or they will be back (50% of the report).' -Level WARN -LogFile $log
