param([ValidateRange(1, 168)][int]$IntervalHours = 1)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$TaskName = "ASTP-Autonomous-Development"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Runner = Join-Path $PSScriptRoot "run.ps1"
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw "Task already exists; remove it explicitly before reinstalling."
}
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Runner`"" -WorkingDirectory $Repo
$Start = (Get-Date).AddHours($IntervalHours)
$Trigger = New-ScheduledTaskTrigger -Once -At $Start -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)
$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal | Out-Null
Disable-ScheduledTask -TaskName $TaskName | Out-Null
Write-Host "Installed DISABLED task $TaskName with ${IntervalHours}h cadence. Human approval is required before enabling it."
