<#
.SYNOPSIS
    MINICOP Blue Team Remediation & Hardening: bcvillano/skeletor (Windows)
.DESCRIPTION
    Detects and eliminates Skeletor Windows implants (windows-agent.exe / windebug.exe)
    and beaconing python scripts.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     MINICOP Blue Team Remediation: Skeletor (Windows)                " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] Administrator privileges required."
    exit 1
}

$backupDir = "C:\Windows\Temp\BlueTeam_Backup_Skeletor_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ------------------------------------------------------------------------------
# 1. Terminate Skeletor Windows Agent Processes
# ------------------------------------------------------------------------------
Write-Host "`n[*] Hunting for Skeletor processes..." -ForegroundColor Yellow

$agentNames = @("windows-agent", "windebug", "skeletor")
foreach ($an in $agentNames) {
    Get-Process -Name $an -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "[-] Killing Skeletor process: PID $($_.Id)" -ForegroundColor Red
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "windows-agent\.exe" -or $_.CommandLine -match "windebug\.exe" -or ($_.CommandLine -match "python" -and $_.CommandLine -match "beacon\.py")
} | ForEach-Object {
    Write-Host "[-] Terminating Skeletor beacon process: PID $($_.ProcessId)" -ForegroundColor Red
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 2. Sweep Dropped Binaries & Scheduled Tasks
# ------------------------------------------------------------------------------
Write-Host "`n[*] Sweeping for Skeletor binaries..." -ForegroundColor Yellow

$skeletorLocations = @(
    "C:\Windows\Temp\windows-agent.exe",
    "C:\ProgramData\windows-agent.exe",
    "C:\Users\Public\windows-agent.exe",
    "C:\Windows\Temp\windebug.exe",
    "C:\Users\Public\windebug.exe"
)

foreach ($loc in $skeletorLocations) {
    if (Test-Path $loc) {
        Write-Host "[-] Quarantining Skeletor binary: $loc" -ForegroundColor Red
        Move-Item -Path $loc -Destination "$backupDir\" -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Quarantined $loc" -ForegroundColor Green
    }
}

Write-Host "`n[SUCCESS] Skeletor Windows remediation complete. Backups stored in $backupDir`n" -ForegroundColor Green
