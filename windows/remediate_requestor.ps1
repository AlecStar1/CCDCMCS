<#
.SYNOPSIS
    MINICOP Blue Team Remediation & Hardening: drew-young/requestor (Windows)
.DESCRIPTION
    Detects and eliminates Requestor Windows agent persistence:
    - Binary path: C:\Windows\Fonts\snss.exe (hidden)
    - Registry Run Key: "Font Loader"
    - Command: PowerShell.exe -WindowStyle hidden C:\Windows\Fonts\snss.exe --EnableFonts --EnableUserSelection
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     MINICOP Blue Team Remediation: Requestor (Windows)               " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] Administrator privileges required."
    exit 1
}

$backupDir = "C:\Windows\Temp\BlueTeam_Backup_Requestor_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ------------------------------------------------------------------------------
# 1. Kill Active Requestor Processes
# ------------------------------------------------------------------------------
Write-Host "`n[*] Hunting for active Requestor processes (snss.exe)..." -ForegroundColor Yellow

Get-Process -Name "snss" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "[-] Found running Requestor process: PID $($_.Id)" -ForegroundColor Red
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Terminated PID $($_.Id)" -ForegroundColor Green
}

# Scan running processes for commandline containing --EnableFonts
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "snss\.exe" -or $_.CommandLine -match "--EnableFonts"
} | ForEach-Object {
    Write-Host "[-] Terminating Requestor process from WMI: PID $($_.ProcessId) -> $($_.CommandLine)" -ForegroundColor Red
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 2. Remove Registry Run Key Persistence
# ------------------------------------------------------------------------------
Write-Host "`n[*] Removing Requestor Registry Run persistence..." -ForegroundColor Yellow

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$regKeyName = "Font Loader"

if (Get-ItemProperty -Path $regPath -Name $regKeyName -ErrorAction SilentlyContinue) {
    Write-Host "[-] Removing malicious registry run value: $regKeyName" -ForegroundColor Red
    Remove-ItemProperty -Path $regPath -Name $regKeyName -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Removed 'Font Loader' persistence key." -ForegroundColor Green
}

# Also check RTStatus footprint key mentioned in Requestor ansible
$rtStatusPath = "HKLM:\SYSTEM\State\RTStatus"
if (Test-Path $rtStatusPath) {
    Write-Host "[-] Found Red Team footprint registry key: $rtStatusPath" -ForegroundColor Red
    Remove-Item -Path $rtStatusPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Cleaned RTStatus registry key." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 3. Locate, Unhide, and Quarantine Malicious Binary
# ------------------------------------------------------------------------------
Write-Host "`n[*] Removing Requestor binary (C:\Windows\Fonts\snss.exe)..." -ForegroundColor Yellow

$targetBinary = "C:\Windows\Fonts\snss.exe"
if (Test-Path $targetBinary) {
    Write-Host "[-] Found hidden Requestor binary: $targetBinary" -ForegroundColor Red
    # Unhide file first
    & attrib.exe -h -s -r $targetBinary
    Move-Item -Path $targetBinary -Destination "$backupDir\" -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Quarantined $targetBinary to $backupDir" -ForegroundColor Green
}

# Sweep any other snss.exe files on system
Get-ChildItem -Path "C:\Windows\Temp", "C:\Users\Public", "C:\ProgramData" -Filter "snss.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "[-] Found additional snss.exe copy: $($_.FullName)" -ForegroundColor Red
    Move-Item $_.FullName "$backupDir\" -Force -ErrorAction SilentlyContinue
}

Write-Host "`n[SUCCESS] Requestor Windows remediation complete. Backups stored in $backupDir`n" -ForegroundColor Green
