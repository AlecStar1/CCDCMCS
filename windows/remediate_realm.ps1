<#
.SYNOPSIS
    MINICOP Blue Team Remediation & Hardening: c0unts/realm (Imix Agent for Windows)
.DESCRIPTION
    Detects and eliminates Realm/Imix Windows service and executable:
    - Default path: C:\ProgramData\<executable_name>.exe
    - Windows Service: sc create <name> binpath= ...
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     MINICOP Blue Team Remediation: Realm / Imix (Windows)            " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] Administrator privileges required."
    exit 1
}

$backupDir = "C:\Windows\Temp\BlueTeam_Backup_Realm_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ------------------------------------------------------------------------------
# 1. Stop and Delete Imix Windows Services
# ------------------------------------------------------------------------------
Write-Host "`n[*] Hunting for Imix Windows Services..." -ForegroundColor Yellow

$suspectServices = @("imix")
Get-Service -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match "imix" -or $_.DisplayName -match "imix"
} | ForEach-Object {
    $suspectServices += $_.Name
}

foreach ($svcName in ($suspectServices | Select-Object -Unique)) {
    $svcObj = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svcObj) {
        Write-Host "[-] Stopping and deleting Imix service: $svcName" -ForegroundColor Red
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $svcName | Out-Null
        Write-Host "[+] Deleted service $svcName" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 2. Terminate Imix Running Processes
# ------------------------------------------------------------------------------
Write-Host "`n[*] Hunting for Imix processes..." -ForegroundColor Yellow

Get-Process -Name "imix" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "[-] Terminating active Imix process PID $($_.Id)" -ForegroundColor Red
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ExecutablePath -match "C:\\ProgramData\\.*\.exe" -and ($_.CommandLine -match "imix" -or $_.Name -match "imix")
} | ForEach-Object {
    Write-Host "[-] Killing Imix process PID $($_.ProcessId)" -ForegroundColor Red
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 3. Clean Files in C:\ProgramData\
# ------------------------------------------------------------------------------
Write-Host "`n[*] Removing Imix executables in C:\ProgramData\..." -ForegroundColor Yellow

$imixBin = "C:\ProgramData\imix.exe"
if (Test-Path $imixBin) {
    Write-Host "[-] Found Imix binary: $imixBin" -ForegroundColor Red
    Move-Item -Path $imixBin -Destination "$backupDir\" -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Quarantined $imixBin" -ForegroundColor Green
}

Write-Host "`n[SUCCESS] Realm / Imix Windows remediation complete. Backups stored in $backupDir`n" -ForegroundColor Green
