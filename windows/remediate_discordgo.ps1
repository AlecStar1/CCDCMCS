<#
.SYNOPSIS
    MINICOP Blue Team Remediation & Hardening: c0unts/DiscordGo (Windows)
.DESCRIPTION
    Detects and eliminates DiscordGo C2 implant processes on Windows,
    removes screenshot artifacts in C:\Windows\Tasks, and blocks egress.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     MINICOP Blue Team Remediation: DiscordGo (Windows)               " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] Administrator privileges required."
    exit 1
}

$backupDir = "C:\Windows\Temp\BlueTeam_Backup_DiscordGo_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ------------------------------------------------------------------------------
# 1. Kill Active DiscordGo Agent Processes
# ------------------------------------------------------------------------------
Write-Host "`n[*] Hunting for DiscordGo agent processes..." -ForegroundColor Yellow

# On Windows, DiscordGo uses C:\Windows\Tasks\ for temp files and connects to discord.com via websockets
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
    $_.RemotePort -eq 443 -or $_.RemotePort -eq 80
} | ForEach-Object {
    $pidNum = $_.OwningProcess
    try {
        $p = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
        if ($p -and ($p.ProcessName -match "discordgo" -or $p.Path -match "discordgo")) {
            Write-Host "[-] Killing DiscordGo process: PID $pidNum ($($p.Path))" -ForegroundColor Red
            Stop-Process -Id $pidNum -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Scan processes with handles in C:\Windows\Tasks or matching DiscordGo strings
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "DiscordGo" -or $_.Name -match "DiscordGo"
} | ForEach-Object {
    Write-Host "[-] Killing DiscordGo process PID $($_.ProcessId)" -ForegroundColor Red
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 2. Clean Screenshot Files in C:\Windows\Tasks\
# ------------------------------------------------------------------------------
Write-Host "`n[*] Scrubbing screenshot dumps from C:\Windows\Tasks\..." -ForegroundColor Yellow

$tasksDir = "C:\Windows\Tasks"
if (Test-Path $tasksDir) {
    Get-ChildItem -Path $tasksDir -Filter "*_*x*.png" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "[-] Found DiscordGo screenshot: $($_.FullName)" -ForegroundColor Red
        Move-Item $_.FullName "$backupDir\" -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Quarantined $($_.Name)" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 3. Sinkhole Discord Bot Endpoints in Hosts File
# ------------------------------------------------------------------------------
Write-Host "`n[*] Sinkholing Discord endpoints in hosts file..." -ForegroundColor Yellow

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$discordHosts = @("discord.com", "gateway.discord.gg", "discordapp.com", "cdn.discordapp.com")
foreach ($dom in $discordHosts) {
    if (-not (Select-String -Path $hostsPath -Pattern $dom -Quiet -ErrorAction SilentlyContinue)) {
        Add-Content -Path $hostsPath -Value "127.0.0.1 $dom"
        Write-Host "[+] Sinkholed $dom in hosts file" -ForegroundColor Green
    }
}

Write-Host "`n[SUCCESS] DiscordGo Windows remediation complete. Backups stored in $backupDir`n" -ForegroundColor Green
