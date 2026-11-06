<#
.SYNOPSIS
    MINICOP Blue Team Remediation & Hardening: jamessouthycoder19/Javalanche (Windows)
.DESCRIPTION
    Detects and eliminates Javalanche Windows attack payloads:
    - Scheduled Task: Java-Init, BackupImportantFiles
    - Scripts: C:\Windows\fonts\Javalanche.ps1, C:\Program Files (x86)\Webkinz\backup.ps1
    - Backdoor Accounts: Jimithy, Doug
    - Backdoor Firewall Rules: WinRM Default Rule, HTTP Default Rule, RDP Default Rule
    - Restores PowerShell Module & ScriptBlock Logging
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     MINICOP Blue Team Remediation: Javalanche (Windows)              " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] Administrator privileges required."
    exit 1
}

$backupDir = "C:\Windows\Temp\BlueTeam_Backup_Javalanche_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# ------------------------------------------------------------------------------
# 1. Kill Rogue Javalanche PowerShell Processes
# ------------------------------------------------------------------------------
Write-Host "`n[*] Hunting for active Javalanche processes..." -ForegroundColor Yellow

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "Javalanche\.ps1" -or $_.CommandLine -match "Convert-ROT13" -or $_.CommandLine -match "167\.172\.13\.38"
} | ForEach-Object {
    Write-Host "[-] Killing Javalanche process: PID $($_.ProcessId)" -ForegroundColor Red
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Terminated PID $($_.ProcessId)" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 2. Delete Malicious Scheduled Tasks
# ------------------------------------------------------------------------------
Write-Host "`n[*] Removing Javalanche scheduled tasks..." -ForegroundColor Yellow

$jvlTasks = @("Java-Init", "BackupImportantFiles")
foreach ($t in $jvlTasks) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Write-Host "[-] Unregistering scheduled task: $t" -ForegroundColor Red
        Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Task $t deleted." -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 3. Quarantine Scripts & Persistence Directories
# ------------------------------------------------------------------------------
Write-Host "`n[*] Quarantining Javalanche files..." -ForegroundColor Yellow

$jvlFiles = @(
    "C:\Windows\fonts\Javalanche.ps1",
    "C:\Program Files (x86)\Webkinz\backup.ps1",
    "C:\Windows\System32\wallpaper.*"
)

foreach ($pattern in $jvlFiles) {
    Get-Item $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "[-] Found malicious file: $($_.FullName)" -ForegroundColor Red
        Move-Item $_.FullName "$backupDir\" -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Quarantined $($_.Name)" -ForegroundColor Green
    }
}

if (Test-Path "C:\Program Files (x86)\Webkinz") {
    Remove-Item "C:\Program Files (x86)\Webkinz" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Removed rogue directory 'C:\Program Files (x86)\Webkinz'" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 4. Remove Rogue Local Accounts (Jimithy, Doug)
# ------------------------------------------------------------------------------
Write-Host "`n[*] Auditing local accounts added by Javalanche..." -ForegroundColor Yellow

$backdoorUsers = @("Jimithy", "Doug")
foreach ($u in $backdoorUsers) {
    if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
        Write-Host "[-] Removing backdoor local user account: $u" -ForegroundColor Red
        Remove-LocalUser -Name $u -ErrorAction SilentlyContinue
        Write-Host "[+] Deleted user $u" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 5. Remove Backdoor Firewall Rules
# ------------------------------------------------------------------------------
Write-Host "`n[*] Removing backdoor firewall rules..." -ForegroundColor Yellow

$jvlRules = @(
    "WinRM Default Rule",
    "HTTP Default Rule",
    "RDP Default Rule"
)
foreach ($r in $jvlRules) {
    if (Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue) {
        Write-Host "[-] Removing firewall rule: $r" -ForegroundColor Red
        Remove-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
        Write-Host "[+] Removed rule $r" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 6. Re-enable PowerShell Auditing & ScriptBlock Logging
# ------------------------------------------------------------------------------
Write-Host "`n[*] Restoring PowerShell ScriptBlock and Module Logging..." -ForegroundColor Yellow

$psLoggingKeys = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Value = "EnableModuleLogging"; Data = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Value = "EnableScriptBlockLogging"; Data = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Value = "EnableTranscripting"; Data = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Value = "ProcessCreationIncludeCmdLine_Enabled"; Data = 1 }
)

foreach ($reg in $psLoggingKeys) {
    if (-not (Test-Path $reg.Path)) {
        New-Item -Path $reg.Path -Force | Out-Null
    }
    Set-ItemProperty -Path $reg.Path -Name $reg.Value -Value $reg.Data -Type DWord -Force
    Write-Host "[+] Restored $($reg.Value) = $($reg.Data)" -ForegroundColor Green
}

# Sinkhole known Javalanche beacons in hosts file
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$jvlHosts = @("beacon1.javalanche.net", "http1.javalanche.net", "http2.javalanche.net", "dns1.javalanche.net")
foreach ($dom in $jvlHosts) {
    if (-not (Select-String -Path $hostsPath -Pattern $dom -Quiet -ErrorAction SilentlyContinue)) {
        Add-Content -Path $hostsPath -Value "127.0.0.1 $dom"
        Write-Host "[+] Sinkholed $dom in hosts file" -ForegroundColor Green
    }
}

Write-Host "`n[SUCCESS] Javalanche Windows remediation complete. Backups stored in $backupDir`n" -ForegroundColor Green
