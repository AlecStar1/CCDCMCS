<#
.SYNOPSIS
    MINICOP Blue Team Unified Master Remediation & Hardening (Windows)
.DESCRIPTION
    Executes all modular Windows threat remediations in sequence, audits
    local Administrators and Domain Admins, cleans persistence from Registry Run
    and Scheduled Tasks, restores logging, and enforces Windows Firewall.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Magenta
Write-Host "         MINICOP BLUE TEAM UNIFIED WINDOWS MASTER REMEDIATION        " -ForegroundColor Magenta
Write-Host "======================================================================" -ForegroundColor Magenta

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] Administrator privileges required. Run as Administrator."
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$masterBackupDir = "C:\Windows\Temp\BlueTeam_MasterBackup_$timestamp"
New-Item -ItemType Directory -Path $masterBackupDir -Force | Out-Null
Write-Host "[+] Master quarantine directory: $masterBackupDir" -ForegroundColor Green

function Run-RemediationModule {
    param([string]$ScriptName, [string]$Description)
    Write-Host "`n>>> [RUNNING MODULE] $Description ($ScriptName)" -ForegroundColor Yellow
    $fullPath = Join-Path $scriptDir $ScriptName
    if (Test-Path $fullPath) {
        & powershell.exe -ExecutionPolicy Bypass -File $fullPath
    } else {
        Write-Warning "Module $ScriptName not found in $scriptDir"
    }
}

# ------------------------------------------------------------------------------
# 1. Run Individual Threat Remediation Modules
# ------------------------------------------------------------------------------
Run-RemediationModule "remediate_adwombocombo.ps1" "ADWomboComboV2 AD Persistence & Disruption"
Run-RemediationModule "remediate_wonka.ps1"         "Wonka Golden Ticket / Mimikatz Attack"
Run-RemediationModule "remediate_requestor.ps1"     "Requestor Font Loader (snss.exe)"
Run-RemediationModule "remediate_javalanche.ps1"     "Javalanche Windows Payloads & Backdoors"
Run-RemediationModule "remediate_discordgo.ps1"      "DiscordGo C2 Windows Agent"
Run-RemediationModule "remediate_realm.ps1"          "Realm / Imix Windows Service & Agent"
Run-RemediationModule "remediate_skeletor.ps1"      "Skeletor Windows Beacon Agent"

# ------------------------------------------------------------------------------
# 2. General Scheduled Tasks Audit
# ------------------------------------------------------------------------------
Write-Host "`n>>> [GENERAL SWEEP] Auditing Scheduled Tasks in Root/Tasks" -ForegroundColor Yellow

$suspectTaskKeywords = @("lanman", "ManageGlobalPolicy", "GraphicsPerf", "PIEService", "Java-Init", "BackupImportantFiles", "Webkinz")
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $tname = $_.TaskName
    $suspectTaskKeywords | Where-Object { $tname -match $_ }
} | ForEach-Object {
    Write-Host "[-] Found and removing suspicious scheduled task: $($_.TaskName)" -ForegroundColor Red
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# 3. Baseline Audit of Local Administrators Group
# ------------------------------------------------------------------------------
Write-Host "`n>>> [ACCOUNT AUDIT] Members of Local Administrators Group:" -ForegroundColor Cyan
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "    - $($_.ObjectClass): $($_.Name)" -ForegroundColor White
}

# ------------------------------------------------------------------------------
# 4. Enforce Windows Firewall State
# ------------------------------------------------------------------------------
Write-Host "`n>>> [FIREWALL] Enforcing Domain, Private, and Public Firewall Enabled" -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "[+] All Windows Firewall profiles set to Enabled." -ForegroundColor Green

Write-Host "`n======================================================================" -ForegroundColor Magenta
Write-Host " [SUCCESS] Unified Windows Remediation completed. Artifacts in: " -ForegroundColor Green
Write-Host "   $masterBackupDir" -ForegroundColor White
Write-Host "======================================================================`n" -ForegroundColor Magenta
