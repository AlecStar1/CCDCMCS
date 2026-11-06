<#
.SYNOPSIS
    MINICOP Blue Team Non-Destructive Threat Detection & Audit Suite (Windows)
.DESCRIPTION
    Performs comprehensive, read-only inspection for all Red Team tools cataloged
    in list_of_repos.md.
.POLICY
    STRICTLY NON-DESTRUCTIVE:
    - Does NOT modify, move, quarantine, or delete any files or registry keys.
    - Does NOT kill any processes or change service states.
    - Generates a clear, color-coded detection audit report.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "      MINICOP BLUE TEAM: WINDOWS READ-ONLY THREAT DETECTION SCAN      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$script:TotalChecks = 0
$script:ThreatsDetected = 0
$script:WarningsFound = 0

function Report-Clean {
    param([string]$Message)
    $script:TotalChecks++
    Write-Host "  [CLEAN] $Message" -ForegroundColor Green
}

function Report-Warn {
    param([string]$Message)
    $script:TotalChecks++
    $script:WarningsFound++
    Write-Host "  [WARNING] $Message" -ForegroundColor Yellow
}

function Report-Threat {
    param([string]$Message)
    $script:TotalChecks++
    $script:ThreatsDetected++
    Write-Host "  [THREAT DETECTED] $Message" -ForegroundColor Red
}

function Section-Header {
    param([string]$Title)
    Write-Host "`n>>> [AUDIT] $Title" -ForegroundColor Blue
}

Write-Host "Host:        $env:COMPUTERNAME" -ForegroundColor White
Write-Host "User:        $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor White
Write-Host "Scan Time:   $(Get-Date)" -ForegroundColor White

# ==============================================================================
# 1. ADWomboComboV2 Detection
# ==============================================================================
Section-Header "1. ADWomboComboV2 (Zanex360/cdt-red-team-tool)"

$adwThreat = $false

# Rogue Services
$adwServices = @("edgeupdateq", "edgeupdaten", "ManageGlobalPolicy")
foreach ($svc in $adwServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Report-Threat "Rogue backdoor service present: $svc"
        $adwThreat = $true
    }
}

# Rogue Tasks
$adwTasks = @("GraphicsPerfSvc64", "GraphicsPerfSvc32", "PIEServiceNew", "ManageGlobalPolicy")
foreach ($t in $adwTasks) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Report-Threat "Disruptive / backdoor scheduled task present: $t"
        $adwThreat = $true
    }
}

# Registry Persistence Keys
$adwRun = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Value = "SecurityHealth_3ef64b" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Value = "InternetExplorer" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Value = "msedge_cleanup" }
)
foreach ($r in $adwRun) {
    if (Get-ItemProperty -Path $r.Path -Name $r.Value -ErrorAction SilentlyContinue) {
        Report-Threat "Rogue Registry Run entry detected: $($r.Path) -> $($r.Value)"
        $adwThreat = $true
    }
}

# Hijacked .exe File Association
$exeCmd = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command" -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
if ($exeCmd -and $exeCmd -match "cmd\.exe") {
    Report-Threat "CRITICAL: .exe file association is hijacked to cmd.exe: $exeCmd"
    $adwThreat = $true
}

# Fake Firewall Rules
$fakeRules = @("Remote Event Monitor (RPC-M)", "Remote Volume Management", "SNMP Trap Service")
foreach ($rule in $fakeRules) {
    if (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue) {
        Report-Threat "Backdoor firewall rule active: $rule"
        $adwThreat = $true
    }
}

# Core Service Status
foreach ($cs in @("lanmanserver", "lanmanworkstation")) {
    $csObj = Get-Service -Name $cs -ErrorAction SilentlyContinue
    if ($csObj -and ($csObj.StartType -eq "Disabled" -or $csObj.Status -eq "Stopped")) {
        Report-Warn "Core network service '$cs' is $($csObj.Status) (StartType: $($csObj.StartType))"
    }
}

# Active Directory Domain Admin Obfuscation (if on DC)
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    if (Get-Module ActiveDirectory) {
        $admins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
        foreach ($u in $admins) {
            if ($u.SamAccountName -match "[\u061c\u115f]" -or ($u.SamAccountName -eq "Admin" -and $u.Name -ne "Administrator")) {
                Report-Threat "Suspicious/obfuscated Domain Admin account: $($u.SamAccountName)"
                $adwThreat = $true
            }
        }
    }
}

if (-not $adwThreat) { Report-Clean "No ADWomboComboV2 services, tasks, registry runs, or hijacked handlers found." }

# ==============================================================================
# 2. Wonka / Mimikatz Golden Ticket Defense
# ==============================================================================
Section-Header "2. Wonka Golden Ticket & Mimikatz (bcvillano/wonka)"

$wonkaThreat = $false

$wonkaFiles = @(
    "C:\Windows\System32\mimikatz.exe",
    "C:\Windows\Temp\mimikatz.exe",
    "C:\ProgramData\mimikatz.exe",
    "C:\Users\Public\mimikatz.exe",
    "C:\Windows\Temp\*_dcsync.txt"
)
foreach ($wf in $wonkaFiles) {
    Get-Item $wf -ErrorAction SilentlyContinue | ForEach-Object {
        Report-Threat "Wonka / Mimikatz file found on disk: $($_.FullName)"
        $wonkaThreat = $true
    }
}

Get-Process -Name "mimikatz" -ErrorAction SilentlyContinue | ForEach-Object {
    Report-Threat "Running Mimikatz process: PID $($_.Id)"
    $wonkaThreat = $true
}

# Audit krbtgt account
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    $krbtgt = Get-ADUser -Identity "krbtgt" -ErrorAction SilentlyContinue
    if ($krbtgt -and $krbtgt.Enabled) {
        Report-Warn "Active Directory krbtgt account is ENABLED (standard hardening requires disabled state)"
    }
}

if (-not $wonkaThreat) { Report-Clean "No Mimikatz binaries, running processes, or DCSync loot files found." }

# ==============================================================================
# 3. Requestor Windows C2 Detection
# ==============================================================================
Section-Header "3. Requestor HTTPS C2 (drew-young/requestor)"

$reqThreat = $false

if (Test-Path "C:\Windows\Fonts\snss.exe") {
    Report-Threat "Hidden Requestor binary located: C:\Windows\Fonts\snss.exe"
    $reqThreat = $true
}

$runKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Font Loader" -ErrorAction SilentlyContinue
if ($runKey) {
    Report-Threat "Requestor 'Font Loader' Run key present: $($runKey.'Font Loader')"
    $reqThreat = $true
}

if (Test-Path "HKLM:\SYSTEM\State\RTStatus") {
    Report-Threat "Requestor RTStatus footprint registry key detected."
    $reqThreat = $true
}

Get-Process -Name "snss" -ErrorAction SilentlyContinue | ForEach-Object {
    Report-Threat "Requestor process active: PID $($_.Id) (snss)"
    $reqThreat = $true
}

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "--EnableFonts"
} | ForEach-Object {
    Report-Threat "Process executing with Requestor arguments: PID $($_.ProcessId) -> $($_.CommandLine)"
    $reqThreat = $true
}

if (-not $reqThreat) { Report-Clean "No Requestor snss.exe, Font Loader registry keys, or processes found." }

# ==============================================================================
# 4. Javalanche Windows C2 Detection
# ==============================================================================
Section-Header "4. Javalanche Windows Ecosystem (jamessouthycoder19/Javalanche)"

$jvlThreat = $false

$jvlTasks = @("Java-Init", "BackupImportantFiles")
foreach ($jt in $jvlTasks) {
    if (Get-ScheduledTask -TaskName $jt -ErrorAction SilentlyContinue) {
        Report-Threat "Javalanche scheduled task present: $jt"
        $jvlThreat = $true
    }
}

$jvlFiles = @("C:\Windows\fonts\Javalanche.ps1", "C:\Program Files (x86)\Webkinz\backup.ps1")
foreach ($jf in $jvlFiles) {
    if (Test-Path $jf) {
        Report-Threat "Javalanche script present on disk: $jf"
        $jvlThreat = $true
    }
}

# Check backdoor users
foreach ($bu in @("Jimithy", "Doug")) {
    if (Get-LocalUser -Name $bu -ErrorAction SilentlyContinue) {
        Report-Threat "Javalanche backdoor local user account exists: $bu"
        $jvlThreat = $true
    }
}

# Check firewall rules
foreach ($jr in @("WinRM Default Rule", "HTTP Default Rule", "RDP Default Rule")) {
    if (Get-NetFirewallRule -DisplayName $jr -ErrorAction SilentlyContinue) {
        Report-Threat "Javalanche backdoor firewall rule exists: $jr"
        $jvlThreat = $true
    }
}

# Check disabled PowerShell logging
$psLogKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($psLogKey -and $psLogKey.EnableScriptBlockLogging -eq 0) {
    Report-Warn "PowerShell ScriptBlockLogging is explicitly DISABLED (0)"
}

if (-not $jvlThreat) { Report-Clean "No Javalanche tasks, scripts, backdoor users, or rules detected." }

# ==============================================================================
# 5. DiscordGo Windows Detection
# ==============================================================================
Section-Header "5. DiscordGo C2 Agent (c0unts/DiscordGo)"

$dgThreat = $false

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -match "DiscordGo" -or $_.Name -match "DiscordGo"
} | ForEach-Object {
    Report-Threat "DiscordGo process active: PID $($_.ProcessId)"
    $dgThreat = $true
}

$screens = Get-ChildItem -Path "C:\Windows\Tasks" -Filter "*_*x*.png" -ErrorAction SilentlyContinue
if ($screens) {
    Report-Threat "DiscordGo screenshot files found in C:\Windows\Tasks\ ($($screens.Count) files)"
    $dgThreat = $true
}

if (-not $dgThreat) { Report-Clean "No DiscordGo agent processes or task screenshots found." }

# ==============================================================================
# 6. Realm / Imix Windows Detection
# ==============================================================================
Section-Header "6. Realm / Imix Agent (c0unts/realm)"

$realmThreat = $false

if (Get-Service -Name "imix" -ErrorAction SilentlyContinue) {
    Report-Threat "Imix Windows service installed: imix"
    $realmThreat = $true
}

if (Test-Path "C:\ProgramData\imix.exe") {
    Report-Threat "Imix agent executable present: C:\ProgramData\imix.exe"
    $realmThreat = $true
}

Get-Process -Name "imix" -ErrorAction SilentlyContinue | ForEach-Object {
    Report-Threat "Imix process running: PID $($_.Id)"
    $realmThreat = $true
}

if (-not $realmThreat) { Report-Clean "No Realm / Imix services, executables, or processes found." }

# ==============================================================================
# 7. Skeletor Windows Detection
# ==============================================================================
Section-Header "7. Skeletor HTTP(S) C2 (bcvillano/skeletor)"

$skelThreat = $false

foreach ($an in @("windows-agent", "windebug")) {
    Get-Process -Name $an -ErrorAction SilentlyContinue | ForEach-Object {
        Report-Threat "Skeletor process running: PID $($_.Id) ($an)"
        $skelThreat = $true
    }
}

$skelLocs = @("C:\Windows\Temp\windows-agent.exe", "C:\ProgramData\windows-agent.exe", "C:\Users\Public\windows-agent.exe")
foreach ($sl in $skelLocs) {
    if (Test-Path $sl) {
        Report-Threat "Skeletor binary file detected: $sl"
        $skelThreat = $true
    }
}

if (-not $skelThreat) { Report-Clean "No Skeletor agent binaries or processes found." }

# ==============================================================================
# 8. Firewall Status Audit
# ==============================================================================
Section-Header "8. Windows Firewall State Audit"

$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($p in $profiles) {
    if (-not $p.Enabled) {
        Report-Warn "Windows Firewall profile '$($p.Name)' is DISABLED!"
    } else {
        Report-Clean "Windows Firewall profile '$($p.Name)' is Enabled."
    }
}

# ==============================================================================
# Summary
# ==============================================================================
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "                  WINDOWS DETECTION SCAN SUMMARY                      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Total Checks Run:      $script:TotalChecks" -ForegroundColor White
if ($script:ThreatsDetected -gt 0) {
    Write-Host "Threats Identified:    $script:ThreatsDetected  <-- ACTION REQUIRED" -ForegroundColor Red
    Write-Host "Remediation Script:    .\windows\remediate_all_windows.ps1" -ForegroundColor Cyan
} else {
    Write-Host "Threats Identified:    0 (System appears clean of cataloged threats)" -ForegroundColor Green
}
if ($script:WarningsFound -gt 0) {
    Write-Host "Warnings / Audit Items: $script:WarningsFound" -ForegroundColor Yellow
}
Write-Host "======================================================================`n" -ForegroundColor Cyan
