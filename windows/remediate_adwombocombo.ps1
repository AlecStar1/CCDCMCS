<#
.SYNOPSIS
    MINICOP Blue Team Remediation & Hardening: ADWomboComboV2
.DESCRIPTION
    Remediates and neutralizes the full persistence and disruption payload
    deployed by Zanex360/cdt-red-team-tool (ADWomboComboV2.rb) on Windows
    Domain Controllers and Windows Servers.
.NOTES
    Must be executed in an elevated (Administrator) PowerShell session.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     MINICOP Blue Team Remediation: ADWomboComboV2 (Windows)         " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Check for Administrator elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] This script must be executed with Administrator privileges."
    exit 1
}

$backupDir = "C:\Windows\Temp\BlueTeam_Backup_ADWombo_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Write-Host "[+] Backup directory initialized: $backupDir" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 1. Neutralize Rogue Services & Scheduled Tasks
# ------------------------------------------------------------------------------
Write-Host "`n[*] Neutralizing malicious services and scheduled tasks..." -ForegroundColor Yellow

$rogueServices = @("edgeupdateq", "edgeupdaten", "ManageGlobalPolicy")
foreach ($svc in $rogueServices) {
    $serviceObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($serviceObj) {
        Write-Host "[-] Stopping and deleting rogue service: $svc" -ForegroundColor Red
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        & sc.exe delete $svc | Out-Null
        Write-Host "[+] Service $svc deleted successfully." -ForegroundColor Green
    }
}

$rogueTasks = @(
    "GraphicsPerfSvc64",
    "GraphicsPerfSvc32",
    "PIEServiceNew",
    "ManageGlobalPolicy"
)
foreach ($task in $rogueTasks) {
    $taskObj = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if ($taskObj) {
        Write-Host "[-] Unregistering rogue scheduled task: $task" -ForegroundColor Red
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Scheduled task $task removed." -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 2. Re-enable Critical Windows Services Disabled by Red Team
# ------------------------------------------------------------------------------
Write-Host "`n[*] Restoring disabled core services (lanmanserver / lanmanworkstation)..." -ForegroundColor Yellow

$coreServices = @("lanmanserver", "lanmanworkstation")
foreach ($cs in $coreServices) {
    & sc.exe config $cs start= auto | Out-Null
    Start-Service -Name $cs -ErrorAction SilentlyContinue
    Write-Host "[+] Ensured service '$cs' is set to Auto and Running." -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 3. Clean Malicious Registry Keys & Context Menu Hijacks
# ------------------------------------------------------------------------------
Write-Host "`n[*] Scrubbing registry persistence and file association hijacking..." -ForegroundColor Yellow

# Registry Run & RunOnce values
$runKeys = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Value = "SecurityHealth_3ef64b" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Value = "InternetExplorer" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Value = "msedge_cleanup" }
)
foreach ($item in $runKeys) {
    if (Get-ItemProperty -Path $item.Path -Name $item.Value -ErrorAction SilentlyContinue) {
        Write-Host "[-] Removing malicious registry run value: $($item.Path) -> $($item.Value)" -ForegroundColor Red
        Remove-ItemProperty -Path $item.Path -Name $item.Value -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Removed $($item.Value)" -ForegroundColor Green
    }
}

# Context menu replacement (right-click .exe files)
# Red team runs: reg add "HKCR\exefile\shell\open\command" /ve /t REG_SZ /d "cmd.exe /c" /f
$defaultExeCmd = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command" -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
if ($defaultExeCmd -and $defaultExeCmd -match "cmd\.exe") {
    Write-Host "[-] CRITICAL: Detected hijacked .exe file association: $defaultExeCmd" -ForegroundColor Red
    Set-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command" -Name "(default)" -Value '"%1" %*' -Force
    Write-Host "[+] Restored default exefile open command to '`"%1`" %*'" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 4. Remove Fake Firewall Rules & Re-enable Firewall
# ------------------------------------------------------------------------------
Write-Host "`n[*] Auditing firewall and cleaning fake rules..." -ForegroundColor Yellow

$fakeRules = @(
    "Remote Event Monitor (RPC-M)",
    "Remote Volume Management",
    "SNMP Trap Service"
)
foreach ($rule in $fakeRules) {
    $existingRules = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($existingRules) {
        Write-Host "[-] Removing backdoor firewall rule: $rule" -ForegroundColor Red
        Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
        Write-Host "[+] Deleted rule $rule" -ForegroundColor Green
    }
}

# Re-enable all Windows Firewall profiles
Write-Host "[*] Re-enabling Windows Firewall on all profiles..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "[+] Windows Firewall enabled." -ForegroundColor Green

# ------------------------------------------------------------------------------
# 5. Clean Malicious DNS Sinkholes (dnscmd / hosts file)
# ------------------------------------------------------------------------------
Write-Host "`n[*] Checking for DNS sinkholing of GitHub / Blue Team sites..." -ForegroundColor Yellow

# Check DNS Server records if running on a Domain Controller
if (Get-Command dnscmd -ErrorAction SilentlyContinue) {
    $zones = @("github.com", "raw.githubusercontent.com")
    foreach ($zone in $zones) {
        try {
            & dnscmd . /recorddelete . $zone A 0.0.0.0 /f 2>$null | Out-Null
            & dnscmd . /recorddelete . "*.$zone" A 0.0.0.0 /f 2>$null | Out-Null
        } catch { }
    }
}

# Check C:\Windows\System32\drivers\etc\hosts
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    Copy-Item $hostsPath "$backupDir\hosts.bak" -Force
    $hostsContent = Get-Content $hostsPath
    $cleanHosts = $hostsContent | Where-Object { $_ -notmatch "github\.com" -and $_ -notmatch "raw\.githubusercontent\.com" }
    if ($hostsContent.Count -ne $cleanHosts.Count) {
        Set-Content -Path $hostsPath -Value $cleanHosts -Force
        Write-Host "[+] Cleaned GitHub sinkholes from hosts file." -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 6. Quarantine Malicious Scripts and Mimikatz Dumps
# ------------------------------------------------------------------------------
Write-Host "`n[*] Quarantining malicious dropped files and credential dumps..." -ForegroundColor Yellow

$suspectFiles = @(
    "C:\Windows\Temp\ManageGlobalPolicy.ps1",
    "C:\Windows\Temp\creds_dump.txt",
    "C:\Windows\Temp\mimikatz.exe"
)
foreach ($file in $suspectFiles) {
    if (Test-Path $file) {
        Write-Host "[-] Found malicious artifact: $file" -ForegroundColor Red
        Move-Item -Path $file -Destination "$backupDir\" -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Quarantined $file" -ForegroundColor Green
    }
}

# Check if powershell.exe was disabled/renamed
$psPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$disabledPs = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe.disabled"
if (Test-Path $disabledPs) {
    Write-Host "[-] Restoring disabled PowerShell executable..." -ForegroundColor Red
    Move-Item -Path $disabledPs -Destination $psPath -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Restored powershell.exe" -ForegroundColor Green
}

# ------------------------------------------------------------------------------
# 7. Audit Bogus Domain Admin Accounts & krbtgt
# ------------------------------------------------------------------------------
Write-Host "`n[*] Auditing Active Directory accounts (if running on Domain Controller)..." -ForegroundColor Yellow

if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    if (Get-Module ActiveDirectory) {
        $admins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue
        Write-Host "[*] Current Domain Admins count: $($admins.Count)" -ForegroundColor Cyan
        foreach ($u in $admins) {
            Write-Host "    - $($u.SamAccountName) (Name: $($u.Name))"
            # ADWomboCombo adds unicode hidden chars like \u061c or \u115f
            if ($u.SamAccountName -match "[\u061c\u115f]" -or ($u.SamAccountName -eq "Admin" -and $u.Name -ne "Administrator")) {
                Write-Host "[-] Suspicious Domain Admin account identified: $($u.SamAccountName)" -ForegroundColor Red
                Set-ADUser -Identity $u.DistinguishedName -Enabled $false -ErrorAction SilentlyContinue
                Remove-ADGroupMember -Identity "Domain Admins" -Members $u.DistinguishedName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Host "[+] Disabled and removed $($u.SamAccountName) from Domain Admins." -ForegroundColor Green
            }
        }

        # Check krbtgt account
        $krbtgt = Get-ADUser -Identity "krbtgt" -ErrorAction SilentlyContinue
        if ($krbtgt -and $krbtgt.Enabled) {
            Write-Host "[!] WARNING: krbtgt account is enabled! In standard AD environments krbtgt is disabled." -ForegroundColor Yellow
            Write-Host "[!] Recommend rotating krbtgt password TWICE to invalidate forged Golden Tickets." -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[SUCCESS] ADWomboComboV2 remediation complete. Backups stored in $backupDir`n" -ForegroundColor Green
