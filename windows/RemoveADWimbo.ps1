
<#
.SYNOPSIS
    Remediation script for the ADWomboComboV2 persistence/disruption toolkit.
.DESCRIPTION
    Reverts registry hooks, restores core Windows services, removes rogue scheduled
    tasks and services, resets firewall configuration, cleans DNS sinkholes, deletes
    dropped artifacts, removes rogue Domain Admin accounts, and advises on krbtgt rotation.
.NOTES
    Must be executed in an elevated (Administrator) PowerShell session on the Domain Controller.
#>

[CmdletBinding()]
param()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [*] Starting Blue Team Remediation for ADWomboComboV2..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. Critical Repair: Restore Executable (.exe) File Association
# -------------------------------------------------------------------------
Write-Host "`n[1/8] Repairing File Associations..." -ForegroundColor Yellow
try {
    # Default handler for exefile is: "%1" %*
    $exeCommandPath = "Registry::HKEY_CLASSES_ROOT\exefile\shell\open\command"
    $currentVal = (Get-ItemProperty -Path $exeCommandPath -ErrorAction SilentlyContinue).'(default)'
    
    if ($currentVal -like "*cmd.exe /c*") {
        Set-ItemProperty -Path $exeCommandPath -Name '(default)' -Value '`"%1`" %*' -Force
        Write-Host "  [+] Restored HKEY_CLASSES_ROOT\exefile\shell\open\command to default ('`"%1`" %*')." -ForegroundColor Green
    } else {
        Write-Host "  [-] exefile association does not appear to be hijacked or is already clean." -ForegroundColor Gray
    }
} catch {
    Write-Warning "Failed to check/repair exefile registry key: $_"
}

# -------------------------------------------------------------------------
# 2. Registry Persistence Removal
# -------------------------------------------------------------------------
Write-Host "`n[2/8] Removing Registry Persistence Keys..." -ForegroundColor Yellow
$runKeys = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name = "SecurityHealth_3ef64b" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name = "InternetExplorer" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Name = "msedge_cleanup" }
)

foreach ($entry in $runKeys) {
    if (Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $entry.Path -Name $entry.Name -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed registry value: $($entry.Path)\$($entry.Name)" -ForegroundColor Green
    }
}

# -------------------------------------------------------------------------
# 3. Scheduled Tasks Removal
# -------------------------------------------------------------------------
Write-Host "`n[3/8] Removing Malicious Scheduled Tasks..." -ForegroundColor Yellow
$tasks = @("GraphicsPerfSvc64", "PIEServiceNew", "GraphicsPerfSvc32", "ManageGlobalPolicy")

foreach ($t in $tasks) {
    $exists = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($exists) {
        Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed scheduled task: $t" -ForegroundColor Green
    }
}

# -------------------------------------------------------------------------
# 4. Services Cleanup & Core Service Recovery
# -------------------------------------------------------------------------
Write-Host "`n[4/8] Cleaning Up Rogue Services and Restoring Core Services..." -ForegroundColor Yellow
$rogueServices = @("edgeupdateq", "edgeupdaten", "ManageGlobalPolicy")

foreach ($svc in $rogueServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc | Out-Null
        Write-Host "  [+] Stopped and deleted rogue service: $svc" -ForegroundColor Green
    }
}

# Re-enable core file sharing services disabled by the attack
$coreServices = @("lanmanserver", "lanmanworkstation")
foreach ($svc in $coreServices) {
    Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $svc -ErrorAction SilentlyContinue
    Write-Host "  [+] Restored and started core service: $svc" -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 5. Firewall Restoration
# -------------------------------------------------------------------------
Write-Host "`n[5/8] Reverting Firewall Changes..." -ForegroundColor Yellow
$rogueRules = @(
    "Remote Event Monitor (RPC-M)",
    "Remote Volume Management",
    "SNMP Trap Service"
)

foreach ($rule in $rogueRules) {
    $found = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($found) {
        Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
        Write-Host "  [+] Removed rogue firewall rule: $rule" -ForegroundColor Green
    }
}

# Turn firewall profiles back on
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "  [+] Re-enabled Windows Firewall across all profiles (Domain, Public, Private)." -ForegroundColor Green

# -------------------------------------------------------------------------
# 6. DNS Sinkhole Removal
# -------------------------------------------------------------------------
Write-Host "`n[6/8] Cleaning DNS Sinkhole Entries..." -ForegroundColor Yellow
$sinkholeRecords = @("github.com", "*.github.com", "raw.githubusercontent.com")

foreach ($rec in $sinkholeRecords) {
    try {
        # Attempt removal via dnscmd
        & dnscmd . /recorddelete . $rec A /f 2>$null | Out-Null
        Write-Host "  [+] Removed DNS record override: $rec" -ForegroundColor Green
    } catch {
        Write-Warning "Could not remove DNS record for $rec : $_"
    }
}

# Clear local resolver cache
Clear-DnsClientCache
Write-Host "  [+] Flushed local DNS resolver cache." -ForegroundColor Green

# -------------------------------------------------------------------------
# 7. File System Artifacts & PowerShell Check
# -------------------------------------------------------------------------
Write-Host "`n[7/8] Cleaning Dropped Artifacts & Verifying PowerShell..." -ForegroundColor Yellow
$files = @(
    "C:\Windows\Temp\ManageGlobalPolicy.ps1",
    "C:\Windows\Temp\creds_dump.txt"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] Deleted artifact: $file" -ForegroundColor Green
    }
}

# Check if powershell.exe was renamed
$psDisabled = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.disabled"
$psOriginal = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
if (Test-Path $psDisabled) {
    if (-not (Test-Path $psOriginal)) {
        Rename-Item -Path $psDisabled -NewName "powershell.exe" -Force
        Write-Host "  [+] Restored powershell.exe from disabled state." -ForegroundColor Green
    } else {
        Remove-Item -Path $psDisabled -Force
    }
}

# -------------------------------------------------------------------------
# 8. Active Directory Account Remediation
# -------------------------------------------------------------------------
Write-Host "`n[8/8] Cleaning Rogue Active Directory Accounts..." -ForegroundColor Yellow
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

if (Get-Module ActiveDirectory) {
    # Characters used by the module:
    # Administrator؜ -> U+061C (Arabic Letter Mark)
    # Administratorᅟ -> U+115F (Hangul Choseong Filler)
    $specialAdmins = @(
        "Administrator`u{061C}",
        "Administrator`u{115F}"
    )

    foreach ($rogueUser in $specialAdmins) {
        $userObj = Get-ADUser -Filter "SamAccountName -eq '$rogueUser'" -ErrorAction SilentlyContinue
        if ($userObj) {
            Remove-ADUser -Identity $userObj.DistinguishedName -Confirm:$false
            Write-Host "  [+] Removed Unicode-spoofed rogue user: $($userObj.SamAccountName)" -ForegroundColor Green
        }
    }

    # Verify generic "Admin" account
    $adminCheck = Get-ADUser -Filter "SamAccountName -eq 'Admin'" -Properties MemberOf, WhenCreated -ErrorAction SilentlyContinue
    if ($adminCheck) {
        Write-Warning "  [!] An account named 'Admin' exists (Created: $($adminCheck.WhenCreated))."
        Write-Warning "      Review and remove manually if it is not legitimate:"
        Write-Warning "      Remove-ADUser -Identity '$($adminCheck.DistinguishedName)'"
    }

    Write-Host "`n----------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "CRITICAL AD REMEDIATION ACTION REQUIRED (KRBTGT ROTATION):" -ForegroundColor Red
    Write-Host "The attack reset the krbtgt account password. This gives the"
    Write-Host "attacker the ability to forge Golden and Silver Kerberos tickets."
    Write-Host "To remediate, the krbtgt password MUST be rotated twice."
    Write-Host "Use the Microsoft-recommended script: New-KrbtgtKeys.ps1"
    Write-Host "Allow Active Directory replication time between rotations."
    Write-Host "----------------------------------------------------------" -ForegroundColor Yellow
} else {
    Write-Warning "ActiveDirectory PowerShell module not available on this host. Run AD cleanup from a DC."
}

Write-Host "`n[✓] Remediation completed. Review the warnings above." -ForegroundColor Cyan