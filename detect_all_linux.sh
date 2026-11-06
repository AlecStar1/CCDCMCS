#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Non-Destructive Threat Detection & Audit Suite (Linux)
# Targets: Fedora, Debian, Ubuntu
# Scope: All active Red Team tools identified in list_of_repos.md
# Policy: STRICTLY READ-ONLY. No files are modified, moved, created, or deleted.
#         No services or processes are altered or terminated.
# ==============================================================================

set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TOTAL_CHECKS=0
THREATS_DETECTED=0
WARNINGS_FOUND=0

banner() {
    echo -e "${BOLD}${CYAN}"
    echo "======================================================================"
    echo "       MINICOP BLUE TEAM: LINUX READ-ONLY THREAT DETECTION SCAN       "
    echo "======================================================================"
    echo -e "${NC}"
}

log_section() {
    echo -e "\n${BOLD}${BLUE}>>> [AUDIT] $1${NC}"
}

report_clean() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "  ${GREEN}[CLEAN]${NC} $1"
}

report_warn() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    echo -e "  ${YELLOW}[WARNING]${NC} $1"
}

report_threat() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    THREATS_DETECTED=$((THREATS_DETECTED + 1))
    echo -e "  ${RED}${BOLD}[THREAT DETECTED]${NC} $1"
}

banner

DISTRO="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${PRETTY_NAME:-${ID:-unknown}}"
fi

echo -e "Hostname:    ${BOLD}$(hostname)${NC}"
echo -e "Kernel:      $(uname -r)"
echo -e "OS Distro:   $DISTRO"
echo -e "Scan Time:   $(date)"
echo -e "Executed By: $(whoami) (UID: $EUID)"
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[NOTE] Running as non-root. Some system directories (/proc/*, /etc/*) may have restricted visibility.${NC}"
fi

# ==============================================================================
# 1. cdt-vulnsamba-deploy (CVE-2017-7494 "SambaCry") Detection
# ==============================================================================
log_section "1. Vulnerable Samba & SambaCry (cdt-vulnsamba-deploy)"

# Check processes
samba_threat=false
for pid in $(pgrep -f "smbd|nmbd" 2>/dev/null || true); do
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    if [[ "$cmdline" =~ "samba-4.5" || "$cmdline" =~ "/opt/samba" || "$cmdline" =~ "/usr/src/samba" ]]; then
        report_threat "Rogue custom Samba build running: PID $pid -> $cmdline"
        samba_threat=true
    fi
done

# Check build & install paths
if [ -d "/opt/samba-4.5.9" ]; then
    report_threat "Detected custom Samba deployment directory: /opt/samba-4.5.9"
    samba_threat=true
fi
if [ -d "/usr/src/samba-4.5.9" ]; then
    report_threat "Detected Samba 4.5.9 source build directory: /usr/src/samba-4.5.9"
    samba_threat=true
fi

# Check writable share and .so modules
if [ -d "/srv/samba/vulnshare" ]; then
    report_threat "Found default vulnerable share directory: /srv/samba/vulnshare"
    samba_threat=true
    so_files=$(find /srv/samba/vulnshare -type f -name "*.so*" 2>/dev/null || true)
    if [ -n "$so_files" ]; then
        report_threat "CRITICAL: Malicious shared object (.so) payload present: $so_files"
    fi
fi

# Check system smb.conf for nt pipe support & insecure shares
for conf in /etc/samba/smb.conf /opt/samba-4.5.9/etc/smb.conf; do
    if [ -f "$conf" ]; then
        if grep -iq "^\[vulnshare\]" "$conf" 2>/dev/null; then
            report_threat "smb.conf contains [vulnshare] section: $conf"
            samba_threat=true
        fi
        if ! grep -iq "nt pipe support" "$conf" 2>/dev/null; then
            report_warn "$conf does not configure 'nt pipe support = no' (vulnerable to SambaCry if running 3.5.0-4.6.4)"
        fi
    fi
done

[ "$samba_threat" = false ] && report_clean "No cdt-vulnsamba-deploy artifacts or rogue smbd processes detected."

# ==============================================================================
# 2. c0unts/DiscordGo C2 Detection
# ==============================================================================
log_section "2. DiscordGo C2 Agent (c0unts/DiscordGo)"

dg_threat=false

# Check processes
for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$cmdline" =~ "DiscordGo" || "$exe" =~ "DiscordGo" || "$cmdline" =~ "discordgo" ]]; then
        report_threat "DiscordGo process identified: PID $pid -> $cmdline ($exe)"
        dg_threat=true
    fi
done

# Check /tmp artifacts
if [ -f "/tmp/discordstat.txt" ]; then
    report_threat "DiscordGo statistics file detected: /tmp/discordstat.txt"
    dg_threat=true
fi

dg_screens=$(find /tmp /var/tmp -maxdepth 2 -type f -name "*_[0-9]*x[0-9]*.png" 2>/dev/null || true)
if [ -n "$dg_screens" ]; then
    report_threat "DiscordGo screenshot artifacts detected in /tmp:\n$dg_screens"
    dg_threat=true
fi

# Check active network connections to Discord
if command -v ss >/dev/null 2>&1; then
    disc_conns=$(ss -tp state established 2>/dev/null | grep -iE "discord" || true)
    if [ -n "$disc_conns" ]; then
        report_warn "Active outbound network connection to Discord detected:\n$disc_conns"
    fi
fi

[ "$dg_threat" = false ] && report_clean "No DiscordGo C2 agents or temporary screen dumps detected."

# ==============================================================================
# 3. c0unts/realm (Imix Agent) Detection
# ==============================================================================
log_section "3. Realm / Imix Adversary Agent (c0unts/realm)"

realm_threat=false

# Check services
for svc in imix imix.service; do
    if systemctl is-active "$svc" 2>/dev/null | grep -qw "active" || [ -f "/etc/systemd/system/$svc" ] || [ -f "/lib/systemd/system/$svc" ]; then
        report_threat "Imix systemd service present: $svc"
        realm_threat=true
    fi
done

# Check files
for path in "/bin/imix" "/usr/bin/imix" "/usr/local/bin/imix" "/var/run/imix.pid"; do
    if [ -f "$path" ]; then
        report_threat "Imix binary/PID file located: $path"
        realm_threat=true
    fi
done

# Check running processes
for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$exe" =~ /bin/imix || "$cmdline" =~ \bimix\b ]]; then
        report_threat "Imix agent process running: PID $pid -> $cmdline ($exe)"
        realm_threat=true
    elif [ -f "$exe" ] && strings -n 8 "$exe" 2>/dev/null | grep -iE "(eldritch::|imix::|spellshift)" >/dev/null 2>&1; then
        report_threat "Process PID $pid holds Realm/Eldritch signatures: $exe"
        realm_threat=true
    fi
done

[ "$realm_threat" = false ] && report_clean "No Realm / Imix services, binaries, or active agents detected."

# ==============================================================================
# 4. drew-young/requestor C2 Detection
# ==============================================================================
log_section "4. Requestor HTTPS C2 (drew-young/requestor)"

req_threat=false

# Service file & binary
if [ -f "/lib/systemd/system/systemd-boot-system-key.service" ] || [ -f "/etc/systemd/system/systemd-boot-system-key.service" ]; then
    report_threat "Requestor service file detected: systemd-boot-system-key.service"
    req_threat=true
fi

for bin in "/lib/systemd/systemd-boot-system-key" "/usr/lib/systemd/systemd-boot-system-key" "/tmp/requestor.linux"; do
    if [ -f "$bin" ]; then
        report_threat "Requestor binary detected on disk: $bin"
        req_threat=true
    fi
done

# Processes
for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$cmdline" =~ "systemd-boot-system-key" || "$cmdline" =~ "--verify-boot" || "$exe" =~ "systemd-boot-system-key" ]]; then
        report_threat "Requestor C2 process active: PID $pid -> $cmdline ($exe)"
        req_threat=true
    fi
done

[ "$req_threat" = false ] && report_clean "No Requestor masquerading service or binaries detected."

# ==============================================================================
# 5. jamessouthycoder19/Javalanche C2 Detection
# ==============================================================================
log_section "5. Javalanche C2 Ecosystem (jamessouthycoder19/Javalanche)"

jvl_threat=false

# Check known spoofed service names
JVL_SVCS=("systemd-ssh" "snapd.container" "apparmour" "systemd-logind-ssh" "firewall" "java-init")
for js in "${JVL_SVCS[@]}"; do
    for dir in /lib/systemd/system /etc/systemd/system; do
        if [ -f "$dir/${js}.service" ]; then
            # Verify if it has Javalanche markers
            if grep -iE "(javalanche|Initialize Systemctl|Load AppArmour|Secure Shell Service|snapd\.container|/bin/firewall|ExecStart=/bin/)" "$dir/${js}.service" >/dev/null 2>&1; then
                report_threat "Javalanche spoofed service found: $dir/${js}.service"
                jvl_threat=true
            fi
        fi
    done
done

# Check directories
if [ -d "/var/log/asa" ]; then
    report_threat "Javalanche staging path present: /var/log/asa"
    jvl_threat=true
fi
if [ -d "/etc/javalanche" ]; then
    report_threat "Javalanche server/config path present: /etc/javalanche"
    jvl_threat=true
fi

# Check binaries in /bin/
for fb in /bin/systemd-ssh /bin/snapd.container /bin/apparmour /bin/systemd-logind-ssh /bin/firewall; do
    if [ -f "$fb" ]; then
        report_threat "Suspicious Javalanche target binary present: $fb"
        jvl_threat=true
    fi
done

# Check active processes
for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$cmdline" =~ "beacon1.javalanche.net" || "$cmdline" =~ "rot13" || "$cmdline" =~ "java-23.0.1-bin-java.sh" ]]; then
        report_threat "Javalanche process active: PID $pid -> $cmdline"
        jvl_threat=true
    elif [ -f "$exe" ] && strings -n 12 "$exe" 2>/dev/null | grep -iE "(javalanche\.net|BeaconC2Handler)" >/dev/null 2>&1; then
        report_threat "Process PID $pid matches Javalanche signatures: $exe"
        jvl_threat=true
    fi
done

[ "$jvl_threat" = false ] && report_clean "No Javalanche services, payloads, or rot13 beacons detected."

# ==============================================================================
# 6. bcvillano/heisenberg ICMP Backdoor Detection
# ==============================================================================
log_section "6. Heisenberg ICMP Backdoor (bcvillano/heisenberg)"

hb_threat=false

# Promiscuous interfaces
if command -v ip >/dev/null 2>&1; then
    promisc=$(ip link show 2>/dev/null | grep -i "PROMISC" || true)
    if [ -n "$promisc" ]; then
        report_warn "Network interface operating in PROMISC mode detected:\n$promisc"
    fi
fi

# Secondary implant file
if [ -f "/bin/evil" ]; then
    report_threat "Heisenberg secondary implant path exists: /bin/evil"
    hb_threat=true
fi

# Processes sniffing raw sockets or matching signatures
for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$cmdline" =~ "heisenberg" || "$exe" =~ "heisenberg" ]]; then
        report_threat "Heisenberg process running: PID $pid -> $cmdline ($exe)"
        hb_threat=true
    elif [ -f "$exe" ] && strings -n 6 "$exe" 2>/dev/null | grep -E "(/bin/evil|handlePayload|gopacket)" >/dev/null 2>&1; then
        report_threat "Process PID $pid holds Heisenberg constants: $exe"
        hb_threat=true
    fi
done

[ "$hb_threat" = false ] && report_clean "No Heisenberg ICMP sniffing backdoors or /bin/evil payloads detected."

# ==============================================================================
# 7. bcvillano/skeletor C2 Detection
# ==============================================================================
log_section "7. Skeletor HTTP(S) C2 (bcvillano/skeletor)"

skel_threat=false

for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$exe" =~ "linux-agent.bin" || "$cmdline" =~ "linux-agent.bin" || "$cmdline" =~ "skeletor" || "$cmdline" =~ "python.*beacon\.py" ]]; then
        report_threat "Skeletor implant active: PID $pid -> $cmdline ($exe)"
        skel_threat=true
    elif [ -f "$exe" ] && strings -n 10 "$exe" 2>/dev/null | grep -E "(/register|/tasks|CallbackInterval)" >/dev/null 2>&1; then
        report_threat "Process PID $pid matches Skeletor beacon signatures: $exe"
        skel_threat=true
    fi
done

[ "$skel_threat" = false ] && report_clean "No Skeletor Go/Python implants detected."

# ==============================================================================
# 8. leahkvares/C2 Detection
# ==============================================================================
log_section "8. Leah Kvares Python C2 (leahkvares/C2)"

lk_threat=false

if [ -f "/lib/systemd/system/systemd-sysctl-init.service" ] || [ -f "/etc/systemd/system/systemd-sysctl-init.service" ]; then
    report_threat "Leahkvares C2 service present: systemd-sysctl-init.service"
    lk_threat=true
fi

for lk_bin in "/lib/systemd/systemd-sysctl-init" "/usr/lib/systemd/systemd-sysctl-init"; do
    if [ -f "$lk_bin" ]; then
        report_threat "Leahkvares C2 binary present: $lk_bin"
        lk_threat=true
    fi
done

# Processes connecting to port 5005 or IP 159.203.129.74
for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir##*/}"
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    if [[ "$cmdline" =~ "systemd-sysctl-init" || "$exe" =~ "systemd-sysctl-init" || "$cmdline" =~ "159.203.129.74" ]]; then
        report_threat "Leahkvares C2 process active: PID $pid -> $cmdline"
        lk_threat=true
    fi
done

[ "$lk_threat" = false ] && report_clean "No Leahkvares C2 services, binaries, or active sockets detected."

# ==============================================================================
# 9. Audit SSH Authorized Keys (Read-Only)
# ==============================================================================
log_section "9. System Audit: SSH Authorized Keys"

for auth_file in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$auth_file" ] || continue
    key_count=0
    while IFS= read -r key_line; do
        if [ -n "$key_line" ] && [[ ! "$key_line" =~ ^# ]]; then
            key_count=$((key_count + 1))
            user_part=$(echo "$key_line" | awk '{print $NF}')
            report_warn "Active SSH key in $auth_file (Comment/User: $user_part)"
        fi
    done < "$auth_file"
    if [ "$key_count" -eq 0 ]; then
        report_clean "$auth_file contains no active keys."
    fi
done

# ==============================================================================
# Summary
# ==============================================================================
echo -e "\n======================================================================"
echo -e "                   LINUX DETECTION SCAN SUMMARY                       "
echo -e "======================================================================"
echo -e "Total Checks Run:      ${BOLD}$TOTAL_CHECKS${NC}"
if [ "$THREATS_DETECTED" -gt 0 ]; then
    echo -e "Threats Identified:    ${RED}${BOLD}$THREATS_DETECTED${NC}  <-- ACTION REQUIRED"
    echo -e "Remediation Script:    ${CYAN}sudo ./remediate_all_linux.sh${NC}"
else
    echo -e "Threats Identified:    ${GREEN}${BOLD}0 (System appears clean of cataloged threats)${NC}"
fi
if [ "$WARNINGS_FOUND" -gt 0 ]; then
    echo -e "Warnings / Audit Items: ${YELLOW}$WARNINGS_FOUND${NC}"
fi
echo -e "======================================================================\n"
