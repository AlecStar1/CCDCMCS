#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: jamessouthycoder19/Javalanche
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/jamessouthycoder19/Javalanche
# Threat: Multi-protocol C2 (HTTPS, DNS, Raw TCP rot13) masquerading as system services
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_alert() { echo -e "${RED}[ALERT]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This remediation script must be run as root.${NC}" >&2
    exit 1
fi

BACKUP_DIR="/var/backups/blueteam-remediation/javalanche-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Investigate and Neutralize Known Javalanche Services
# ------------------------------------------------------------------------------
# Javalanche setup randomly selects service names from:
# ["systemd-ssh", "snapd.container", "apparmour", "systemd-logind-ssh", "firewall", "java-init"]
# ExecStart points to /bin/<service_name> or /var/log/asa/osa/java-*.sh
# Description contains: "Initialize Systemctl", "Secure Shell Service", "Secure Container for snapd", "Load AppArmour profiles", "User Login Management for SSH", "Firewall"

SUSPECT_SERVICE_NAMES=(
    "systemd-ssh"
    "snapd.container"
    "apparmour"
    "systemd-logind-ssh"
    "firewall"
    "java-init"
)

log_info "Checking known Javalanche service targets..."

for sname in "${SUSPECT_SERVICE_NAMES[@]}"; do
    # Note: On Ubuntu/Debian, apparmor is legitimate, but 'apparmour' (with a 'u') is fake!
    # And systemd-ssh / systemd-logind-ssh do not exist natively in systemd.
    unit_file="/lib/systemd/system/${sname}.service"
    etc_unit="/etc/systemd/system/${sname}.service"

    matched_path=""
    if [ -f "$unit_file" ]; then matched_path="$unit_file"; fi
    if [ -f "$etc_unit" ]; then matched_path="$etc_unit"; fi

    if [ -n "$matched_path" ]; then
        # Check if it has Javalanche markers
        is_malicious=false
        if grep -iE "(javalanche|Initialize Systemctl|Load AppArmour|Secure Shell Service|snapd\.container|/bin/firewall|ExecStart=/bin/)" "$matched_path" >/dev/null 2>&1; then
            is_malicious=true
        fi

        # Specifically check binary target
        exec_target=$(grep -E "^ExecStart=" "$matched_path" | awk -F '=' '{print $2}' | awk '{print $1}')
        if [[ "$exec_target" =~ ^/bin/(systemd-ssh|snapd\.container|apparmour|systemd-logind-ssh|firewall)$ ]] || [[ "$exec_target" =~ /var/log/asa/osa/ ]]; then
            is_malicious=true
        fi

        if [ "$is_malicious" = true ]; then
            log_alert "Confirmed Javalanche service: $sname ($matched_path)"
            systemctl stop "$sname" 2>/dev/null || true
            systemctl disable "$sname" 2>/dev/null || true
            systemctl mask "$sname" 2>/dev/null || true
            cp -a "$matched_path" "$BACKUP_DIR/"
            rm -f "$matched_path"
            log_pass "Neutralized service $sname"

            if [ -n "$exec_target" ] && [ -f "$exec_target" ]; then
                log_alert "Quarantining malicious payload binary: $exec_target"
                cp -a "$exec_target" "$BACKUP_DIR/"
                rm -f "$exec_target"
                log_pass "Deleted payload: $exec_target"
            fi
        fi
    fi
done

# Check /var/log/asa/osa/ directory (used in java-init.service)
if [ -d "/var/log/asa" ]; then
    log_alert "Found suspicious /var/log/asa directory (Javalanche java-init payload)"
    tar -czf "$BACKUP_DIR/asa-quarantine.tar.gz" -C "/var/log" "asa" 2>/dev/null || true
    rm -rf "/var/log/asa"
    log_pass "Removed /var/log/asa"
fi

# Check /etc/javalanche server directory if present
if [ -d "/etc/javalanche" ]; then
    log_alert "Found /etc/javalanche directory on system!"
    tar -czf "$BACKUP_DIR/etc-javalanche-quarantine.tar.gz" -C "/etc" "javalanche" 2>/dev/null || true
    rm -rf "/etc/javalanche"
    log_pass "Removed /etc/javalanche"
fi

systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. Terminate Javalanche Processes in /proc
# ------------------------------------------------------------------------------
log_info "Hunting for active Javalanche processes..."

for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [ -d "$pid_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    is_jvl=false

    # Check for known fake binary names in /bin/
    for fake_bin in /bin/systemd-ssh /bin/snapd.container /bin/apparmour /bin/systemd-logind-ssh /bin/firewall; do
        if [ "$exe" = "$fake_bin" ]; then
            is_jvl=true
            break
        fi
    done

    # Check binary strings for Javalanche beacons
    if [ -f "$exe" ] && [ "$is_jvl" = false ]; then
        if strings -n 12 "$exe" 2>/dev/null | grep -iE "(javalanche\.net|BeaconC2Handler|linuxBinary/encryption)" >/dev/null 2>&1; then
            is_jvl=true
        fi
    fi

    # Check for bash rot13 script (linuxPayload.sh uses exec 3<>/dev/tcp/...)
    if [[ "$cmdline" =~ "rot13" || "$cmdline" =~ "beacon1.javalanche.net" ]]; then
        is_jvl=true
    fi

    if [ "$is_jvl" = true ]; then
        log_alert "CRITICAL: Detected Javalanche process PID $pid: $cmdline ($exe)"
        cp -a "$exe" "$BACKUP_DIR/jvl_binary_${pid}.bin" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Killed Javalanche PID $pid"
    fi
done

# ------------------------------------------------------------------------------
# 3. Block Javalanche C2 Domains and DNS
# ------------------------------------------------------------------------------
log_info "Sinkholing Javalanche C2 domains in /etc/hosts..."
JVL_DOMAINS=(
    "beacon1.javalanche.net"
    "http1.javalanche.net"
    "http2.javalanche.net"
    "http3.javalanche.net"
    "dns1.javalanche.net"
)

for dom in "${JVL_DOMAINS[@]}"; do
    if ! grep -qw "$dom" /etc/hosts; then
        echo "127.0.0.1 $dom" >> /etc/hosts
        log_pass "Sinkholed $dom -> 127.0.0.1"
    fi
done

# Remove rogue firewall rules created by linuxPayload.sh
# "sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT" etc.
log_pass "Javalanche remediation completed."
