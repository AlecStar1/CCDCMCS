#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: Master Triage & Hardening Script
# Targets: Fedora, Debian, Ubuntu
# Scope: All active Red Team tools identified in list_of_repos.md
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MASTER_BACKUP_DIR="/var/backups/blueteam-remediation/master-${TIMESTAMP}"
mkdir -p "$MASTER_BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${BOLD}${BLUE}"
    echo "======================================================================"
    echo "            MINICOP BLUE TEAM UNIFIED INCIDENT REMEDIATION           "
    echo "======================================================================"
    echo -e "${NC}"
}

log_section() { echo -e "\n${BOLD}${YELLOW}>>> [SECTION] $1${NC}"; }
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_alert()   { echo -e "${RED}[ALERT]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[FATAL ERROR] This script requires administrative privileges. Execute as root (sudo).${NC}" >&2
    exit 1
fi

banner

# Detect OS
DISTRO="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
fi
log_info "Host: $(hostname) | Kernel: $(uname -r) | Distro: $DISTRO"
log_info "Master quarantine location: $MASTER_BACKUP_DIR"

# ------------------------------------------------------------------------------
# 1. Execute Modular Repository Remediation Scripts
# ------------------------------------------------------------------------------
run_subscript() {
    local script_name="$1"
    local desc="$2"
    log_section "Executing Remediation Module: $desc ($script_name)"
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        chmod +x "$SCRIPT_DIR/$script_name"
        bash "$SCRIPT_DIR/$script_name" || log_warn "Module $script_name exited with non-zero status"
    else
        log_warn "Module $script_name not found in $SCRIPT_DIR; proceeding with inline checks..."
    fi
}

run_subscript "remediate_vulnsamba.sh" "SambaCry Exploits (cdt-vulnsamba-deploy)"
run_subscript "remediate_discordgo.sh" "DiscordGo C2 Agent (c0unts/DiscordGo)"
run_subscript "remediate_realm.sh" "Realm / Imix Adversary Agent (c0unts/realm)"
run_subscript "remediate_requestor.sh" "Requestor HTTPS Implant (drew-young/requestor)"
run_subscript "remediate_javalanche.sh" "Javalanche C2 Ecosystem (jamessouthycoder19/Javalanche)"
run_subscript "remediate_heisenberg.sh" "Heisenberg ICMP Backdoor (bcvillano/heisenberg)"
run_subscript "remediate_skeletor.sh" "Skeletor HTTP(S) C2 (bcvillano/skeletor)"
run_subscript "remediate_leahkvares_c2.sh" "Leah Kvares C2 (leahkvares/C2)"

# ------------------------------------------------------------------------------
# 2. Comprehensive Systemd & Autostart Persistence Sweep
# ------------------------------------------------------------------------------
log_section "Comprehensive Sweep of Systemd & Autostart Persistence"

SUSPECT_SERVICE_PATTERNS=(
    "systemd-boot-system-key"
    "systemd-sysctl-init"
    "systemd-logind-ssh"
    "systemd-ssh"
    "snapd.container"
    "apparmour"
    "java-init"
    "imix"
)

for pattern in "${SUSPECT_SERVICE_PATTERNS[@]}"; do
    find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 2 -name "*${pattern}*" 2>/dev/null | while read -r unit_path; do
        log_alert "Found suspicious unit file matching threat footprint: $unit_path"
        svc_name=$(basename "$unit_path" .service)
        systemctl stop "$svc_name" 2>/dev/null || true
        systemctl disable "$svc_name" 2>/dev/null || true
        systemctl mask "$svc_name" 2>/dev/null || true
        cp -a "$unit_path" "$MASTER_BACKUP_DIR/"
        rm -f "$unit_path"
        log_pass "Neutralized service $svc_name"
    done
done

systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------------------------
# 3. Sweep Suspicious Binaries Dropped in System Directories
# ------------------------------------------------------------------------------
log_section "Sweeping Binary Drop Paths"

SUSPECT_FILES=(
    "/lib/systemd/systemd-boot-system-key"
    "/lib/systemd/systemd-sysctl-init"
    "/bin/evil"
    "/bin/imix"
    "/usr/bin/imix"
    "/bin/systemd-ssh"
    "/bin/snapd.container"
    "/bin/apparmour"
    "/bin/systemd-logind-ssh"
    "/tmp/discordstat.txt"
    "/srv/samba/vulnshare"
    "/etc/javalanche"
    "/var/log/asa"
)

for sfile in "${SUSPECT_FILES[@]}"; do
    if [ -e "$sfile" ]; then
        log_alert "Discovered malicious/vulnerable artifact: $sfile"
        cp -r "$sfile" "$MASTER_BACKUP_DIR/" 2>/dev/null || true
        rm -rf "$sfile"
        log_pass "Quarantined and deleted: $sfile"
    fi
done

# ------------------------------------------------------------------------------
# 4. Check for SSH Keys Injection in /root & User Directories
# ------------------------------------------------------------------------------
log_section "Auditing SSH Authorized Keys"

for auth_file in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$auth_file" ] || continue
    log_info "Inspecting $auth_file"
    # Back up key file
    cp -a "$auth_file" "$MASTER_BACKUP_DIR/$(basename $(dirname $(dirname $auth_file)))_authorized_keys.bak"
    # Print keys for manual blue team inspection
    while IFS= read -r key_line; do
        if [ -n "$key_line" ] && [[ ! "$key_line" =~ ^# ]]; then
            log_warn "Active SSH key: $(echo "$key_line" | awk '{print $NF}')"
        fi
    done < "$auth_file"
done

# ------------------------------------------------------------------------------
# 5. Core Network Hardening (iptables)
# ------------------------------------------------------------------------------
log_section "Applying Baseline Firewall Protection (iptables)"

if command -v iptables >/dev/null 2>&1; then
    # Block outgoing connections to common C2 test ports unless required by competition
    # Block default leahkvares C2
    iptables -C OUTPUT -d 159.203.129.74 -j REJECT 2>/dev/null || iptables -I OUTPUT 1 -d 159.203.129.74 -j REJECT 2>/dev/null || true
    iptables -C OUTPUT -p tcp --dport 5005 -j REJECT 2>/dev/null || iptables -I OUTPUT 1 -p tcp --dport 5005 -j REJECT 2>/dev/null || true

    # Drop ICMP echo triggers (Heisenberg)
    for trig in "REBORN" "SHELL" "CMD "; do
        iptables -C INPUT -p icmp --icmp-type echo-request -m string --string "$trig" --algo bm -j DROP 2>/dev/null || \
        iptables -I INPUT 1 -p icmp --icmp-type echo-request -m string --string "$trig" --algo bm -j DROP 2>/dev/null || true
    done
    log_pass "iptables defense rules active"
fi

# ------------------------------------------------------------------------------
# 6. Summary and Completion
# ------------------------------------------------------------------------------
log_section "Remediation Complete"
echo -e "${BOLD}${GREEN}[SUCCESS] All Linux systems (Fedora, Debian, Ubuntu) threat mitigations applied.${NC}"
echo -e "Quarantined artifacts, configurations, and binaries saved to:\n  -> ${MASTER_BACKUP_DIR}\n"
