#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: leahkvares/C2
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/leahkvares/C2
# Threat: Python HTTP C2 deployed via Ansible as systemd-sysctl-init service
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

BACKUP_DIR="/var/backups/blueteam-remediation/leahkvares-c2-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Stop, Disable, and Mask systemd-sysctl-init Service
# ------------------------------------------------------------------------------
# leahkvares/C2 Linux Ansible deployment details:
# - Service file: /lib/systemd/system/systemd-sysctl-init.service
# - Binary / script: /lib/systemd/systemd-sysctl-init
# - Service Description: "Initialize Systemctl"
# - ExecStart: /lib/systemd/systemd-sysctl-init

SVC_NAME="systemd-sysctl-init"
log_info "Checking for rogue service: ${SVC_NAME}..."

if systemctl is-active "$SVC_NAME" >/dev/null 2>&1 || systemctl is-enabled "$SVC_NAME" >/dev/null 2>&1 || [ -f "/lib/systemd/system/${SVC_NAME}.service" ] || [ -f "/etc/systemd/system/${SVC_NAME}.service" ]; then
    log_alert "Detected active or enabled rogue service: ${SVC_NAME}"
    systemctl stop "$SVC_NAME" 2>/dev/null || true
    systemctl disable "$SVC_NAME" 2>/dev/null || true
    systemctl mask "$SVC_NAME" 2>/dev/null || true
    log_pass "Stopped, disabled, and masked ${SVC_NAME}"
fi

# Remove unit files
for unit_loc in "/lib/systemd/system/${SVC_NAME}.service" "/etc/systemd/system/${SVC_NAME}.service" "/usr/lib/systemd/system/${SVC_NAME}.service"; do
    if [ -f "$unit_loc" ]; then
        log_alert "Quarantining and removing unit file: $unit_loc"
        cp -a "$unit_loc" "$BACKUP_DIR/"
        rm -f "$unit_loc"
        log_pass "Deleted $unit_loc"
    fi
done

systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. Terminate Running C2 Processes
# ------------------------------------------------------------------------------
log_info "Hunting for C2 implant processes in /proc..."

for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [ -d "$pid_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    is_c2=false

    # Check for direct binary match or arguments
    if [[ "$cmdline" =~ "systemd-sysctl-init" || "$exe" =~ "systemd-sysctl-init" ]]; then
        is_c2=true
    # Check Python client signatures (endpoints: /register-client, /command)
    elif [[ "$cmdline" =~ "client.py" ]]; then
        if grep -E "(/register-client|/command)" "/proc/$pid/cmdline" >/dev/null 2>&1; then
            is_c2=true
        fi
    fi

    # Inspect open sockets connecting to port 5005 (default port in client.py)
    if [ "$is_c2" = false ] && command -v ss >/dev/null 2>&1; then
        if ss -tp 2>/dev/null | grep -E "pid=$pid\b" | grep -E "(:5005|159\.203\.129\.74)" >/dev/null 2>&1; then
            log_alert "PID $pid has active socket to leahkvares C2 endpoint (:5005)!"
            is_c2=true
        fi
    fi

    if [ "$is_c2" = true ]; then
        log_alert "CRITICAL: Detected leahkvares C2 process PID $pid -> $cmdline ($exe)"
        if [ -f "$exe" ]; then
            cp -a "$exe" "$BACKUP_DIR/c2_binary_${pid}.bin" 2>/dev/null || true
        fi
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Killed PID $pid"
    fi
done

# ------------------------------------------------------------------------------
# 3. Remove Implant Binary & Artifacts
# ------------------------------------------------------------------------------
MALICIOUS_BINARIES=(
    "/lib/systemd/systemd-sysctl-init"
    "/usr/lib/systemd/systemd-sysctl-init"
    "/bin/systemd-sysctl-init"
    "/usr/bin/systemd-sysctl-init"
)

for b in "${MALICIOUS_BINARIES[@]}"; do
    if [ -f "$b" ]; then
        log_alert "Quarantining and removing malicious binary: $b"
        cp -a "$b" "$BACKUP_DIR/"
        rm -f "$b"
        log_pass "Deleted $b"
    fi
done

# ------------------------------------------------------------------------------
# 4. Block Known Default C2 IP / Port via Firewall
# ------------------------------------------------------------------------------
DEFAULT_C2_IP="159.203.129.74"
log_info "Blocking communication with known C2 server IP ($DEFAULT_C2_IP) and default port 5005..."

if command -v iptables >/dev/null 2>&1; then
    if ! iptables -C OUTPUT -d "$DEFAULT_C2_IP" -j REJECT 2>/dev/null; then
        iptables -I OUTPUT 1 -d "$DEFAULT_C2_IP" -j REJECT 2>/dev/null || true
        log_pass "Blocked outbound traffic to $DEFAULT_C2_IP via iptables"
    fi
    if ! iptables -C OUTPUT -p tcp --dport 5005 -j REJECT 2>/dev/null; then
        iptables -I OUTPUT 1 -p tcp --dport 5005 -j REJECT 2>/dev/null || true
        log_pass "Blocked outbound traffic on port 5005 via iptables"
    fi
fi

log_pass "leahkvares/C2 remediation complete."
