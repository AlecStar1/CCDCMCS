#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: drew-young/requestor
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/drew-young/requestor
# Threat: Rust HTTPS C2 implant masquerading as systemd-boot-system-key
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

BACKUP_DIR="/var/backups/blueteam-remediation/requestor-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Stop, Disable, and Mask Requestor Service
# ------------------------------------------------------------------------------
# In Requestor's Ansible playbooks:
# linux_binary: /lib/systemd/systemd-boot-system-key
# linux_service: /lib/systemd/system/systemd-boot-system-key.service
# ExecStart: /lib/systemd/systemd-boot-system-key --verify-boot

SVC_NAME="systemd-boot-system-key"
log_info "Checking for malicious service: ${SVC_NAME}..."

if systemctl is-active "$SVC_NAME" >/dev/null 2>&1 || systemctl is-enabled "$SVC_NAME" >/dev/null 2>&1 || [ -f "/lib/systemd/system/${SVC_NAME}.service" ] || [ -f "/etc/systemd/system/${SVC_NAME}.service" ]; then
    log_alert "Found active or enabled Requestor service: ${SVC_NAME}"
    systemctl stop "$SVC_NAME" 2>/dev/null || true
    systemctl disable "$SVC_NAME" 2>/dev/null || true
    systemctl mask "$SVC_NAME" 2>/dev/null || true
    log_pass "Stopped, disabled, and masked ${SVC_NAME}"
fi

# Remove service unit files
for sdir in "/lib/systemd/system" "/etc/systemd/system" "/usr/lib/systemd/system"; do
    unit_file="$sdir/${SVC_NAME}.service"
    if [ -f "$unit_file" ]; then
        log_alert "Quarantining and removing malicious unit file: $unit_file"
        cp -a "$unit_file" "$BACKUP_DIR/"
        rm -f "$unit_file"
        log_pass "Deleted $unit_file"
    fi
done

systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. Terminate Requestor Processes
# ------------------------------------------------------------------------------
log_info "Hunting for Requestor processes in /proc..."

for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [ -d "$pid_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    is_req=false
    if [[ "$exe" =~ "systemd-boot-system-key" || "$cmdline" =~ "systemd-boot-system-key" || "$cmdline" =~ "--verify-boot" || "$cmdline" =~ "requestor" ]]; then
        is_req=true
    elif [ -f "$exe" ]; then
        # Check binary strings for Requestor Rust signatures
        if strings -n 10 "$exe" 2>/dev/null | grep -iE "(requestor::|requestor\.linux|/tasks/complete)" >/dev/null 2>&1; then
            is_req=true
        fi
    fi

    if [ "$is_req" = true ]; then
        log_alert "CRITICAL: Found running Requestor process PID $pid -> $cmdline ($exe)"
        cp -a "$exe" "$BACKUP_DIR/requestor_binary_${pid}.bin" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Terminated PID $pid"
    fi
done

# ------------------------------------------------------------------------------
# 3. Remove Malicious Binary & Artifacts
# ------------------------------------------------------------------------------
SUSPECT_PATHS=(
    "/lib/systemd/systemd-boot-system-key"
    "/usr/lib/systemd/systemd-boot-system-key"
    "/bin/systemd-boot-system-key"
    "/usr/bin/systemd-boot-system-key"
    "/tmp/requestor.linux"
    "/var/tmp/requestor.linux"
)

for p in "${SUSPECT_PATHS[@]}"; do
    if [ -f "$p" ]; then
        log_alert "Quarantining and removing Requestor binary: $p"
        cp -a "$p" "$BACKUP_DIR/"
        rm -f "$p"
        log_pass "Removed: $p"
    fi
done

# Also check for other service units pretending to be systemd-boot-* with unusual arguments
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 1 -type f -name "*.service" 2>/dev/null | while read -r sfile; do
    if grep -q "\-\-verify\-boot" "$sfile" 2>/dev/null; then
        log_alert "Found masquerading service file with '--verify-boot': $sfile"
        cp -a "$sfile" "$BACKUP_DIR/"
        svc_name=$(basename "$sfile" .service)
        systemctl stop "$svc_name" 2>/dev/null || true
        systemctl disable "$svc_name" 2>/dev/null || true
        rm -f "$sfile"
        log_pass "Neutralized service: $svc_name"
    fi
done

systemctl daemon-reload 2>/dev/null || true
log_pass "Requestor remediation completed successfully."
