#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: bcvillano/skeletor
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/bcvillano/skeletor
# Threat: HTTP(S) beaconing C2 implant (Go/Python) executing periodic remote tasks
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

BACKUP_DIR="/var/backups/blueteam-remediation/skeletor-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Hunt and Terminate Skeletor Processes (Go & Python Implants)
# ------------------------------------------------------------------------------
# Skeletor signatures:
# - Binary name defaults: linux-agent.bin, arm-agent.bin
# - Routes beaconed: /register, /tasks, /results
# - Go symbols / strings: "CallbackInterval", "Skeletor", "agent_id", "implant_type"
# - Python symbols: "Beacon", "SKELETOR_IP", "implant_type"

log_info "Scanning for active Skeletor implants..."

for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [ -d "$pid_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    is_skeletor=false

    if [[ "$exe" =~ "linux-agent.bin" || "$cmdline" =~ "linux-agent.bin" || "$cmdline" =~ "skeletor" ]]; then
        is_skeletor=true
    elif [ -f "$exe" ]; then
        if strings -n 10 "$exe" 2>/dev/null | grep -E "(/register|/tasks|implant_type.*Go|CallbackInterval)" >/dev/null 2>&1; then
            is_skeletor=true
        fi
    fi

    if [ "$is_skeletor" = true ]; then
        log_alert "CRITICAL: Detected Skeletor agent PID $pid -> $cmdline ($exe)"
        cp -a "$exe" "$BACKUP_DIR/skeletor_binary_${pid}.bin" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Killed Skeletor PID $pid"

        if [ -f "$exe" ] && [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm|home|opt|usr/local|root)/ ]]; then
            rm -f "$exe"
            log_pass "Deleted agent binary: $exe"
        fi
    fi
done

# Check Python processes running beacon.py
for py_pid in $(pgrep -f "python.*beacon\.py" || true); do
    log_alert "Found Python Skeletor beacon process: PID $py_pid"
    kill -9 "$py_pid" 2>/dev/null || true
    log_pass "Terminated Python beacon PID $py_pid"
done

# ------------------------------------------------------------------------------
# 2. Check for Cron Jobs or Systemd Services Running Skeletor
# ------------------------------------------------------------------------------
log_info "Auditing crontabs and systemd services for agent references..."

for cron_file in /etc/crontab /etc/cron.*/* /var/spool/cron/crontabs/*; do
    [ -f "$cron_file" ] || continue
    if grep -iE "(linux-agent|skeletor|beacon\.py)" "$cron_file" >/dev/null 2>&1; then
        log_alert "Found persistence reference in cron file: $cron_file"
        cp -a "$cron_file" "$BACKUP_DIR/"
        sed -i -E '/(linux-agent|skeletor|beacon\.py)/d' "$cron_file"
        log_pass "Cleaned suspicious entries from $cron_file"
    fi
done

find /etc/systemd/system /lib/systemd/system -maxdepth 1 -type f -name "*.service" 2>/dev/null | while read -r sfile; do
    if grep -iE "(linux-agent|skeletor|beacon\.py)" "$sfile" >/dev/null 2>&1; then
        log_alert "Found systemd service running Skeletor: $sfile"
        sname=$(basename "$sfile" .service)
        systemctl stop "$sname" 2>/dev/null || true
        systemctl disable "$sname" 2>/dev/null || true
        cp -a "$sfile" "$BACKUP_DIR/"
        rm -f "$sfile"
        log_pass "Removed service $sname"
    fi
done

systemctl daemon-reload 2>/dev/null || true
log_pass "Skeletor remediation completed."
