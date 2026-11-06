#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: c0unts/realm (Imix Agent)
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/c0unts/realm
# Threat: Rust adversary emulation agent (Imix) using Eldritch DSL & systemd/sysvinit persistence
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

BACKUP_DIR="/var/backups/blueteam-remediation/realm-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Neutralize Default & Custom Imix Services
# ------------------------------------------------------------------------------
log_info "Scanning for Realm / Imix services in systemd and sysvinit..."

KNOWN_SERVICE_NAMES=("imix")

# Search systemd directories for units executing imix or containing Eldritch keywords
SYSTEMD_DIRS=(
    "/etc/systemd/system"
    "/lib/systemd/system"
    "/usr/lib/systemd/system"
    "/run/systemd/system"
)

for dir in "${SYSTEMD_DIRS[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r svc_path; do
        [ -f "$svc_path" ] || continue
        svc_name=$(basename "$svc_path")
        # Check content of unit file
        if grep -iE "(imix|eldritch|tome|spellshift)" "$svc_path" >/dev/null 2>&1; then
            log_alert "Identified Realm/Imix systemd service file: $svc_path"
            base_unit="${svc_name%.service}"
            KNOWN_SERVICE_NAMES+=("$base_unit")
        fi
    done < <(find "$dir" -maxdepth 2 -type f -name "*.service" 2>/dev/null || true)
done

# Deduplicate service names
readarray -t UNIQUE_SERVICES < <(printf '%s\n' "${KNOWN_SERVICE_NAMES[@]}" | sort -u)

for svc in "${UNIQUE_SERVICES[@]}"; do
    if systemctl list-unit-files | grep -qw "^${svc}.service" || systemctl is-active "$svc" >/dev/null 2>&1 || [ -f "/etc/systemd/system/${svc}.service" ] || [ -f "/lib/systemd/system/${svc}.service" ]; then
        log_alert "Stopping and disabling suspicious service: $svc"
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
        log_pass "Disabled & masked service: $svc"
    fi
done

# Check SysVinit (/etc/init.d/)
if [ -d "/etc/init.d" ]; then
    for init_script in /etc/init.d/*; do
        [ -f "$init_script" ] || continue
        if grep -iE "(imix|eldritch|tome)" "$init_script" >/dev/null 2>&1; then
            svc_name=$(basename "$init_script")
            log_alert "Found Realm/Imix SysVinit script: $init_script"
            "$init_script" stop 2>/dev/null || true
            cp -a "$init_script" "$BACKUP_DIR/"
            if command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d -f "$svc_name" remove || true
            elif command -v chkconfig >/dev/null 2>&1; then
                chkconfig --del "$svc_name" || true
            fi
            rm -f "$init_script"
            log_pass "Removed SysVinit script: $init_script"
        fi
    done
fi

# Reload systemd
systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. Terminate Imix Implant Processes
# ------------------------------------------------------------------------------
log_info "Hunting for active Imix processes..."

for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [ -d "$pid_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)

    is_imix=false
    if [[ "$exe" =~ /bin/imix || "$cmdline" =~ \bimix\b ]]; then
        is_imix=true
    elif [ -f "$exe" ]; then
        # Check binary strings for Imix signatures (Rust crate names, eldritch, tome)
        if strings -n 8 "$exe" 2>/dev/null | grep -iE "(eldritch::|imix::|spellshift|tavern\.proto)" >/dev/null 2>&1; then
            is_imix=true
        fi
    fi

    if [ "$is_imix" = true ]; then
        log_alert "CRITICAL: Found running Realm/Imix process PID $pid -> $cmdline ($exe)"
        cp -a "$exe" "$BACKUP_DIR/imix_${pid}.bin" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Killed Imix process PID $pid"
        if [ -f "$exe" ] && [ "$exe" != "/bin/bash" ] && [ "$exe" != "/bin/sh" ]; then
            log_warn "Quarantining and removing Imix binary: $exe"
            rm -f "$exe"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 3. Clean Known Binary & Config Locations
# ------------------------------------------------------------------------------
log_info "Removing static Imix binary locations..."
SUSPECT_BINARIES=(
    "/bin/imix"
    "/usr/bin/imix"
    "/usr/local/bin/imix"
    "/var/run/imix.pid"
)

for f in "${SUSPECT_BINARIES[@]}"; do
    if [ -f "$f" ]; then
        log_alert "Removing suspect Realm/Imix file: $f"
        cp -a "$f" "$BACKUP_DIR/"
        rm -f "$f"
        log_pass "Deleted $f"
    fi
done

# ------------------------------------------------------------------------------
# 4. Outbound Network Filtering for Tavern Server Ports
# ------------------------------------------------------------------------------
log_info "Checking network connections for gRPC callbacks (commonly port 8000)..."
if command -v ss >/dev/null 2>&1; then
    ss -tp state established '( dport = :8000 )' 2>/dev/null | while read -r line; do
        if [ -n "$line" ]; then
            log_warn "Suspicious connection on port 8000: $line"
        fi
    done
fi

log_pass "Realm / Imix remediation completed successfully."
