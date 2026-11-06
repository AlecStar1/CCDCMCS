#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Hardening: cdt-vulnsamba-deploy
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/Zanex360/cdt-vulnsamba-deploy (and cdt-samba-deploy)
# Vulnerability: CVE-2017-7494 ("SambaCry" Remote Code Execution via writable share)
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

DETECTED_DISTRO="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DETECTED_DISTRO="${ID:-unknown}"
fi
log_info "Detected OS Distribution: ${DETECTED_DISTRO}"

BACKUP_DIR="/var/backups/blueteam-remediation/vulnsamba-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Terminate Rogue / Source-Built Samba Processes
# ------------------------------------------------------------------------------
log_info "Checking for running vulnerable Samba processes (/opt/samba-4.5.9 or smbd)..."

# Look for custom prefix binaries deployed by ansible
CUSTOM_PREFIX="/opt/samba-4.5.9"
CUSTOM_SMBD="$CUSTOM_PREFIX/sbin/smbd"
CUSTOM_NMBD="$CUSTOM_PREFIX/sbin/nmbd"

for proc in "$CUSTOM_SMBD" "$CUSTOM_NMBD"; do
    if pgrep -f "$proc" >/dev/null 2>&1; then
        log_alert "Found active process matching custom vulnerable Samba: $proc"
        pkill -9 -f "$proc" || true
        log_pass "Terminated process: $proc"
    fi
done

# If smbd/nmbd is running from /usr/src or non-standard paths
for pid in $(pgrep -f "smbd|nmbd" || true); do
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    if [[ "$cmdline" =~ "samba-4.5" || "$cmdline" =~ "/opt/samba" || "$cmdline" =~ "/usr/src/samba" ]]; then
        log_alert "Killing rogue Samba process PID $pid: $cmdline"
        kill -9 "$pid" 2>/dev/null || true
    fi
done

# ------------------------------------------------------------------------------
# 2. Inspect and Quarantine Malicious Shared Objects (.so) in Shared Directories
# ------------------------------------------------------------------------------
DEFAULT_VULN_SHARE="/srv/samba/vulnshare"
log_info "Scanning for writable Samba directories and uploaded .so payload modules..."

SHARE_PATHS=("$DEFAULT_VULN_SHARE")

# Extract additional share paths from any smb.conf on system
for conf in "$CUSTOM_PREFIX/etc/smb.conf" /etc/samba/smb.conf /usr/local/samba/etc/smb.conf; do
    if [ -f "$conf" ]; then
        log_info "Found Samba configuration at $conf; extracting share paths..."
        while IFS= read -r line; do
            path=$(echo "$line" | awk -F '=' '{print $2}' | xargs)
            if [ -n "$path" ] && [ -d "$path" ]; then
                SHARE_PATHS+=("$path")
            fi
        done < <(grep -iE "^\s*path\s*=" "$conf" || true)
    fi
done

# Deduplicate share paths
readarray -t UNIQUE_SHARE_PATHS < <(printf '%s\n' "${SHARE_PATHS[@]}" | sort -u)

for share_dir in "${UNIQUE_SHARE_PATHS[@]}"; do
    if [ -d "$share_dir" ]; then
        log_info "Analyzing share directory: $share_dir"
        find "$share_dir" -type f -name "*.so*" 2>/dev/null | while read -r so_file; do
            log_alert "CRITICAL: Malicious shared object (.so) detected in share: $so_file"
            cp -a "$so_file" "$BACKUP_DIR/"
            rm -f "$so_file"
            log_pass "Quarantined and removed: $so_file"
        done

        # Fix overly permissive 0777 share permissions
        log_info "Hardening permissions on $share_dir from 777 to 0750 root:root"
        chmod 0750 "$share_dir"
    fi
done

# ------------------------------------------------------------------------------
# 3. Neutralize Rogue Custom Samba Installation
# ------------------------------------------------------------------------------
if [ -d "$CUSTOM_PREFIX" ]; then
    log_alert "Found custom vulnerable Samba installation directory at $CUSTOM_PREFIX"
    tar -czf "$BACKUP_DIR/opt-samba-4.5.9-quarantine.tar.gz" -C "/opt" "samba-4.5.9" 2>/dev/null || true
    rm -rf "$CUSTOM_PREFIX"
    log_pass "Archived and removed $CUSTOM_PREFIX"
fi

if [ -d "/usr/src/samba-4.5.9" ]; then
    log_warn "Removing build directory /usr/src/samba-4.5.9"
    rm -rf "/usr/src/samba-4.5.9"
fi
if [ -f "/usr/src/samba-4.5.9.tar.gz" ]; then
    rm -f "/usr/src/samba-4.5.9.tar.gz"
fi

# Clean up rogue PID and socket files
rm -f /var/run/samba/smbd.pid /var/run/samba/nmbd.pid 2>/dev/null || true

# ------------------------------------------------------------------------------
# 4. Harden Official OS Samba Configuration (CVE-2017-7494 Mitigation)
# ------------------------------------------------------------------------------
SYS_SMB_CONF="/etc/samba/smb.conf"
if [ -f "$SYS_SMB_CONF" ]; then
    log_info "Securing system Samba configuration ($SYS_SMB_CONF)..."
    cp -a "$SYS_SMB_CONF" "$BACKUP_DIR/smb.conf.bak"

    # Add nt pipe support = no under [global] if not already present
    if grep -iq "^\[global\]" "$SYS_SMB_CONF"; then
        if ! grep -iq "nt pipe support" "$SYS_SMB_CONF"; then
            sed -i '/^\[global\]/a \   nt pipe support = no' "$SYS_SMB_CONF"
            log_pass "Added 'nt pipe support = no' to [global] section"
        fi
        if ! grep -iq "server min protocol" "$SYS_SMB_CONF"; then
            sed -i '/^\[global\]/a \   server min protocol = SMB2' "$SYS_SMB_CONF"
            log_pass "Enforced 'server min protocol = SMB2'"
        fi
    fi

    # Disable vulnerable shares if vulnshare is defined
    if grep -iq "^\[vulnshare\]" "$SYS_SMB_CONF"; then
        log_alert "Disabling vulnerable [vulnshare] section in $SYS_SMB_CONF"
        sed -i 's/^\[vulnshare\]/# [vulnshare]/' "$SYS_SMB_CONF"
    fi

    # Validate syntax if testparm is installed
    if command -v testparm >/dev/null 2>&1; then
        testparm -s >/dev/null 2>&1 || log_warn "testparm reported syntax errors in $SYS_SMB_CONF"
    fi

    # Restart official distro Samba service if enabled
    if systemctl is-active smbd >/dev/null 2>&1; then
        systemctl restart smbd
        log_pass "Restarted hardened system smbd service"
    elif systemctl is-active smb >/dev/null 2>&1; then
        systemctl restart smb
        log_pass "Restarted hardened system smb service (Fedora/RHEL)"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Check Package Status / Upgrade Samba if Needed
# ------------------------------------------------------------------------------
log_info "Checking installed package manager version of Samba..."
if command -v apt-get >/dev/null 2>&1; then
    if dpkg -l | grep -E "\bsamba\b" >/dev/null 2>&1; then
        log_info "Debian/Ubuntu Samba package detected. Verifying version..."
        samba_ver=$(samba -V 2>/dev/null || smbd -V 2>/dev/null || echo "Unknown")
        log_info "Installed system Samba: $samba_ver"
    fi
elif command -v dnf >/dev/null 2>&1; then
    if rpm -q samba >/dev/null 2>&1; then
        log_info "Fedora Samba package detected: $(rpm -q samba)"
    fi
fi

log_pass "cdt-vulnsamba-deploy remediation complete. Backups stored in $BACKUP_DIR"
