#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: bcvillano/heisenberg
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/bcvillano/heisenberg
# Threat: ICMP packet sniffing backdoor (libpcap / raw socket promiscuous sniffer)
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

BACKUP_DIR="/var/backups/blueteam-remediation/heisenberg-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Detect Promiscuous Network Interfaces & Raw ICMP Packet Sniffers
# ------------------------------------------------------------------------------
log_info "Checking for network interfaces operating in PROMISC mode..."
if command -v ip >/dev/null 2>&1; then
    promisc_ifaces=$(ip link show | grep -i "PROMISC" || true)
    if [ -n "$promisc_ifaces" ]; then
        log_warn "Network interface(s) in PROMISC mode detected:\n$promisc_ifaces"
    fi
fi

# Detect processes holding raw packet sockets (AF_PACKET / SOCK_RAW)
log_info "Scanning for processes utilizing raw sockets (packet sniffers)..."
SNIFFER_PIDS=()

if command -v ss >/dev/null 2>&1; then
    while IFS= read -r pid; do
        if [ -n "$pid" ] && [ "$pid" -gt 1 ]; then
            SNIFFER_PIDS+=("$pid")
        fi
    done < <(ss -0 -p 2>/dev/null | grep -oP 'pid=\K[0-9]+' || true)
fi

# ------------------------------------------------------------------------------
# 2. Hunt for Heisenberg Process Signatures
# ------------------------------------------------------------------------------
# Heisenberg characteristics:
# - Golang binary linked with libpcap
# - Contains strings: "gopacket", "REBORN", "/bin/evil", "SHELL", "CMD "
# - Default payload binary path: /bin/evil

for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir##*/}"
    [ -d "$pid_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    exe=$(readlink -f "$pid_dir/exe" 2>/dev/null || true)
    cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)

    is_heisenberg=false

    if [[ "$cmdline" =~ "heisenberg" || "$exe" =~ "heisenberg" ]]; then
        is_heisenberg=true
    elif [ -f "$exe" ]; then
        # Check binary strings for Heisenberg specific constants
        # const INTERFACE = "eth0"; const IMPLANT_PATH = "/bin/evil"
        # commands: REBORN, SHELL, CMD
        if strings -n 6 "$exe" 2>/dev/null | grep -E "(/bin/evil|handlePayload|gopacket/layers)" >/dev/null 2>&1; then
            is_heisenberg=true
        fi
    fi

    if [ "$is_heisenberg" = true ]; then
        log_alert "CRITICAL: Detected Heisenberg ICMP backdoor PID $pid -> $cmdline ($exe)"
        cp -a "$exe" "$BACKUP_DIR/heisenberg_binary_${pid}.bin" 2>/dev/null || true
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Killed Heisenberg process PID $pid"

        if [ -f "$exe" ] && [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm|root|home|opt)/ ]]; then
            rm -f "$exe"
            log_pass "Removed executable: $exe"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 3. Check and Remove Default Secondary Implant (/bin/evil)
# ------------------------------------------------------------------------------
if [ -f "/bin/evil" ]; then
    log_alert "CRITICAL: Found default Heisenberg restart payload at /bin/evil"
    cp -a "/bin/evil" "$BACKUP_DIR/"
    rm -f "/bin/evil"
    log_pass "Quarantined and deleted /bin/evil"
fi

# ------------------------------------------------------------------------------
# 4. Filter / Rate-Limit ICMP Echo Requests (Firewall Hardening)
# ------------------------------------------------------------------------------
log_info "Hardening ICMP traffic via iptables..."
if command -v iptables >/dev/null 2>&1; then
    # Drop abnormal ICMP payloads or rate limit ping requests
    # Heisenberg requires ICMP Echo Requests with payload containing "CMD", "SHELL", or "REBORN"
    for trigger_str in "REBORN" "SHELL" "CMD "; do
        if ! iptables -C INPUT -p icmp --icmp-type echo-request -m string --string "$trigger_str" --algo bm -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -p icmp --icmp-type echo-request -m string --string "$trigger_str" --algo bm -j DROP 2>/dev/null || true
            log_pass "Configured iptables rule to drop ICMP packets matching payload '$trigger_str'"
        fi
    done
fi

log_pass "Heisenberg remediation and ICMP defense complete."
