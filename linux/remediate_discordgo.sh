#!/usr/bin/env bash
# ==============================================================================
# MINICOP Blue Team Remediation & Detection: c0unts/DiscordGo
# Targets: Fedora, Debian, Ubuntu
# Repository: https://github.com/c0unts/DiscordGo
# Threat: Discord-based C2 agent executing remote reverse shells & commands
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

BACKUP_DIR="/var/backups/blueteam-remediation/discordgo-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory initialized at ${BACKUP_DIR}"

# ------------------------------------------------------------------------------
# 1. Detect & Terminate Processes Communicating with Discord API or Gateway
# ------------------------------------------------------------------------------
log_info "Scanning for active connections to Discord API/Gateway (TCP 443 / discord.com / discordapp.com)..."

# Find sockets connecting to Discord IPs or ports via ss or netstat
DISCORD_PIDS=()

if command -v ss >/dev/null 2>&1; then
    while IFS= read -r pid; do
        if [ -n "$pid" ] && [ "$pid" -gt 1 ]; then
            DISCORD_PIDS+=("$pid")
        fi
    done < <(ss -tp state established '( dport = :https or dport = :http )' 2>/dev/null | grep -iE "discord" | grep -oP 'pid=\K[0-9]+' || true)
fi

# Fallback: inspect /proc for processes holding strings 'discordgo' or 'letredin' or communicating to discord.gg
for proc_dir in /proc/[0-9]*; do
    pid="${proc_dir##*/}"
    [ -d "$proc_dir" ] || continue
    [ "$pid" -eq $$ ] && continue

    cmdline=$(tr '\0' ' ' < "$proc_dir/cmdline" 2>/dev/null || true)
    exe=$(readlink -f "$proc_dir/exe" 2>/dev/null || true)

    # Check for DiscordGo signatures in binary / memory strings
    if [[ "$cmdline" =~ "DiscordGo" || "$cmdline" =~ "discordgo" || "$exe" =~ "DiscordGo" ]]; then
        log_alert "Detected DiscordGo by commandline/path: PID $pid -> $cmdline ($exe)"
        DISCORD_PIDS+=("$pid")
    elif [ -f "$proc_dir/environ" ]; then
        if grep -q "letredin" "$proc_dir/environ" 2>/dev/null; then
            log_alert "Detected DiscordGo environment signature in PID $pid"
            DISCORD_PIDS+=("$pid")
        fi
    fi
done

# Deduplicate PIDs
readarray -t UNIQUE_DISCORD_PIDS < <(printf '%s\n' "${DISCORD_PIDS[@]:-}" | sort -u | grep -v '^$' || true)

for pid in "${UNIQUE_DISCORD_PIDS[@]}"; do
    if [ -d "/proc/$pid" ]; then
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
        log_alert "Killing DiscordGo process PID $pid: $cmd"
        if [ -f "$exe" ]; then
            cp -a "$exe" "$BACKUP_DIR/discordgo_binary_${pid}.bin" 2>/dev/null || true
            log_info "Preserved binary to $BACKUP_DIR/discordgo_binary_${pid}.bin"
        fi
        kill -9 "$pid" 2>/dev/null || true
        log_pass "Killed PID $pid"
        if [ -f "$exe" ] && [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm|home|opt|usr/local)/ ]]; then
            log_warn "Deleting implant executable: $exe"
            rm -f "$exe"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 2. Inspect Artifacts Dropped in /tmp
# ------------------------------------------------------------------------------
log_info "Cleaning DiscordGo temporary artifacts in /tmp..."
# DiscordGo writes:
# - /tmp/*_<width>x<height>.png (screenshots)
# - /tmp/discordstat.txt (organizer stats)
find /tmp /var/tmp -maxdepth 2 -type f -name "*_[0-9]*x[0-9]*.png" 2>/dev/null | while read -r img; do
    log_alert "Found DiscordGo screenshot file: $img"
    cp -a "$img" "$BACKUP_DIR/"
    rm -f "$img"
    log_pass "Quarantined and removed screenshot: $img"
done

if [ -f "/tmp/discordstat.txt" ]; then
    log_alert "Found DiscordGo organizer file: /tmp/discordstat.txt"
    cp -a "/tmp/discordstat.txt" "$BACKUP_DIR/"
    rm -f "/tmp/discordstat.txt"
    log_pass "Removed /tmp/discordstat.txt"
fi

# ------------------------------------------------------------------------------
# 3. Network Outbound Filtering / Egress Blocking for Discord API
# ------------------------------------------------------------------------------
log_info "Configuring network controls to block unauthorized Discord bot egress..."
if command -v iptables >/dev/null 2>&1; then
    # Block outbound connections to discord.com / discordapp.com endpoints
    # Check if rule already exists
    if ! iptables -C OUTPUT -p tcp -m string --string "discord.com" --algo bm -j REJECT 2>/dev/null; then
        iptables -I OUTPUT 1 -p tcp -m string --string "discord.com" --algo bm -j REJECT 2>/dev/null || true
        log_pass "Added iptables rule blocking discord.com traffic string"
    fi
    if ! iptables -C OUTPUT -p tcp -m string --string "discordapp.com" --algo bm -j REJECT 2>/dev/null; then
        iptables -I OUTPUT 1 -p tcp -m string --string "discordapp.com" --algo bm -j REJECT 2>/dev/null || true
        log_pass "Added iptables rule blocking discordapp.com traffic string"
    fi
fi

# Sinkhole discord domains in /etc/hosts as defense-in-depth
SINKHOLE_DOMAINS=(
    "discord.com"
    "discordapp.com"
    "gateway.discord.gg"
    "status.discord.com"
    "cdn.discordapp.com"
)

log_info "Sinkholing Discord bot domains in /etc/hosts..."
for domain in "${SINKHOLE_DOMAINS[@]}"; do
    if ! grep -qw "$domain" /etc/hosts; then
        echo "127.0.0.1 $domain" >> /etc/hosts
        log_pass "Added 127.0.0.1 $domain to /etc/hosts"
    fi
done

log_pass "DiscordGo remediation and blocking complete."
