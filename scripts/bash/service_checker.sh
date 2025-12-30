#!/usr/bin/env bash
#
# Service Status Checker
#
# Monitors system services and identifies security-relevant changes.
#
# Usage:
#   ./service_checker.sh [options]
#
# Options:
#   -c, --critical    Only show critical services
#   -a, --all         Show all services
#   -j, --json        Output in JSON format
#   -h, --help        Show help
#

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Critical services to monitor
CRITICAL_SERVICES=(
    "sshd"
    "ssh"
    "firewalld"
    "ufw"
    "iptables"
    "auditd"
    "rsyslog"
    "systemd-journald"
    "fail2ban"
    "apparmor"
    "selinux"
)

# Options
SHOW_ALL=false
CRITICAL_ONLY=false
JSON_OUTPUT=false

usage() {
    cat << EOF
Service Status Checker

Usage: $(basename "$0") [options]

Options:
    -c, --critical    Only show critical security services
    -a, --all         Show all services
    -j, --json        Output in JSON format
    -h, --help        Show this help message

Critical services monitored:
    sshd, firewalld, ufw, auditd, rsyslog, fail2ban, apparmor

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--critical) CRITICAL_ONLY=true; shift ;;
            -a|--all)      SHOW_ALL=true; shift ;;
            -j|--json)     JSON_OUTPUT=true; shift ;;
            -h|--help)     usage; exit 0 ;;
            *)             echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

check_service_systemd() {
    local service="$1"
    local status

    if systemctl is-active --quiet "$service" 2>/dev/null; then
        status="running"
    elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
        status="stopped"
    elif systemctl list-unit-files "$service.service" &>/dev/null; then
        status="disabled"
    else
        status="not_installed"
    fi

    echo "$status"
}

check_service_sysv() {
    local service="$1"

    if [[ -f "/etc/init.d/$service" ]]; then
        if service "$service" status &>/dev/null; then
            echo "running"
        else
            echo "stopped"
        fi
    else
        echo "not_installed"
    fi
}

get_service_status() {
    local service="$1"
    local status

    # Try systemd first
    if command -v systemctl &>/dev/null; then
        status=$(check_service_systemd "$service")
    else
        status=$(check_service_sysv "$service")
    fi

    echo "$status"
}

print_service_status() {
    local service="$1"
    local status="$2"
    local is_critical="$3"

    local status_color="$NC"
    local status_symbol="?"

    case "$status" in
        running)       status_color="$GREEN"; status_symbol="+" ;;
        stopped)       status_color="$RED"; status_symbol="-" ;;
        disabled)      status_color="$YELLOW"; status_symbol="!" ;;
        not_installed) status_color="$BLUE"; status_symbol="~" ;;
    esac

    local critical_marker=""
    [[ "$is_critical" == "true" ]] && critical_marker=" [CRITICAL]"

    printf "[%b%s%b] %-25s %b%-12s%b%s\n" \
        "$status_color" "$status_symbol" "$NC" \
        "$service" \
        "$status_color" "$status" "$NC" \
        "$critical_marker"
}

check_critical_services() {
    echo "Critical Security Services"
    echo "=========================="
    echo ""

    local issues=0

    for service in "${CRITICAL_SERVICES[@]}"; do
        local status
        status=$(get_service_status "$service")

        if [[ "$status" != "not_installed" ]]; then
            print_service_status "$service" "$status" "true"

            if [[ "$status" == "stopped" || "$status" == "disabled" ]]; then
                ((issues++)) || true
            fi
        fi
    done

    echo ""
    if [[ $issues -gt 0 ]]; then
        echo -e "${YELLOW}Warning: $issues critical service(s) not running${NC}"
    else
        echo -e "${GREEN}All installed critical services are running${NC}"
    fi
}

check_all_services() {
    echo "All System Services"
    echo "==================="
    echo ""

    local running=0
    local stopped=0
    local disabled=0

    while IFS= read -r service; do
        local status
        status=$(get_service_status "$service")

        local is_critical="false"
        for cs in "${CRITICAL_SERVICES[@]}"; do
            if [[ "$service" == "$cs" || "$service" == "${cs}.service" ]]; then
                is_critical="true"
                break
            fi
        done

        print_service_status "$service" "$status" "$is_critical"

        case "$status" in
            running) ((running++)) || true ;;
            stopped) ((stopped++)) || true ;;
            disabled) ((disabled++)) || true ;;
        esac
    done < <(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//')

    echo ""
    echo "Summary: $running running, $stopped stopped, $disabled disabled"
}

check_listening_services() {
    echo ""
    echo "Network-Listening Services"
    echo "=========================="
    echo ""

    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | tail -n +2 | while read -r line; do
            local port proto process
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            process=$(echo "$line" | awk '{print $NF}' | grep -oP '\"[^\"]+\"' | tr -d '"' || echo "unknown")

            printf "  Port %-6s : %s\n" "$port" "$process"
        done
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | tail -n +3 | while read -r line; do
            local port process
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            process=$(echo "$line" | awk '{print $NF}' | cut -d/ -f2 || echo "unknown")

            printf "  Port %-6s : %s\n" "$port" "$process"
        done
    else
        echo "  (ss/netstat not available)"
    fi
}

check_recent_service_changes() {
    echo ""
    echo "Recent Service Changes (last 24h)"
    echo "=================================="
    echo ""

    if command -v journalctl &>/dev/null; then
        journalctl --since "24 hours ago" -u "*.service" --no-pager -q 2>/dev/null | \
            grep -E "(Started|Stopped|Failed)" | \
            tail -20 || echo "  No recent changes found"
    else
        echo "  (journalctl not available)"
    fi
}

output_json() {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"services\": {"

    local first=true
    for service in "${CRITICAL_SERVICES[@]}"; do
        local status
        status=$(get_service_status "$service")

        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        printf "    \"%s\": \"%s\"" "$service" "$status"
    done

    echo ""
    echo "  }"
    echo "}"
}

main() {
    parse_args "$@"

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        output_json
        exit 0
    fi

    echo "Service Status Checker"
    echo "======================"
    echo "Host: $(hostname)"
    echo "Date: $(date)"
    echo ""

    if [[ "$CRITICAL_ONLY" == "true" ]]; then
        check_critical_services
    elif [[ "$SHOW_ALL" == "true" ]]; then
        check_all_services
    else
        check_critical_services
        check_listening_services
        check_recent_service_changes
    fi
}

main "$@"

