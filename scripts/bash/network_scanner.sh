#!/usr/bin/env bash
#
# Script: network_scanner.sh
# Description: Network connection and port scanner
# Version: 1.0.0
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

SHOW_LISTENING=false
SHOW_ESTABLISHED=false
SHOW_ALL=true

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--listening) SHOW_LISTENING=true; SHOW_ALL=false; shift ;;
            -e|--established) SHOW_ESTABLISHED=true; SHOW_ALL=false; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) shift ;;
        esac
    done
}

show_help() {
    echo "Usage: $0 [options]"
    echo "  -l, --listening    Show listening ports only"
    echo "  -e, --established  Show established connections only"
}

scan_listeners() {
    log_section "Listening Ports"

    if command_exists ss; then
        ss -tulnp 2>/dev/null
    elif command_exists netstat; then
        netstat -tulnp 2>/dev/null
    else
        log_error "Neither ss nor netstat available"
    fi

    # Suspicious ports check
    log_subsection "Suspicious Port Check"
    local suspicious_ports="4444|5555|6666|6667|31337|12345"
    local found
    found=$(ss -tulnp 2>/dev/null | grep -E ":($suspicious_ports)" || true)

    if [[ -n "${found}" ]]; then
        log_result "Suspicious ports" "WARN" "Found potentially suspicious listeners"
        echo "${found}"
    else
        log_result "Suspicious ports" "OK" "None detected"
    fi
}

scan_established() {
    log_section "Established Connections"

    if command_exists ss; then
        ss -tunp state established 2>/dev/null
    elif command_exists netstat; then
        netstat -tunp 2>/dev/null | grep ESTABLISHED
    fi
}

scan_interfaces() {
    log_section "Network Interfaces"

    ip addr show 2>/dev/null || ifconfig 2>/dev/null
}

main() {
    parse_args "$@"

    echo "=============================================="
    echo "  Network Scanner"
    echo "=============================================="
    echo "Host: $(get_hostname)"
    echo "Date: $(get_timestamp)"
    echo ""

    scan_interfaces

    if [[ "${SHOW_ALL}" == "true" ]] || [[ "${SHOW_LISTENING}" == "true" ]]; then
        scan_listeners
    fi

    if [[ "${SHOW_ALL}" == "true" ]] || [[ "${SHOW_ESTABLISHED}" == "true" ]]; then
        scan_established
    fi
}

main "$@"



