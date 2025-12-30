#!/usr/bin/env bash
#
# Firewall Rules Auditor
#
# Audits firewall configuration for security issues.
#
# Usage:
#   ./firewall_audit.sh [options]
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
JSON_OUTPUT=false
VERBOSE=false

# Results
FIREWALL_TYPE=""
ISSUES=0
WARNINGS=0

usage() {
    cat << EOF
Firewall Rules Auditor

Usage: $(basename "$0") [options]

Options:
    -v, --verbose    Show all rules
    -j, --json       Output in JSON format
    -h, --help       Show this help message

Supported firewalls:
    - iptables/nftables
    - firewalld
    - ufw
    - nftables

Checks performed:
    - Firewall status (enabled/disabled)
    - Default policies
    - Open ports
    - Overly permissive rules
    - Missing essential rules

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose) VERBOSE=true; shift ;;
            -j|--json)    JSON_OUTPUT=true; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

log_issue() {
    local severity="$1"
    local message="$2"

    if [[ "$severity" == "high" ]]; then
        ((ISSUES++)) || true
    else
        ((WARNINGS++)) || true
    fi

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        local color="$NC"
        case "$severity" in
            high)   color="$RED" ;;
            medium) color="$YELLOW" ;;
            low)    color="$CYAN" ;;
        esac
        echo -e "  [${color}${severity^^}${NC}] $message"
    fi
}

detect_firewall() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "${CYAN}Detecting firewall type...${NC}"

    # Check for firewalld
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL_TYPE="firewalld"
        return
    fi

    # Check for ufw
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_TYPE="ufw"
        return
    fi

    # Check for nftables
    if command -v nft &>/dev/null && nft list ruleset &>/dev/null 2>&1; then
        local rules
        rules=$(nft list ruleset 2>/dev/null | wc -l)
        if [[ $rules -gt 0 ]]; then
            FIREWALL_TYPE="nftables"
            return
        fi
    fi

    # Check for iptables
    if command -v iptables &>/dev/null; then
        local rules
        rules=$(iptables -L -n 2>/dev/null | wc -l)
        if [[ $rules -gt 3 ]]; then
            FIREWALL_TYPE="iptables"
            return
        fi
    fi

    FIREWALL_TYPE="none"
}

audit_iptables() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}iptables Configuration${NC}"

    # Check default policies
    echo "  Default Policies:"
    for chain in INPUT FORWARD OUTPUT; do
        local policy
        policy=$(iptables -L "$chain" -n 2>/dev/null | head -1 | grep -oP '\(policy \K\w+' || echo "?")
        echo "    $chain: $policy"

        if [[ "$chain" == "INPUT" && "$policy" == "ACCEPT" ]]; then
            log_issue "high" "INPUT chain has permissive default policy (ACCEPT)"
        fi
        if [[ "$chain" == "FORWARD" && "$policy" == "ACCEPT" ]]; then
            log_issue "medium" "FORWARD chain has permissive default policy (ACCEPT)"
        fi
    done

    # Count rules
    echo ""
    echo "  Rule Counts:"
    for chain in INPUT FORWARD OUTPUT; do
        local count
        count=$(iptables -L "$chain" -n 2>/dev/null | tail -n +3 | wc -l)
        echo "    $chain: $count rules"
    done

    # Check for overly permissive rules
    echo ""
    echo "  Security Analysis:"

    # Check for ACCEPT all from anywhere
    if iptables -L INPUT -n 2>/dev/null | grep -q "ACCEPT.*0.0.0.0/0.*0.0.0.0/0"; then
        log_issue "high" "Found rule accepting all traffic from anywhere"
    fi

    # List open ports
    echo ""
    echo "  Open Ports (ACCEPT rules):"
    iptables -L INPUT -n 2>/dev/null | grep ACCEPT | while read -r line; do
        local port
        port=$(echo "$line" | grep -oP 'dpt:\K\d+' || echo "")
        [[ -n "$port" ]] && echo "    Port $port"
    done

    # Show all rules if verbose
    if [[ "$VERBOSE" == "true" ]]; then
        echo ""
        echo "  All INPUT Rules:"
        iptables -L INPUT -n -v 2>/dev/null | tail -n +3 | while read -r line; do
            echo "    $line"
        done
    fi
}

audit_firewalld() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}firewalld Configuration${NC}"

    # Check if running
    local state
    state=$(firewall-cmd --state 2>/dev/null || echo "not running")
    echo "  State: $state"

    if [[ "$state" != "running" ]]; then
        log_issue "high" "firewalld is not running"
        return
    fi

    # Get default zone
    local default_zone
    default_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
    echo "  Default Zone: $default_zone"

    # Get active zones
    echo "  Active Zones:"
    firewall-cmd --get-active-zones 2>/dev/null | while read -r line; do
        echo "    $line"
    done

    # List services and ports
    echo ""
    echo "  Open Services (default zone):"
    firewall-cmd --list-services 2>/dev/null | tr ' ' '\n' | while read -r service; do
        [[ -n "$service" ]] && echo "    $service"
    done

    echo ""
    echo "  Open Ports (default zone):"
    firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | while read -r port; do
        [[ -n "$port" ]] && echo "    $port"
    done

    # Check for permissive settings
    if firewall-cmd --list-all 2>/dev/null | grep -q "target: ACCEPT"; then
        log_issue "medium" "Zone target is ACCEPT (permissive)"
    fi

    # Check rich rules
    local rich_rules
    rich_rules=$(firewall-cmd --list-rich-rules 2>/dev/null | wc -l)
    echo ""
    echo "  Rich Rules: $rich_rules"

    if [[ "$VERBOSE" == "true" && $rich_rules -gt 0 ]]; then
        firewall-cmd --list-rich-rules 2>/dev/null | while read -r rule; do
            echo "    $rule"
        done
    fi
}

audit_ufw() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}UFW Configuration${NC}"

    # Get status
    local status
    status=$(ufw status 2>/dev/null | head -1)
    echo "  $status"

    if echo "$status" | grep -q "inactive"; then
        log_issue "high" "UFW is inactive"
        return
    fi

    # Get default policies
    echo ""
    echo "  Default Policies:"
    ufw status verbose 2>/dev/null | grep "Default:" | while read -r line; do
        echo "    $line"

        if echo "$line" | grep -q "incoming.*allow"; then
            log_issue "high" "Default incoming policy is ALLOW"
        fi
    done

    # List rules
    echo ""
    echo "  Rules:"
    ufw status numbered 2>/dev/null | tail -n +5 | while read -r line; do
        [[ -n "$line" ]] && echo "    $line"

        # Check for overly permissive rules
        if echo "$line" | grep -q "Anywhere.*ALLOW.*Anywhere"; then
            log_issue "medium" "Found rule allowing traffic from anywhere to anywhere"
        fi
    done

    # Application profiles
    if [[ "$VERBOSE" == "true" ]]; then
        echo ""
        echo "  Application Profiles:"
        ufw app list 2>/dev/null | tail -n +2 | while read -r app; do
            echo "    $app"
        done
    fi
}

audit_nftables() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}nftables Configuration${NC}"

    # List tables
    echo "  Tables:"
    nft list tables 2>/dev/null | while read -r line; do
        echo "    $line"
    done

    # Count rules
    local rule_count
    rule_count=$(nft list ruleset 2>/dev/null | grep -c "^[[:space:]]*" || echo "0")
    echo ""
    echo "  Total rules: $rule_count"

    # Check for default drop policy
    if ! nft list ruleset 2>/dev/null | grep -q "policy drop"; then
        log_issue "medium" "No default DROP policy found"
    fi

    # Show ruleset if verbose
    if [[ "$VERBOSE" == "true" ]]; then
        echo ""
        echo "  Ruleset:"
        nft list ruleset 2>/dev/null | head -50 | while read -r line; do
            echo "    $line"
        done
    fi
}

check_listening_ports() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Listening Ports${NC}"

    if command -v ss &>/dev/null; then
        echo "  TCP Listeners:"
        ss -tlnp 2>/dev/null | tail -n +2 | while read -r line; do
            local addr port process
            addr=$(echo "$line" | awk '{print $4}')
            port=$(echo "$addr" | rev | cut -d: -f1 | rev)
            process=$(echo "$line" | awk '{print $NF}')

            printf "    %-6s %s\n" "$port" "$process"

            # Check for services listening on all interfaces
            if echo "$addr" | grep -qE "^0\.0\.0\.0:|^\*:|^\[::\]:"; then
                [[ $port -ne 22 ]] && log_issue "low" "Service on port $port listening on all interfaces"
            fi
        done
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | tail -n +3 | while read -r line; do
            echo "    $line"
        done
    fi
}

check_ip_forwarding() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}IP Forwarding${NC}"

    local ipv4_forward ipv6_forward

    ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
    ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "?")

    echo "  IPv4 forwarding: $ipv4_forward"
    echo "  IPv6 forwarding: $ipv6_forward"

    if [[ "$ipv4_forward" == "1" ]]; then
        log_issue "low" "IPv4 forwarding is enabled (may be intentional for routers/containers)"
    fi
}

print_summary() {
    echo ""
    echo "Summary"
    echo "======="
    echo "Firewall type: $FIREWALL_TYPE"
    echo -e "Issues:        ${RED}$ISSUES${NC}"
    echo -e "Warnings:      ${YELLOW}$WARNINGS${NC}"

    if [[ "$FIREWALL_TYPE" == "none" ]]; then
        echo ""
        echo -e "${RED}CRITICAL: No active firewall detected!${NC}"
        echo "Recommendation: Enable a firewall (ufw, firewalld, or iptables)"
    elif [[ $ISSUES -gt 0 ]]; then
        echo ""
        echo -e "${RED}Security issues detected. Review firewall configuration.${NC}"
    elif [[ $WARNINGS -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Some warnings detected. Review recommended.${NC}"
    else
        echo ""
        echo -e "${GREEN}Firewall configuration appears secure.${NC}"
    fi
}

main() {
    parse_args "$@"

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        echo "Firewall Rules Auditor"
        echo "======================"
        echo "Host: $(hostname)"
        echo "Date: $(date)"
        echo ""
    fi

    detect_firewall

    [[ "$JSON_OUTPUT" != "true" ]] && echo "  Detected: $FIREWALL_TYPE"

    case "$FIREWALL_TYPE" in
        iptables)  audit_iptables ;;
        firewalld) audit_firewalld ;;
        ufw)       audit_ufw ;;
        nftables)  audit_nftables ;;
        none)      log_issue "high" "No active firewall detected" ;;
    esac

    check_listening_ports
    check_ip_forwarding

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        print_summary
    fi

    [[ $ISSUES -gt 0 || "$FIREWALL_TYPE" == "none" ]] && exit 1
    exit 0
}

main "$@"

