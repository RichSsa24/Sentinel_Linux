#!/usr/bin/env bash
#
# Suspicious Process Hunter
#
# Detects potentially malicious or suspicious processes.
#
# Usage:
#   ./process_hunter.sh [options]
#
# Options:
#   -v, --verbose    Show detailed information
#   -j, --json       Output in JSON format
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
VERBOSE=false
JSON_OUTPUT=false

# Suspicious indicators
SUSPICIOUS_NAMES=(
    "nc" "ncat" "netcat"
    "nmap" "masscan" "zmap"
    "tcpdump" "wireshark" "tshark"
    "hydra" "medusa" "john"
    "hashcat" "aircrack"
    "mimikatz" "meterpreter"
    "bind" "reverse" "shell"
    "cryptominer" "xmrig" "minerd"
    "wget" "curl"  # When running without terminal
)

SUSPICIOUS_PATHS=(
    "/tmp"
    "/dev/shm"
    "/var/tmp"
    "/home/*/\."
    "/run/user"
)

# Results
declare -a FINDINGS

usage() {
    cat << EOF
Suspicious Process Hunter

Usage: $(basename "$0") [options]

Options:
    -v, --verbose    Show detailed process information
    -j, --json       Output in JSON format
    -h, --help       Show this help message

Detection criteria:
    - Known hacking/pentesting tools
    - Processes running from suspicious paths (/tmp, /dev/shm)
    - Hidden processes (names starting with .)
    - Processes with deleted executables
    - Cryptocurrency miners
    - Processes with suspicious network connections

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

add_finding() {
    local severity="$1"
    local category="$2"
    local pid="$3"
    local name="$4"
    local details="$5"

    FINDINGS+=("{\"severity\": \"$severity\", \"category\": \"$category\", \"pid\": $pid, \"name\": \"$name\", \"details\": \"$details\"}")

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        local color="$NC"
        case "$severity" in
            high)     color="$RED" ;;
            medium)   color="$YELLOW" ;;
            low)      color="$CYAN" ;;
        esac
        echo -e "[${color}${severity^^}${NC}] $category: $name (PID: $pid)"
        [[ "$VERBOSE" == "true" ]] && echo "         Details: $details"
    fi
}

check_suspicious_names() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for suspicious process names...${NC}"

    for name in "${SUSPICIOUS_NAMES[@]}"; do
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue

            local pid pname
            pid=$(echo "$line" | awk '{print $1}')
            pname=$(echo "$line" | awk '{print $2}')

            # Skip if it's just the grep process
            [[ "$pname" == "grep" ]] && continue

            local exe
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")

            add_finding "high" "Suspicious Tool" "$pid" "$pname" "Executable: $exe"
        done < <(ps aux 2>/dev/null | grep -i "$name" | grep -v grep | awk '{print $2, $11}')
    done
}

check_suspicious_paths() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for processes running from suspicious paths...${NC}"

    while IFS= read -r pid; do
        [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue

        local exe
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || continue)

        for path in "${SUSPICIOUS_PATHS[@]}"; do
            if [[ "$exe" == $path* ]]; then
                local name
                name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
                local user
                user=$(ps -o user= -p "$pid" 2>/dev/null || echo "unknown")

                add_finding "high" "Suspicious Path" "$pid" "$name" "Running from: $exe (User: $user)"
                break
            fi
        done
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')
}

check_deleted_executables() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for processes with deleted executables...${NC}"

    while IFS= read -r pid; do
        [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue

        local exe
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || continue)

        if [[ "$exe" == *"(deleted)"* ]]; then
            local name
            name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
            local user
            user=$(ps -o user= -p "$pid" 2>/dev/null || echo "unknown")

            add_finding "high" "Deleted Executable" "$pid" "$name" "Original path: $exe (User: $user)"
        fi
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')
}

check_hidden_processes() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for hidden processes...${NC}"

    while IFS= read -r pid; do
        [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue

        local name
        name=$(cat "/proc/$pid/comm" 2>/dev/null || continue)

        # Check for names starting with .
        if [[ "$name" == .* ]]; then
            local exe user
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
            user=$(ps -o user= -p "$pid" 2>/dev/null || echo "unknown")

            add_finding "medium" "Hidden Process" "$pid" "$name" "Executable: $exe (User: $user)"
        fi
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')
}

check_high_cpu_processes() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for high CPU usage processes...${NC}"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local cpu pid user name
        cpu=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        user=$(echo "$line" | awk '{print $3}')
        name=$(echo "$line" | awk '{print $11}')

        # Check if CPU > 80%
        if (( $(echo "$cpu > 80" | bc -l 2>/dev/null || echo 0) )); then
            local exe
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")

            add_finding "medium" "High CPU Usage" "$pid" "$name" "CPU: ${cpu}% (User: $user, Exe: $exe)"
        fi
    done < <(ps aux --sort=-%cpu 2>/dev/null | tail -n +2 | head -20)
}

check_network_processes() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking processes with network connections...${NC}"

    if ! command -v ss &>/dev/null && ! command -v netstat &>/dev/null; then
        [[ "$JSON_OUTPUT" != "true" ]] && echo "  (ss/netstat not available)"
        return
    fi

    # Check for processes listening on unusual ports
    local unusual_ports=()

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local port pid name
        if command -v ss &>/dev/null; then
            port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
            pid=$(echo "$line" | grep -oP 'pid=\K\d+' || echo "0")
        else
            port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
            pid=$(echo "$line" | awk '{print $7}' | cut -d/ -f1)
        fi

        [[ -z "$pid" || "$pid" == "0" ]] && continue

        name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")

        # Check for high ports (common for backdoors)
        if [[ "$port" =~ ^[0-9]+$ ]] && [[ $port -gt 10000 ]]; then
            add_finding "low" "High Port Listener" "$pid" "$name" "Listening on port $port"
        fi
    done < <(ss -tlnp 2>/dev/null | tail -n +2 || netstat -tlnp 2>/dev/null | tail -n +3)
}

check_crypto_miners() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for cryptocurrency miners...${NC}"

    local miner_signatures=(
        "stratum"
        "pool."
        "mining"
        "xmr"
        "monero"
        "bitcoin"
        "ethereum"
    )

    # Check process command lines
    for pid in /proc/[0-9]*/; do
        pid="${pid%/}"
        pid="${pid##*/}"

        [[ ! -d "/proc/$pid" ]] && continue

        local cmdline
        cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || continue)

        for sig in "${miner_signatures[@]}"; do
            if [[ "$cmdline" == *"$sig"* ]]; then
                local name
                name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")

                add_finding "high" "Crypto Miner" "$pid" "$name" "Signature: $sig in cmdline"
                break
            fi
        done
    done
}

check_reverse_shells() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Checking for potential reverse shells...${NC}"

    # Look for bash/sh with network connections
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local pid name
        pid=$(echo "$line" | awk '{print $2}')
        name=$(echo "$line" | awk '{print $11}')

        # Check if this shell has network file descriptors
        if ls -la "/proc/$pid/fd" 2>/dev/null | grep -q "socket:"; then
            local user
            user=$(ps -o user= -p "$pid" 2>/dev/null || echo "unknown")

            add_finding "high" "Potential Reverse Shell" "$pid" "$name" "Shell process with network socket (User: $user)"
        fi
    done < <(ps aux 2>/dev/null | grep -E '\s(bash|sh|dash|zsh)\s*$' | grep -v grep)
}

print_summary() {
    local high=0 medium=0 low=0

    for finding in "${FINDINGS[@]}"; do
        case "$finding" in
            *'"severity": "high"'*)   ((high++)) || true ;;
            *'"severity": "medium"'*) ((medium++)) || true ;;
            *'"severity": "low"'*)    ((low++)) || true ;;
        esac
    done

    echo ""
    echo "Summary"
    echo "======="
    echo -e "High severity:   ${RED}$high${NC}"
    echo -e "Medium severity: ${YELLOW}$medium${NC}"
    echo -e "Low severity:    ${CYAN}$low${NC}"
    echo ""

    if [[ $high -gt 0 ]]; then
        echo -e "${RED}ALERT: High severity findings detected! Investigate immediately.${NC}"
    elif [[ $medium -gt 0 ]]; then
        echo -e "${YELLOW}Warning: Medium severity findings require attention.${NC}"
    else
        echo -e "${GREEN}No critical suspicious processes detected.${NC}"
    fi
}

output_json() {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"findings\": ["

    local first=true
    for finding in "${FINDINGS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        echo "    $finding"
    done

    echo ""
    echo "  ]"
    echo "}"
}

main() {
    parse_args "$@"

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        echo "Suspicious Process Hunter"
        echo "========================="
        echo "Host: $(hostname)"
        echo "Date: $(date)"
    fi

    check_suspicious_names
    check_suspicious_paths
    check_deleted_executables
    check_hidden_processes
    check_high_cpu_processes
    check_network_processes
    check_crypto_miners
    check_reverse_shells

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        output_json
    else
        print_summary
    fi

    # Exit with error if high severity findings
    for finding in "${FINDINGS[@]}"; do
        [[ "$finding" == *'"severity": "high"'* ]] && exit 1
    done

    exit 0
}

main "$@"

