#!/usr/bin/env bash
#
# Log Analyzer Script
#
# Analyzes system logs for security-relevant events.
#
# Usage:
#   ./log_analyzer.sh [options]
#
# Options:
#   -t, --time HOURS   Analyze logs from last N hours (default: 24)
#   -f, --file FILE    Analyze specific log file
#   -s, --summary      Show summary only
#   -j, --json         Output in JSON format
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
TIME_HOURS=24
LOG_FILE=""
SUMMARY_ONLY=false
JSON_OUTPUT=false

# Counters
declare -A EVENT_COUNTS

usage() {
    cat << EOF
Log Analyzer - Security Event Detection

Usage: $(basename "$0") [options]

Options:
    -t, --time HOURS   Analyze logs from last N hours (default: 24)
    -f, --file FILE    Analyze specific log file
    -s, --summary      Show summary only
    -j, --json         Output in JSON format
    -h, --help         Show this help message

Analyzed events:
    - Failed SSH logins
    - Successful SSH logins
    - Sudo usage
    - Authentication failures
    - Service changes
    - Suspicious commands

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--time)     TIME_HOURS="$2"; shift 2 ;;
            -f|--file)     LOG_FILE="$2"; shift 2 ;;
            -s|--summary)  SUMMARY_ONLY=true; shift ;;
            -j|--json)     JSON_OUTPUT=true; shift ;;
            -h|--help)     usage; exit 0 ;;
            *)             echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

find_auth_log() {
    local logs=("/var/log/auth.log" "/var/log/secure" "/var/log/messages")

    for log in "${logs[@]}"; do
        if [[ -r "$log" ]]; then
            echo "$log"
            return
        fi
    done

    echo ""
}

get_recent_logs() {
    local log_file="$1"
    local hours="$2"

    if [[ ! -r "$log_file" ]]; then
        return
    fi

    # Get logs from last N hours
    local since_date
    since_date=$(date -d "$hours hours ago" '+%b %e' 2>/dev/null || date -v-${hours}H '+%b %e' 2>/dev/null || echo "")

    if [[ -n "$since_date" ]]; then
        # Try to filter by date (works for syslog format)
        grep -E "^${since_date}" "$log_file" 2>/dev/null || cat "$log_file"
    else
        # Fallback: return all logs
        cat "$log_file"
    fi
}

count_event() {
    local event="$1"
    EVENT_COUNTS["$event"]=$(( ${EVENT_COUNTS["$event"]:-0} + 1 ))
}

analyze_ssh_failures() {
    local log_file="$1"
    local failures

    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}SSH Failed Logins${NC}"
    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "=================="

    failures=$(grep -c "Failed password\|Failed publickey\|Invalid user" "$log_file" 2>/dev/null || echo "0")
    EVENT_COUNTS["ssh_failures"]=$failures

    if [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]]; then
        if [[ $failures -gt 0 ]]; then
            echo "Total failures: $failures"
            echo ""
            echo "Top source IPs:"
            grep -oP "from \K[\d.]+" "$log_file" 2>/dev/null | \
                grep -v "^$" | sort | uniq -c | sort -rn | head -10 | \
                while read -r count ip; do
                    printf "  %-15s : %d attempts\n" "$ip" "$count"
                done

            echo ""
            echo "Top failed usernames:"
            grep -oP "(Failed password for|Invalid user) \K\w+" "$log_file" 2>/dev/null | \
                sort | uniq -c | sort -rn | head -10 | \
                while read -r count user; do
                    printf "  %-15s : %d attempts\n" "$user" "$count"
                done
        else
            echo "No failed SSH logins found"
        fi
    fi
}

analyze_ssh_success() {
    local log_file="$1"
    local successes

    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}SSH Successful Logins${NC}"
    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "====================="

    successes=$(grep -c "Accepted password\|Accepted publickey" "$log_file" 2>/dev/null || echo "0")
    EVENT_COUNTS["ssh_successes"]=$successes

    if [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]]; then
        if [[ $successes -gt 0 ]]; then
            echo "Total successful logins: $successes"
            echo ""
            grep -E "Accepted (password|publickey)" "$log_file" 2>/dev/null | \
                tail -10 | while read -r line; do
                    local user ip
                    user=$(echo "$line" | grep -oP "for \K\w+")
                    ip=$(echo "$line" | grep -oP "from \K[\d.]+")
                    local time
                    time=$(echo "$line" | awk '{print $1, $2, $3}')
                    printf "  %s - User: %-12s from %s\n" "$time" "$user" "$ip"
                done
        else
            echo "No successful SSH logins found"
        fi
    fi
}

analyze_sudo_usage() {
    local log_file="$1"
    local sudo_count

    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Sudo Usage${NC}"
    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "=========="

    sudo_count=$(grep -c "sudo:" "$log_file" 2>/dev/null || echo "0")
    EVENT_COUNTS["sudo_usage"]=$sudo_count

    if [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]]; then
        if [[ $sudo_count -gt 0 ]]; then
            echo "Total sudo events: $sudo_count"
            echo ""
            echo "Users using sudo:"
            grep "sudo:" "$log_file" 2>/dev/null | \
                grep -oP "sudo:\s+\K\w+" | sort | uniq -c | sort -rn | \
                while read -r count user; do
                    printf "  %-15s : %d commands\n" "$user" "$count"
                done

            echo ""
            echo "Recent sudo commands:"
            grep "COMMAND=" "$log_file" 2>/dev/null | tail -5 | \
                while read -r line; do
                    local user cmd
                    user=$(echo "$line" | grep -oP "sudo:\s+\K\w+")
                    cmd=$(echo "$line" | grep -oP "COMMAND=\K.*" | cut -c1-60)
                    printf "  %s : %s\n" "$user" "$cmd"
                done
        else
            echo "No sudo usage found"
        fi
    fi
}

analyze_auth_failures() {
    local log_file="$1"
    local failures

    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Authentication Failures${NC}"
    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "========================"

    failures=$(grep -c "authentication failure\|auth.*fail" "$log_file" 2>/dev/null || echo "0")
    EVENT_COUNTS["auth_failures"]=$failures

    if [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]]; then
        echo "Total authentication failures: $failures"

        if [[ $failures -gt 0 ]]; then
            echo ""
            echo "Failure types:"
            grep -oP "pam_\w+\([^)]+\)" "$log_file" 2>/dev/null | \
                sort | uniq -c | sort -rn | head -5 | \
                while read -r count type; do
                    printf "  %-30s : %d\n" "$type" "$count"
                done
        fi
    fi
}

analyze_service_changes() {
    local log_file="$1"

    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Service Changes${NC}"
    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "==============="

    if command -v journalctl &>/dev/null; then
        local started stopped
        started=$(journalctl --since "$TIME_HOURS hours ago" 2>/dev/null | grep -c "Started " || echo "0")
        stopped=$(journalctl --since "$TIME_HOURS hours ago" 2>/dev/null | grep -c "Stopped " || echo "0")

        EVENT_COUNTS["services_started"]=$started
        EVENT_COUNTS["services_stopped"]=$stopped

        if [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]]; then
            echo "Services started: $started"
            echo "Services stopped: $stopped"
        fi
    else
        [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "(journalctl not available)"
    fi
}

analyze_suspicious_patterns() {
    local log_file="$1"

    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Suspicious Patterns${NC}"
    [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "==================="

    local patterns=(
        "BREAK-IN ATTEMPT"
        "POSSIBLE BREAK"
        "refused connect"
        "Did not receive"
        "Bad protocol"
        "Connection closed by"
        "maximum authentication"
    )

    local total=0

    for pattern in "${patterns[@]}"; do
        local count
        count=$(grep -c "$pattern" "$log_file" 2>/dev/null || echo "0")
        if [[ $count -gt 0 ]]; then
            [[ "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]] && echo "  $pattern: $count"
            total=$((total + count))
        fi
    done

    EVENT_COUNTS["suspicious_patterns"]=$total

    if [[ $total -eq 0 && "$SUMMARY_ONLY" != "true" && "$JSON_OUTPUT" != "true" ]]; then
        echo "  No suspicious patterns detected"
    fi
}

print_summary() {
    echo ""
    echo -e "${CYAN}Summary${NC}"
    echo "======="
    echo "Time range: Last $TIME_HOURS hours"
    echo ""
    printf "%-25s : %s\n" "SSH failures" "${EVENT_COUNTS[ssh_failures]:-0}"
    printf "%-25s : %s\n" "SSH successes" "${EVENT_COUNTS[ssh_successes]:-0}"
    printf "%-25s : %s\n" "Sudo events" "${EVENT_COUNTS[sudo_usage]:-0}"
    printf "%-25s : %s\n" "Auth failures" "${EVENT_COUNTS[auth_failures]:-0}"
    printf "%-25s : %s\n" "Suspicious patterns" "${EVENT_COUNTS[suspicious_patterns]:-0}"

    # Calculate risk score
    local risk_score=0
    [[ ${EVENT_COUNTS[ssh_failures]:-0} -gt 100 ]] && risk_score=$((risk_score + 3))
    [[ ${EVENT_COUNTS[ssh_failures]:-0} -gt 10 ]] && risk_score=$((risk_score + 1))
    [[ ${EVENT_COUNTS[auth_failures]:-0} -gt 50 ]] && risk_score=$((risk_score + 2))
    [[ ${EVENT_COUNTS[suspicious_patterns]:-0} -gt 0 ]] && risk_score=$((risk_score + 2))

    echo ""
    echo -n "Risk Assessment: "
    if [[ $risk_score -eq 0 ]]; then
        echo -e "${GREEN}LOW${NC}"
    elif [[ $risk_score -lt 3 ]]; then
        echo -e "${YELLOW}MEDIUM${NC}"
    else
        echo -e "${RED}HIGH${NC}"
    fi
}

output_json() {
    cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "time_range_hours": $TIME_HOURS,
  "events": {
    "ssh_failures": ${EVENT_COUNTS[ssh_failures]:-0},
    "ssh_successes": ${EVENT_COUNTS[ssh_successes]:-0},
    "sudo_usage": ${EVENT_COUNTS[sudo_usage]:-0},
    "auth_failures": ${EVENT_COUNTS[auth_failures]:-0},
    "suspicious_patterns": ${EVENT_COUNTS[suspicious_patterns]:-0}
  }
}
EOF
}

main() {
    parse_args "$@"

    # Find log file
    if [[ -z "$LOG_FILE" ]]; then
        LOG_FILE=$(find_auth_log)
    fi

    if [[ -z "$LOG_FILE" || ! -r "$LOG_FILE" ]]; then
        echo "Error: Cannot read auth log file" >&2
        echo "Try running with sudo or specify a file with -f" >&2
        exit 1
    fi

    # Create temp file with recent logs
    local temp_log
    temp_log=$(mktemp) || {
        log_error "Failed to create temporary file"
        exit 1
    }
    # Ensure cleanup on exit
    trap "rm -f '${temp_log}'" EXIT INT TERM
    trap "rm -f $temp_log" EXIT

    get_recent_logs "$LOG_FILE" "$TIME_HOURS" > "$temp_log"

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        echo "Log Analyzer"
        echo "============"
        echo "Host: $(hostname)"
        echo "Log file: $LOG_FILE"
        echo "Time range: Last $TIME_HOURS hours"
    fi

    # Run analyses
    analyze_ssh_failures "$temp_log"
    analyze_ssh_success "$temp_log"
    analyze_sudo_usage "$temp_log"
    analyze_auth_failures "$temp_log"
    analyze_service_changes "$temp_log"
    analyze_suspicious_patterns "$temp_log"

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        output_json
    else
        print_summary
    fi
}

main "$@"

