#!/usr/bin/env bash
#
# Cron Job Security Auditor
#
# Audits scheduled tasks for security issues.
#
# Usage:
#   ./cron_auditor.sh [options]
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

# Counters
ISSUES=0
WARNINGS=0

usage() {
    cat << EOF
Cron Job Security Auditor

Usage: $(basename "$0") [options]

Options:
    -v, --verbose    Show all cron entries
    -j, --json       Output in JSON format
    -h, --help       Show this help message

Checks performed:
    - System crontabs (/etc/crontab, /etc/cron.d/*)
    - User crontabs (/var/spool/cron/*)
    - Cron directories (/etc/cron.{hourly,daily,weekly,monthly})
    - Suspicious commands in cron jobs
    - World-writable cron files
    - Cron jobs running as root

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

    if [[ "$severity" == "high" || "$severity" == "medium" ]]; then
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

check_file_permissions() {
    local file="$1"
    local expected="$2"

    if [[ ! -e "$file" ]]; then
        return
    fi

    local actual
    actual=$(stat -c %a "$file" 2>/dev/null || echo "?")

    # Check for world-writable
    if [[ "$actual" == *7 || "$actual" == *6 || "$actual" == *3 || "$actual" == *2 ]]; then
        log_issue "high" "World-writable: $file (perms: $actual)"
        return 1
    fi

    return 0
}

analyze_cron_entry() {
    local entry="$1"
    local source="$2"

    # Skip comments and empty lines
    [[ "$entry" =~ ^[[:space:]]*# ]] && return
    [[ -z "${entry// /}" ]] && return

    # Suspicious patterns
    local suspicious_patterns=(
        "wget\|curl.*\|"          # Downloads
        "bash -c"                  # Bash execution
        "sh -c"                    # Shell execution
        "python.*-c"               # Python one-liners
        "perl.*-e"                 # Perl one-liners
        "nc\s\|netcat\|ncat"      # Netcat
        "base64"                   # Base64 encoding
        "eval"                     # Eval statements
        "/dev/tcp"                 # Bash TCP
        ">/dev/null.*2>&1"         # Hidden output
        "rm -rf /"                 # Dangerous deletion
    )

    for pattern in "${suspicious_patterns[@]}"; do
        if echo "$entry" | grep -qE "$pattern"; then
            log_issue "medium" "Suspicious pattern in $source: $pattern"
            [[ "$VERBOSE" == "true" ]] && echo "         Entry: ${entry:0:80}..."
        fi
    done

    # Check for root execution
    if [[ "$entry" =~ ^[0-9\*].*root ]]; then
        [[ "$VERBOSE" == "true" ]] && log_issue "low" "Root cron job in $source"
    fi
}

check_system_crontab() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}System Crontab (/etc/crontab)${NC}"

    if [[ -f /etc/crontab ]]; then
        check_file_permissions /etc/crontab 644

        while IFS= read -r line; do
            analyze_cron_entry "$line" "/etc/crontab"
            [[ "$VERBOSE" == "true" && -n "$line" && ! "$line" =~ ^# ]] && echo "  $line"
        done < /etc/crontab
    else
        [[ "$JSON_OUTPUT" != "true" ]] && echo "  /etc/crontab not found"
    fi
}

check_cron_d() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Cron.d Directory (/etc/cron.d/)${NC}"

    if [[ -d /etc/cron.d ]]; then
        for file in /etc/cron.d/*; do
            [[ ! -f "$file" ]] && continue

            local filename
            filename=$(basename "$file")

            check_file_permissions "$file" 644

            [[ "$VERBOSE" == "true" ]] && echo "  File: $filename"

            while IFS= read -r line; do
                analyze_cron_entry "$line" "$file"
            done < "$file"
        done
    else
        [[ "$JSON_OUTPUT" != "true" ]] && echo "  /etc/cron.d not found"
    fi
}

check_user_crontabs() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}User Crontabs${NC}"

    local crontab_dirs=("/var/spool/cron/crontabs" "/var/spool/cron")

    for dir in "${crontab_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue

        for file in "$dir"/*; do
            [[ ! -f "$file" ]] && continue

            local user
            user=$(basename "$file")

            [[ "$JSON_OUTPUT" != "true" ]] && echo "  User: $user"

            # Check permissions
            local perms
            perms=$(stat -c %a "$file" 2>/dev/null || echo "?")
            if [[ "$perms" != "600" ]]; then
                log_issue "medium" "Crontab permissions for $user: $perms (should be 600)"
            fi

            while IFS= read -r line; do
                analyze_cron_entry "$line" "$file"
                [[ "$VERBOSE" == "true" && -n "$line" && ! "$line" =~ ^# ]] && echo "    $line"
            done < "$file"
        done
    done
}

check_cron_directories() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Cron Directories${NC}"

    local dirs=("hourly" "daily" "weekly" "monthly")

    for period in "${dirs[@]}"; do
        local dir="/etc/cron.$period"

        if [[ -d "$dir" ]]; then
            local count
            count=$(find "$dir" -type f -executable 2>/dev/null | wc -l)

            [[ "$JSON_OUTPUT" != "true" ]] && echo "  /etc/cron.$period: $count scripts"

            # Check directory permissions
            check_file_permissions "$dir" 755

            # Check each script
            for script in "$dir"/*; do
                [[ ! -f "$script" ]] && continue

                check_file_permissions "$script" 755

                # Check for suspicious content
                if [[ -r "$script" ]]; then
                    while IFS= read -r line; do
                        analyze_cron_entry "$line" "$script"
                    done < "$script"
                fi
            done
        fi
    done
}

check_at_jobs() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}AT Jobs${NC}"

    if command -v atq &>/dev/null; then
        local at_jobs
        at_jobs=$(atq 2>/dev/null | wc -l)

        [[ "$JSON_OUTPUT" != "true" ]] && echo "  Pending AT jobs: $at_jobs"

        if [[ $at_jobs -gt 0 ]]; then
            [[ "$VERBOSE" == "true" ]] && atq 2>/dev/null | while read -r line; do
                echo "    $line"
            done
        fi
    else
        [[ "$JSON_OUTPUT" != "true" ]] && echo "  AT command not available"
    fi
}

check_systemd_timers() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Systemd Timers${NC}"

    if command -v systemctl &>/dev/null; then
        local timer_count
        timer_count=$(systemctl list-timers --all --no-legend 2>/dev/null | wc -l)

        [[ "$JSON_OUTPUT" != "true" ]] && echo "  Active timers: $timer_count"

        if [[ "$VERBOSE" == "true" ]]; then
            systemctl list-timers --all --no-legend 2>/dev/null | head -10 | while read -r line; do
                echo "    $line"
            done
        fi

        # Check for user timers
        for user_dir in /home/*/.config/systemd/user/; do
            [[ ! -d "$user_dir" ]] && continue

            local user
            user=$(echo "$user_dir" | cut -d/ -f3)

            local user_timers
            user_timers=$(find "$user_dir" -name "*.timer" 2>/dev/null | wc -l)

            if [[ $user_timers -gt 0 ]]; then
                [[ "$JSON_OUTPUT" != "true" ]] && echo "  User $user has $user_timers custom timer(s)"
            fi
        done
    fi
}

check_anacron() {
    [[ "$JSON_OUTPUT" != "true" ]] && echo -e "\n${CYAN}Anacron${NC}"

    if [[ -f /etc/anacrontab ]]; then
        check_file_permissions /etc/anacrontab 644

        local entries
        entries=$(grep -v "^#" /etc/anacrontab 2>/dev/null | grep -v "^$" | wc -l)
        [[ "$JSON_OUTPUT" != "true" ]] && echo "  Anacron entries: $entries"

        if [[ "$VERBOSE" == "true" ]]; then
            grep -v "^#" /etc/anacrontab 2>/dev/null | grep -v "^$" | while read -r line; do
                echo "    $line"
            done
        fi
    else
        [[ "$JSON_OUTPUT" != "true" ]] && echo "  Anacron not configured"
    fi
}

print_summary() {
    echo ""
    echo "Summary"
    echo "======="
    echo -e "Issues found:   ${RED}$ISSUES${NC}"
    echo -e "Warnings:       ${YELLOW}$WARNINGS${NC}"

    if [[ $ISSUES -gt 0 ]]; then
        echo ""
        echo -e "${RED}Security issues detected in scheduled tasks. Review immediately.${NC}"
    elif [[ $WARNINGS -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Some warnings detected. Review recommended.${NC}"
    else
        echo ""
        echo -e "${GREEN}No critical issues found in scheduled tasks.${NC}"
    fi
}

main() {
    parse_args "$@"

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        echo "Cron Job Security Auditor"
        echo "========================="
        echo "Host: $(hostname)"
        echo "Date: $(date)"
    fi

    check_system_crontab
    check_cron_d
    check_user_crontabs
    check_cron_directories
    check_at_jobs
    check_systemd_timers
    check_anacron

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        print_summary
    fi

    [[ $ISSUES -gt 0 ]] && exit 1
    exit 0
}

main "$@"

