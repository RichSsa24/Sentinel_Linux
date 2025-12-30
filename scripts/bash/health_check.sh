#!/usr/bin/env bash
#
# Health check script for Linux Security Monitor
#
# Verifies that all components are functioning correctly.
# Returns 0 if healthy, non-zero otherwise.
#
# Usage:
#   ./health_check.sh [options]
#
# Options:
#   -v, --verbose    Show detailed output
#   -q, --quiet      Only show errors
#   -j, --json       Output in JSON format
#

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh" 2>/dev/null || true
source "${SCRIPT_DIR}/lib/colors.sh" 2>/dev/null || true

# Configuration
INSTALL_DIR="${LSM_INSTALL_DIR:-/opt/linux-security-monitor}"
CONFIG_DIR="${LSM_CONFIG_DIR:-/etc/linux-security-monitor}"
LOG_DIR="${LSM_LOG_DIR:-/var/log/linux-security-monitor}"
DATA_DIR="${LSM_DATA_DIR:-/var/lib/linux-security-monitor}"
PID_FILE="/var/run/linux-security-monitor.pid"

# Output settings
VERBOSE=false
QUIET=false
JSON_OUTPUT=false

# Colors (fallback if colors.sh not loaded)
RED="${RED:-\033[0;31m}"
GREEN="${GREEN:-\033[0;32m}"
YELLOW="${YELLOW:-\033[0;33m}"
NC="${NC:-\033[0m}"

# Health status
declare -A HEALTH_CHECKS
OVERALL_STATUS="healthy"

usage() {
    cat << EOF
Linux Security Monitor Health Check

Usage: $(basename "$0") [options]

Options:
    -v, --verbose    Show detailed output
    -q, --quiet      Only show errors
    -j, --json       Output in JSON format
    -h, --help       Show this help message

Exit Codes:
    0   All checks passed
    1   One or more checks failed
    2   Critical failure
EOF
}

log_check() {
    local name="$1"
    local status="$2"
    local message="${3:-}"

    HEALTH_CHECKS["$name"]="$status"

    if [[ "$status" == "failed" || "$status" == "critical" ]]; then
        OVERALL_STATUS="unhealthy"
    elif [[ "$status" == "warning" && "$OVERALL_STATUS" == "healthy" ]]; then
        OVERALL_STATUS="degraded"
    fi

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        return
    fi

    if [[ "$QUIET" == "true" && "$status" == "passed" ]]; then
        return
    fi

    local color="$NC"
    local symbol="?"
    case "$status" in
        passed)   color="$GREEN"; symbol="+" ;;
        warning)  color="$YELLOW"; symbol="!" ;;
        failed)   color="$RED"; symbol="x" ;;
        critical) color="$RED"; symbol="X" ;;
    esac

    echo -e "[${color}${symbol}${NC}] ${name}: ${message:-$status}"
}

check_installation() {
    if [[ -d "$INSTALL_DIR" ]]; then
        log_check "Installation directory" "passed" "$INSTALL_DIR exists"
    else
        log_check "Installation directory" "failed" "$INSTALL_DIR not found"
        return 1
    fi

    if [[ -f "$INSTALL_DIR/venv/bin/python" ]]; then
        log_check "Python environment" "passed" "Virtual environment exists"
    else
        log_check "Python environment" "failed" "Virtual environment not found"
        return 1
    fi

    return 0
}

check_configuration() {
    local config_file="$CONFIG_DIR/config.yaml"

    if [[ -f "$config_file" ]]; then
        log_check "Configuration file" "passed" "$config_file exists"
    else
        log_check "Configuration file" "warning" "Using default configuration"
        return 0
    fi

    # Validate config syntax
    if command -v python3 &>/dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$config_file'))" 2>/dev/null; then
            log_check "Configuration syntax" "passed" "Valid YAML"
        else
            log_check "Configuration syntax" "failed" "Invalid YAML syntax"
            return 1
        fi
    fi

    return 0
}

check_directories() {
    local dirs=("$LOG_DIR" "$DATA_DIR" "$CONFIG_DIR")
    local all_ok=true

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            if [[ -w "$dir" ]]; then
                [[ "$VERBOSE" == "true" ]] && log_check "Directory $dir" "passed" "Exists and writable"
            else
                log_check "Directory $dir" "warning" "Exists but not writable"
            fi
        else
            log_check "Directory $dir" "warning" "Does not exist"
        fi
    done

    log_check "Required directories" "passed" "Checked"
    return 0
}

check_process() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null)

        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log_check "Monitor process" "passed" "Running (PID: $pid)"
            return 0
        else
            log_check "Monitor process" "warning" "Stale PID file (process not running)"
            return 1
        fi
    fi

    # Check via systemd
    if systemctl is-active --quiet linux-security-monitor 2>/dev/null; then
        log_check "Monitor process" "passed" "Running via systemd"
        return 0
    fi

    # Check via pgrep
    if pgrep -f "linux-security-monitor" &>/dev/null; then
        log_check "Monitor process" "passed" "Running"
        return 0
    fi

    log_check "Monitor process" "warning" "Not running"
    return 1
}

check_log_file() {
    local log_file="$LOG_DIR/monitor.log"

    if [[ -f "$log_file" ]]; then
        local age_seconds
        age_seconds=$(( $(date +%s) - $(stat -c %Y "$log_file" 2>/dev/null || stat -f %m "$log_file" 2>/dev/null) ))

        if [[ $age_seconds -lt 300 ]]; then
            log_check "Log file" "passed" "Recently updated (${age_seconds}s ago)"
        elif [[ $age_seconds -lt 3600 ]]; then
            log_check "Log file" "warning" "Not updated in $((age_seconds / 60)) minutes"
        else
            log_check "Log file" "warning" "Not updated in $((age_seconds / 3600)) hours"
        fi
    else
        log_check "Log file" "warning" "Log file not found"
    fi

    return 0
}

check_disk_space() {
    local min_space_mb=100

    for dir in "$LOG_DIR" "$DATA_DIR"; do
        if [[ -d "$dir" ]]; then
            local available_mb
            available_mb=$(df -m "$dir" 2>/dev/null | awk 'NR==2 {print $4}')

            if [[ -n "$available_mb" ]]; then
                if [[ $available_mb -lt $min_space_mb ]]; then
                    log_check "Disk space ($dir)" "warning" "${available_mb}MB available"
                else
                    [[ "$VERBOSE" == "true" ]] && log_check "Disk space ($dir)" "passed" "${available_mb}MB available"
                fi
            fi
        fi
    done

    log_check "Disk space" "passed" "Sufficient"
    return 0
}

check_python_deps() {
    local python="$INSTALL_DIR/venv/bin/python"

    if [[ ! -x "$python" ]]; then
        log_check "Python dependencies" "failed" "Python not found"
        return 1
    fi

    # Check critical imports
    local deps=("yaml" "psutil" "pydantic" "click")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! "$python" -c "import $dep" 2>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_check "Python dependencies" "passed" "All required packages installed"
    else
        log_check "Python dependencies" "failed" "Missing: ${missing[*]}"
        return 1
    fi

    return 0
}

check_permissions() {
    # Check auth.log readability
    local auth_logs=("/var/log/auth.log" "/var/log/secure")

    for log in "${auth_logs[@]}"; do
        if [[ -f "$log" ]]; then
            if [[ -r "$log" ]]; then
                log_check "Auth log access" "passed" "Can read $log"
                break
            else
                log_check "Auth log access" "warning" "Cannot read $log (may need root)"
            fi
        fi
    done

    return 0
}

output_json() {
    echo "{"
    echo "  \"status\": \"$OVERALL_STATUS\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"checks\": {"

    local first=true
    for check in "${!HEALTH_CHECKS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        printf "    \"%s\": \"%s\"" "$check" "${HEALTH_CHECKS[$check]}"
    done

    echo ""
    echo "  }"
    echo "}"
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose) VERBOSE=true; shift ;;
            -q|--quiet)   QUIET=true; shift ;;
            -j|--json)    JSON_OUTPUT=true; shift ;;
            -h|--help)    usage; exit 0 ;;
            *)            echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    [[ "$JSON_OUTPUT" != "true" && "$QUIET" != "true" ]] && echo "Linux Security Monitor Health Check"
    [[ "$JSON_OUTPUT" != "true" && "$QUIET" != "true" ]] && echo "===================================="
    [[ "$JSON_OUTPUT" != "true" && "$QUIET" != "true" ]] && echo ""

    # Run checks
    check_installation || true
    check_configuration || true
    check_directories || true
    check_process || true
    check_log_file || true
    check_disk_space || true
    check_python_deps || true
    check_permissions || true

    # Output results
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        output_json
    else
        echo ""
        echo -n "Overall Status: "
        case "$OVERALL_STATUS" in
            healthy)   echo -e "${GREEN}HEALTHY${NC}" ;;
            degraded)  echo -e "${YELLOW}DEGRADED${NC}" ;;
            unhealthy) echo -e "${RED}UNHEALTHY${NC}" ;;
        esac
    fi

    # Exit code based on status
    case "$OVERALL_STATUS" in
        healthy)   exit 0 ;;
        degraded)  exit 0 ;;
        unhealthy) exit 1 ;;
    esac
}

main "$@"

