#!/usr/bin/env bash
#
# Script: system_audit.sh
# Description: Comprehensive system security audit
# Version: 1.0.0
#
# Usage:
#   ./system_audit.sh [options]
#
# Options:
#   -h, --help     Show this help message
#   -o, --output   Output file path
#   -f, --format   Output format (text, json)
#   -q, --quick    Quick mode (skip slow checks)
#

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
OUTPUT_FILE=""
OUTPUT_FORMAT="text"
QUICK_MODE=false

# Common functions
command_exists() {
    command -v "$1" &>/dev/null
}

get_hostname() {
    hostname 2>/dev/null || echo "unknown"
}

get_os_release() {
    if [[ -f /etc/os-release ]]; then
        grep "^PRETTY_NAME=" /etc/os-release | cut -d'"' -f2 || echo "Unknown"
    elif [[ -f /etc/redhat-release ]]; then
        cat /etc/redhat-release
    else
        echo "Unknown"
    fi
}

get_kernel_version() {
    uname -r
}

get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

get_service_status() {
    local service="$1"
    if command_exists systemctl; then
        systemctl is-active "$service" 2>/dev/null || echo "not-found"
    elif command_exists service; then
        service "$service" status &>/dev/null && echo "running" || echo "stopped"
    else
        echo "unknown"
    fi
}

log_section() {
    echo ""
    echo "=== $1 ==="
}

log_subsection() {
    echo ""
    echo "--- $1 ---"
}

log_result() {
    local name="$1"
    local status="$2"
    local message="$3"
    case "$status" in
        OK)   echo "[OK]   $name: $message" ;;
        WARN) echo "[WARN] $name: $message" ;;
        FAIL) echo "[FAIL] $name: $message" ;;
        INFO) echo "[INFO] $name: $message" ;;
        SKIP) echo "[SKIP] $name: $message" ;;
        *)    echo "[$status] $name: $message" ;;
    esac
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_warning() {
    echo "[WARN] $1"
}

print_table_row() {
    printf "  %-20s %s\n" "$1:" "$2"
}

show_help() {
    cat << 'EOF'
System Security Audit Script

Usage: ./system_audit.sh [options]

Options:
  -h, --help      Show this help message
  -o, --output    Output file path
  -f, --format    Output format (text, json)
  -q, --quick     Quick mode (skip slow checks)

Examples:
  ./system_audit.sh                    # Full audit to stdout
  ./system_audit.sh -o report.txt      # Save to file
  ./system_audit.sh -q                 # Quick audit
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

audit_system_info() {
    log_section "System Information"

    print_table_row "Hostname" "$(get_hostname)"
    print_table_row "OS" "$(get_os_release)"
    print_table_row "Kernel" "$(get_kernel_version)"
    print_table_row "Architecture" "$(uname -m)"
    print_table_row "Uptime" "$(uptime -p 2>/dev/null || uptime)"
    print_table_row "Date" "$(date)"

    # Boot time
    if command_exists last; then
        local last_boot
        last_boot=$(last reboot -1 2>/dev/null | head -1 | awk '{print $5, $6, $7, $8}')
        print_table_row "Last Boot" "${last_boot:-Unknown}"
    fi
}

audit_users() {
    log_section "User Accounts"

    # Root account check
    local root_shells
    root_shells=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [[ -n "${root_shells}" ]]; then
        log_result "UID 0 accounts" "FAIL" "Non-root users with UID 0: ${root_shells}"
    else
        log_result "UID 0 accounts" "OK" "Only root has UID 0"
    fi

    # Users with empty passwords
    if [[ -r /etc/shadow ]]; then
        local empty_pass
        empty_pass=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") && $1 != "root" {print $1}' /etc/shadow | head -5)
        if [[ -n "${empty_pass}" ]]; then
            log_result "Empty passwords" "WARN" "Users: ${empty_pass}"
        else
            log_result "Empty passwords" "OK" "No empty passwords"
        fi
    fi

    # Currently logged in users
    log_subsection "Logged In Users"
    who 2>/dev/null || echo "Unable to determine"

    # Recent logins
    log_subsection "Recent Logins (last 10)"
    last -n 10 2>/dev/null | head -12 || echo "Unable to retrieve"
}

audit_ssh() {
    log_section "SSH Configuration"

    local ssh_config="/etc/ssh/sshd_config"

    if [[ ! -f "${ssh_config}" ]]; then
        log_result "SSH Configuration" "SKIP" "sshd_config not found"
        return
    fi

    # Check key settings
    local permit_root
    permit_root=$(grep -i "^PermitRootLogin" "${ssh_config}" 2>/dev/null | awk '{print $2}')
    if [[ "${permit_root}" == "no" ]]; then
        log_result "PermitRootLogin" "OK" "Disabled"
    elif [[ "${permit_root}" == "prohibit-password" || "${permit_root}" == "without-password" ]]; then
        log_result "PermitRootLogin" "OK" "Key-only"
    else
        log_result "PermitRootLogin" "WARN" "${permit_root:-yes (default)}"
    fi

    local password_auth
    password_auth=$(grep -i "^PasswordAuthentication" "${ssh_config}" 2>/dev/null | awk '{print $2}')
    if [[ "${password_auth}" == "no" ]]; then
        log_result "PasswordAuthentication" "OK" "Disabled"
    else
        log_result "PasswordAuthentication" "INFO" "${password_auth:-yes (default)}"
    fi

    local permit_empty
    permit_empty=$(grep -i "^PermitEmptyPasswords" "${ssh_config}" 2>/dev/null | awk '{print $2}')
    if [[ "${permit_empty}" == "yes" ]]; then
        log_result "PermitEmptyPasswords" "FAIL" "Enabled"
    else
        log_result "PermitEmptyPasswords" "OK" "Disabled"
    fi
}

audit_network() {
    log_section "Network Configuration"

    # Listening ports
    log_subsection "Listening Ports"
    if command_exists ss; then
        ss -tulnp 2>/dev/null | head -20
    elif command_exists netstat; then
        netstat -tulnp 2>/dev/null | head -20
    fi

    # Active connections
    log_subsection "Established Connections"
    if command_exists ss; then
        ss -tunp state established 2>/dev/null | head -15
    fi

    # Firewall status
    log_subsection "Firewall Status"
    if command_exists firewall-cmd; then
        firewall-cmd --state 2>/dev/null || echo "firewalld not running"
    elif command_exists ufw; then
        ufw status 2>/dev/null || echo "ufw not active"
    elif command_exists iptables; then
        iptables -L -n 2>/dev/null | head -20 || echo "Cannot read iptables"
    else
        echo "No firewall detected"
    fi
}

audit_services() {
    log_section "Services"

    # Running services
    log_subsection "Running Services"
    if command_exists systemctl; then
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -25
    fi

    # Critical services check
    log_subsection "Critical Services Status"
    local critical_services=("sshd" "auditd" "rsyslog" "firewalld")

    for svc in "${critical_services[@]}"; do
        local status
        status=$(get_service_status "${svc}")
        case "${status}" in
            running)
                log_result "${svc}" "OK" "Running"
                ;;
            stopped)
                log_result "${svc}" "WARN" "Stopped"
                ;;
            *)
                log_result "${svc}" "INFO" "${status}"
                ;;
        esac
    done
}

audit_processes() {
    log_section "Process Analysis"

    # High CPU processes
    log_subsection "Top CPU Processes"
    ps aux --sort=-%cpu 2>/dev/null | head -10

    # Processes running from /tmp or /dev/shm
    log_subsection "Processes from Suspicious Paths"
    local suspicious
    suspicious=$(find /proc/*/exe -type l 2>/dev/null | \
        xargs -I{} readlink {} 2>/dev/null | \
        grep -E "^(/tmp|/dev/shm|/var/tmp)" || true)

    if [[ -n "${suspicious}" ]]; then
        log_result "Suspicious paths" "WARN" "Found: ${suspicious}"
    else
        log_result "Suspicious paths" "OK" "None found"
    fi
}

audit_filesystem() {
    log_section "File System Security"

    # World-writable files (quick sample)
    if [[ "${QUICK_MODE}" != "true" ]]; then
        log_subsection "World-Writable Files (sample)"
        find /etc /usr -type f -perm -0002 2>/dev/null | head -10 || echo "None found in /etc, /usr"
    fi

    # SUID/SGID files
    log_subsection "SUID Files (common locations)"
    find /usr/bin /usr/sbin /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -15

    # Disk usage
    log_subsection "Disk Usage"
    df -h 2>/dev/null | head -10
}

audit_logs() {
    log_section "Log Analysis"

    # Auth failures
    log_subsection "Recent Auth Failures"
    local auth_log
    for log in /var/log/auth.log /var/log/secure; do
        if [[ -r "${log}" ]]; then
            auth_log="${log}"
            break
        fi
    done

    if [[ -n "${auth_log:-}" ]]; then
        grep -i "failed" "${auth_log}" 2>/dev/null | tail -10 || echo "No failures found"
    else
        echo "Auth log not readable"
    fi

    # Recent sudo usage
    log_subsection "Recent Sudo Usage"
    if [[ -n "${auth_log:-}" ]]; then
        grep "sudo" "${auth_log}" 2>/dev/null | tail -10 || echo "No sudo activity"
    fi
}

generate_summary() {
    log_section "Audit Summary"

    echo "Audit completed at: $(get_timestamp)"
    echo "Host: $(get_hostname)"
    echo ""
    echo "Review the sections above for security findings."
    echo "Items marked [FAIL] or [WARN] require attention."
}

main() {
    parse_args "$@"

    if [[ $EUID -ne 0 ]]; then
        log_warning "Running without root - some checks will be limited"
    fi

    # Header
    echo "=============================================="
    echo "  Linux Security Monitor - System Audit"
    echo "=============================================="
    echo "Started: $(get_timestamp)"
    echo ""

    # Run audits
    audit_system_info
    audit_users
    audit_ssh
    audit_network
    audit_services
    audit_processes
    audit_filesystem
    audit_logs
    generate_summary
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ -n "${OUTPUT_FILE:-}" ]]; then
        main "$@" | tee "${OUTPUT_FILE}"
    else
        main "$@"
    fi
fi



