#!/usr/bin/env bash
#
# Script: user_audit.sh
# Description: User account and privilege auditing
# Version: 1.0.0
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

audit_passwd() {
    log_section "User Account Analysis"

    # Count users
    local total_users
    total_users=$(wc -l < /etc/passwd)
    print_table_row "Total accounts" "${total_users}"

    # System vs regular users
    local system_users regular_users
    system_users=$(awk -F: '$3 < 1000 {count++} END {print count}' /etc/passwd)
    regular_users=$(awk -F: '$3 >= 1000 {count++} END {print count}' /etc/passwd)
    print_table_row "System accounts" "${system_users}"
    print_table_row "Regular accounts" "${regular_users}"

    # Users with login shell
    log_subsection "Users with Login Shell"
    awk -F: '$7 !~ /nologin|false/ && $7 != "" {print $1 " -> " $7}' /etc/passwd

    # UID 0 accounts
    log_subsection "Accounts with UID 0"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
}

audit_groups() {
    log_section "Group Analysis"

    # Privileged groups
    log_subsection "Privileged Group Members"

    local priv_groups=("wheel" "sudo" "admin" "root" "adm")
    for grp in "${priv_groups[@]}"; do
        local members
        members=$(getent group "${grp}" 2>/dev/null | cut -d: -f4)
        if [[ -n "${members}" ]]; then
            print_table_row "${grp}" "${members}"
        fi
    done
}

audit_sudo() {
    log_section "Sudo Configuration"

    # sudoers file
    if [[ -r /etc/sudoers ]]; then
        log_subsection "Sudoers Rules (non-comment)"
        grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | head -20
    fi

    # sudoers.d
    if [[ -d /etc/sudoers.d ]]; then
        log_subsection "Files in sudoers.d"
        ls -la /etc/sudoers.d/ 2>/dev/null
    fi
}

audit_login_history() {
    log_section "Login History"

    log_subsection "Last 20 Logins"
    last -n 20 2>/dev/null | head -22

    log_subsection "Failed Login Attempts"
    lastb -n 10 2>/dev/null || echo "No failed logins recorded or insufficient permissions"
}

main() {
    require_root

    echo "=============================================="
    echo "  User Account Audit"
    echo "=============================================="
    echo "Host: $(get_hostname)"
    echo "Date: $(get_timestamp)"
    echo ""

    audit_passwd
    audit_groups
    audit_sudo
    audit_login_history
}

main "$@"



