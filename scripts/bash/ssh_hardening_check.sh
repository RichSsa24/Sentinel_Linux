#!/usr/bin/env bash
#
# Script: ssh_hardening_check.sh
# Description: SSH configuration security audit
# Version: 1.0.0
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

SSH_CONFIG="${1:-/etc/ssh/sshd_config}"

check_setting() {
    local setting="$1"
    local expected="$2"
    local severity="${3:-WARN}"

    local actual
    actual=$(grep -i "^${setting}" "${SSH_CONFIG}" 2>/dev/null | awk '{print $2}' | head -1)

    if [[ "${actual,,}" == "${expected,,}" ]]; then
        log_result "${setting}" "OK" "${actual}"
    else
        log_result "${setting}" "${severity}" "${actual:-not set} (expected: ${expected})"
    fi
}

main() {
    echo "=============================================="
    echo "  SSH Hardening Check"
    echo "=============================================="
    echo "Config: ${SSH_CONFIG}"
    echo ""

    if [[ ! -f "${SSH_CONFIG}" ]]; then
        log_error "SSH config not found: ${SSH_CONFIG}"
        exit 1
    fi

    log_section "Security Settings"

    check_setting "PermitRootLogin" "no" "WARN"
    check_setting "PasswordAuthentication" "no" "INFO"
    check_setting "PermitEmptyPasswords" "no" "FAIL"
    check_setting "X11Forwarding" "no" "INFO"
    check_setting "MaxAuthTries" "3" "INFO"
    check_setting "Protocol" "2" "FAIL"
    check_setting "UsePAM" "yes" "INFO"
    check_setting "AllowAgentForwarding" "no" "INFO"
    check_setting "AllowTcpForwarding" "no" "INFO"

    log_section "Key Exchange and Ciphers"

    local kex_algos
    kex_algos=$(grep -i "^KexAlgorithms" "${SSH_CONFIG}" 2>/dev/null || echo "default")
    print_table_row "KexAlgorithms" "${kex_algos}"

    local ciphers
    ciphers=$(grep -i "^Ciphers" "${SSH_CONFIG}" 2>/dev/null || echo "default")
    print_table_row "Ciphers" "${ciphers}"

    log_section "Summary"
    echo "Review settings marked [WARN] or [FAIL] for hardening opportunities."
}

main "$@"



