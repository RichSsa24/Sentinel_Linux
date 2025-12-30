#!/usr/bin/env bash
#
# File Permission Security Auditor
#
# Checks file permissions for security issues.
#
# Usage:
#   ./permission_checker.sh [options]
#
# Options:
#   -d, --directory DIR   Check specific directory
#   -f, --fix             Attempt to fix issues (requires root)
#   -j, --json            Output in JSON format
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Options
CHECK_DIR=""
FIX_ISSUES=false
JSON_OUTPUT=false

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Results for JSON
declare -a RESULTS

usage() {
    cat << EOF
File Permission Security Auditor

Usage: $(basename "$0") [options]

Options:
    -d, --directory DIR   Check specific directory
    -f, --fix             Attempt to fix issues (requires root)
    -j, --json            Output in JSON format
    -h, --help            Show this help message

Checks performed:
    - Critical system file permissions
    - World-writable files
    - SUID/SGID binaries
    - Unowned files
    - SSH directory permissions

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--directory) CHECK_DIR="$2"; shift 2 ;;
            -f|--fix)       FIX_ISSUES=true; shift ;;
            -j|--json)      JSON_OUTPUT=true; shift ;;
            -h|--help)      usage; exit 0 ;;
            *)              echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

log_result() {
    local name="$1"
    local status="$2"
    local message="$3"

    case "$status" in
        pass)    ((PASSED++)) || true ;;
        fail)    ((FAILED++)) || true ;;
        warning) ((WARNINGS++)) || true ;;
    esac

    RESULTS+=("{\"check\": \"$name\", \"status\": \"$status\", \"message\": \"$message\"}")

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        local color="$NC"
        local symbol="?"
        case "$status" in
            pass)    color="$GREEN"; symbol="+" ;;
            fail)    color="$RED"; symbol="x" ;;
            warning) color="$YELLOW"; symbol="!" ;;
        esac
        echo -e "[${color}${symbol}${NC}] ${name}: ${message}"
    fi
}

check_file_perms() {
    local file="$1"
    local expected="$2"
    local name="$3"

    if [[ ! -e "$file" ]]; then
        log_result "$name" "warning" "File not found: $file"
        return
    fi

    local actual
    actual=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file" 2>/dev/null)

    if [[ "$actual" == "$expected" ]]; then
        log_result "$name" "pass" "Permissions correct ($actual)"
    else
        log_result "$name" "fail" "Permissions $actual, expected $expected"

        if [[ "$FIX_ISSUES" == "true" && $EUID -eq 0 ]]; then
            chmod "$expected" "$file"
            echo "    -> Fixed: chmod $expected $file"
        fi
    fi
}

check_critical_files() {
    echo "Critical System Files"
    echo "====================="

    # Check /etc/passwd
    check_file_perms "/etc/passwd" "644" "/etc/passwd permissions"

    # Check /etc/shadow
    check_file_perms "/etc/shadow" "640" "/etc/shadow permissions"

    # Check /etc/group
    check_file_perms "/etc/group" "644" "/etc/group permissions"

    # Check /etc/gshadow
    check_file_perms "/etc/gshadow" "640" "/etc/gshadow permissions"

    # Check /etc/sudoers
    check_file_perms "/etc/sudoers" "440" "/etc/sudoers permissions"

    # Check SSH config
    check_file_perms "/etc/ssh/sshd_config" "600" "/etc/ssh/sshd_config permissions"

    # Check crontab
    check_file_perms "/etc/crontab" "600" "/etc/crontab permissions"
}

check_world_writable() {
    echo ""
    echo "World-Writable Files"
    echo "===================="

    local dir="${CHECK_DIR:-/}"
    local excludes="-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o"

    local count=0
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        ((count++)) || true
        if [[ "$JSON_OUTPUT" != "true" && $count -le 20 ]]; then
            echo "  $file"
        fi
    done < <(find "$dir" $excludes -type f -perm -0002 -print 2>/dev/null | head -100)

    if [[ $count -eq 0 ]]; then
        log_result "World-writable files" "pass" "None found"
    elif [[ $count -le 10 ]]; then
        log_result "World-writable files" "warning" "Found $count files"
    else
        log_result "World-writable files" "fail" "Found $count files"
    fi
}

check_suid_sgid() {
    echo ""
    echo "SUID/SGID Binaries"
    echo "=================="

    # Known safe SUID binaries
    local known_suid=(
        "/usr/bin/passwd"
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/newgrp"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/gpasswd"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/ping"
        "/usr/sbin/unix_chkpwd"
    )

    local count=0
    local unknown=0

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        ((count++)) || true

        local is_known=false
        for known in "${known_suid[@]}"; do
            if [[ "$file" == "$known" ]]; then
                is_known=true
                break
            fi
        done

        if [[ "$is_known" != "true" ]]; then
            ((unknown++)) || true
            if [[ "$JSON_OUTPUT" != "true" ]]; then
                local perms owner
                perms=$(stat -c %a "$file" 2>/dev/null || echo "?")
                owner=$(stat -c %U "$file" 2>/dev/null || echo "?")
                echo "  [!] $file (perms: $perms, owner: $owner)"
            fi
        fi
    done < <(find /usr /bin /sbin -perm /6000 -type f 2>/dev/null | head -100)

    echo ""
    if [[ $unknown -eq 0 ]]; then
        log_result "SUID/SGID binaries" "pass" "All $count binaries are known"
    else
        log_result "SUID/SGID binaries" "warning" "$unknown unknown out of $count total"
    fi
}

check_unowned_files() {
    echo ""
    echo "Unowned Files"
    echo "============="

    local dir="${CHECK_DIR:-/}"
    local count=0

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        ((count++)) || true
        if [[ "$JSON_OUTPUT" != "true" && $count -le 10 ]]; then
            echo "  $file"
        fi
    done < <(find "$dir" -path /proc -prune -o -path /sys -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -50)

    if [[ $count -eq 0 ]]; then
        log_result "Unowned files" "pass" "None found"
    else
        log_result "Unowned files" "warning" "Found $count files without valid owner/group"
    fi
}

check_ssh_permissions() {
    echo ""
    echo "SSH Directory Permissions"
    echo "========================="

    local users=()
    while IFS=: read -r user _ uid _ _ home _; do
        [[ $uid -ge 1000 || "$user" == "root" ]] && [[ -d "$home/.ssh" ]] && users+=("$user:$home")
    done < /etc/passwd

    for entry in "${users[@]}"; do
        local user="${entry%%:*}"
        local home="${entry#*:}"
        local ssh_dir="$home/.ssh"

        if [[ -d "$ssh_dir" ]]; then
            local perms
            perms=$(stat -c %a "$ssh_dir" 2>/dev/null || echo "?")

            if [[ "$perms" == "700" ]]; then
                [[ "$JSON_OUTPUT" != "true" ]] && echo "  [$user] .ssh directory: OK ($perms)"
            else
                log_result "SSH dir ($user)" "fail" ".ssh permissions $perms, should be 700"
            fi

            # Check authorized_keys
            if [[ -f "$ssh_dir/authorized_keys" ]]; then
                perms=$(stat -c %a "$ssh_dir/authorized_keys" 2>/dev/null || echo "?")
                if [[ "$perms" != "600" && "$perms" != "644" ]]; then
                    log_result "SSH keys ($user)" "fail" "authorized_keys permissions $perms"
                fi
            fi

            # Check private keys
            for key in "$ssh_dir"/id_*; do
                [[ ! -f "$key" ]] && continue
                [[ "$key" == *.pub ]] && continue

                perms=$(stat -c %a "$key" 2>/dev/null || echo "?")
                if [[ "$perms" != "600" ]]; then
                    log_result "Private key ($user)" "fail" "$key permissions $perms, should be 600"
                fi
            done
        fi
    done

    [[ ${#users[@]} -eq 0 ]] && log_result "SSH directories" "pass" "No SSH directories found"
}

check_tmp_permissions() {
    echo ""
    echo "Temporary Directories"
    echo "===================="

    local tmp_dirs=("/tmp" "/var/tmp" "/dev/shm")

    for dir in "${tmp_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local perms
            perms=$(stat -c %a "$dir" 2>/dev/null || echo "?")

            # Should have sticky bit (1777)
            if [[ "$perms" == "1777" ]]; then
                log_result "$dir" "pass" "Sticky bit set correctly"
            else
                log_result "$dir" "fail" "Permissions $perms, should be 1777 (sticky bit)"
            fi
        fi
    done
}

print_summary() {
    echo ""
    echo "Summary"
    echo "======="
    echo -e "Passed:   ${GREEN}$PASSED${NC}"
    echo -e "Failed:   ${RED}$FAILED${NC}"
    echo -e "Warnings: ${YELLOW}$WARNINGS${NC}"

    if [[ $FAILED -gt 0 ]]; then
        echo ""
        echo -e "${RED}Security issues found. Review and fix the failed checks.${NC}"
        if [[ "$FIX_ISSUES" != "true" ]]; then
            echo "Run with -f flag to attempt automatic fixes (requires root)."
        fi
    fi
}

output_json() {
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"summary\": {"
    echo "    \"passed\": $PASSED,"
    echo "    \"failed\": $FAILED,"
    echo "    \"warnings\": $WARNINGS"
    echo "  },"
    echo "  \"results\": ["

    local first=true
    for result in "${RESULTS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo ","
        fi
        echo "    $result"
    done

    echo ""
    echo "  ]"
    echo "}"
}

main() {
    parse_args "$@"

    if [[ "$JSON_OUTPUT" != "true" ]]; then
        echo "File Permission Security Auditor"
        echo "================================"
        echo "Host: $(hostname)"
        echo "Date: $(date)"
        echo ""
    fi

    check_critical_files
    check_world_writable
    check_suid_sgid
    check_unowned_files
    check_ssh_permissions
    check_tmp_permissions

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        output_json
    else
        print_summary
    fi

    [[ $FAILED -gt 0 ]] && exit 1
    exit 0
}

main "$@"

