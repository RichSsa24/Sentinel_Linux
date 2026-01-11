#!/bin/bash
# Common utility functions for Sentinel Linux bash scripts
#
# This library provides shared functions used across multiple bash scripts
# in the Sentinel Linux project.

# Logging functions
log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_warning() {
    echo "[WARNING] $*" >&2
}

log_success() {
    echo "[SUCCESS] $*"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if a file exists and is readable
file_readable() {
    [[ -r "$1" ]] && [[ -f "$1" ]]
}

# Check if a directory exists and is writable
dir_writable() {
    [[ -w "$1" ]] && [[ -d "$1" ]]
}

# Safe path validation (prevents path traversal)
validate_path() {
    local path="$1"
    local base_dir="${2:-/}"
    
    # Resolve to absolute path
    local abs_path=$(readlink -f "$path" 2>/dev/null || echo "$path")
    local abs_base=$(readlink -f "$base_dir" 2>/dev/null || echo "$base_dir")
    
    # Check if path is within base directory
    [[ "$abs_path" == "$abs_base"* ]]
}

# Get script directory (works with symlinks)
get_script_dir() {
    local script_path="${BASH_SOURCE[0]}"
    while [[ -L "$script_path" ]]; do
        script_path=$(readlink "$script_path")
    done
    dirname "$(cd "$(dirname "$script_path")" && pwd -P)"
}


