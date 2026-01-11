#!/usr/bin/env bash
#
# Script: run_monitor.sh
# Description: Secure wrapper script to start Linux Security Monitor daemon
# CIS: N/A
# MITRE: N/A
# Author: SENTINEL-AUDITOR
# Version: 1.0.0
#
# This script provides a secure, production-ready wrapper for starting
# the Sentinel Linux security monitoring daemon with proper validation,
# error handling, and security checks.

set -euo pipefail

# Script metadata
readonly SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly VERSION="1.0.0"

# Default configuration
readonly DEFAULT_CONFIG="/etc/Sentinel_Linux/config.yaml"
readonly DEFAULT_LOG_LEVEL="INFO"
readonly PID_FILE="/var/run/Sentinel_Linux.pid"
readonly LOCK_FILE="/var/lock/Sentinel_Linux.lock"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
CONFIG_FILE="${DEFAULT_CONFIG}"
LOG_LEVEL="${DEFAULT_LOG_LEVEL}"
DRY_RUN=false
FOREGROUND=false
DEBUG=false

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_debug() {
    if [[ "${DEBUG}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $*" >&2
    fi
}

# Error handling
die() {
    log_error "$*"
    cleanup_on_exit
    exit 1
}

# Cleanup function
cleanup_on_exit() {
    if [[ -f "${LOCK_FILE}" ]]; then
        rm -f "${LOCK_FILE}" || true
    fi
}

# Trap signals
trap cleanup_on_exit EXIT INT TERM

# Check if running as root (optional, depends on configuration)
check_privileges() {
    local required_uid="${1:-0}"
    
    if [[ $EUID -ne ${required_uid} ]]; then
        log_warn "Not running as UID ${required_uid}. Some features may be limited."
        log_warn "For full functionality, run as root or with appropriate capabilities."
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Validate Python installation
check_python() {
    if ! command_exists python3; then
        die "python3 is not installed or not in PATH"
    fi

    local python_version
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null) || {
        die "Failed to determine Python version"
    }

    local major minor
    IFS='.' read -r major minor <<< "${python_version}"
    
    if [[ ${major} -lt 3 ]] || [[ ${major} -eq 3 && ${minor} -lt 9 ]]; then
        die "Python 3.9+ required, found ${python_version}"
    fi

    log_debug "Python version: ${python_version}"
}

# Validate configuration file
validate_config() {
    local config_path="$1"
    
    if [[ ! -f "${config_path}" ]]; then
        die "Configuration file not found: ${config_path}"
    fi

    if [[ ! -r "${config_path}" ]]; then
        die "Configuration file is not readable: ${config_path}"
    fi

    # Basic YAML syntax check
    if command_exists python3; then
        if ! python3 -c "import yaml; yaml.safe_load(open('${config_path}'))" 2>/dev/null; then
            log_warn "Configuration file may have syntax errors. Continuing anyway..."
        fi
    fi

    log_debug "Configuration file validated: ${config_path}"
}

# Check if monitor is already running
check_running() {
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid=$(cat "${PID_FILE}" 2>/dev/null || echo "")
        
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            log_warn "Monitor appears to be running (PID: ${pid})"
            log_warn "Use 'stop' command or kill the process manually"
            return 1
        else
            log_warn "Stale PID file found. Removing..."
            rm -f "${PID_FILE}" || true
        fi
    fi

    # Check lock file
    if [[ -f "${LOCK_FILE}" ]]; then
        local lock_pid
        lock_pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")
        
        if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
            die "Another instance appears to be running (lock PID: ${lock_pid})"
        else
            log_warn "Stale lock file found. Removing..."
            rm -f "${LOCK_FILE}" || true
        fi
    fi

    return 0
}

# Create lock file
create_lock() {
    echo $$ > "${LOCK_FILE}" || die "Failed to create lock file: ${LOCK_FILE}"
    log_debug "Lock file created: ${LOCK_FILE}"
}

# Find Python executable
find_python_executable() {
    # Get absolute path of script directory (works even with sudo)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    
    # Try venv in scripts directory first (most common location)
    local scripts_venv_python="${script_dir}/scripts/venv/bin/python"
    
    # Try venv in root directory
    local venv_python="${script_dir}/venv/bin/python"
    
    # Try venv from current environment (if activated)
    # Note: VIRTUAL_ENV may not be preserved with sudo, so we check the file directly
    local env_python=""
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        env_python="${VIRTUAL_ENV}/bin/python"
    fi
    
    local system_python
    
    # Check scripts/venv first (most common location)
    if [[ -f "${scripts_venv_python}" ]] && [[ -x "${scripts_venv_python}" ]]; then
        log_debug "Found venv at: ${scripts_venv_python}"
        echo "${scripts_venv_python}"
        return 0
    fi
    
    # Check root venv
    if [[ -f "${venv_python}" ]] && [[ -x "${venv_python}" ]]; then
        log_debug "Found venv at: ${venv_python}"
        echo "${venv_python}"
        return 0
    fi
    
    # Check activated venv (if VIRTUAL_ENV is set)
    if [[ -n "${env_python}" ]] && [[ -f "${env_python}" ]] && [[ -x "${env_python}" ]]; then
        log_debug "Found venv from VIRTUAL_ENV: ${env_python}"
        echo "${env_python}"
        return 0
    fi

    # Fallback to system python
    system_python=$(command -v python3) || die "python3 not found in PATH"
    log_warn "Using system Python: ${system_python} (venv not found)"
    log_warn "This may cause import errors. Install dependencies with: pip install -e ."
    echo "${system_python}"
}

# Start monitor in foreground
start_foreground() {
    local python_exec
    python_exec=$(find_python_executable)
    
    # Log which Python is being used for debugging
    log_info "Using Python: ${python_exec}"
    log_debug "Python version: $("${python_exec}" --version 2>&1 || echo 'unknown')"
    
    # Verify pydantic_settings is available
    if ! "${python_exec}" -c "import pydantic_settings" 2>/dev/null; then
        log_error "pydantic_settings not found in ${python_exec}"
        log_error "Please install dependencies: pip install -e ."
        die "Missing required dependency: pydantic_settings"
    fi
    
    log_info "Starting Linux Security Monitor (foreground mode)..."
    log_info "Configuration: ${CONFIG_FILE}"
    log_info "Log level: ${LOG_LEVEL}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "DRY RUN MODE: No alerts will be sent"
    fi

    # Build command arguments
    local cmd_args=(
        "-m" "src.cli.main"
        "run"
        "--config" "${CONFIG_FILE}"
        "--log-level" "${LOG_LEVEL}"
    )

    if [[ "${DRY_RUN}" == "true" ]]; then
        cmd_args+=("--dry-run")
    fi

    if [[ "${DEBUG}" == "true" ]]; then
        cmd_args+=("--debug")
    fi

    # Change to script directory
    cd "${SCRIPT_DIR}" || die "Failed to change to directory: ${SCRIPT_DIR}"

    # Execute monitor
    exec "${python_exec}" "${cmd_args[@]}"
}

# Start monitor in background
start_background() {
    local python_exec
    python_exec=$(find_python_executable)
    
    log_info "Starting Linux Security Monitor (daemon mode)..."
    
    # Create lock file
    create_lock

    # Build command
    local cmd_args=(
        "-m" "src.cli.main"
        "run"
        "--config" "${CONFIG_FILE}"
        "--log-level" "${LOG_LEVEL}"
    )

    if [[ "${DRY_RUN}" == "true" ]]; then
        cmd_args+=("--dry-run")
    fi

    if [[ "${DEBUG}" == "true" ]]; then
        cmd_args+=("--debug")
    fi

    # Change to script directory
    cd "${SCRIPT_DIR}" || die "Failed to change to directory: ${SCRIPT_DIR}"

    # Start in background and capture PID
    "${python_exec}" "${cmd_args[@]}" >/dev/null 2>&1 &
    local pid=$!

    # Save PID
    echo "${pid}" > "${PID_FILE}" || log_warn "Failed to write PID file"

    # Wait a moment to check if process started successfully
    sleep 1

    if ! kill -0 "${pid}" 2>/dev/null; then
        rm -f "${PID_FILE}" "${LOCK_FILE}"
        die "Monitor failed to start. Check logs for details."
    fi

    log_info "Monitor started successfully (PID: ${pid})"
    log_info "PID file: ${PID_FILE}"
    log_info "Use 'stop' command or 'kill ${pid}' to stop"
}

# Stop monitor
stop_monitor() {
    if [[ ! -f "${PID_FILE}" ]]; then
        log_warn "PID file not found. Monitor may not be running."
        return 0
    fi

    local pid
    pid=$(cat "${PID_FILE}" 2>/dev/null || echo "")

    if [[ -z "${pid}" ]]; then
        log_warn "PID file is empty"
        rm -f "${PID_FILE}"
        return 0
    fi

    if ! kill -0 "${pid}" 2>/dev/null; then
        log_warn "Process ${pid} is not running. Removing stale PID file."
        rm -f "${PID_FILE}" "${LOCK_FILE}"
        return 0
    fi

    log_info "Stopping monitor (PID: ${pid})..."
    
    # Send SIGTERM
    kill -TERM "${pid}" 2>/dev/null || true
    
    # Wait for graceful shutdown
    local count=0
    while kill -0 "${pid}" 2>/dev/null && [[ ${count} -lt 10 ]]; do
        sleep 1
        count=$((count + 1))
    done

    # Force kill if still running
    if kill -0 "${pid}" 2>/dev/null; then
        log_warn "Process did not terminate gracefully. Sending SIGKILL..."
        kill -KILL "${pid}" 2>/dev/null || true
        sleep 1
    fi

    # Cleanup
    rm -f "${PID_FILE}" "${LOCK_FILE}"
    log_info "Monitor stopped"
}

# Show status
show_status() {
    if [[ ! -f "${PID_FILE}" ]]; then
        echo "Status: NOT RUNNING"
        return 0
    fi

    local pid
    pid=$(cat "${PID_FILE}" 2>/dev/null || echo "")

    if [[ -z "${pid}" ]]; then
        echo "Status: UNKNOWN (empty PID file)"
        return 0
    fi

    if kill -0 "${pid}" 2>/dev/null; then
        echo "Status: RUNNING (PID: ${pid})"
        
        # Show process info
        if command_exists ps; then
            ps -p "${pid}" -o pid,user,cmd --no-headers 2>/dev/null || true
        fi
    else
        echo "Status: NOT RUNNING (stale PID file)"
    fi
}

# Show usage
show_usage() {
    cat << EOF
${SCRIPT_NAME} - Linux Security Monitor Control Script

Usage:
    ${SCRIPT_NAME} [OPTIONS] COMMAND

Commands:
    start       Start the monitor in background (daemon mode)
    foreground  Start the monitor in foreground
    stop        Stop the running monitor
    status      Show monitor status
    restart     Restart the monitor
    help        Show this help message

Options:
    -c, --config FILE     Configuration file path (default: ${DEFAULT_CONFIG})
    -l, --log-level LEVEL Log level: DEBUG, INFO, WARNING, ERROR (default: ${DEFAULT_LOG_LEVEL})
    -d, --dry-run         Run without sending alerts
    -f, --foreground      Run in foreground (same as 'foreground' command)
    --debug               Enable debug output
    -h, --help            Show this help message
    -v, --version         Show version

Examples:
    ${SCRIPT_NAME} start
    ${SCRIPT_NAME} start --config /custom/path/config.yaml
    ${SCRIPT_NAME} start --log-level DEBUG --dry-run
    ${SCRIPT_NAME} foreground
    ${SCRIPT_NAME} stop
    ${SCRIPT_NAME} status
    ${SCRIPT_NAME} restart

Environment Variables:
    SENTINEL_CONFIG       Override default configuration file path
    SENTINEL_LOG_LEVEL    Override default log level

EOF
}

# Parse command line arguments
parse_args() {
    # Check for environment variables
    if [[ -n "${SENTINEL_CONFIG:-}" ]]; then
        CONFIG_FILE="${SENTINEL_CONFIG}"
    fi

    if [[ -n "${SENTINEL_LOG_LEVEL:-}" ]]; then
        LOG_LEVEL="${SENTINEL_LOG_LEVEL}"
    fi

    local command=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -l|--log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--foreground)
                FOREGROUND=true
                shift
                ;;
            --debug)
                DEBUG=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "${SCRIPT_NAME} version ${VERSION}"
                exit 0
                ;;
            start|foreground|stop|status|restart|help)
                command="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Handle command
    case "${command}" in
        start)
            check_python
            validate_config "${CONFIG_FILE}"
            check_running || exit 1
            start_background
            ;;
        foreground|"")
            if [[ "${FOREGROUND}" == "true" ]] || [[ -z "${command}" ]]; then
                check_python
                validate_config "${CONFIG_FILE}"
                check_running || exit 1
                start_foreground
            else
                show_usage
                exit 1
            fi
            ;;
        stop)
            stop_monitor
            ;;
        status)
            show_status
            ;;
        restart)
            stop_monitor
            sleep 2
            check_python
            validate_config "${CONFIG_FILE}"
            check_running || exit 1
            start_background
            ;;
        help|*)
            show_usage
            exit 0
            ;;
    esac
}

# Main function
main() {
    # Check if script is being sourced
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        # Optional: Check privileges (comment out if not needed)
        # check_privileges 0
        
        # Parse arguments and execute
        parse_args "$@"
    fi
}

# Execute main function
main "$@"

