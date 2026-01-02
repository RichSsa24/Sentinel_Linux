#!/usr/bin/env bash
#
# Uninstallation script for Linux Security Monitor
#
# Usage:
#   sudo ./uninstall.sh [options]
#
# Options:
#   -y, --yes       Skip confirmation prompts
#   -k, --keep-data Keep configuration and log files
#   -h, --help      Show this help message
#

set -euo pipefail

# Configuration
INSTALL_DIR="/opt/Sentinel_Linux"
CONFIG_DIR="/etc/Sentinel_Linux"
LOG_DIR="/var/log/Sentinel_Linux"
DATA_DIR="/var/lib/Sentinel_Linux"
SERVICE_NAME="Sentinel_Linux"
SERVICE_USER="security-monitor"

# Options
SKIP_CONFIRM=false
KEEP_DATA=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    cat << EOF
Linux Security Monitor Uninstallation Script

Usage: sudo $(basename "$0") [options]

Options:
    -y, --yes       Skip confirmation prompts
    -k, --keep-data Keep configuration, logs, and data files
    -h, --help      Show this help message

This script will:
  1. Stop and disable the systemd service
  2. Remove installation files
  3. Remove configuration files (unless --keep-data)
  4. Remove log files (unless --keep-data)
  5. Remove the service user (if created)

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -y|--yes)       SKIP_CONFIRM=true; shift ;;
            -k|--keep-data) KEEP_DATA=true; shift ;;
            -h|--help)      usage; exit 0 ;;
            *)              log_error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

confirm_uninstall() {
    if [[ "$SKIP_CONFIRM" == "true" ]]; then
        return 0
    fi

    echo "This will uninstall Linux Security Monitor and remove:"
    echo "  - Installation directory: $INSTALL_DIR"
    [[ "$KEEP_DATA" != "true" ]] && echo "  - Configuration: $CONFIG_DIR"
    [[ "$KEEP_DATA" != "true" ]] && echo "  - Log files: $LOG_DIR"
    [[ "$KEEP_DATA" != "true" ]] && echo "  - Data files: $DATA_DIR"
    echo ""

    read -rp "Are you sure you want to continue? [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) log_info "Uninstallation cancelled"; exit 0 ;;
    esac
}

stop_service() {
    log_info "Stopping service..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        log_info "Service stopped"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        log_info "Service disabled"
    fi

    # Remove service file
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    if [[ -f "$service_file" ]]; then
        rm -f "$service_file"
        systemctl daemon-reload
        log_info "Service file removed"
    fi
}

remove_installation() {
    log_info "Removing installation directory..."

    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        log_info "Removed: $INSTALL_DIR"
    else
        log_warn "Installation directory not found: $INSTALL_DIR"
    fi
}

remove_data() {
    if [[ "$KEEP_DATA" == "true" ]]; then
        log_info "Keeping configuration and data files"
        return
    fi

    log_info "Removing configuration and data files..."

    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        log_info "Removed: $CONFIG_DIR"
    fi

    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"
        log_info "Removed: $LOG_DIR"
    fi

    if [[ -d "$DATA_DIR" ]]; then
        rm -rf "$DATA_DIR"
        log_info "Removed: $DATA_DIR"
    fi

    # Remove PID file
    rm -f /var/run/Sentinel_Linux.pid
}

remove_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "Removing service user: $SERVICE_USER"

        # Kill any processes owned by the user
        pkill -u "$SERVICE_USER" 2>/dev/null || true

        # Remove user
        userdel "$SERVICE_USER" 2>/dev/null || true
        log_info "Service user removed"
    fi
}

cleanup_symlinks() {
    log_info "Cleaning up symlinks..."

    # Remove any symlinks in /usr/local/bin
    local symlinks=("/usr/local/bin/lsm" "/usr/local/bin/Sentinel_Linux" "/usr/local/bin/sentinel")
    for link in "${symlinks[@]}"; do
        if [[ -L "$link" ]]; then
            rm -f "$link"
            log_info "Removed symlink: $link"
        fi
    done
}

print_summary() {
    echo ""
    echo "=============================================="
    echo "  Linux Security Monitor Uninstalled"
    echo "=============================================="
    echo ""

    if [[ "$KEEP_DATA" == "true" ]]; then
        echo "The following directories were preserved:"
        [[ -d "$CONFIG_DIR" ]] && echo "  - $CONFIG_DIR"
        [[ -d "$LOG_DIR" ]] && echo "  - $LOG_DIR"
        [[ -d "$DATA_DIR" ]] && echo "  - $DATA_DIR"
        echo ""
        echo "To completely remove all data, run:"
        echo "  sudo rm -rf $CONFIG_DIR $LOG_DIR $DATA_DIR"
    else
        echo "All files have been removed."
    fi
    echo ""
}

main() {
    parse_args "$@"
    check_root
    confirm_uninstall

    echo ""
    log_info "Starting uninstallation..."
    echo ""

    stop_service
    remove_installation
    remove_data
    remove_user
    cleanup_symlinks

    print_summary
}

main "$@"

