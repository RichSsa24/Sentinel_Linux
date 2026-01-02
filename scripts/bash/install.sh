#!/usr/bin/env bash
#
# Installation script for Linux Security Monitor
#
# Usage:
#   sudo ./install.sh [options]
#
# Options:
#   -h, --help      Show this help message
#   -d, --dir DIR   Installation directory (default: /opt/Sentinel_Linux)
#   -u, --user      Create dedicated service user
#   -s, --systemd   Install systemd service
#

set -euo pipefail

# Default values
INSTALL_DIR="/opt/Sentinel_Linux"
CREATE_USER=false
INSTALL_SERVICE=false
SERVICE_USER="security-monitor"
CONFIG_DIR="/etc/Sentinel_Linux"
LOG_DIR="/var/log/Sentinel_Linux"
DATA_DIR="/var/lib/Sentinel_Linux"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Logging
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_help() {
    cat << EOF
Linux Security Monitor Installation Script

Usage: sudo ./install.sh [options]

Options:
  -h, --help      Show this help message
  -d, --dir DIR   Installation directory (default: /opt/Sentinel_Linux)
  -u, --user      Create dedicated service user
  -s, --systemd   Install systemd service

Examples:
  sudo ./install.sh                    # Basic installation
  sudo ./install.sh -u -s              # Full installation with service
  sudo ./install.sh -d /usr/local/lsm  # Custom install directory
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -u|--user)
                CREATE_USER=true
                shift
                ;;
            -s|--systemd)
                INSTALL_SERVICE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_python() {
    if ! command -v python3 &>/dev/null; then
        log_error "Python 3.9+ is required but not found"
        exit 1
    fi

    local python_version
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')

    # Compare versions without bc (which may not be installed)
    local major minor
    IFS='.' read -r major minor <<< "${python_version}"
    if [[ ${major} -lt 3 ]] || [[ ${major} -eq 3 && ${minor} -lt 9 ]]; then
        log_error "Python 3.9+ required, found ${python_version}"
        exit 1
    fi

    log_info "Found Python ${python_version}"
}

create_directories() {
    log_info "Creating directories..."

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${LOG_DIR}"
    mkdir -p "${DATA_DIR}"/{baselines,cache,ioc,rules}

    log_info "Directories created"
}

create_service_user() {
    if [[ "${CREATE_USER}" != "true" ]]; then
        return
    fi

    log_info "Creating service user: ${SERVICE_USER}"

    if id "${SERVICE_USER}" &>/dev/null; then
        log_warn "User ${SERVICE_USER} already exists"
    else
        useradd -r -s /sbin/nologin -d "${DATA_DIR}" "${SERVICE_USER}"
        log_info "User ${SERVICE_USER} created"
    fi

    # Add to required groups
    usermod -aG adm "${SERVICE_USER}" 2>/dev/null || true
}

install_files() {
    log_info "Installing files to ${INSTALL_DIR}..."

    # Get script directory
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

    # Copy source files
    cp -r "${script_dir}/src" "${INSTALL_DIR}/"
    cp -r "${script_dir}/scripts" "${INSTALL_DIR}/"

    # Copy templates if exists
    if [[ -d "${script_dir}/templates" ]]; then
        cp -r "${script_dir}/templates" "${INSTALL_DIR}/"
    fi

    # Copy data directory if exists
    if [[ -d "${script_dir}/data" ]]; then
        cp -r "${script_dir}/data" "${INSTALL_DIR}/"
    fi

    cp "${script_dir}/requirements.txt" "${INSTALL_DIR}/"
    cp "${script_dir}/pyproject.toml" "${INSTALL_DIR}/"
    cp "${script_dir}/setup.py" "${INSTALL_DIR}/"

    # Copy default config
    if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
        cp "${script_dir}/src/config/default_config.yaml" "${CONFIG_DIR}/config.yaml"
        log_info "Default configuration copied to ${CONFIG_DIR}/config.yaml"
    else
        log_warn "Configuration already exists, not overwriting"
    fi

    # Create symlinks for CLI tools
    local bin_dir="/usr/local/bin"
    if [[ -d "${bin_dir}" ]]; then
        ln -sf "${INSTALL_DIR}/venv/bin/lsm" "${bin_dir}/lsm" 2>/dev/null || true
        ln -sf "${INSTALL_DIR}/venv/bin/sentinel" "${bin_dir}/sentinel" 2>/dev/null || true
        ln -sf "${INSTALL_DIR}/venv/bin/Sentinel_Linux" "${bin_dir}/Sentinel_Linux" 2>/dev/null || true
    fi
}

setup_virtualenv() {
    log_info "Setting up Python virtual environment..."

    python3 -m venv "${INSTALL_DIR}/venv"
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip

    log_info "Installing Python dependencies..."
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
    "${INSTALL_DIR}/venv/bin/pip" install -e "${INSTALL_DIR}"

    log_info "Python environment ready"
}

set_permissions() {
    log_info "Setting permissions..."

    chmod 750 "${CONFIG_DIR}"
    chmod 640 "${CONFIG_DIR}/config.yaml"
    chmod 750 "${LOG_DIR}"
    chmod 750 "${DATA_DIR}"

    # Make scripts executable
    find "${INSTALL_DIR}/scripts" -name "*.sh" -exec chmod +x {} \;

    if [[ "${CREATE_USER}" == "true" ]]; then
        chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
        chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    fi
}

install_systemd_service() {
    if [[ "${INSTALL_SERVICE}" != "true" ]]; then
        return
    fi

    log_info "Installing systemd service..."

    local service_file="/etc/systemd/system/Sentinel_Linux.service"
    local template_file="${INSTALL_DIR}/templates/Sentinel_Linux.service"

    # Check if template exists
    if [[ -f "${template_file}" ]]; then
        # Copy and customize template
        sed -e "s|/opt/linux-security-monitor|${INSTALL_DIR}|g" \
            -e "s|/etc/linux-security-monitor|${CONFIG_DIR}|g" \
            -e "s|/var/log/linux-security-monitor|${LOG_DIR}|g" \
            -e "s|/var/lib/linux-security-monitor|${DATA_DIR}|g" \
            "${template_file}" > "${service_file}"
    else
        # Create service file inline
        cat > "${service_file}" << EOF
[Unit]
Description=Linux Security Monitor - Enterprise Security Monitoring
Documentation=https://github.com/RichSsa24/Sentinel_Linux
After=network.target syslog.target auditd.service
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}

# Main process
ExecStart=${INSTALL_DIR}/venv/bin/python -m src.cli.main run --config ${CONFIG_DIR}/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=Sentinel_Linux

# Environment
Environment=PYTHONUNBUFFERED=1
Environment=LSM_LOG_LEVEL=INFO

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Read-write paths for logs and data
ReadWritePaths=${LOG_DIR}
ReadWritePaths=${DATA_DIR}
ReadWritePaths=/var/run

# Allow reading system logs
ReadOnlyPaths=/var/log

# Capabilities needed for monitoring
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_SYS_PTRACE CAP_AUDIT_READ
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_SYS_PTRACE CAP_AUDIT_READ

[Install]
WantedBy=multi-user.target
EOF
    fi

    chmod 644 "${service_file}"
    systemctl daemon-reload

    if systemctl enable Sentinel_Linux 2>/dev/null; then
        log_info "Systemd service enabled"
    else
        log_warn "Could not enable service (may need manual enable)"
    fi

    log_info "Systemd service installed: ${service_file}"
    log_info "Start with: systemctl start Sentinel_Linux"
    log_info "Check status: systemctl status Sentinel_Linux"
}

print_summary() {
    echo ""
    echo "=============================================="
    echo "  Linux Security Monitor Installation Complete"
    echo "=============================================="
    echo ""
    echo "Installation directory: ${INSTALL_DIR}"
    echo "Configuration file:     ${CONFIG_DIR}/config.yaml"
    echo "Log directory:          ${LOG_DIR}"
    echo "Data directory:         ${DATA_DIR}"
    echo ""
    echo "Quick start:"
    echo "  sudo ${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/scripts/python/run_monitor.py"
    echo ""
    echo "Run system audit:"
    echo "  sudo ${INSTALL_DIR}/scripts/bash/system_audit.sh"
    echo ""
    if [[ "${INSTALL_SERVICE}" == "true" ]]; then
        echo "Systemd service:"
        echo "  sudo systemctl start Sentinel_Linux"
        echo "  sudo systemctl status Sentinel_Linux"
        echo ""
    fi
}

main() {
    parse_args "$@"
    check_root
    check_python
    create_directories
    create_service_user
    install_files
    setup_virtualenv
    set_permissions
    install_systemd_service
    print_summary
}

main "$@"



