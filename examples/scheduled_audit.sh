#!/usr/bin/env bash
#
# Scheduled audit example for Linux Security Monitor
#
# This script demonstrates how to run security audits on a schedule.
# Add to cron for regular execution:
#   0 2 * * * /opt/Sentinel_Linux/examples/scheduled_audit.sh
#

set -euo pipefail

# Configuration
INSTALL_DIR="${LSM_INSTALL_DIR:-/opt/Sentinel_Linux}"
OUTPUT_DIR="${LSM_OUTPUT_DIR:-/var/log/Sentinel_Linux/audits}"
RETENTION_DAYS="${LSM_RETENTION_DAYS:-30}"

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE=$(date +%Y-%m-%d)

# Log file for this run
LOG_FILE="${OUTPUT_DIR}/audit_${TIMESTAMP}.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

log "Starting scheduled security audit"

# Run system audit
log "Running system audit..."
if [[ -x "${INSTALL_DIR}/scripts/bash/system_audit.sh" ]]; then
    "${INSTALL_DIR}/scripts/bash/system_audit.sh" > "${OUTPUT_DIR}/system_audit_${TIMESTAMP}.txt" 2>&1
    log "System audit complete"
else
    log "WARNING: system_audit.sh not found"
fi

# Run user audit
log "Running user audit..."
if [[ -x "${INSTALL_DIR}/scripts/bash/user_audit.sh" ]]; then
    "${INSTALL_DIR}/scripts/bash/user_audit.sh" > "${OUTPUT_DIR}/user_audit_${TIMESTAMP}.txt" 2>&1
    log "User audit complete"
fi

# Run SSH hardening check
log "Running SSH hardening check..."
if [[ -x "${INSTALL_DIR}/scripts/bash/ssh_hardening_check.sh" ]]; then
    "${INSTALL_DIR}/scripts/bash/ssh_hardening_check.sh" > "${OUTPUT_DIR}/ssh_audit_${TIMESTAMP}.txt" 2>&1
    log "SSH audit complete"
fi

# Generate security report
log "Generating security report..."
if [[ -f "${INSTALL_DIR}/scripts/python/generate_report.py" ]]; then
    "${INSTALL_DIR}/venv/bin/python" "${INSTALL_DIR}/scripts/python/generate_report.py" \
        --output "${OUTPUT_DIR}/report_${TIMESTAMP}" \
        --format both 2>&1 | tee -a "${LOG_FILE}"
    log "Report generation complete"
fi

# Clean up old audit files
log "Cleaning up old audit files (>${RETENTION_DAYS} days)..."
find "${OUTPUT_DIR}" -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true

# Summary
TOTAL_FILES=$(find "${OUTPUT_DIR}" -name "*_${TIMESTAMP}*" -type f | wc -l)
log "Audit complete. Generated ${TOTAL_FILES} files."

# Check for critical findings
if grep -l "CRITICAL\|FAIL" "${OUTPUT_DIR}"/*_${TIMESTAMP}.txt 2>/dev/null; then
    log "WARNING: Critical findings detected - review audit results"
    # Optionally send alert
    # mail -s "Security Audit Alert - ${HOSTNAME}" security@example.com < "${LOG_FILE}"
fi

log "Scheduled audit finished"



