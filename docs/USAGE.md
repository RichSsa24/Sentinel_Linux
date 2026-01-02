# Usage Guide

## Overview

**What this guide covers**: This document explains how to use Sentinel Linux, including running monitors, configuring settings, generating reports, and integrating with other systems.

**Who should read this**:
- **System Administrators**: Setting up and running Sentinel Linux in production
- **SOC Analysts**: Using Sentinel Linux for threat detection and incident response
- **Security Engineers**: Configuring advanced features and custom rules
- **DevOps Engineers**: Integrating Sentinel Linux into automated workflows

**Why this guide exists**: Sentinel Linux has many features and configuration options. This guide helps you use them effectively.

## Quick Start

**What this section covers**: Basic commands to get started quickly.

**For**: Users who want to start using Sentinel Linux immediately.

### Running the Monitor

**What this does**: Starts the security monitoring system.

**Why you need it**: Monitoring must be running to detect threats.

**Basic execution with default configuration**:
```bash
# What this does: Starts monitoring with default settings from /etc/Sentinel_Linux/config.yaml
# When to use: Standard production deployment
# Why sudo: Requires root privileges to access system resources
sudo python scripts/python/run_monitor.py
```

**With custom configuration**:
```bash
# What this does: Starts monitoring with a specific configuration file
# When to use: Testing different configurations, per-environment configs
# Why it's useful: Allows multiple configurations for different scenarios
sudo python scripts/python/run_monitor.py --config /path/to/config.yaml
```

**Verbose output**:
```bash
# What this does: Enables detailed logging to console
# When to use: Debugging, initial setup, troubleshooting
# Why it's useful: Shows what's happening in real-time
sudo python scripts/python/run_monitor.py --verbose
```

**Dry run (no alerts sent)**:
```bash
# What this does: Runs monitoring but doesn't send alerts
# When to use: Testing configuration, verifying detection without alerting
# Why it's useful: Safe way to test without generating false alerts
sudo python scripts/python/run_monitor.py --dry-run
```

### Running Audit Scripts

```bash
# Comprehensive system audit
sudo ./scripts/bash/system_audit.sh

# User account audit
sudo ./scripts/bash/user_audit.sh

# Network connections scan
sudo ./scripts/bash/network_scanner.sh

# SSH configuration check
sudo ./scripts/bash/ssh_hardening_check.sh
```

## Configuration

**What this section covers**: How to configure Sentinel Linux to match your environment and requirements.

**For**: All users who want to customize Sentinel Linux behavior.

**Why configuration matters**: Default settings may not be appropriate for all environments. Proper configuration ensures:
- Relevant threats are detected
- Alert fatigue is minimized
- System performance is optimized
- Integration with existing tools works correctly

### Configuration File Location

**What this means**: Where Sentinel Linux looks for configuration files.

**Why multiple locations**: Different scenarios require different configuration sources:
- Command line: Override for testing or one-time runs
- Environment variable: Useful in containers or automated deployments
- System directory: Standard location for production
- Current directory: Convenient for development
- Default: Fallback if no other config is found

**Precedence order** (first found is used):
1. `--config` command line argument - Highest priority, overrides everything
   - **When to use**: Testing, temporary changes
2. `$LSM_CONFIG` environment variable - Useful for automation
   - **When to use**: Container deployments, CI/CD pipelines
3. `/etc/Sentinel_Linux/config.yaml` - Standard production location
   - **When to use**: Production deployments, system-wide configuration
4. `./config.yaml` - Current directory
   - **When to use**: Development, per-project configurations
5. `src/config/default_config.yaml` - Default fallback
   - **When used**: No other configuration found

### Configuration Options

#### Global Settings

**What this section does**: Controls overall behavior of Sentinel Linux.

**For**: All users who want to customize basic settings.

**Configuration**:

```yaml
# Global configuration
global:
  # Hostname override (default: system hostname)
  # What this does: Overrides system hostname in alerts and reports
  # When to use: Virtual environments, containers, multi-homed systems
  # Why it's useful: Ensures consistent hostname identification
  hostname: ""
  
  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  # What this does: Controls verbosity of logging
  # When to use each level:
  #   DEBUG: Development, troubleshooting (very verbose)
  #   INFO: Production (normal operation)
  #   WARNING: Production (only warnings and errors)
  #   ERROR: Critical systems (only errors)
  #   CRITICAL: Emergency (only critical failures)
  # Why it matters: Reduces log volume in production
  log_level: INFO
  
  # Log file path
  # What this does: Where application logs are written
  # Why /var/log: Standard location for application logs
  # Why it matters: Centralized log management, rotation
  log_file: /var/log/Sentinel_Linux/monitor.log
  
  # PID file for daemon mode
  # What this does: Stores process ID when running as daemon
  # Why it's needed: Allows scripts to find and manage the process
  # When to use: Running as systemd service or daemon
  pid_file: /var/run/Sentinel_Linux.pid
  
  # Enable debug mode
  # What this does: Enables additional debugging information
  # When to use: Troubleshooting, development
  # Why it's off by default: Generates large amounts of output
  debug: false
```

#### Monitor Configuration

```yaml
monitors:
  # User activity monitoring
  user_monitor:
    enabled: true
    poll_interval: 60  # seconds
    auth_log_path: /var/log/auth.log
    track_commands: false  # Requires auditd
    alert_on_root_login: true
    alert_on_sudo: true
    
  # Process monitoring
  process_monitor:
    enabled: true
    poll_interval: 30
    baseline_path: /var/lib/Sentinel_Linux/baselines/processes.json
    alert_on_new_process: false
    suspicious_paths:
      - /tmp
      - /dev/shm
      - /var/tmp
    suspicious_names:
      - nc
      - ncat
      - netcat
      - nmap
      - tcpdump
      
  # Network monitoring
  network_monitor:
    enabled: true
    poll_interval: 30
    alert_on_new_listener: true
    alert_on_outbound: false
    whitelisted_ports:
      - 22
      - 80
      - 443
    whitelisted_ips:
      - 127.0.0.1
      - "::1"
      
  # File integrity monitoring
  file_integrity_monitor:
    enabled: true
    poll_interval: 300
    watched_paths:
      - /etc/passwd
      - /etc/shadow
      - /etc/group
      - /etc/sudoers
      - /etc/sudoers.d
      - /etc/ssh/sshd_config
      - /etc/crontab
      - /etc/cron.d
    recursive_paths:
      - /etc/systemd/system
    exclude_patterns:
      - "*.swp"
      - "*~"
    hash_algorithm: sha256
    
  # Authentication monitoring
  auth_monitor:
    enabled: true
    poll_interval: 30
    brute_force_threshold: 5
    brute_force_window: 300  # seconds
    alert_on_failed_auth: true
    
  # Service monitoring
  service_monitor:
    enabled: true
    poll_interval: 60
    critical_services:
      - sshd
      - firewalld
      - auditd
    alert_on_new_service: true
    
  # Log monitoring
  log_monitor:
    enabled: true
    poll_interval: 10
    log_paths:
      - /var/log/syslog
      - /var/log/messages
      - /var/log/secure
    patterns:
      - pattern: "Failed password"
        severity: MEDIUM
      - pattern: "BREAK-IN ATTEMPT"
        severity: CRITICAL
      - pattern: "segfault"
        severity: LOW
```

#### Analyzer Configuration

```yaml
analyzers:
  threat_analyzer:
    enabled: true
    rules_path: /var/lib/Sentinel_Linux/rules
    
  anomaly_detector:
    enabled: true
    baseline_path: /var/lib/Sentinel_Linux/baselines
    sensitivity: medium  # low, medium, high
    learning_period: 86400  # seconds (24 hours)
    
  ioc_matcher:
    enabled: true
    ioc_database: /var/lib/Sentinel_Linux/ioc/iocs.json
    update_interval: 3600
    
  mitre_mapper:
    enabled: true
    include_sub_techniques: true
```

#### Reporter Configuration

```yaml
reporters:
  console:
    enabled: true
    color: true
    severity_threshold: INFO
    
  json:
    enabled: true
    output_path: /var/log/Sentinel_Linux/events.json
    rotate: true
    max_size_mb: 100
    backup_count: 5
    
  syslog:
    enabled: false
    host: localhost
    port: 514
    protocol: udp  # udp, tcp, tls
    facility: LOCAL0
    
  webhook:
    enabled: false
    url: https://hooks.slack.com/services/xxx
    method: POST
    headers:
      Content-Type: application/json
    template: |
      {
        "text": "Security Alert: ${alert.title}",
        "severity": "${alert.severity}",
        "host": "${alert.host}"
      }
    retry_count: 3
    timeout: 10
```

#### Alert Configuration

```yaml
alerting:
  # Minimum severity to generate alerts
  severity_threshold: LOW
  
  # Deduplication window in seconds
  deduplication_window: 300
  
  # Rate limiting
  rate_limit:
    enabled: true
    max_alerts_per_minute: 60
    
  # Alert enrichment
  enrichment:
    add_hostname: true
    add_ip: true
    add_mitre: true
    
  # Suppression rules
  suppressions:
    - pattern: "Failed password for invalid user"
      duration: 3600
      max_count: 10
```

## Command Line Interface

### Main Monitor

```bash
usage: run_monitor.py [-h] [-c CONFIG] [-v] [-d] [--dry-run]
                      [--validate-config] [--daemon] [--pid-file PID_FILE]
                      [--log-file LOG_FILE] [--log-level LOG_LEVEL]

Linux Security Monitor

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configuration file path
  -v, --verbose         Enable verbose output
  -d, --debug           Enable debug mode
  --dry-run             Run without sending alerts
  --validate-config     Validate configuration and exit
  --daemon              Run as daemon
  --pid-file PID_FILE   PID file path for daemon mode
  --log-file LOG_FILE   Log file path
  --log-level LOG_LEVEL
                        Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
```

### Report Generator

```bash
usage: generate_report.py [-h] [-c CONFIG] [-o OUTPUT] [-f FORMAT]
                          [--start-time START] [--end-time END]
                          [--severity SEVERITY] [--type TYPE]

Generate Security Reports

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configuration file path
  -o OUTPUT, --output OUTPUT
                        Output file path
  -f FORMAT, --format FORMAT
                        Output format (json, html, pdf)
  --start-time START    Report start time (ISO 8601)
  --end-time END        Report end time (ISO 8601)
  --severity SEVERITY   Minimum severity to include
  --type TYPE           Event type filter
```

### Baseline Creator

```bash
usage: baseline_creator.py [-h] [-c CONFIG] [-o OUTPUT] [--type TYPE]
                           [--include-processes] [--include-network]
                           [--include-files] [--include-services]

Create System Baseline

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Configuration file path
  -o OUTPUT, --output OUTPUT
                        Baseline output directory
  --type TYPE           Baseline type (full, incremental)
  --include-processes   Include process baseline
  --include-network     Include network baseline
  --include-files       Include file integrity baseline
  --include-services    Include service baseline
```

## Bash Scripts Usage

### System Audit

```bash
# Full system audit
sudo ./scripts/bash/system_audit.sh

# With specific output file
sudo ./scripts/bash/system_audit.sh -o /tmp/audit_report.txt

# JSON output
sudo ./scripts/bash/system_audit.sh -f json -o /tmp/audit.json

# Quick mode (skip slow checks)
sudo ./scripts/bash/system_audit.sh --quick
```

### User Audit

```bash
# Audit all users
sudo ./scripts/bash/user_audit.sh

# Check specific user
sudo ./scripts/bash/user_audit.sh -u username

# Include inactive accounts
sudo ./scripts/bash/user_audit.sh --include-inactive

# Check for empty passwords
sudo ./scripts/bash/user_audit.sh --check-passwords
```

### Network Scanner

```bash
# Scan all connections
sudo ./scripts/bash/network_scanner.sh

# Show listening ports only
sudo ./scripts/bash/network_scanner.sh --listening

# Show established connections
sudo ./scripts/bash/network_scanner.sh --established

# Check for suspicious ports
sudo ./scripts/bash/network_scanner.sh --suspicious
```

### SSH Hardening Check

```bash
# Full SSH audit
sudo ./scripts/bash/ssh_hardening_check.sh

# Check specific config file
sudo ./scripts/bash/ssh_hardening_check.sh -c /etc/ssh/sshd_config

# CIS benchmark compliance
sudo ./scripts/bash/ssh_hardening_check.sh --cis
```

## Examples

### Basic Monitoring Session

```bash
# Start monitoring with console output
sudo python scripts/python/run_monitor.py --verbose

# Output:
# [2024-01-15 10:30:01] INFO - Linux Security Monitor starting...
# [2024-01-15 10:30:01] INFO - Loading configuration from /etc/Sentinel_Linux/config.yaml
# [2024-01-15 10:30:02] INFO - UserMonitor initialized
# [2024-01-15 10:30:02] INFO - ProcessMonitor initialized
# [2024-01-15 10:30:02] INFO - NetworkMonitor initialized
# [2024-01-15 10:30:02] INFO - All monitors started
# [2024-01-15 10:30:15] WARNING - New SSH login detected: user=admin from=192.168.1.100
# [2024-01-15 10:30:45] ALERT - Suspicious process detected: /tmp/suspicious.sh (pid=12345)
```

### Creating a Baseline

```bash
# Create full system baseline
sudo python scripts/python/baseline_creator.py --type full

# Output:
# Creating process baseline...
# - Captured 245 processes
# Creating network baseline...
# - Captured 32 listeners, 156 connections
# Creating file integrity baseline...
# - Hashed 1,234 files
# Baseline saved to /var/lib/Sentinel_Linux/baselines/

# View baseline
cat /var/lib/Sentinel_Linux/baselines/processes.json | jq '.processes | length'
# 245
```

### Generating Reports

```bash
# Generate daily report
sudo python scripts/python/generate_report.py \
  --start-time "2024-01-14T00:00:00" \
  --end-time "2024-01-15T00:00:00" \
  --format json \
  --output /tmp/daily_report.json

# Generate high-severity report
sudo python scripts/python/generate_report.py \
  --severity HIGH \
  --format html \
  --output /tmp/critical_events.html
```

### SIEM Integration

```bash
# Configure syslog forwarding
cat >> /etc/Sentinel_Linux/config.yaml << 'EOF'
reporters:
  syslog:
    enabled: true
    host: siem.internal.company.com
    port: 514
    protocol: tcp
    facility: LOCAL0
EOF

# Restart monitor
sudo systemctl restart Sentinel_Linux

# Verify syslog output
sudo tcpdump -i any port 514 -A | head -20
```

### Webhook Alerts to Slack

```yaml
# In config.yaml
reporters:
  webhook:
    enabled: true
    url: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX
    method: POST
    headers:
      Content-Type: application/json
    template: |
      {
        "blocks": [
          {
            "type": "header",
            "text": {
              "type": "plain_text",
              "text": "Security Alert: ${alert.severity}"
            }
          },
          {
            "type": "section",
            "fields": [
              {"type": "mrkdwn", "text": "*Host:*\n${alert.host}"},
              {"type": "mrkdwn", "text": "*Type:*\n${alert.event_type}"},
              {"type": "mrkdwn", "text": "*Time:*\n${alert.timestamp}"},
              {"type": "mrkdwn", "text": "*MITRE:*\n${alert.mitre_technique}"}
            ]
          },
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Details:*\n```${alert.details}```"
            }
          }
        ]
      }
```

## Advanced Usage

### Custom Detection Rules

Create custom Sigma rules in `/var/lib/Sentinel_Linux/rules/sigma/`:

```yaml
# custom_ssh_bruteforce.yml
title: SSH Brute Force Detection
status: experimental
description: Detects SSH brute force attempts
logsource:
    product: linux
    service: auth
detection:
    selection:
        EventType: authentication
        Status: failed
        Service: ssh
    condition: selection | count() by SourceIP > 5
    timeframe: 5m
level: high
tags:
    - attack.credential_access
    - attack.t1110
```

### Custom YARA Rules

Create YARA rules in `/var/lib/Sentinel_Linux/rules/yara/`:

```yara
rule SuspiciousScript
{
    meta:
        description = "Detects potentially malicious scripts"
        severity = "medium"
        
    strings:
        $s1 = "/dev/tcp/" nocase
        $s2 = "nc -e" nocase
        $s3 = "bash -i" nocase
        $s4 = "curl | sh" nocase
        $s5 = "wget | sh" nocase
        
    condition:
        any of them
}
```

### Scheduled Audits with Cron

```bash
# Add to /etc/cron.d/Sentinel_Linux
# Daily system audit at 2 AM
0 2 * * * root /opt/Sentinel_Linux/scripts/bash/system_audit.sh -o /var/log/Sentinel_Linux/daily_audit_$(date +\%Y\%m\%d).txt

# Hourly user audit
0 * * * * root /opt/Sentinel_Linux/scripts/bash/user_audit.sh --quick >> /var/log/Sentinel_Linux/user_audit.log

# Weekly comprehensive report
0 3 * * 0 root /opt/Sentinel_Linux/venv/bin/python /opt/Sentinel_Linux/scripts/python/generate_report.py --format html --output /var/www/html/security_report.html
```

## Troubleshooting

### Debug Mode

```bash
# Enable debug logging
sudo python scripts/python/run_monitor.py --debug --log-level DEBUG

# Check debug output
tail -f /var/log/Sentinel_Linux/monitor.log
```

### Common Issues

**High CPU Usage**
```yaml
# Reduce polling frequency
monitors:
  process_monitor:
    poll_interval: 60  # Increase from 30
```

**Too Many Alerts**
```yaml
# Adjust thresholds
alerting:
  severity_threshold: MEDIUM
  rate_limit:
    max_alerts_per_minute: 30
```

**Missing Events**
```bash
# Check monitor status
python -c "from src.monitors import *; print(UserMonitor().get_status())"
```



