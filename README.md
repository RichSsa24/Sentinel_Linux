# Linux Security Monitor

A comprehensive, enterprise-grade security monitoring framework for Linux systems. Designed for SOC analysts, system administrators, and security engineers to detect threats, monitor system integrity, and maintain security compliance.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-brightgreen.svg)](https://www.shellcheck.net/)

## Features

### Real-Time Monitoring
- **User Activity Monitoring**: Track login events, privilege escalations, and suspicious user behavior
- **Process Monitoring**: Detect anomalous processes, unauthorized binaries, and suspicious execution patterns
- **Network Monitoring**: Monitor connections, detect C2 beacons, and identify data exfiltration attempts
- **File Integrity Monitoring (FIM)**: Track changes to critical system files and configurations
- **Authentication Monitoring**: Analyze auth logs for brute force attempts and credential abuse
- **Service Monitoring**: Track service status changes and detect unauthorized services
- **Log Analysis**: Real-time parsing and correlation of system logs

### Threat Detection
- **MITRE ATT&CK Mapping**: Automatic technique identification and classification
- **IOC Matching**: Match system artifacts against known Indicators of Compromise
- **Anomaly Detection**: Statistical analysis to identify deviations from baseline behavior
- **Sigma Rule Support**: Compatible with Sigma detection rules
- **YARA Integration**: Script and malware detection using YARA rules

### Reporting & Integration
- **Multiple Output Formats**: Console, JSON, Syslog
- **Webhook Notifications**: Slack, Teams, PagerDuty integration
- **SIEM Compatible**: Native support for Splunk, ELK Stack, QRadar
- **Customizable Alerts**: Severity-based alerting with configurable thresholds

## Quick Start

### Prerequisites
- Linux system (RHEL 8+, Debian 10+, Ubuntu 20.04+)
- Python 3.9 or higher
- Root or sudo privileges for full monitoring capabilities

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/linux-security-monitor.git
cd linux-security-monitor

# Run the installation script
chmod +x scripts/bash/install.sh
sudo ./scripts/bash/install.sh

# Or install via pip
pip install -e .
```

### Basic Usage

```bash
# Run the security monitor with default settings
sudo python scripts/python/run_monitor.py

# Run a system audit
sudo ./scripts/bash/system_audit.sh

# Generate a security report
sudo python scripts/python/generate_report.py --output report.json
```

### Configuration

Copy the default configuration and customize:

```bash
cp src/config/default_config.yaml /etc/linux-security-monitor/config.yaml
# Edit configuration as needed
```

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Monitors      |     |    Analyzers     |     |    Reporters     |
|------------------|     |------------------|     |------------------|
| - User Monitor   |---->| - Threat Analyzer|---->| - Console        |
| - Process Monitor|     | - Anomaly Detect |     | - JSON           |
| - Network Monitor|     | - IOC Matcher    |     | - Syslog         |
| - FIM            |     | - MITRE Mapper   |     | - Webhook        |
| - Auth Monitor   |     +------------------+     +------------------+
| - Service Monitor|              |
| - Log Monitor    |              v
+------------------+     +------------------+
                         |  Alert Manager   |
                         +------------------+
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md) - Detailed installation instructions
- [Architecture](docs/ARCHITECTURE.md) - System design and components
- [Usage Guide](docs/USAGE.md) - Comprehensive usage examples
- [API Reference](docs/API_REFERENCE.md) - Module and function documentation
- [Threat Model](docs/THREAT_MODEL.md) - Security considerations

## Bash Scripts

| Script | Description |
|--------|-------------|
| `system_audit.sh` | Comprehensive system security audit |
| `user_audit.sh` | User account and privilege analysis |
| `service_checker.sh` | Service status and security check |
| `log_analyzer.sh` | System log analysis and threat detection |
| `network_scanner.sh` | Active connection monitoring |
| `permission_checker.sh` | File permission security audit |
| `process_hunter.sh` | Suspicious process detection |
| `cron_auditor.sh` | Scheduled task security review |
| `ssh_hardening_check.sh` | SSH configuration audit |
| `firewall_audit.sh` | Firewall rules analysis |

## Python Modules

### Monitors
Monitor components collect security-relevant data from various system sources.

### Analyzers
Analyzer components process collected data to identify threats and anomalies.

### Reporters
Reporter components format and deliver alerts and reports to various destinations.

## Security Considerations

This tool requires elevated privileges to access system logs and monitor processes. See [SECURITY.md](SECURITY.md) for:
- Privilege requirements and minimization
- Secure deployment guidelines
- Vulnerability reporting procedures

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run security tests
pytest tests/security/ -v
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- MITRE ATT&CK Framework
- Sigma Detection Rules Project
- YARA Project
- CIS Benchmarks
- NIST Cybersecurity Framework

## Author
José Ricardo Solís Arias - Cybersecurity Engineer
---

**Disclaimer**: This tool is intended for authorized security monitoring and incident response. Ensure proper authorization before deploying in any environment.



