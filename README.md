# Sentinel Linux - Enterprise Security Monitoring Framework

## What is Sentinel Linux?

**Sentinel Linux** is a comprehensive, enterprise-grade security monitoring framework specifically designed for Linux systems. It provides real-time threat detection, system integrity analysis, and security event correlation.

### Who is it for?

This project is designed for:

- **SOC Analysts (Security Operations Center Analysts)**: Need to detect and respond to threats in real-time, correlate security events, and generate actionable alerts. They require tools that help them identify incidents quickly and understand the full context of security events.

- **System Administrators**: Require monitoring of their systems' integrity, detection of unauthorized changes, and maintaining security policy compliance. They need tools that integrate with their existing infrastructure and provide clear, actionable information.

- **Security Engineers**: Seek an open-source solution they can customize, integrate with existing SIEMs, and extend with custom detection rules. They need flexibility and the ability to adapt the tool to their specific security requirements.

- **DevOps/SRE Teams**: Need security monitoring integrated into their pipelines and the ability to detect anomalies in production environments. They require tools that work well in automated, cloud-native environments.

- **Security Researchers**: Want a solid foundation for threat detection research, behavior analysis, and event correlation. They need extensible tools that can be adapted for research purposes.

### Why does Sentinel Linux exist?

**Problem it solves**: Most security monitoring solutions for Linux are:
- Expensive and closed-source (proprietary code only)
- Difficult to customize
- Don't integrate well with open-source tools
- Require complex infrastructure
- Don't provide MITRE ATT&CK-based detection

**Solution**: Sentinel Linux offers:
- ✅ **100% Open Source** - Completely open and auditable code
- ✅ **Easy to customize** - Modular and extensible architecture
- ✅ **Native integration** - Compatible with popular SIEMs (Splunk, ELK, QRadar)
- ✅ **Lightweight and efficient** - Low resource consumption
- ✅ **Advanced detection** - Support for Sigma rules, YARA, and anomaly detection
- ✅ **MITRE ATT&CK mapping** - Automatic attack technique identification

## Key Features

### Real-Time Monitoring

#### User Activity Monitoring
**What it does**: Tracks login events, privilege escalations, and suspicious user behavior patterns.

**Why it's important**: Attackers frequently compromise legitimate user accounts. Detecting anomalous user activity is crucial for identifying compromises early.

**Who uses it**: SOC analysts detecting compromised accounts, administrators monitoring unauthorized access.

#### Process Monitoring
**What it does**: Detects anomalous processes, unauthorized binaries, and suspicious execution patterns.

**Why it's important**: Malware and attack tools run as processes. Detecting suspicious processes allows early identification of malicious activity.

**Who uses it**: Security engineers detecting malware, administrators monitoring unauthorized executions.

#### Network Monitoring
**What it does**: Monitors network connections, detects C2 (Command & Control) beacons, and identifies data exfiltration attempts.

**Why it's important**: Communication with command and control servers is a strong indicator of compromise. Detecting these connections allows blocking active threats.

**Who uses it**: SOC analysts detecting malicious communications, administrators monitoring suspicious network traffic.

#### File Integrity Monitoring (FIM)
**What it does**: Tracks changes to critical system files and configurations using cryptographic hashing.

**Why it's important**: Attackers modify system files to maintain persistence or evade detection. Detecting these changes is essential for maintaining system integrity.

**Who uses it**: Administrators needing compliance with standards (PCI-DSS, HIPAA), security engineers monitoring unauthorized changes.

#### Authentication Monitoring
**What it does**: Analyzes authentication logs to detect brute force attempts and credential abuse.

**Why it's important**: Brute force attacks are common and can compromise systems if not detected. Identifying these patterns allows blocking attackers before they compromise accounts.

**Who uses it**: SOC analysts monitoring intrusion attempts, administrators protecting exposed services.

#### Service Monitoring
**What it does**: Tracks system service status changes and detects unauthorized services.

**Why it's important**: Attackers install malicious services to maintain persistence. Detecting new or modified services helps identify compromises.

**Who uses it**: Administrators monitoring changes to critical services, security engineers looking for persistence.

#### Log Analysis
**What it does**: Real-time parsing and correlation of system logs.

**Why it's important**: Logs contain valuable information about system activity. Analyzing them in real-time allows detecting attack patterns that wouldn't be visible otherwise.

**Who uses it**: SOC analysts correlating events, administrators analyzing system activity.

### Threat Detection

#### MITRE ATT&CK Mapping
**What it does**: Automatically identifies and classifies attack techniques according to the MITRE ATT&CK framework.

**Why it's important**: MITRE ATT&CK is the industry standard for describing attack tactics and techniques. Mapping events to this framework allows:
- Communicating threats in a standardized way
- Understanding the complete context of an attack
- Comparing with threat intelligence

**Who uses it**: SOC analysts classifying incidents, security engineers reporting to management.

#### IOC Matching
**What it does**: Compares system artifacts against known Indicators of Compromise (IOCs).

**Why it's important**: IOCs are evidence of known malicious activity. Detecting IOCs allows quickly identifying if a system is compromised.

**Who uses it**: SOC analysts working with threat intelligence, incident responders investigating compromises.

#### Anomaly Detection
**What it does**: Statistical analysis to identify deviations from normal behavior (baseline).

**Why it's important**: Advanced attacks can evade signature-based detection. Anomaly detection identifies unusual behavior that may indicate an attack.

**Who uses it**: Security engineers detecting advanced attacks, administrators monitoring system behavior.

#### Sigma Rule Support
**What it does**: Compatible with detection rules in Sigma format, an open-source standard for detection rules.

**Why it's important**: Sigma allows sharing detection rules between different tools. This means access to thousands of detection rules from the community.

**Who uses it**: Security engineers wanting to use community rules, SOC analysts needing specific rules.

#### YARA Integration
**What it does**: Script and malware detection using YARA rules.

**Why it's important**: YARA is the industry standard for malware detection. It allows detecting known malware and creating custom rules.

**Who uses it**: Malware analysts, security engineers needing malware detection.

### Reporting & Integration

#### Multiple Output Formats
**What it does**: Supports Console, JSON, and Syslog output.

**Why it's important**: Different tools require different formats. Supporting multiple formats allows flexible integration.

**Who uses it**: Administrators needing console alerts, engineers integrating with SIEMs.

#### Webhook Notifications
**What it does**: Integration with Slack, Teams, PagerDuty, and other notification systems.

**Why it's important**: Real-time notifications allow quick response to incidents. Webhooks are the standard method for integration with modern tools.

**Who uses it**: SOC teams needing immediate notifications, administrators wanting alerts in their communication tools.

#### SIEM Compatible
**What it does**: Native support for Splunk, ELK Stack, QRadar, and other popular SIEMs.

**Why it's important**: SIEMs centralize and correlate events from multiple sources. Integrating Sentinel Linux with SIEMs allows more comprehensive analysis.

**Who uses it**: SOC analysts working with SIEMs, security engineers centralizing events.

#### Customizable Alerts
**What it does**: Severity-based alerting system with configurable thresholds.

**Why it's important**: Not all events require the same response. Customizable alerts allow prioritizing and avoiding alert fatigue.

**Who uses it**: SOC managers configuring alert policies, administrators adjusting sensitivity.

## Quick Start

### Prerequisites

**Supported Operating Systems**:
- Red Hat Enterprise Linux 8+ / CentOS Stream 8+
- Debian 10+ (Buster and later)
- Ubuntu 20.04 LTS and later
- Fedora 35+
- Amazon Linux 2023

**Hardware Requirements**:
- **Minimum**: 1 CPU core, 512 MB RAM, 100 MB disk
- **Recommended**: 2+ CPU cores, 2 GB RAM, 1 GB disk (for logs/baselines)

**Software Requirements**:
- Python 3.9 or higher
- pip 21.0 or higher
- Root/sudo access for full monitoring capabilities

**Why are elevated privileges required?**
- Read system logs (`/var/log/*`)
- Monitor processes from all users (`/proc/*`)
- Monitor network connections (raw sockets)
- Read system configuration files
- Access user information (`/etc/passwd`, `wtmp`, `lastlog`)

### Installation

#### Method 1: Quick Install (Recommended)

**For**: Users who want a quick, automated installation.

**What it does**: The installation script automates the entire installation process.

```bash
# Clone the repository
git clone https://github.com/RichSsa24/Sentinel_Linux.git
cd Sentinel_Linux

# Run the installation script
chmod +x scripts/bash/install.sh
sudo ./scripts/bash/install.sh
```

**What the script does**:
1. Checks system requirements
2. Installs Python dependencies
3. Creates configuration directories
4. Sets up systemd service (optional)
5. Creates dedicated service account

#### Method 2: Manual Installation

**For**: Users who want complete control over installation or are in restricted environments.

**What it does**: Allows step-by-step installation with control over each component.

See [Detailed Installation Guide](docs/INSTALLATION.md) for complete instructions.

#### Method 3: pip Installation

**For**: Developers who want to use Sentinel Linux as a library or install in existing Python environments.

**What it does**: Installs Sentinel Linux as a standard Python package.

```bash
pip install -e .
```

### Basic Usage

#### Running the Monitor

**For**: Users who want continuous monitoring.

**What it does**: Starts security monitoring with default configuration.

```bash
# Run with default configuration
sudo python scripts/python/run_monitor.py

# With custom configuration
sudo python scripts/python/run_monitor.py --config /path/to/config.yaml

# Verbose mode (more debug information)
sudo python scripts/python/run_monitor.py --verbose

# Dry run (doesn't send alerts, only shows what it would detect)
sudo python scripts/python/run_monitor.py --dry-run
```

#### Running Audits

**For**: Administrators who want point-in-time security assessments.

**What it does**: Runs security audits that evaluate the current security state of the system.

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

#### Generating Reports

**For**: Administrators and managers who need security reports.

**What it does**: Generates security reports in different formats.

```bash
# Generate JSON report
sudo python scripts/python/generate_report.py --output report.json

# Generate HTML report
sudo python scripts/python/generate_report.py --format html --output report.html

# Report for last 24 hours
sudo python scripts/python/generate_report.py --last 24 --output report.json
```

### Configuration

**For**: All users who want to customize behavior.

**What it does**: Allows configuring what to monitor, how to detect threats, and where to send alerts.

```bash
# Copy default configuration
cp src/config/default_config.yaml /etc/Sentinel_Linux/config.yaml

# Edit configuration
sudo nano /etc/Sentinel_Linux/config.yaml
```

**Configuration file locations** (in order of precedence):
1. `--config` command line argument
2. `$LSM_CONFIG` environment variable
3. `/etc/Sentinel_Linux/config.yaml`
4. `./config.yaml` (current directory)
5. `src/config/default_config.yaml` (fallback)

See [Usage Guide](docs/USAGE.md) for detailed configuration options.

## Architecture

**For**: Developers who want to understand how it works internally, security architects evaluating the solution.

**What it does**: Describes the system architecture and how components interact.

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

**Data flow**:
1. **Monitors**: Collect security data from the system
2. **Event Handler**: Normalizes and routes events
3. **Analyzers**: Process events to detect threats
4. **Alert Manager**: Manages deduplication and rate limiting
5. **Reporters**: Send alerts to configured destinations

See [Architecture Documentation](docs/ARCHITECTURE.md) for complete details.

## Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Detailed installation instructions
  - **For**: First-time installers, system administrators
  - **Contains**: Installation methods, requirements, post-installation configuration, troubleshooting

- **[Architecture](docs/ARCHITECTURE.md)** - System design and components
  - **For**: Developers, security architects
  - **Contains**: Component design, data flow, architectural decisions

- **[Usage Guide](docs/USAGE.md)** - Comprehensive usage examples
  - **For**: End users, administrators
  - **Contains**: Configuration examples, use cases, best practices

- **[API Reference](docs/API_REFERENCE.md)** - Module and function documentation
  - **For**: Developers extending the system
  - **Contains**: Class documentation, methods, parameters, code examples

- **[Threat Model](docs/THREAT_MODEL.md)** - Security considerations
  - **For**: Security engineers, security auditors
  - **Contains**: Threat analysis, attack vectors, mitigations

## Bash Scripts

**For**: System administrators who prefer command-line tools, automation scripts.

**What they do**: Provide audit and analysis functionality that can be run independently or integrated into automation scripts.

| Script | Description | When to Use |
|--------|-------------|-------------|
| `system_audit.sh` | Comprehensive system security audit | Periodic assessments, compliance checks |
| `user_audit.sh` | User account and privilege analysis | Access audits, detecting compromised accounts |
| `service_checker.sh` | Service status and security check | Monitoring critical services |
| `log_analyzer.sh` | System log analysis and threat detection | Incident investigation, forensic analysis |
| `network_scanner.sh` | Active connection monitoring | Detecting malicious communications |
| `permission_checker.sh` | File permission security audit | Compliance, system hardening |
| `process_hunter.sh` | Suspicious process detection | Malware hunting, behavior analysis |
| `cron_auditor.sh` | Scheduled task security review | Detecting persistence, automation analysis |
| `ssh_hardening_check.sh` | SSH configuration audit | Hardening, compliance with standards |
| `firewall_audit.sh` | Firewall rules analysis | Network policy verification |

## Python Modules

**For**: Developers who want to extend or integrate Sentinel Linux.

### Monitors

**What they do**: Components that collect security-relevant data from various system sources.

**Why they exist**: Each data source (logs, processes, network) requires specific collection logic. Monitors encapsulate this logic.

**Main modules**:
- `src.monitors.user_monitor` - User activity monitoring
- `src.monitors.process_monitor` - Process monitoring
- `src.monitors.network_monitor` - Network monitoring
- `src.monitors.file_integrity_monitor` - File integrity monitoring
- `src.monitors.auth_monitor` - Authentication monitoring
- `src.monitors.service_monitor` - Service monitoring
- `src.monitors.log_monitor` - Log analysis

### Analyzers

**What they do**: Components that process collected data to identify threats and anomalies.

**Why they exist**: Threat detection requires specialized analysis. Analyzers provide different types of analysis (rule-based, anomaly, IOC).

**Main modules**:
- `src.analyzers.threat_analyzer` - Rule-based threat detection
- `src.analyzers.anomaly_detector` - Statistical anomaly detection
- `src.analyzers.ioc_matcher` - Indicator of Compromise matching
- `src.analyzers.mitre_mapper` - MITRE ATT&CK technique mapping

### Reporters

**What they do**: Components that format and deliver alerts and reports to various destinations.

**Why they exist**: Different systems require different formats. Reporters encapsulate formatting and delivery logic.

**Main modules**:
- `src.reporters.console_reporter` - Colored console output
- `src.reporters.json_reporter` - JSON file output
- `src.reporters.syslog_reporter` - Syslog integration
- `src.reporters.webhook_reporter` - HTTP/webhook notifications

## Security Considerations

**For**: Security engineers, auditors, administrators responsible for security.

**What it covers**: Privilege requirements, secure deployment guidelines, vulnerability reporting procedures.

**Why it's important**: Sentinel Linux requires elevated privileges to function. It's crucial to understand the risks and mitigations.

See [SECURITY.md](SECURITY.md) for:
- Privilege requirements and minimization
- Secure deployment guidelines
- Vulnerability reporting procedures
- Security best practices

## Testing

**For**: Developers contributing code, users who want to verify installation.

**What it does**: Validates that code works correctly and detects regressions.

**Note**: Make sure to install dependencies first:
```bash
pip install -e ".[dev]"
```

**Run tests**:
```bash
# Run all tests
pytest tests/ -v

# With code coverage
pytest tests/ --cov=src --cov-report=html

# Security tests only
pytest tests/security/ -v
```

## Contributing

**For**: Developers who want to contribute code, improvements, or documentation.

**What you need to know**: The project follows specific code, testing, and documentation standards.

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code standards
- Pull request process
- Testing guidelines
- Commit conventions

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

**What this means**:
- You can freely use, modify, and distribute
- You must include the original copyright notice
- No warranties or liability from the author

## Acknowledgments

**Why they're listed**: These are the tools and frameworks that Sentinel Linux uses or is inspired by.

- **MITRE ATT&CK Framework** - Standard framework for attack tactics and techniques
- **Sigma Detection Rules Project** - Open-source standard for detection rules
- **YARA Project** - Malware detection tool
- **CIS Benchmarks** - System hardening standards
- **NIST Cybersecurity Framework** - Cybersecurity risk management framework

## Author

**Ricardo Solís** - Cybersecurity Engineer

---

## Disclaimer

**IMPORTANT**: This tool is intended for authorized security monitoring and incident response. **Ensure you have appropriate authorization before deploying in any environment.**

**Why this disclaimer?**
- Monitoring systems without authorization can be illegal
- Unauthorized use may violate privacy policies
- Always obtain explicit permission before monitoring systems

**When to use**:
- ✅ On your own systems or with explicit authorization
- ✅ In test environments with permission
- ✅ For authorized security research
- ❌ NOT on systems without authorization
- ❌ NOT for malicious activities
- ❌ NOT violating laws or policies
