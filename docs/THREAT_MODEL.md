# Threat Model

## Overview

This document describes the threat model for Linux Security Monitor, identifying potential threats, attack vectors, and mitigations.

## System Context

```
┌─────────────────────────────────────────────────────────────────┐
│                      Monitored System                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐         ┌─────────────────┐               │
│  │  System Logs    │────────▶│                 │               │
│  └─────────────────┘         │                 │               │
│                              │  Linux Security │               │
│  ┌─────────────────┐         │     Monitor     │               │
│  │  Processes      │────────▶│                 │               │
│  └─────────────────┘         │                 │               │
│                              │                 │               │
│  ┌─────────────────┐         │                 │               │
│  │  Network        │────────▶│                 │               │
│  └─────────────────┘         └────────┬────────┘               │
│                                       │                         │
└───────────────────────────────────────┼─────────────────────────┘
                                        │
                                        ▼
                          ┌─────────────────────────┐
                          │   External Systems      │
                          │  - SIEM                 │
                          │  - Webhook Endpoints    │
                          │  - Syslog Servers       │
                          └─────────────────────────┘
```

## Trust Boundaries

### Trust Boundary 1: System Boundary
- LSM runs with elevated privileges on the monitored system
- System logs, process data, and network state are trusted inputs
- Configuration files are trusted (must be protected)

### Trust Boundary 2: Network Boundary
- External SIEM/webhook endpoints are partially trusted
- TLS required for sensitive communications
- API responses from external systems are untrusted

### Trust Boundary 3: User Input Boundary
- Configuration values are validated before use
- IOC databases from external sources require verification
- Rule files are validated before loading

## Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| System Logs | High | Contains authentication events, user activity |
| Configuration | High | May contain webhook URLs, API keys |
| IOC Database | Medium | Threat intelligence data |
| Baselines | Medium | System state information |
| Alert Data | Medium | Security event information |
| Detection Rules | Medium | Security detection logic |

## Threat Actors

### External Attacker
- **Motivation**: System compromise, data theft
- **Capabilities**: Network access, malware deployment
- **Goals**: Evade detection, disable monitoring

### Malicious Insider
- **Motivation**: Data theft, sabotage
- **Capabilities**: Legitimate system access
- **Goals**: Cover tracks, disable alerts

### Compromised Account
- **Motivation**: Varies based on attacker
- **Capabilities**: Limited to account privileges
- **Goals**: Privilege escalation, persistence

## Threats and Mitigations

### T1: Monitor Evasion

**Description**: Attacker modifies system to evade detection.

**Attack Vectors**:
- Clearing or modifying logs before LSM reads them
- Using rootkit to hide processes/connections
- Timing attacks between log write and LSM read

**STRIDE Category**: Tampering, Elevation of Privilege

**MITRE ATT&CK**: T1070 (Indicator Removal), T1014 (Rootkit)

**Mitigations**:
- Real-time log monitoring reduces window for manipulation
- Multiple data source correlation (logs + proc + network)
- Kernel-level monitoring integration (auditd)
- Baseline deviation detection

**Implementation**:
```python
# Multiple source correlation
def correlate_sources(log_events, proc_events, net_events):
    """Cross-reference events from multiple sources."""
    # Attacker must evade all sources simultaneously
```

### T2: Configuration Tampering

**Description**: Attacker modifies LSM configuration to disable detection.

**Attack Vectors**:
- Direct config file modification
- Environment variable manipulation
- Symbolic link attacks

**STRIDE Category**: Tampering

**MITRE ATT&CK**: T1562 (Impair Defenses)

**Mitigations**:
- Strict file permissions (root:root 600)
- Configuration file integrity monitoring
- Environment variable validation
- Immutable configuration option

**Implementation**:
```yaml
# Monitor own configuration
file_integrity_monitor:
  watched_paths:
    - /etc/Sentinel_Linux/config.yaml
```

### T3: Alert Suppression

**Description**: Attacker prevents alerts from reaching SOC.

**Attack Vectors**:
- Network blocking to SIEM
- Webhook endpoint DoS
- Local alert queue manipulation

**STRIDE Category**: Denial of Service

**MITRE ATT&CK**: T1562.006 (Indicator Blocking)

**Mitigations**:
- Multiple reporter destinations
- Local alert persistence
- Alert delivery confirmation
- Network connectivity monitoring

**Implementation**:
```python
# Redundant alert delivery
reporters:
  - type: syslog
    primary: true
  - type: webhook
    failover: true
  - type: local_file
    always: true  # Persist locally regardless
```

### T4: Privilege Escalation via LSM

**Description**: Attacker exploits LSM to gain elevated privileges.

**Attack Vectors**:
- Command injection via log parsing
- Path traversal in file operations
- Unsafe deserialization of configuration

**STRIDE Category**: Elevation of Privilege

**MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation)

**Mitigations**:
- Input validation for all external data
- Safe parsing libraries
- Principle of least privilege
- No shell command execution with user input

**Implementation**:
```python
# Safe log parsing
def parse_log_entry(entry: str) -> LogEntry:
    """Parse log entry without shell execution."""
    # Never use shell=True
    # Validate and sanitize all fields
    sanitized = sanitize_log_message(entry)
    return LogEntry.from_string(sanitized)
```

### T5: Information Disclosure

**Description**: Sensitive information leaked through LSM.

**Attack Vectors**:
- Verbose error messages exposing system info
- Alert data containing credentials
- Log files readable by unauthorized users

**STRIDE Category**: Information Disclosure

**MITRE ATT&CK**: T1552 (Unsecured Credentials)

**Mitigations**:
- Credential sanitization in logs/alerts
- Restrictive file permissions
- Minimal error messages externally
- TLS for network communications

**Implementation**:
```python
# Sanitize sensitive data
def sanitize_for_alert(event: Event) -> Event:
    """Remove sensitive data before alerting."""
    sanitized = event.copy()
    sanitized.raw = redact_credentials(event.raw)
    return sanitized
```

### T6: Denial of Service

**Description**: LSM resource exhaustion prevents monitoring.

**Attack Vectors**:
- Log flooding to exhaust processing
- Process spawning to overwhelm monitor
- Memory exhaustion via large files

**STRIDE Category**: Denial of Service

**MITRE ATT&CK**: T1499 (Endpoint Denial of Service)

**Mitigations**:
- Rate limiting on event processing
- Resource limits and quotas
- Sampling under high load
- Alert on resource exhaustion

**Implementation**:
```python
# Rate limiting
class RateLimitedProcessor:
    def process(self, events: List[Event]) -> List[Event]:
        if len(events) > self.max_events_per_second:
            self.alert_high_volume()
            events = self.sample(events)
        return events
```

### T7: Spoofed Events

**Description**: Attacker injects false events to trigger false alerts.

**Attack Vectors**:
- Crafted log entries
- Fake process information
- Spoofed network connections

**STRIDE Category**: Spoofing

**MITRE ATT&CK**: T1036 (Masquerading)

**Mitigations**:
- Source verification where possible
- Anomaly detection for unusual patterns
- Correlation with multiple sources
- Alert fatigue monitoring

**Implementation**:
```python
# Multi-source verification
def verify_process_event(proc_event: Event) -> bool:
    """Verify process event against multiple sources."""
    # Check /proc directly
    # Verify against audit logs
    # Cross-reference with network activity
```

### T8: Supply Chain Attack

**Description**: Compromised dependencies introduce vulnerabilities.

**Attack Vectors**:
- Malicious Python packages
- Compromised update mechanism
- Tampered IOC databases

**STRIDE Category**: Tampering

**MITRE ATT&CK**: T1195 (Supply Chain Compromise)

**Mitigations**:
- Dependency pinning with hashes
- Signature verification for updates
- IOC database integrity checks
- Regular dependency auditing

**Implementation**:
```bash
# requirements.txt with hashes
pyyaml==6.0.1 \
    --hash=sha256:...

# Verify IOC database
def load_iocs(path: str) -> List[IOC]:
    verify_signature(path, expected_signature)
    verify_checksum(path, expected_hash)
```

## Security Controls Summary

| Control | Threats Addressed | Implementation |
|---------|-------------------|----------------|
| Input Validation | T4, T7 | `src/utils/validators.py` |
| Output Sanitization | T5 | `src/utils/sanitizers.py` |
| File Permissions | T2, T5 | Install script, docs |
| TLS Communication | T5 | Reporter configuration |
| Rate Limiting | T6 | Event handler |
| Multi-source Correlation | T1, T7 | Event handler |
| Integrity Monitoring | T2 | FIM self-monitoring |
| Dependency Pinning | T8 | requirements.txt |
| Audit Logging | All | Core functionality |

## Attack Trees

### Attack Tree: Disable Monitoring

```
Goal: Disable Security Monitoring
├── 1. Stop LSM Process
│   ├── 1.1 Kill process (requires root)
│   ├── 1.2 Stop systemd service (requires root)
│   └── 1.3 Resource exhaustion DoS
│
├── 2. Prevent Alert Delivery
│   ├── 2.1 Block network to SIEM
│   ├── 2.2 Modify reporter configuration
│   └── 2.3 Fill local storage
│
├── 3. Evade Detection
│   ├── 3.1 Use rootkit to hide activity
│   ├── 3.2 Operate during monitoring gaps
│   └── 3.3 Mimic legitimate behavior
│
└── 4. Corrupt Detection Logic
    ├── 4.1 Modify detection rules
    ├── 4.2 Poison baselines
    └── 4.3 Add suppression rules
```

### Attack Tree: Exploit LSM for Access

```
Goal: Gain System Access via LSM
├── 1. Exploit Vulnerabilities
│   ├── 1.1 Command injection via log parsing
│   ├── 1.2 Deserialization vulnerabilities
│   └── 1.3 Path traversal
│
├── 2. Abuse Elevated Privileges
│   ├── 2.1 Configuration file with malicious commands
│   ├── 2.2 Symbolic link attacks
│   └── 2.3 Race conditions in file operations
│
└── 3. Credential Theft
    ├── 3.1 Extract credentials from logs
    ├── 3.2 Capture webhook authentication
    └── 3.3 Access stored baselines
```

## Residual Risks

| Risk | Likelihood | Impact | Mitigation Status |
|------|------------|--------|-------------------|
| Kernel rootkit evasion | Low | High | Partially mitigated |
| Zero-day in dependencies | Low | High | Monitoring, updates |
| Insider with root access | Low | Critical | Logging, separation |
| Advanced persistent threats | Low | Critical | Defense in depth |

## Recommendations

### For Deployment
1. Run LSM on hardened systems
2. Use separate log aggregation
3. Implement network segmentation
4. Enable comprehensive audit logging
5. Regular security assessments

### For Development
1. Security code review for all changes
2. Dependency vulnerability scanning
3. Fuzzing for input parsers
4. Penetration testing annually
5. Bug bounty program consideration

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- STRIDE Threat Model: Microsoft SDL
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- CIS Controls: https://www.cisecurity.org/controls



