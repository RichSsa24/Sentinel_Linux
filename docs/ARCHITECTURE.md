# Architecture Documentation

## System Overview

Linux Security Monitor is designed as a modular, extensible security monitoring framework. The architecture follows a pipeline pattern where data flows from collection through analysis to reporting.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Linux Security Monitor                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Monitors   │───▶│   Analyzers  │───▶│  Reporters   │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│         │                   │                   │                        │
│         ▼                   ▼                   ▼                        │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │ Event Handler│───▶│Alert Manager │───▶│   Output     │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Monitors Layer

Monitors are responsible for collecting security-relevant data from various system sources.

```
┌─────────────────────────────────────────────────────────────────┐
│                        BaseMonitor (ABC)                         │
├─────────────────────────────────────────────────────────────────┤
│ + start() -> None                                                │
│ + stop() -> None                                                 │
│ + collect() -> List[Event]                                       │
│ + get_status() -> MonitorStatus                                  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────┴───────┐   ┌────────┴────────┐   ┌───────┴───────┐
│  UserMonitor  │   │ ProcessMonitor  │   │NetworkMonitor │
├───────────────┤   ├─────────────────┤   ├───────────────┤
│ - auth_log    │   │ - proc_fs       │   │ - connections │
│ - wtmp        │   │ - baseline      │   │ - listeners   │
│ - lastlog     │   │ - thresholds    │   │ - dns_queries │
└───────────────┘   └─────────────────┘   └───────────────┘
        │                     │                     │
        ├─────────────────────┼─────────────────────┤
        │                     │                     │
┌───────┴───────┐   ┌────────┴────────┐   ┌───────┴───────┐
│  AuthMonitor  │   │ ServiceMonitor  │   │  FIMMonitor   │
├───────────────┤   ├─────────────────┤   ├───────────────┤
│ - pam_events  │   │ - systemd       │   │ - watched_dirs│
│ - sudo_logs   │   │ - init_scripts  │   │ - hashes      │
│ - ssh_events  │   │ - cron_jobs     │   │ - permissions │
└───────────────┘   └─────────────────┘   └───────────────┘
```

#### Monitor Responsibilities

| Monitor | Data Sources | Events Generated |
|---------|--------------|------------------|
| UserMonitor | `/var/log/auth.log`, `utmp`, `wtmp` | Login, logout, privilege escalation |
| ProcessMonitor | `/proc`, process table | New process, suspicious execution |
| NetworkMonitor | `netstat`, `ss`, `/proc/net` | New connection, suspicious port |
| AuthMonitor | PAM logs, sudo logs | Auth failure, brute force |
| ServiceMonitor | systemd, init scripts | Service start/stop, new service |
| FIMMonitor | Configured directories | File change, permission change |
| LogMonitor | Syslog, application logs | Pattern match, anomaly |

### 2. Analyzers Layer

Analyzers process events from monitors to identify threats and anomalies.

```
┌─────────────────────────────────────────────────────────────────┐
│                       Analysis Pipeline                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Events ──▶ ┌────────────────┐                                 │
│              │ ThreatAnalyzer │──▶ Threat Events                │
│              └────────────────┘                                 │
│                      │                                           │
│                      ▼                                           │
│              ┌────────────────┐                                 │
│              │AnomalyDetector │──▶ Anomaly Scores               │
│              └────────────────┘                                 │
│                      │                                           │
│                      ▼                                           │
│              ┌────────────────┐                                 │
│              │  IOC Matcher   │──▶ IOC Matches                  │
│              └────────────────┘                                 │
│                      │                                           │
│                      ▼                                           │
│              ┌────────────────┐                                 │
│              │ MITRE Mapper   │──▶ Technique IDs                │
│              └────────────────┘                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Analysis Components

**ThreatAnalyzer**
- Rule-based detection using Sigma-compatible rules
- Correlation of multiple events
- Threshold-based alerting

**AnomalyDetector**
- Statistical baseline comparison
- Time-series analysis
- Behavioral profiling

**IOCMatcher**
- Hash matching (MD5, SHA256)
- IP/Domain matching
- File path pattern matching
- Registry of known bad indicators

**MITREMapper**
- Maps detected threats to ATT&CK techniques
- Provides tactic context
- Enables threat intelligence integration

### 3. Reporters Layer

Reporters format and deliver alerts and reports to various destinations.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Reporter System                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│              ┌────────────────┐                                 │
│   Alerts ──▶ │ AlertManager   │                                 │
│              └───────┬────────┘                                 │
│                      │                                           │
│         ┌────────────┼────────────┬────────────┐                │
│         ▼            ▼            ▼            ▼                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Console  │ │   JSON   │ │  Syslog  │ │ Webhook  │          │
│  │ Reporter │ │ Reporter │ │ Reporter │ │ Reporter │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│       │            │            │            │                  │
│       ▼            ▼            ▼            ▼                  │
│   Terminal      Files      Syslog       Slack/                 │
│   Output        (.json)    Server      Teams/etc               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Core Components

#### Event Handler

Central event processing and routing:

```python
class EventHandler:
    """
    Processes events from monitors and routes to analyzers.
    
    Responsibilities:
    - Event normalization
    - Event enrichment
    - Event correlation
    - Routing to appropriate analyzers
    """
```

#### Alert Manager

Manages alert lifecycle:

```python
class AlertManager:
    """
    Manages alert generation and delivery.
    
    Responsibilities:
    - Alert deduplication
    - Severity classification
    - Alert routing to reporters
    - Alert state management
    """
```

## Data Flow

### Event Processing Pipeline

```
1. Collection
   Monitor.collect() → Raw Events

2. Normalization
   EventHandler.normalize() → Normalized Events
   
3. Enrichment
   EventHandler.enrich() → Enriched Events
   - Add hostname, timestamp
   - Add user context
   - Add process context

4. Analysis
   Analyzer.analyze() → Analysis Results
   - Threat detection
   - Anomaly scoring
   - IOC matching

5. Alert Generation
   AlertManager.process() → Alerts
   - Threshold evaluation
   - Deduplication
   - Severity assignment

6. Reporting
   Reporter.report() → Output
   - Format conversion
   - Delivery to destinations
```

### Event Schema

```json
{
    "event_id": "uuid",
    "timestamp": "ISO8601",
    "event_type": "string",
    "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
    "source": {
        "monitor": "string",
        "host": "string",
        "ip": "string"
    },
    "subject": {
        "user": "string",
        "process": "string",
        "pid": "integer"
    },
    "object": {
        "type": "file|process|network|user",
        "path": "string",
        "details": {}
    },
    "analysis": {
        "threat_score": "float",
        "anomaly_score": "float",
        "ioc_matches": [],
        "mitre_techniques": []
    },
    "raw": "string"
}
```

## Configuration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Configuration System                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                                               │
│  │ Environment  │──┐                                            │
│  │  Variables   │  │                                            │
│  └──────────────┘  │    ┌────────────────┐                     │
│                    ├───▶│    Settings    │                     │
│  ┌──────────────┐  │    │    Manager     │                     │
│  │  YAML Files  │──┤    └───────┬────────┘                     │
│  └──────────────┘  │            │                               │
│                    │            ▼                               │
│  ┌──────────────┐  │    ┌────────────────┐                     │
│  │   Defaults   │──┘    │  Pydantic      │                     │
│  └──────────────┘       │  Validation    │                     │
│                         └────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Configuration precedence (highest to lowest):
1. Command-line arguments
2. Environment variables
3. User configuration file
4. Default configuration

## Security Architecture

### Privilege Separation

```
┌─────────────────────────────────────────────────────────────────┐
│                   Privilege Model                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────┐    │
│  │                    Root Process                         │    │
│  │  - Monitor initialization                               │    │
│  │  - Privileged data collection                          │    │
│  └───────────────────────┬────────────────────────────────┘    │
│                          │                                      │
│                          ▼                                      │
│  ┌────────────────────────────────────────────────────────┐    │
│  │              Unprivileged Workers                       │    │
│  │  - Event processing                                     │    │
│  │  - Analysis                                             │    │
│  │  - Reporting                                            │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Input Validation

All external inputs are validated:

```
External Input ──▶ Validator ──▶ Sanitizer ──▶ Internal Use
                      │              │
                      ▼              ▼
                   Reject         Escape/
                   Invalid        Normalize
```

## Deployment Architecture

### Standalone Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                        Linux Host                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Linux Security Monitor                       │  │
│  │                                                           │  │
│  │  Monitors ──▶ Analyzers ──▶ Reporters ──▶ Local Output   │  │
│  │                                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### SIEM Integration

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Linux Host 1  │     │   Linux Host 2  │     │   Linux Host N  │
│                 │     │                 │     │                 │
│  ┌───────────┐  │     │  ┌───────────┐  │     │  ┌───────────┐  │
│  │    LSM    │  │     │  │    LSM    │  │     │  │    LSM    │  │
│  └─────┬─────┘  │     │  └─────┬─────┘  │     │  └─────┬─────┘  │
└────────┼────────┘     └────────┼────────┘     └────────┼────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │      SIEM Platform     │
                    │  (Splunk/ELK/QRadar)   │
                    └────────────────────────┘
```

## Extension Points

### Custom Monitors

```python
from src.core.base_monitor import BaseMonitor

class CustomMonitor(BaseMonitor):
    """Implement custom monitoring logic."""
    
    def collect(self) -> List[Event]:
        # Custom collection logic
        pass
```

### Custom Analyzers

```python
from src.analyzers.base import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    """Implement custom analysis logic."""
    
    def analyze(self, event: Event) -> AnalysisResult:
        # Custom analysis logic
        pass
```

### Custom Reporters

```python
from src.reporters.base import BaseReporter

class CustomReporter(BaseReporter):
    """Implement custom reporting logic."""
    
    def report(self, alert: Alert) -> None:
        # Custom reporting logic
        pass
```

## Performance Considerations

### Resource Limits

| Component | CPU Target | Memory Target |
|-----------|------------|---------------|
| Monitors | < 5% per monitor | < 50MB per monitor |
| Analyzers | < 10% total | < 200MB total |
| Reporters | < 2% total | < 50MB total |

### Scalability

- Event batching for high-volume environments
- Configurable sampling for resource-constrained systems
- Async I/O for network operations
- Connection pooling for SIEM integration

## Dependencies

### Runtime Dependencies

```
psutil >= 5.9.0      # Process and system monitoring
watchdog >= 3.0.0    # File system monitoring
pyyaml >= 6.0        # Configuration parsing
cryptography >= 41.0 # Secure hashing
aiohttp >= 3.9       # Async HTTP client
pydantic >= 2.5      # Data validation
```

### Optional Dependencies

```
yara-python >= 4.3   # YARA rule support
```

## Testing Architecture

```
tests/
├── unit/           # Unit tests for individual components
├── integration/    # Integration tests for component interaction
└── security/       # Security-focused tests
```

Test coverage targets:
- Unit tests: 80% minimum
- Integration tests: Critical paths
- Security tests: All input validation



