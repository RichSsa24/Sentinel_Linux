# API Reference

## Core Module

### `src.core.base_monitor`

#### `BaseMonitor`

Abstract base class for all monitors.

```python
class BaseMonitor(ABC):
    """
    Abstract base class for security monitors.
    
    All monitor implementations must inherit from this class
    and implement the required abstract methods.
    
    Attributes:
        name: Monitor identifier string.
        config: Monitor-specific configuration dictionary.
        enabled: Whether the monitor is active.
        poll_interval: Seconds between collection cycles.
    """
    
    @abstractmethod
    def start(self) -> None:
        """
        Initialize and start the monitor.
        
        Raises:
            MonitorInitError: If initialization fails.
            PermissionError: If insufficient privileges.
        """
        
    @abstractmethod
    def stop(self) -> None:
        """
        Stop the monitor and cleanup resources.
        """
        
    @abstractmethod
    def collect(self) -> List[Event]:
        """
        Collect security events from the monitored source.
        
        Returns:
            List of Event objects representing detected activity.
            
        Raises:
            CollectionError: If data collection fails.
        """
        
    def get_status(self) -> MonitorStatus:
        """
        Get current monitor status.
        
        Returns:
            MonitorStatus with running state and statistics.
        """
```

### `src.core.event_handler`

#### `EventHandler`

Processes and routes events between components.

```python
class EventHandler:
    """
    Central event processing and routing.
    
    Handles event normalization, enrichment, and routing
    to appropriate analyzers and reporters.
    """
    
    def __init__(
        self,
        analyzers: List[BaseAnalyzer],
        reporters: List[BaseReporter],
        config: EventHandlerConfig
    ) -> None:
        """
        Initialize the event handler.
        
        Args:
            analyzers: List of analyzer instances.
            reporters: List of reporter instances.
            config: Handler configuration.
        """
        
    def process(self, event: Event) -> ProcessedEvent:
        """
        Process a single event through the pipeline.
        
        Args:
            event: Raw event from a monitor.
            
        Returns:
            ProcessedEvent with analysis results.
        """
        
    def process_batch(self, events: List[Event]) -> List[ProcessedEvent]:
        """
        Process multiple events efficiently.
        
        Args:
            events: List of raw events.
            
        Returns:
            List of processed events.
        """
        
    def normalize(self, event: Event) -> NormalizedEvent:
        """
        Normalize event to standard schema.
        
        Args:
            event: Raw event with source-specific format.
            
        Returns:
            Event normalized to common schema.
        """
        
    def enrich(self, event: NormalizedEvent) -> EnrichedEvent:
        """
        Add contextual information to event.
        
        Args:
            event: Normalized event.
            
        Returns:
            Event enriched with context (hostname, IP, etc.).
        """
```

### `src.core.alert_manager`

#### `AlertManager`

Manages alert generation and delivery.

```python
class AlertManager:
    """
    Manages alert lifecycle from generation to delivery.
    
    Handles deduplication, severity classification, and
    routing to appropriate reporters.
    """
    
    def __init__(
        self,
        reporters: List[BaseReporter],
        config: AlertConfig
    ) -> None:
        """
        Initialize alert manager.
        
        Args:
            reporters: List of reporter instances for delivery.
            config: Alert configuration.
        """
        
    def create_alert(self, event: ProcessedEvent) -> Optional[Alert]:
        """
        Create an alert from a processed event.
        
        Applies deduplication, rate limiting, and severity
        threshold filtering.
        
        Args:
            event: Processed event that triggered the alert.
            
        Returns:
            Alert object if thresholds met, None otherwise.
        """
        
    def send_alert(self, alert: Alert) -> List[DeliveryResult]:
        """
        Send alert to all configured reporters.
        
        Args:
            alert: Alert to deliver.
            
        Returns:
            List of delivery results from each reporter.
        """
        
    def suppress(
        self,
        pattern: str,
        duration: int,
        reason: str
    ) -> SuppressionRule:
        """
        Add temporary alert suppression rule.
        
        Args:
            pattern: Regex pattern to match against alerts.
            duration: Suppression duration in seconds.
            reason: Reason for suppression.
            
        Returns:
            Created suppression rule.
        """
```

### `src.core.exceptions`

Custom exception classes.

```python
class SecurityMonitorError(Exception):
    """Base exception for all security monitor errors."""

class ConfigurationError(SecurityMonitorError):
    """Invalid or missing configuration."""

class MonitorInitError(SecurityMonitorError):
    """Monitor failed to initialize."""

class CollectionError(SecurityMonitorError):
    """Data collection failed."""

class AnalysisError(SecurityMonitorError):
    """Analysis processing failed."""

class ReporterError(SecurityMonitorError):
    """Reporter failed to deliver."""

class ValidationError(SecurityMonitorError):
    """Input validation failed."""

class PermissionDeniedError(SecurityMonitorError):
    """Insufficient privileges for operation."""
```

---

## Monitors Module

### `src.monitors.user_monitor`

#### `UserMonitor`

Monitors user activity and authentication events.

```python
class UserMonitor(BaseMonitor):
    """
    Monitors user login, logout, and privilege escalation.
    
    Data sources:
    - /var/log/auth.log (Debian/Ubuntu)
    - /var/log/secure (RHEL/CentOS)
    - utmp, wtmp, lastlog
    
    Detected events:
    - User login (local, remote, su)
    - User logout
    - Privilege escalation (sudo, su)
    - Failed authentication
    """
    
    def __init__(self, config: UserMonitorConfig) -> None:
        """
        Initialize user monitor.
        
        Args:
            config: Monitor configuration with log paths and thresholds.
        """
        
    def get_current_users(self) -> List[UserSession]:
        """
        Get currently logged-in users.
        
        Returns:
            List of active user sessions.
        """
        
    def get_login_history(
        self,
        user: Optional[str] = None,
        since: Optional[datetime] = None
    ) -> List[LoginEvent]:
        """
        Get login history for user(s).
        
        Args:
            user: Filter by username (None for all users).
            since: Filter by time (None for all history).
            
        Returns:
            List of login events.
        """
```

### `src.monitors.process_monitor`

#### `ProcessMonitor`

Monitors process creation and behavior.

```python
class ProcessMonitor(BaseMonitor):
    """
    Monitors process activity and detects anomalies.
    
    Data sources:
    - /proc filesystem
    - Process audit events
    
    Detected events:
    - New process creation
    - Suspicious process paths
    - Process anomalies
    - Hidden processes
    """
    
    def __init__(self, config: ProcessMonitorConfig) -> None:
        """
        Initialize process monitor.
        
        Args:
            config: Configuration with baseline and thresholds.
        """
        
    def get_processes(self) -> List[ProcessInfo]:
        """
        Get list of running processes.
        
        Returns:
            List of process information objects.
        """
        
    def analyze_process(self, pid: int) -> ProcessAnalysis:
        """
        Perform detailed analysis of a specific process.
        
        Args:
            pid: Process ID to analyze.
            
        Returns:
            Detailed analysis including risk indicators.
            
        Raises:
            ProcessNotFoundError: If process doesn't exist.
        """
        
    def compare_to_baseline(
        self,
        processes: List[ProcessInfo]
    ) -> BaselineComparison:
        """
        Compare current processes against baseline.
        
        Args:
            processes: Current process list.
            
        Returns:
            Comparison with new, missing, and changed processes.
        """
```

### `src.monitors.network_monitor`

#### `NetworkMonitor`

Monitors network connections and traffic.

```python
class NetworkMonitor(BaseMonitor):
    """
    Monitors network connections and identifies suspicious activity.
    
    Data sources:
    - /proc/net/*
    - netstat/ss output
    - Connection state tables
    
    Detected events:
    - New listening ports
    - Outbound connections
    - Connection to known-bad IPs
    - Unusual protocols
    """
    
    def __init__(self, config: NetworkMonitorConfig) -> None:
        """
        Initialize network monitor.
        
        Args:
            config: Configuration with whitelist and thresholds.
        """
        
    def get_connections(
        self,
        state: Optional[ConnectionState] = None
    ) -> List[Connection]:
        """
        Get current network connections.
        
        Args:
            state: Filter by connection state.
            
        Returns:
            List of active connections.
        """
        
    def get_listeners(self) -> List[Listener]:
        """
        Get listening ports and their processes.
        
        Returns:
            List of listening services.
        """
```

### `src.monitors.file_integrity_monitor`

#### `FileIntegrityMonitor`

Monitors file system changes.

```python
class FileIntegrityMonitor(BaseMonitor):
    """
    Monitors file integrity using cryptographic hashes.
    
    Capabilities:
    - File content change detection
    - Permission change detection
    - Ownership change detection
    - New file detection
    - Deleted file detection
    
    Watched paths are configurable.
    """
    
    def __init__(self, config: FIMConfig) -> None:
        """
        Initialize FIM.
        
        Args:
            config: Configuration with paths and hash algorithm.
        """
        
    def create_baseline(
        self,
        paths: List[str]
    ) -> FileBaseline:
        """
        Create baseline of file hashes.
        
        Args:
            paths: List of paths to baseline.
            
        Returns:
            Baseline containing file hashes and metadata.
        """
        
    def check_integrity(
        self,
        baseline: FileBaseline
    ) -> IntegrityCheckResult:
        """
        Check files against baseline.
        
        Args:
            baseline: Previously created baseline.
            
        Returns:
            Result with changed, new, and deleted files.
        """
        
    def hash_file(self, path: str) -> FileHash:
        """
        Calculate hash of a file.
        
        Args:
            path: Path to file.
            
        Returns:
            FileHash with multiple hash algorithms.
            
        Raises:
            FileNotFoundError: If file doesn't exist.
            PermissionError: If file cannot be read.
        """
```

---

## Analyzers Module

### `src.analyzers.threat_analyzer`

#### `ThreatAnalyzer`

Analyzes events for threat indicators.

```python
class ThreatAnalyzer:
    """
    Rule-based threat detection engine.
    
    Supports:
    - Sigma rule format
    - Custom detection rules
    - Event correlation
    """
    
    def __init__(self, config: ThreatAnalyzerConfig) -> None:
        """
        Initialize threat analyzer.
        
        Args:
            config: Configuration with rules path.
        """
        
    def analyze(self, event: Event) -> ThreatAnalysisResult:
        """
        Analyze event for threat indicators.
        
        Args:
            event: Event to analyze.
            
        Returns:
            Analysis result with matched rules and score.
        """
        
    def load_rules(self, path: str) -> int:
        """
        Load detection rules from path.
        
        Args:
            path: Directory containing rule files.
            
        Returns:
            Number of rules loaded.
        """
        
    def correlate(
        self,
        events: List[Event],
        window: int
    ) -> List[CorrelatedThreat]:
        """
        Correlate multiple events to identify complex threats.
        
        Args:
            events: Events to correlate.
            window: Time window in seconds.
            
        Returns:
            List of correlated threat detections.
        """
```

### `src.analyzers.anomaly_detector`

#### `AnomalyDetector`

Statistical anomaly detection.

```python
class AnomalyDetector:
    """
    Detects statistical anomalies compared to baseline behavior.
    
    Methods:
    - Standard deviation analysis
    - Moving average comparison
    - Seasonal decomposition
    """
    
    def __init__(self, config: AnomalyDetectorConfig) -> None:
        """
        Initialize anomaly detector.
        
        Args:
            config: Configuration with sensitivity and baseline.
        """
        
    def analyze(self, event: Event) -> AnomalyResult:
        """
        Analyze event for anomalies.
        
        Args:
            event: Event to analyze.
            
        Returns:
            Result with anomaly score and indicators.
        """
        
    def update_baseline(self, events: List[Event]) -> None:
        """
        Update baseline with new events.
        
        Args:
            events: Events to add to baseline.
        """
        
    def get_anomaly_score(
        self,
        metric: str,
        value: float
    ) -> float:
        """
        Calculate anomaly score for a specific metric.
        
        Args:
            metric: Metric name.
            value: Current value.
            
        Returns:
            Anomaly score (0.0 = normal, 1.0 = highly anomalous).
        """
```

### `src.analyzers.ioc_matcher`

#### `IOCMatcher`

Matches against known Indicators of Compromise.

```python
class IOCMatcher:
    """
    Matches system artifacts against known IOCs.
    
    Supported IOC types:
    - IP addresses
    - Domain names
    - File hashes (MD5, SHA1, SHA256)
    - File paths
    - Process names
    - URLs
    """
    
    def __init__(self, config: IOCMatcherConfig) -> None:
        """
        Initialize IOC matcher.
        
        Args:
            config: Configuration with IOC database path.
        """
        
    def match(self, event: Event) -> List[IOCMatch]:
        """
        Check event for IOC matches.
        
        Args:
            event: Event to check.
            
        Returns:
            List of IOC matches found.
        """
        
    def add_ioc(self, ioc: IOC) -> None:
        """
        Add IOC to the database.
        
        Args:
            ioc: IOC to add.
        """
        
    def load_iocs(self, path: str) -> int:
        """
        Load IOCs from file.
        
        Args:
            path: Path to IOC file (JSON or CSV).
            
        Returns:
            Number of IOCs loaded.
        """
```

### `src.analyzers.mitre_mapper`

#### `MITREMapper`

Maps events to MITRE ATT&CK framework.

```python
class MITREMapper:
    """
    Maps detected threats to MITRE ATT&CK techniques.
    
    Provides:
    - Technique identification
    - Tactic context
    - Sub-technique mapping
    - ATT&CK Navigator export
    """
    
    def __init__(self, config: MITREMapperConfig) -> None:
        """
        Initialize MITRE mapper.
        
        Args:
            config: Configuration options.
        """
        
    def map(self, event: Event) -> List[MITRETechnique]:
        """
        Map event to ATT&CK techniques.
        
        Args:
            event: Event to map.
            
        Returns:
            List of mapped techniques.
        """
        
    def get_technique(self, technique_id: str) -> TechniqueDetails:
        """
        Get details for a specific technique.
        
        Args:
            technique_id: ATT&CK technique ID (e.g., T1059).
            
        Returns:
            Technique details including tactics and description.
        """
        
    def export_navigator(
        self,
        techniques: List[str]
    ) -> Dict[str, Any]:
        """
        Export techniques as ATT&CK Navigator layer.
        
        Args:
            techniques: List of technique IDs.
            
        Returns:
            Navigator layer JSON structure.
        """
```

---

## Reporters Module

### `src.reporters.console_reporter`

#### `ConsoleReporter`

Formats output for terminal display.

```python
class ConsoleReporter(BaseReporter):
    """
    Outputs alerts to the terminal with formatting.
    
    Features:
    - Color-coded severity
    - Structured output
    - Progress indicators
    """
    
    def report(self, alert: Alert) -> None:
        """
        Output alert to console.
        
        Args:
            alert: Alert to display.
        """
```

### `src.reporters.json_reporter`

#### `JSONReporter`

Outputs alerts as JSON.

```python
class JSONReporter(BaseReporter):
    """
    Writes alerts to JSON files.
    
    Features:
    - JSON Lines format
    - File rotation
    - Compression support
    """
    
    def report(self, alert: Alert) -> None:
        """
        Write alert to JSON file.
        
        Args:
            alert: Alert to write.
        """
        
    def flush(self) -> None:
        """Force write any buffered alerts."""
```

### `src.reporters.webhook_reporter`

#### `WebhookReporter`

Sends alerts to webhook endpoints.

```python
class WebhookReporter(BaseReporter):
    """
    Sends alerts to webhook endpoints.
    
    Features:
    - Template-based payloads
    - Retry logic
    - Rate limiting
    """
    
    async def report(self, alert: Alert) -> DeliveryResult:
        """
        Send alert to webhook.
        
        Args:
            alert: Alert to send.
            
        Returns:
            Delivery result with status.
        """
```

---

## Utils Module

### `src.utils.validators`

Input validation utilities.

```python
def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""

def validate_path(path: str, must_exist: bool = False) -> bool:
    """Validate file path."""

def validate_port(port: int) -> bool:
    """Validate port number (1-65535)."""

def validate_config(config: Dict[str, Any], schema: Dict[str, Any]) -> ValidationResult:
    """Validate configuration against schema."""
```

### `src.utils.sanitizers`

Data sanitization utilities.

```python
def sanitize_log_message(message: str) -> str:
    """Remove sensitive data from log messages."""

def sanitize_path(path: str) -> str:
    """Canonicalize and validate file path."""

def sanitize_command(command: str) -> str:
    """Sanitize command for safe logging."""
```

### `src.utils.crypto_utils`

Cryptographic utilities.

```python
def hash_file(path: str, algorithm: str = "sha256") -> str:
    """Calculate file hash."""

def hash_string(data: str, algorithm: str = "sha256") -> str:
    """Calculate string hash."""

def generate_event_id() -> str:
    """Generate unique event identifier."""

def verify_signature(data: bytes, signature: bytes, key: bytes) -> bool:
    """Verify HMAC signature."""
```

---

## Data Types

### Event

```python
@dataclass
class Event:
    event_id: str
    timestamp: datetime
    event_type: EventType
    severity: Severity
    source: EventSource
    subject: Optional[EventSubject]
    object: Optional[EventObject]
    raw: str
    metadata: Dict[str, Any]
```

### Alert

```python
@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    title: str
    description: str
    severity: Severity
    source_events: List[Event]
    mitre_techniques: List[str]
    ioc_matches: List[IOCMatch]
    recommendations: List[str]
```

### Severity

```python
class Severity(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
```



