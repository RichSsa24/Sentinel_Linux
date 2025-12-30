"""
Event handler for processing and routing security events.

Provides centralized event processing with:
- Event normalization
- Event enrichment
- Routing to analyzers
- Event correlation
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from src.config.logging_config import get_logger
from src.core.base_monitor import Event, Severity

if TYPE_CHECKING:
    from src.core.alert_manager import AlertManager


logger = get_logger(__name__)


@dataclass
class AnalysisResult:
    """Result from an analyzer."""

    analyzer_name: str
    threat_score: float = 0.0
    anomaly_score: float = 0.0
    ioc_matches: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessedEvent:
    """An event that has been processed through the analysis pipeline."""

    event: Event
    analysis_results: List[AnalysisResult] = field(default_factory=list)
    enrichment: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: float = 0.0

    @property
    def max_threat_score(self) -> float:
        """Get maximum threat score from all analyzers."""
        if not self.analysis_results:
            return 0.0
        return max(r.threat_score for r in self.analysis_results)

    @property
    def all_mitre_techniques(self) -> List[str]:
        """Get all MITRE techniques from all analyzers."""
        techniques = []
        for result in self.analysis_results:
            techniques.extend(result.mitre_techniques)
        return list(set(techniques))

    @property
    def all_ioc_matches(self) -> List[str]:
        """Get all IOC matches from all analyzers."""
        matches = []
        for result in self.analysis_results:
            matches.extend(result.ioc_matches)
        return list(set(matches))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event": self.event.to_dict(),
            "analysis_results": [
                {
                    "analyzer": r.analyzer_name,
                    "threat_score": r.threat_score,
                    "anomaly_score": r.anomaly_score,
                    "ioc_matches": r.ioc_matches,
                    "mitre_techniques": r.mitre_techniques,
                    "findings": r.findings,
                }
                for r in self.analysis_results
            ],
            "enrichment": self.enrichment,
            "processing_time_ms": self.processing_time_ms,
        }


class EventHandler:
    """
    Central event processing and routing component.

    Handles:
    - Event normalization and validation
    - Event enrichment with context
    - Routing to configured analyzers
    - Event correlation
    - Alert generation
    """

    def __init__(
        self,
        analyzers: Optional[List[Any]] = None,
        alert_manager: Optional["AlertManager"] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the event handler.

        Args:
            analyzers: List of analyzer instances.
            alert_manager: Alert manager for generating alerts.
            config: Handler configuration.
        """
        self.analyzers = analyzers or []
        self.alert_manager = alert_manager
        self.config = config or {}

        self._hostname = self._get_hostname()
        self._local_ips = self._get_local_ips()

        self._event_callbacks: List[Callable[[ProcessedEvent], None]] = []
        self._events_processed = 0
        self._processing_errors = 0

        logger.debug("EventHandler initialized")

    def _get_hostname(self) -> str:
        """Get system hostname."""
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    def _get_local_ips(self) -> List[str]:
        """Get local IP addresses."""
        ips = ["127.0.0.1", "::1"]
        try:
            hostname = socket.gethostname()
            ips.extend(socket.gethostbyname_ex(hostname)[2])
        except Exception:
            pass
        return ips

    def add_analyzer(self, analyzer: Any) -> None:
        """
        Add an analyzer to the processing pipeline.

        Args:
            analyzer: Analyzer instance with analyze() method.
        """
        self.analyzers.append(analyzer)
        logger.debug(f"Added analyzer: {analyzer.__class__.__name__}")

    def add_callback(self, callback: Callable[[ProcessedEvent], None]) -> None:
        """
        Add a callback for processed events.

        Args:
            callback: Function called with each processed event.
        """
        self._event_callbacks.append(callback)

    def process(self, event: Event) -> ProcessedEvent:
        """
        Process a single event through the pipeline.

        Args:
            event: Raw event from a monitor.

        Returns:
            ProcessedEvent with analysis results.
        """
        start_time = datetime.now()

        try:
            # Enrich the event
            enrichment = self._enrich(event)

            # Run through analyzers
            analysis_results = []
            for analyzer in self.analyzers:
                try:
                    result = analyzer.analyze(event)
                    if result:
                        analysis_results.append(result)
                except Exception as e:
                    logger.warning(
                        f"Analyzer {analyzer.__class__.__name__} failed: {e}"
                    )

            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds() * 1000

            processed = ProcessedEvent(
                event=event,
                analysis_results=analysis_results,
                enrichment=enrichment,
                processing_time_ms=processing_time,
            )

            self._events_processed += 1

            # Notify callbacks
            for callback in self._event_callbacks:
                try:
                    callback(processed)
                except Exception as e:
                    logger.error(f"Event callback failed: {e}")

            # Check if alert should be generated
            if self.alert_manager:
                self._check_alert(processed)

            return processed

        except Exception as e:
            self._processing_errors += 1
            logger.error(f"Event processing failed: {e}", exc_info=True)
            raise

    def process_batch(self, events: List[Event]) -> List[ProcessedEvent]:
        """
        Process multiple events.

        Args:
            events: List of raw events.

        Returns:
            List of processed events.
        """
        return [self.process(event) for event in events]

    def _enrich(self, event: Event) -> Dict[str, Any]:
        """
        Enrich event with additional context.

        Args:
            event: Event to enrich.

        Returns:
            Dictionary of enrichment data.
        """
        enrichment: Dict[str, Any] = {
            "processed_at": datetime.now().isoformat(),
            "processor_host": self._hostname,
        }

        # Add geolocation for IPs (placeholder)
        if event.source.ip and event.source.ip not in self._local_ips:
            enrichment["source_geo"] = {"note": "Geolocation lookup placeholder"}

        # Add user context
        if event.subject and event.subject.user:
            enrichment["user_context"] = self._get_user_context(event.subject.user)

        # Add process context
        if event.subject and event.subject.pid:
            enrichment["process_context"] = self._get_process_context(event.subject.pid)

        return enrichment

    def _get_user_context(self, username: str) -> Dict[str, Any]:
        """
        Get additional context about a user.

        Args:
            username: Username to look up.

        Returns:
            Dictionary of user context.
        """
        context: Dict[str, Any] = {"username": username}

        try:
            import pwd
            pw_entry = pwd.getpwnam(username)
            context.update({
                "uid": pw_entry.pw_uid,
                "gid": pw_entry.pw_gid,
                "home": pw_entry.pw_dir,
                "shell": pw_entry.pw_shell,
            })
        except (ImportError, KeyError):
            pass

        return context

    def _get_process_context(self, pid: int) -> Dict[str, Any]:
        """
        Get additional context about a process.

        Args:
            pid: Process ID to look up.

        Returns:
            Dictionary of process context.
        """
        context: Dict[str, Any] = {"pid": pid}

        try:
            import psutil
            proc = psutil.Process(pid)
            context.update({
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": proc.cmdline(),
                "username": proc.username(),
                "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
            })
        except Exception:
            pass

        return context

    def _check_alert(self, processed: ProcessedEvent) -> None:
        """
        Check if an alert should be generated for this event.

        Args:
            processed: Processed event to check.
        """
        if not self.alert_manager:
            return

        # Alert on high severity events
        if processed.event.severity >= Severity.HIGH:
            self.alert_manager.create_alert(processed)
            return

        # Alert on high threat scores
        if processed.max_threat_score >= 0.7:
            self.alert_manager.create_alert(processed)
            return

        # Alert on IOC matches
        if processed.all_ioc_matches:
            self.alert_manager.create_alert(processed)
            return

    def correlate(
        self,
        events: List[Event],
        window_seconds: int = 300,
    ) -> List[Dict[str, Any]]:
        """
        Correlate events to identify related activity.

        Args:
            events: Events to correlate.
            window_seconds: Time window for correlation.

        Returns:
            List of correlated event groups.
        """
        if not events:
            return []

        # Group events by various criteria
        correlations: List[Dict[str, Any]] = []

        # Correlate by user
        user_events: Dict[str, List[Event]] = {}
        for event in events:
            if event.subject and event.subject.user:
                user = event.subject.user
                if user not in user_events:
                    user_events[user] = []
                user_events[user].append(event)

        for user, user_event_list in user_events.items():
            if len(user_event_list) > 1:
                correlations.append({
                    "type": "user_activity",
                    "user": user,
                    "event_count": len(user_event_list),
                    "event_types": list(set(e.event_type.value for e in user_event_list)),
                    "time_span_seconds": self._calculate_time_span(user_event_list),
                })

        # Correlate by source IP
        ip_events: Dict[str, List[Event]] = {}
        for event in events:
            if event.source.ip:
                ip = event.source.ip
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event)

        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) > 1:
                correlations.append({
                    "type": "source_ip_activity",
                    "ip": ip,
                    "event_count": len(ip_event_list),
                    "event_types": list(set(e.event_type.value for e in ip_event_list)),
                    "time_span_seconds": self._calculate_time_span(ip_event_list),
                })

        return correlations

    def _calculate_time_span(self, events: List[Event]) -> float:
        """Calculate time span between first and last event."""
        if len(events) < 2:
            return 0.0

        timestamps = [e.timestamp for e in events]
        return (max(timestamps) - min(timestamps)).total_seconds()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get handler statistics.

        Returns:
            Dictionary of statistics.
        """
        return {
            "events_processed": self._events_processed,
            "processing_errors": self._processing_errors,
            "analyzer_count": len(self.analyzers),
            "callback_count": len(self._event_callbacks),
        }



