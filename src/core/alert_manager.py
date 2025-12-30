"""
Alert manager for generating and delivering security alerts.

Handles:
- Alert generation from processed events
- Alert deduplication
- Rate limiting
- Delivery to configured reporters
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from src.config.logging_config import get_logger
from src.core.base_monitor import Severity

if TYPE_CHECKING:
    from src.core.event_handler import ProcessedEvent


logger = get_logger(__name__)


@dataclass
class Alert:
    """
    Represents a security alert generated from one or more events.

    Alerts are the output of the analysis pipeline, suitable
    for delivery to SOC analysts and SIEM systems.
    """

    alert_id: str
    timestamp: datetime
    title: str
    description: str
    severity: Severity
    source_events: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    ioc_matches: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    host: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "source_events": self.source_events,
            "mitre_techniques": self.mitre_techniques,
            "ioc_matches": self.ioc_matches,
            "recommendations": self.recommendations,
            "host": self.host,
            "metadata": self.metadata,
        }


@dataclass
class DeliveryResult:
    """Result of alert delivery to a reporter."""

    reporter: str
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None
    response: Optional[Dict[str, Any]] = None


@dataclass
class SuppressionRule:
    """Rule for suppressing alerts."""

    rule_id: str
    pattern: str
    expires_at: datetime
    reason: str
    created_at: datetime = field(default_factory=datetime.now)


class AlertManager:
    """
    Manages alert generation, deduplication, and delivery.

    Features:
    - Alert creation from processed events
    - Deduplication within configurable window
    - Rate limiting to prevent alert fatigue
    - Delivery to multiple reporters
    - Suppression rules
    """

    def __init__(
        self,
        reporters: Optional[List[Any]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the alert manager.

        Args:
            reporters: List of reporter instances.
            config: Alert configuration.
        """
        self.reporters = reporters or []
        self.config = config or {}

        self._severity_threshold = Severity[
            self.config.get("severity_threshold", "LOW")
        ]
        self._dedup_window = self.config.get("deduplication_window", 300)

        rate_limit_config = self.config.get("rate_limit", {})
        self._rate_limit_enabled = rate_limit_config.get("enabled", True)
        self._max_alerts_per_minute = rate_limit_config.get("max_alerts_per_minute", 60)

        self._alert_cache: Dict[str, datetime] = {}
        self._alert_counts: Dict[str, int] = defaultdict(int)
        self._suppression_rules: List[SuppressionRule] = []
        self._lock = threading.Lock()

        self._alerts_generated = 0
        self._alerts_deduplicated = 0
        self._alerts_rate_limited = 0
        self._alerts_suppressed = 0
        self._delivery_failures = 0

        logger.debug("AlertManager initialized")

    def add_reporter(self, reporter: Any) -> None:
        """
        Add a reporter for alert delivery.

        Args:
            reporter: Reporter instance with report() method.
        """
        self.reporters.append(reporter)
        logger.debug(f"Added reporter: {reporter.__class__.__name__}")

    def create_alert(self, processed_event: "ProcessedEvent") -> Optional[Alert]:
        """
        Create an alert from a processed event.

        Applies deduplication, rate limiting, and severity filtering.

        Args:
            processed_event: Processed event to create alert from.

        Returns:
            Alert if thresholds met, None otherwise.
        """
        event = processed_event.event

        # Check severity threshold
        if event.severity < self._severity_threshold:
            return None

        # Generate deduplication key
        dedup_key = self._generate_dedup_key(processed_event)

        with self._lock:
            # Check deduplication
            if self._is_duplicate(dedup_key):
                self._alerts_deduplicated += 1
                logger.debug(f"Alert deduplicated: {dedup_key[:16]}...")
                return None

            # Check rate limiting
            if self._is_rate_limited():
                self._alerts_rate_limited += 1
                logger.warning("Alert rate limit exceeded")
                return None

            # Check suppression rules
            if self._is_suppressed(processed_event):
                self._alerts_suppressed += 1
                logger.debug("Alert suppressed by rule")
                return None

            # Record this alert
            self._alert_cache[dedup_key] = datetime.now()
            self._alert_counts[self._get_minute_key()] += 1

        # Create the alert
        alert = self._build_alert(processed_event)
        self._alerts_generated += 1

        # Deliver to reporters
        self.send_alert(alert)

        return alert

    def send_alert(self, alert: Alert) -> List[DeliveryResult]:
        """
        Send alert to all configured reporters.

        Args:
            alert: Alert to deliver.

        Returns:
            List of delivery results.
        """
        results: List[DeliveryResult] = []

        for reporter in self.reporters:
            try:
                reporter.report(alert)
                results.append(DeliveryResult(
                    reporter=reporter.__class__.__name__,
                    success=True,
                ))
            except Exception as e:
                self._delivery_failures += 1
                logger.error(
                    f"Failed to deliver alert to {reporter.__class__.__name__}: {e}"
                )
                results.append(DeliveryResult(
                    reporter=reporter.__class__.__name__,
                    success=False,
                    error=str(e),
                ))

        return results

    def suppress(
        self,
        pattern: str,
        duration: int,
        reason: str,
    ) -> SuppressionRule:
        """
        Add a temporary alert suppression rule.

        Args:
            pattern: Regex pattern to match against alerts.
            duration: Suppression duration in seconds.
            reason: Reason for suppression.

        Returns:
            Created suppression rule.
        """
        import uuid

        rule = SuppressionRule(
            rule_id=str(uuid.uuid4()),
            pattern=pattern,
            expires_at=datetime.now() + timedelta(seconds=duration),
            reason=reason,
        )

        with self._lock:
            self._suppression_rules.append(rule)

        logger.info(f"Added suppression rule: {pattern} for {duration}s")
        return rule

    def remove_suppression(self, rule_id: str) -> bool:
        """
        Remove a suppression rule.

        Args:
            rule_id: ID of the rule to remove.

        Returns:
            True if rule was found and removed.
        """
        with self._lock:
            for i, rule in enumerate(self._suppression_rules):
                if rule.rule_id == rule_id:
                    del self._suppression_rules[i]
                    logger.info(f"Removed suppression rule: {rule_id}")
                    return True

        return False

    def _generate_dedup_key(self, processed_event: "ProcessedEvent") -> str:
        """Generate a deduplication key for the event."""
        event = processed_event.event

        key_parts = [
            event.event_type.value,
            event.source.host,
            event.subject.user if event.subject else "",
            event.object.path if event.object else "",
        ]

        key_string = "|".join(str(p) for p in key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_duplicate(self, dedup_key: str) -> bool:
        """Check if this alert is a duplicate."""
        if dedup_key not in self._alert_cache:
            return False

        last_seen = self._alert_cache[dedup_key]
        if datetime.now() - last_seen > timedelta(seconds=self._dedup_window):
            return False

        return True

    def _is_rate_limited(self) -> bool:
        """Check if rate limit is exceeded."""
        if not self._rate_limit_enabled:
            return False

        minute_key = self._get_minute_key()
        return self._alert_counts[minute_key] >= self._max_alerts_per_minute

    def _get_minute_key(self) -> str:
        """Get key for current minute for rate limiting."""
        now = datetime.now()
        return f"{now.year}{now.month}{now.day}{now.hour}{now.minute}"

    def _is_suppressed(self, processed_event: "ProcessedEvent") -> bool:
        """Check if event matches any suppression rules."""
        import re

        event = processed_event.event
        now = datetime.now()

        # Clean up expired rules
        self._suppression_rules = [
            r for r in self._suppression_rules if r.expires_at > now
        ]

        # Check active rules
        event_str = f"{event.event_type.value} {event.description}"
        for rule in self._suppression_rules:
            try:
                if re.search(rule.pattern, event_str):
                    return True
            except re.error:
                logger.warning(f"Invalid suppression pattern: {rule.pattern}")

        return False

    def _build_alert(self, processed_event: "ProcessedEvent") -> Alert:
        """Build an alert from a processed event."""
        import uuid

        event = processed_event.event

        # Determine title based on event type
        title = f"{event.severity.name}: {event.event_type.value.replace('_', ' ').title()}"

        # Build recommendations
        recommendations = self._get_recommendations(processed_event)

        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            title=title,
            description=event.description,
            severity=event.severity,
            source_events=[event.to_dict()],
            mitre_techniques=processed_event.all_mitre_techniques,
            ioc_matches=processed_event.all_ioc_matches,
            recommendations=recommendations,
            host=event.source.host,
            metadata={
                "threat_score": processed_event.max_threat_score,
                "processing_time_ms": processed_event.processing_time_ms,
                "enrichment": processed_event.enrichment,
            },
        )

    def _get_recommendations(self, processed_event: "ProcessedEvent") -> List[str]:
        """Get response recommendations for the event."""
        recommendations: List[str] = []
        event = processed_event.event

        if event.event_type.value.startswith("auth_"):
            recommendations.extend([
                "Review authentication logs for related activity",
                "Check for other failed authentication attempts from same source",
                "Consider implementing account lockout if not already configured",
            ])

        if event.event_type.value.startswith("process_"):
            recommendations.extend([
                "Investigate the process and its parent process tree",
                "Check for persistence mechanisms",
                "Review process network connections",
            ])

        if event.event_type.value.startswith("network_"):
            recommendations.extend([
                "Review network traffic patterns",
                "Check for data exfiltration indicators",
                "Consider blocking suspicious IP addresses",
            ])

        if event.event_type.value.startswith("file_"):
            recommendations.extend([
                "Review file change history",
                "Check for unauthorized modifications",
                "Verify file integrity against known good baseline",
            ])

        if processed_event.all_ioc_matches:
            recommendations.append(
                "IOC match detected - prioritize investigation"
            )

        if processed_event.all_mitre_techniques:
            recommendations.append(
                f"MITRE techniques identified: {', '.join(processed_event.all_mitre_techniques)}"
            )

        return recommendations

    def cleanup_cache(self) -> int:
        """
        Clean up expired entries from caches.

        Returns:
            Number of entries removed.
        """
        removed = 0
        now = datetime.now()
        cutoff = now - timedelta(seconds=self._dedup_window)

        with self._lock:
            expired_keys = [
                k for k, v in self._alert_cache.items() if v < cutoff
            ]
            for key in expired_keys:
                del self._alert_cache[key]
                removed += 1

            # Clean up old minute counters
            current_minute = self._get_minute_key()
            old_keys = [k for k in self._alert_counts if k != current_minute]
            for key in old_keys:
                del self._alert_counts[key]

        return removed

    def get_stats(self) -> Dict[str, Any]:
        """
        Get alert manager statistics.

        Returns:
            Dictionary of statistics.
        """
        with self._lock:
            return {
                "alerts_generated": self._alerts_generated,
                "alerts_deduplicated": self._alerts_deduplicated,
                "alerts_rate_limited": self._alerts_rate_limited,
                "alerts_suppressed": self._alerts_suppressed,
                "delivery_failures": self._delivery_failures,
                "active_suppression_rules": len(self._suppression_rules),
                "cache_size": len(self._alert_cache),
                "reporters_count": len(self.reporters),
            }



