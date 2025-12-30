"""Integration tests for the monitoring pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import List

import pytest

from src.core.base_monitor import Event, EventSource, EventType, Severity
from src.core.event_handler import EventHandler, ProcessedEvent
from src.core.alert_manager import AlertManager
from src.analyzers.threat_analyzer import ThreatAnalyzer
from src.analyzers.mitre_mapper import MITREMapper
from src.reporters.console_reporter import ConsoleReporter


@pytest.fixture
def pipeline() -> tuple[EventHandler, AlertManager]:
    """Set up a test monitoring pipeline."""
    # Create components
    threat_analyzer = ThreatAnalyzer({"enabled": True})
    mitre_mapper = MITREMapper({"enabled": True})

    alert_manager = AlertManager(
        reporters=[],
        config={"severity_threshold": "LOW"},
    )

    event_handler = EventHandler(
        analyzers=[threat_analyzer, mitre_mapper],
        alert_manager=alert_manager,
    )

    return event_handler, alert_manager


class TestMonitoringPipeline:
    """Integration tests for event processing pipeline."""

    def test_event_flows_through_pipeline(
        self,
        pipeline: tuple[EventHandler, AlertManager],
    ) -> None:
        """Events should flow through the complete pipeline."""
        event_handler, alert_manager = pipeline

        event = Event(
            event_id="test-001",
            timestamp=datetime.now(),
            event_type=EventType.BRUTE_FORCE,
            severity=Severity.HIGH,
            source=EventSource(monitor="test", host="testhost"),
            description="Test brute force event",
        )

        result = event_handler.process(event)

        assert isinstance(result, ProcessedEvent)
        assert result.event.event_id == "test-001"
        assert len(result.analysis_results) > 0

    def test_high_severity_generates_alert(
        self,
        pipeline: tuple[EventHandler, AlertManager],
    ) -> None:
        """High severity events should generate alerts."""
        event_handler, alert_manager = pipeline

        initial_count = alert_manager._alerts_generated

        event = Event(
            event_id="test-002",
            timestamp=datetime.now(),
            event_type=EventType.PROCESS_SUSPICIOUS,
            severity=Severity.CRITICAL,
            source=EventSource(monitor="test", host="testhost"),
            description="Suspicious process detected",
        )

        event_handler.process(event)

        assert alert_manager._alerts_generated > initial_count

    def test_multiple_events_processed(
        self,
        pipeline: tuple[EventHandler, AlertManager],
    ) -> None:
        """Multiple events should be processed correctly."""
        event_handler, alert_manager = pipeline

        events = [
            Event(
                event_id=f"test-{i}",
                timestamp=datetime.now(),
                event_type=EventType.USER_LOGIN,
                severity=Severity.INFO,
                source=EventSource(monitor="test", host="testhost"),
                description=f"Test event {i}",
            )
            for i in range(5)
        ]

        results = event_handler.process_batch(events)

        assert len(results) == 5
        assert all(isinstance(r, ProcessedEvent) for r in results)

    def test_correlation_detects_patterns(
        self,
        pipeline: tuple[EventHandler, AlertManager],
    ) -> None:
        """Event correlation should detect patterns."""
        event_handler, _ = pipeline

        # Create events from same user
        from src.core.base_monitor import EventSubject

        events = [
            Event(
                event_id=f"test-{i}",
                timestamp=datetime.now(),
                event_type=EventType.AUTH_FAILURE,
                severity=Severity.MEDIUM,
                source=EventSource(monitor="test", host="testhost"),
                description="Auth failure",
                subject=EventSubject(user="attacker"),
            )
            for i in range(10)
        ]

        correlations = event_handler.correlate(events, window_seconds=300)

        assert len(correlations) > 0
        assert any(c["type"] == "user_activity" for c in correlations)



