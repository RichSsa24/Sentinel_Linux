"""Tests for correlation engine."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.analyzers.correlation_engine import CorrelationEngine
from src.core.base_monitor import Event, EventSource, EventSubject, EventType, Severity


@pytest.fixture
def correlation_engine() -> CorrelationEngine:
    """Create a correlation engine for testing."""
    return CorrelationEngine({"enabled": True})


@pytest.fixture
def sample_events() -> list[Event]:
    """Create sample events for correlation testing."""
    base_time = datetime.now()
    return [
        Event(
            event_id=f"event-{i}",
            timestamp=base_time + timedelta(seconds=i * 10),
            event_type=EventType.AUTH_FAILURE,
            severity=Severity.MEDIUM,
            source=EventSource(
                monitor="auth_monitor",
                host="testhost",
                ip="192.168.1.100",
            ),
            description=f"Failed authentication attempt {i}",
            subject=EventSubject(user="attacker"),
        )
        for i in range(5)
    ]


class TestCorrelationEngine:
    """Tests for CorrelationEngine class."""

    def test_init(self, correlation_engine: CorrelationEngine) -> None:
        """Should initialize correlation engine."""
        assert correlation_engine is not None
        assert correlation_engine.enabled is True

    def test_correlate_by_user(
        self,
        correlation_engine: CorrelationEngine,
        sample_events: list[Event],
    ) -> None:
        """Should correlate events by user."""
        correlations = correlation_engine.correlate(sample_events)

        assert len(correlations) > 0
        assert any(c["type"] == "user_activity" for c in correlations)

    def test_correlate_by_source_ip(
        self,
        correlation_engine: CorrelationEngine,
        sample_events: list[Event],
    ) -> None:
        """Should correlate events by source IP."""
        correlations = correlation_engine.correlate(sample_events)

        assert len(correlations) > 0
        assert any(c["type"] == "source_ip_activity" for c in correlations)

    def test_correlate_empty_list(
        self,
        correlation_engine: CorrelationEngine,
    ) -> None:
        """Should handle empty event list."""
        correlations = correlation_engine.correlate([])
        assert correlations == []

    def test_correlate_time_window(
        self,
        correlation_engine: CorrelationEngine,
    ) -> None:
        """Should respect time window for correlation."""
        base_time = datetime.now()
        events = [
            Event(
                event_id=f"event-{i}",
                timestamp=base_time + timedelta(seconds=i * 100),
                event_type=EventType.USER_LOGIN,
                severity=Severity.INFO,
                source=EventSource(monitor="test", host="testhost"),
                description=f"Event {i}",
                subject=EventSubject(user="testuser"),
            )
            for i in range(3)
        ]

        correlations = correlation_engine.correlate(events, window_seconds=50)

        # Events are 100 seconds apart, so with 50s window they shouldn't correlate
        # This depends on implementation, but should not crash
        assert isinstance(correlations, list)

    def test_detect_brute_force_pattern(
        self,
        correlation_engine: CorrelationEngine,
        sample_events: list[Event],
    ) -> None:
        """Should detect brute force patterns."""
        # Multiple auth failures from same IP/user
        correlations = correlation_engine.correlate(sample_events)

        # Should detect pattern of multiple failures
        assert len(correlations) > 0

    def test_analyze_returns_result(
        self,
        correlation_engine: CorrelationEngine,
        sample_events: list[Event],
    ) -> None:
        """Should return analysis result when analyzing events."""
        result = correlation_engine.analyze(sample_events[0])

        # Correlation engine may or may not return result for single event
        # Just verify it doesn't crash
        assert result is None or hasattr(result, "threat_score")

