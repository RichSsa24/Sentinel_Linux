"""Tests for threat analyzer."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.analyzers.threat_analyzer import ThreatAnalyzer, DetectionRule
from src.core.base_monitor import Event, EventSource, EventType, Severity


@pytest.fixture
def threat_analyzer() -> ThreatAnalyzer:
    """Create a threat analyzer for testing."""
    return ThreatAnalyzer({"enabled": True})


@pytest.fixture
def brute_force_event() -> Event:
    """Create a brute force event for testing."""
    return Event(
        event_id="test-001",
        timestamp=datetime.now(),
        event_type=EventType.BRUTE_FORCE,
        severity=Severity.CRITICAL,
        source=EventSource(monitor="auth_monitor", host="testhost"),
        description="Brute force detected",
    )


@pytest.fixture
def login_event() -> Event:
    """Create a login event for testing."""
    return Event(
        event_id="test-002",
        timestamp=datetime.now(),
        event_type=EventType.USER_LOGIN,
        severity=Severity.MEDIUM,
        source=EventSource(monitor="user_monitor", host="testhost"),
        description="User login",
    )


class TestThreatAnalyzer:
    """Tests for ThreatAnalyzer class."""

    def test_init_loads_builtin_rules(self, threat_analyzer: ThreatAnalyzer) -> None:
        """Should load built-in rules on initialization."""
        assert len(threat_analyzer.rules) > 0

    def test_analyze_brute_force(
        self,
        threat_analyzer: ThreatAnalyzer,
        brute_force_event: Event,
    ) -> None:
        """Should detect brute force events."""
        result = threat_analyzer.analyze(brute_force_event)

        assert result is not None
        assert result.threat_score > 0
        assert "T1110" in result.mitre_techniques

    def test_analyze_login_event(
        self,
        threat_analyzer: ThreatAnalyzer,
        login_event: Event,
    ) -> None:
        """Should analyze login events."""
        result = threat_analyzer.analyze(login_event)
        # May or may not match depending on rules
        # Just verify it doesn't crash

    def test_add_custom_rule(self, threat_analyzer: ThreatAnalyzer) -> None:
        """Should allow adding custom rules."""
        initial_count = len(threat_analyzer.rules)

        rule = DetectionRule(
            id="custom-001",
            title="Custom Rule",
            description="Test rule",
            severity=Severity.HIGH,
            detection={"event_type": "test"},
        )
        threat_analyzer.add_rule(rule)

        assert len(threat_analyzer.rules) == initial_count + 1

    def test_get_rules(self, threat_analyzer: ThreatAnalyzer) -> None:
        """Should return list of rules."""
        rules = threat_analyzer.get_rules()

        assert isinstance(rules, list)
        assert len(rules) > 0
        assert "id" in rules[0]
        assert "title" in rules[0]



