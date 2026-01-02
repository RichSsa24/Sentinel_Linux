"""
Pytest configuration and fixtures for Linux Security Monitor tests.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List

import pytest

from src.core.base_monitor import Event, EventSource, EventSubject, EventType, Severity
from src.core.alert_manager import Alert


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_event() -> Event:
    """Create a sample event for testing."""
    return Event(
        event_id="test-event-001",
        timestamp=datetime.now(),
        event_type=EventType.USER_LOGIN,
        severity=Severity.MEDIUM,
        source=EventSource(
            monitor="test_monitor",
            host="testhost",
            ip="192.168.1.100",
        ),
        description="Test user login event",
        raw="test raw log line",
        subject=EventSubject(
            user="testuser",
            pid=12345,
        ),
    )


@pytest.fixture
def sample_alert(sample_event: Event) -> Alert:
    """Create a sample alert for testing."""
    return Alert(
        alert_id="test-alert-001",
        timestamp=datetime.now(),
        title="Test Alert",
        description="This is a test alert",
        severity=Severity.HIGH,
        source_events=[sample_event.to_dict()],
        mitre_techniques=["T1078"],
        ioc_matches=[],
        recommendations=["Review the activity"],
        host="testhost",
    )


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Create a mock configuration for testing."""
    return {
        "enabled": True,
        "poll_interval": 60,
    }


@pytest.fixture
def sample_auth_log(temp_dir: Path) -> Path:
    """Create a sample auth.log file for testing."""
    log_file = temp_dir / "auth.log"

    log_lines = [
        (
            "Dec 14 10:30:00 testhost sshd[1234]: "
            "Accepted publickey for testuser from 192.168.1.100 port 22 ssh2"
        ),
        (
            "Dec 14 10:31:00 testhost sshd[1235]: "
            "Failed password for invalid user baduser from 10.0.0.1 port 22"
        ),
        (
            "Dec 14 10:32:00 testhost sudo: testuser : "
            "TTY=pts/0 ; PWD=/home/testuser ; COMMAND=/bin/ls"
        ),
    ]

    log_file.write_text("\n".join(log_lines))
    return log_file


@pytest.fixture
def sample_processes() -> List[Dict[str, Any]]:
    """Create sample process data for testing."""
    return [
        {
            "pid": 1,
            "name": "systemd",
            "exe": "/usr/lib/systemd/systemd",
            "username": "root",
            "status": "sleeping",
        },
        {
            "pid": 1234,
            "name": "sshd",
            "exe": "/usr/sbin/sshd",
            "username": "root",
            "status": "sleeping",
        },
        {
            "pid": 5678,
            "name": "bash",
            "exe": "/bin/bash",
            "username": "testuser",
            "status": "running",
        },
    ]


@pytest.fixture
def sample_iocs() -> List[Dict[str, Any]]:
    """Create sample IOC data for testing."""
    return [
        {
            "type": "ip",
            "value": "10.0.0.1",
            "description": "Known bad IP",
            "severity": "high",
        },
        {
            "type": "hash",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "description": "Malware hash",
            "severity": "critical",
        },
        {
            "type": "process",
            "value": "mimikatz",
            "description": "Credential dumper",
            "severity": "critical",
        },
    ]


@pytest.fixture
def ioc_file(temp_dir: Path, sample_iocs: List[Dict[str, Any]]) -> Path:
    """Create a sample IOC file for testing."""
    ioc_path = temp_dir / "iocs.json"
    ioc_path.write_text(json.dumps(sample_iocs))
    return ioc_path


# Markers for test categorization
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "security: marks security tests")
    config.addinivalue_line("markers", "requires_root: marks tests needing root")


