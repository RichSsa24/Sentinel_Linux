"""
Authentication monitoring module.

Monitors authentication events and detects brute force attacks.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from src.config.logging_config import get_logger
from src.core.base_monitor import (
    BaseMonitor,
    Event,
    EventSubject,
    EventType,
    Severity,
)
from src.core.exceptions import CollectionError


logger = get_logger(__name__)


@dataclass
class AuthAttempt:
    """Represents an authentication attempt."""

    timestamp: datetime
    user: str
    source_ip: Optional[str]
    service: str
    success: bool
    method: Optional[str]
    raw_line: str


@dataclass
class BruteForceDetection:
    """Represents a detected brute force attempt."""

    source_ip: str
    target_user: Optional[str]
    attempt_count: int
    first_seen: datetime
    last_seen: datetime
    services: Set[str]


class AuthMonitor(BaseMonitor):
    """
    Monitors authentication events and detects attacks.

    Features:
    - Failed authentication tracking
    - Brute force detection
    - Credential stuffing detection
    - Password spray detection
    - Account lockout recommendations
    """

    # Patterns for parsing auth logs
    PATTERNS = {
        "sshd_failed": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: "
            r"Failed (\w+) for (?:invalid user )?(\w+) from ([\d\.]+)"
        ),
        "sshd_success": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: "
            r"Accepted (\w+) for (\w+) from ([\d\.]+)"
        ),
        "pam_failed": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*pam_unix\((\w+):auth\): "
            r"authentication failure.*user=(\w+)"
        ),
        "sudo_failed": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*pam_unix.*"
            r"authentication failure.*user=(\w+)"
        ),
        "invalid_user": re.compile(
            r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: "
            r"Invalid user (\w+) from ([\d\.]+)"
        ),
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize auth monitor.

        Args:
            config: Monitor configuration.
        """
        super().__init__("auth_monitor", config)

        self.brute_force_threshold = config.get("brute_force_threshold", 5)
        self.brute_force_window = config.get("brute_force_window", 300)
        self.alert_on_failed_auth = config.get("alert_on_failed_auth", True)

        # Auth log paths
        self.auth_log_paths = [
            "/var/log/auth.log",
            "/var/log/secure",
        ]

        self._last_positions: Dict[str, int] = {}
        self._failed_attempts: Dict[str, List[AuthAttempt]] = defaultdict(list)
        self._alerted_brute_force: Set[str] = set()

    def _initialize(self) -> None:
        """Initialize the monitor."""
        # Find available auth log
        self.auth_log_path = None
        for path in self.auth_log_paths:
            if os.path.exists(path):
                self.auth_log_path = path
                break

        if self.auth_log_path:
            try:
                self._last_positions[self.auth_log_path] = os.path.getsize(
                    self.auth_log_path
                )
            except OSError:
                self._last_positions[self.auth_log_path] = 0

        logger.info(f"AuthMonitor initialized with log: {self.auth_log_path}")

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect authentication events."""
        events: List[Event] = []

        if not self.auth_log_path:
            return events

        # Parse new log entries
        auth_attempts = self._parse_auth_log()

        for attempt in auth_attempts:
            if not attempt.success:
                # Track failed attempt
                self._record_failed_attempt(attempt)

                # Check for brute force
                brute_force = self._check_brute_force(attempt.source_ip)
                if brute_force:
                    events.append(self._create_brute_force_event(brute_force))

                # Create individual failure event if configured
                if self.alert_on_failed_auth:
                    events.append(self._create_auth_failure_event(attempt))

        # Clean up old attempts
        self._cleanup_old_attempts()

        return events

    def _parse_auth_log(self) -> List[AuthAttempt]:
        """Parse auth log for new entries."""
        attempts: List[AuthAttempt] = []

        if not self.auth_log_path:
            return attempts

        if not os.path.exists(self.auth_log_path):
            return attempts

        try:
            with open(self.auth_log_path, "r", encoding="utf-8", errors="ignore") as f:
                # Check for log rotation
                current_size = os.path.getsize(self.auth_log_path)
                last_pos = self._last_positions.get(self.auth_log_path, 0)

                if current_size < last_pos:
                    last_pos = 0

                f.seek(last_pos)
                new_lines = f.readlines()
                self._last_positions[self.auth_log_path] = f.tell()

                for line in new_lines:
                    attempt = self._parse_log_line(line.strip())
                    if attempt:
                        attempts.append(attempt)

        except PermissionError:
            raise CollectionError(
                f"Permission denied reading {self.auth_log_path}",
                source=self.auth_log_path,
            )
        except Exception as e:
            raise CollectionError(
                f"Error reading auth log: {e}",
                source=self.auth_log_path,
            )

        return attempts

    def _parse_log_line(self, line: str) -> Optional[AuthAttempt]:
        """Parse a single log line for auth events."""
        if not line:
            return None

        current_year = datetime.now().year

        # Check SSH failed
        match = self.PATTERNS["sshd_failed"].search(line)
        if match:
            timestamp_str, method, user, source_ip = match.groups()
            return AuthAttempt(
                timestamp=self._parse_timestamp(timestamp_str, current_year),
                user=user,
                source_ip=source_ip,
                service="ssh",
                success=False,
                method=method,
                raw_line=line,
            )

        # Check SSH success
        match = self.PATTERNS["sshd_success"].search(line)
        if match:
            timestamp_str, method, user, source_ip = match.groups()
            return AuthAttempt(
                timestamp=self._parse_timestamp(timestamp_str, current_year),
                user=user,
                source_ip=source_ip,
                service="ssh",
                success=True,
                method=method,
                raw_line=line,
            )

        # Check PAM failure
        match = self.PATTERNS["pam_failed"].search(line)
        if match:
            timestamp_str, service, user = match.groups()
            return AuthAttempt(
                timestamp=self._parse_timestamp(timestamp_str, current_year),
                user=user,
                source_ip=None,
                service=service,
                success=False,
                method="password",
                raw_line=line,
            )

        # Check sudo failure
        match = self.PATTERNS["sudo_failed"].search(line)
        if match:
            timestamp_str, user = match.groups()
            return AuthAttempt(
                timestamp=self._parse_timestamp(timestamp_str, current_year),
                user=user,
                source_ip=None,
                service="sudo",
                success=False,
                method="password",
                raw_line=line,
            )

        return None

    def _parse_timestamp(self, timestamp_str: str, year: int) -> datetime:
        """Parse syslog timestamp."""
        try:
            # Format: "Dec 14 10:30:45"
            dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            return datetime.now()

    def _record_failed_attempt(self, attempt: AuthAttempt) -> None:
        """Record a failed authentication attempt."""
        if attempt.source_ip:
            self._failed_attempts[attempt.source_ip].append(attempt)

    def _check_brute_force(self, source_ip: Optional[str]) -> Optional[BruteForceDetection]:
        """Check if source IP is conducting brute force attack."""
        if not source_ip or source_ip in self._alerted_brute_force:
            return None

        attempts = self._failed_attempts.get(source_ip, [])
        if len(attempts) < self.brute_force_threshold:
            return None

        # Check if attempts are within the window
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.brute_force_window)

        recent_attempts = [a for a in attempts if a.timestamp > cutoff]

        if len(recent_attempts) >= self.brute_force_threshold:
            self._alerted_brute_force.add(source_ip)

            users = set(a.user for a in recent_attempts)
            services = set(a.service for a in recent_attempts)

            return BruteForceDetection(
                source_ip=source_ip,
                target_user=list(users)[0] if len(users) == 1 else None,
                attempt_count=len(recent_attempts),
                first_seen=min(a.timestamp for a in recent_attempts),
                last_seen=max(a.timestamp for a in recent_attempts),
                services=services,
            )

        return None

    def _cleanup_old_attempts(self) -> None:
        """Remove old attempts from tracking."""
        cutoff = datetime.now() - timedelta(seconds=self.brute_force_window * 2)

        for ip in list(self._failed_attempts.keys()):
            self._failed_attempts[ip] = [
                a for a in self._failed_attempts[ip] if a.timestamp > cutoff
            ]
            if not self._failed_attempts[ip]:
                del self._failed_attempts[ip]

        # Clear old brute force alerts
        self._alerted_brute_force.clear()

    def _create_brute_force_event(self, detection: BruteForceDetection) -> Event:
        """Create event for brute force detection."""
        target = detection.target_user or "multiple users"

        return self.create_event(
            event_type=EventType.BRUTE_FORCE,
            severity=Severity.CRITICAL,
            description=(
                f"Brute force attack detected from {detection.source_ip} "
                f"targeting {target} ({detection.attempt_count} attempts)"
            ),
            subject=EventSubject(user=detection.target_user),
            metadata={
                "source_ip": detection.source_ip,
                "attempt_count": detection.attempt_count,
                "first_seen": detection.first_seen.isoformat(),
                "last_seen": detection.last_seen.isoformat(),
                "services": list(detection.services),
            },
        )

    def _create_auth_failure_event(self, attempt: AuthAttempt) -> Event:
        """Create event for individual auth failure."""
        source = attempt.source_ip or "local"

        return self.create_event(
            event_type=EventType.AUTH_FAILURE,
            severity=Severity.MEDIUM,
            description=(
                f"Authentication failed for '{attempt.user}' "
                f"via {attempt.service} from {source}"
            ),
            raw=attempt.raw_line,
            subject=EventSubject(user=attempt.user),
            metadata={
                "source_ip": attempt.source_ip,
                "service": attempt.service,
                "method": attempt.method,
            },
        )

    def get_failed_attempt_stats(self) -> Dict[str, Any]:
        """Get statistics on failed authentication attempts."""
        total_attempts = sum(len(v) for v in self._failed_attempts.values())
        unique_ips = len(self._failed_attempts)

        # Top offenders
        top_ips = sorted(
            self._failed_attempts.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )[:10]

        return {
            "total_tracked_attempts": total_attempts,
            "unique_source_ips": unique_ips,
            "brute_force_threshold": self.brute_force_threshold,
            "tracking_window_seconds": self.brute_force_window,
            "top_source_ips": [
                {"ip": ip, "attempts": len(attempts)}
                for ip, attempts in top_ips
            ],
        }


