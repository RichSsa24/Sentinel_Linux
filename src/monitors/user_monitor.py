"""
User activity monitoring module.

Monitors user login/logout events, privilege escalation,
and tracks active user sessions.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime
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
class UserSession:
    """Represents an active user session."""

    user: str
    terminal: str
    host: str
    login_time: datetime
    pid: int
    session_type: str  # local, remote, unknown

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user": self.user,
            "terminal": self.terminal,
            "host": self.host,
            "login_time": self.login_time.isoformat(),
            "pid": self.pid,
            "session_type": self.session_type,
        }


@dataclass
class LoginEvent:
    """Represents a login event from logs."""

    timestamp: datetime
    user: str
    source_ip: Optional[str]
    terminal: Optional[str]
    success: bool
    method: str  # password, publickey, etc.
    raw_line: str


class UserMonitor(BaseMonitor):
    """
    Monitors user activity including logins, logouts, and privilege escalation.

    Data sources:
    - /var/log/auth.log or /var/log/secure
    - utmp for current sessions
    - wtmp for historical sessions
    - lastlog for last login info
    """

    # Auth log patterns
    PATTERNS = {
        "ssh_login_success": re.compile(
            r"sshd\[\d+\]: Accepted (\w+) for (\w+) from ([\d\.]+) port \d+"
        ),
        "ssh_login_failure": re.compile(
            r"sshd\[\d+\]: Failed (\w+) for (?:invalid user )?(\w+) from ([\d\.]+)"
        ),
        "sudo_success": re.compile(
            r"sudo:\s+(\w+) : .* COMMAND=(.*)"
        ),
        "sudo_failure": re.compile(
            r"sudo:\s+(\w+) : .* authentication failure"
        ),
        "su_success": re.compile(
            r"su\[\d+\]: .* session opened for user (\w+) by (\w+)"
        ),
        "session_opened": re.compile(
            r"pam_unix\((\w+):session\): session opened for user (\w+)"
        ),
        "session_closed": re.compile(
            r"pam_unix\((\w+):session\): session closed for user (\w+)"
        ),
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize user monitor.

        Args:
            config: Monitor configuration.
        """
        super().__init__("user_monitor", config)

        self.auth_log_path = config.get("auth_log_path", "/var/log/auth.log")
        self.alert_on_root_login = config.get("alert_on_root_login", True)
        self.alert_on_sudo = config.get("alert_on_sudo", True)

        self._last_position = 0
        self._known_sessions: Set[str] = set()

    def _initialize(self) -> None:
        """Initialize the monitor."""
        # Find the auth log
        if not os.path.exists(self.auth_log_path):
            # Try alternative paths
            alternatives = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/messages",
            ]
            for alt in alternatives:
                if os.path.exists(alt):
                    self.auth_log_path = alt
                    break

        if not os.path.exists(self.auth_log_path):
            logger.warning(f"Auth log not found: {self.auth_log_path}")

        # Initialize with current log position
        if os.path.exists(self.auth_log_path):
            try:
                self._last_position = os.path.getsize(self.auth_log_path)
            except OSError:
                pass

        # Get current sessions
        for session in self.get_current_users():
            self._known_sessions.add(f"{session.user}:{session.terminal}")

        logger.info(f"UserMonitor initialized with log: {self.auth_log_path}")

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect user activity events."""
        events: List[Event] = []

        # Check for new sessions
        session_events = self._check_sessions()
        events.extend(session_events)

        # Parse auth log for new entries
        log_events = self._parse_auth_log()
        events.extend(log_events)

        return events

    def _check_sessions(self) -> List[Event]:
        """Check for new or ended sessions."""
        events: List[Event] = []
        current_sessions: Set[str] = set()

        for session in self.get_current_users():
            session_key = f"{session.user}:{session.terminal}"
            current_sessions.add(session_key)

            if session_key not in self._known_sessions:
                # New session detected
                severity = Severity.HIGH if session.user == "root" else Severity.MEDIUM

                events.append(self.create_event(
                    event_type=EventType.USER_LOGIN,
                    severity=severity,
                    description=f"User '{session.user}' logged in from {session.host or 'local'}",
                    raw=str(session.to_dict()),
                    subject=EventSubject(
                        user=session.user,
                        pid=session.pid,
                    ),
                    metadata={
                        "terminal": session.terminal,
                        "host": session.host,
                        "session_type": session.session_type,
                    },
                ))

        # Check for ended sessions
        ended = self._known_sessions - current_sessions
        for session_key in ended:
            user, terminal = session_key.split(":", 1)
            events.append(self.create_event(
                event_type=EventType.USER_LOGOUT,
                severity=Severity.INFO,
                description=f"User '{user}' logged out from {terminal}",
                subject=EventSubject(user=user),
                metadata={"terminal": terminal},
            ))

        self._known_sessions = current_sessions
        return events

    def _parse_auth_log(self) -> List[Event]:
        """Parse auth log for new entries."""
        events: List[Event] = []

        if not os.path.exists(self.auth_log_path):
            return events

        try:
            with open(self.auth_log_path, "r", encoding="utf-8", errors="ignore") as f:
                # Check for log rotation
                current_size = os.path.getsize(self.auth_log_path)
                if current_size < self._last_position:
                    self._last_position = 0

                f.seek(self._last_position)
                new_lines = f.readlines()
                self._last_position = f.tell()

                for line in new_lines:
                    line_events = self._parse_log_line(line.strip())
                    events.extend(line_events)

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

        return events

    def _parse_log_line(self, line: str) -> List[Event]:
        """Parse a single log line for security events."""
        events: List[Event] = []

        if not line:
            return events

        # SSH successful login
        match = self.PATTERNS["ssh_login_success"].search(line)
        if match:
            method, user, source_ip = match.groups()
            severity = Severity.HIGH if user == "root" else Severity.MEDIUM

            events.append(self.create_event(
                event_type=EventType.USER_LOGIN,
                severity=severity,
                description=f"SSH login: user '{user}' from {source_ip} via {method}",
                raw=line,
                subject=EventSubject(user=user),
                metadata={
                    "method": method,
                    "source_ip": source_ip,
                    "service": "ssh",
                },
            ))
            return events

        # SSH failed login
        match = self.PATTERNS["ssh_login_failure"].search(line)
        if match:
            method, user, source_ip = match.groups()
            events.append(self.create_event(
                event_type=EventType.AUTH_FAILURE,
                severity=Severity.MEDIUM,
                description=f"SSH login failed: user '{user}' from {source_ip}",
                raw=line,
                subject=EventSubject(user=user),
                metadata={
                    "method": method,
                    "source_ip": source_ip,
                    "service": "ssh",
                },
            ))
            return events

        # Sudo usage
        match = self.PATTERNS["sudo_success"].search(line)
        if match and self.alert_on_sudo:
            user, command = match.groups()
            events.append(self.create_event(
                event_type=EventType.USER_PRIVILEGE_ESCALATION,
                severity=Severity.MEDIUM,
                description=f"Sudo executed by '{user}': {command[:100]}",
                raw=line,
                subject=EventSubject(user=user),
                metadata={
                    "command": command,
                    "method": "sudo",
                },
            ))
            return events

        # Sudo failure
        match = self.PATTERNS["sudo_failure"].search(line)
        if match:
            user = match.group(1)
            events.append(self.create_event(
                event_type=EventType.AUTH_FAILURE,
                severity=Severity.HIGH,
                description=f"Sudo authentication failed for '{user}'",
                raw=line,
                subject=EventSubject(user=user),
                metadata={"method": "sudo"},
            ))
            return events

        # Su session
        match = self.PATTERNS["su_success"].search(line)
        if match:
            target_user, source_user = match.groups()
            severity = Severity.HIGH if target_user == "root" else Severity.MEDIUM

            events.append(self.create_event(
                event_type=EventType.USER_PRIVILEGE_ESCALATION,
                severity=severity,
                description=f"User '{source_user}' switched to '{target_user}'",
                raw=line,
                subject=EventSubject(user=source_user),
                metadata={
                    "target_user": target_user,
                    "method": "su",
                },
            ))
            return events

        return events

    def get_current_users(self) -> List[UserSession]:
        """
        Get currently logged-in users.

        Returns:
            List of active user sessions.
        """
        sessions: List[UserSession] = []

        try:
            import psutil
            for user in psutil.users():
                session_type = "remote" if user.host else "local"
                sessions.append(UserSession(
                    user=user.name,
                    terminal=user.terminal or "",
                    host=user.host or "",
                    login_time=datetime.fromtimestamp(user.started),
                    pid=user.pid or 0,
                    session_type=session_type,
                ))
        except Exception as e:
            logger.debug(f"Failed to get users via psutil: {e}")

            # Fallback to utmp parsing
            sessions = self._parse_utmp()

        return sessions

    def _parse_utmp(self) -> List[UserSession]:
        """Parse utmp file directly for user sessions."""
        sessions: List[UserSession] = []
        utmp_paths = ["/var/run/utmp", "/run/utmp"]

        for utmp_path in utmp_paths:
            if not os.path.exists(utmp_path):
                continue

            try:
                with open(utmp_path, "rb"):
                    # utmp struct size varies by system
                    # This is a simplified parser
                    pass
            except Exception:
                pass

        return sessions

    def get_login_history(
        self,
        user: Optional[str] = None,
        limit: int = 100,
    ) -> List[LoginEvent]:
        """
        Get login history from wtmp.

        Args:
            user: Filter by username (None for all).
            limit: Maximum number of entries.

        Returns:
            List of login events.
        """
        events: List[LoginEvent] = []

        try:
            import subprocess
            cmd = ["last", "-n", str(limit)]
            if user:
                cmd.append(user)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.strip().split("\n"):
                if not line or line.startswith("wtmp begins"):
                    continue
                # Parse last output (simplified)
                parts = line.split()
                if len(parts) >= 3:
                    events.append(LoginEvent(
                        timestamp=datetime.now(),  # Would need proper parsing
                        user=parts[0],
                        source_ip=parts[2] if len(parts) > 2 else None,
                        terminal=parts[1] if len(parts) > 1 else None,
                        success=True,
                        method="unknown",
                        raw_line=line,
                    ))
        except Exception as e:
            logger.debug(f"Failed to get login history: {e}")

        return events[:limit]


