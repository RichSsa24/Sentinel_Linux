"""
Log file monitoring module.

Monitors system logs for patterns and anomalies.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.config.logging_config import get_logger
from src.core.base_monitor import (
    BaseMonitor,
    Event,
    EventType,
    Severity,
)
from src.core.exceptions import CollectionError


logger = get_logger(__name__)


@dataclass
class LogPattern:
    """A pattern to match in logs."""

    pattern: str
    severity: Severity
    description: str
    compiled: re.Pattern

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "LogPattern":
        return cls(
            pattern=config["pattern"],
            severity=Severity[config.get("severity", "MEDIUM").upper()],
            description=config.get("description", "Pattern match"),
            compiled=re.compile(config["pattern"]),
        )


@dataclass
class LogMatch:
    """A matched log entry."""

    pattern: LogPattern
    line: str
    log_file: str
    line_number: int
    timestamp: datetime


class LogMonitor(BaseMonitor):
    """
    Monitors system log files for security-relevant patterns.

    Features:
    - Pattern-based detection
    - Multiple log file support
    - Real-time tail monitoring
    - Log rotation handling
    """

    DEFAULT_PATTERNS = [
        {"pattern": "Failed password", "severity": "MEDIUM", "description": "Failed authentication"},
        {"pattern": "BREAK-IN ATTEMPT", "severity": "CRITICAL", "description": "Break-in attempt"},
        {"pattern": "segfault", "severity": "LOW", "description": "Segmentation fault"},
        {"pattern": "Out of memory", "severity": "HIGH", "description": "OOM condition"},
        {"pattern": "kernel panic", "severity": "CRITICAL", "description": "Kernel panic"},
    ]

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize log monitor."""
        super().__init__("log_monitor", config)

        self.log_paths = config.get("log_paths", [
            "/var/log/syslog",
            "/var/log/messages",
        ])

        pattern_configs = config.get("patterns", self.DEFAULT_PATTERNS)
        self.patterns = [LogPattern.from_config(p) for p in pattern_configs]

        self._file_positions: Dict[str, int] = {}
        self._file_inodes: Dict[str, int] = {}

    def _initialize(self) -> None:
        """Initialize the monitor."""
        for path in self.log_paths:
            if os.path.exists(path):
                try:
                    stat = os.stat(path)
                    self._file_positions[path] = stat.st_size
                    self._file_inodes[path] = stat.st_ino
                except OSError:
                    pass

        logger.info(f"LogMonitor initialized, monitoring {len(self.log_paths)} files")

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect log events."""
        events: List[Event] = []

        for log_path in self.log_paths:
            if not os.path.exists(log_path):
                continue

            try:
                matches = self._scan_log_file(log_path)
                for match in matches:
                    events.append(self._create_match_event(match))
            except PermissionError:
                logger.warning(f"Permission denied: {log_path}")
            except Exception as e:
                logger.error(f"Error reading {log_path}: {e}")

        return events

    def _scan_log_file(self, path: str) -> List[LogMatch]:
        """Scan a log file for pattern matches."""
        matches: List[LogMatch] = []

        try:
            stat = os.stat(path)
            current_inode = stat.st_ino
            current_size = stat.st_size

            # Check for rotation
            if path in self._file_inodes and self._file_inodes[path] != current_inode:
                self._file_positions[path] = 0
            elif current_size < self._file_positions.get(path, 0):
                self._file_positions[path] = 0

            self._file_inodes[path] = current_inode

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._file_positions.get(path, 0))
                line_num = 0

                for line in f:
                    line_num += 1
                    line = line.strip()

                    for pattern in self.patterns:
                        if pattern.compiled.search(line):
                            matches.append(LogMatch(
                                pattern=pattern,
                                line=line,
                                log_file=path,
                                line_number=line_num,
                                timestamp=datetime.now(),
                            ))

                self._file_positions[path] = f.tell()

        except Exception as e:
            raise CollectionError(f"Error scanning {path}: {e}", source=path)

        return matches

    def _create_match_event(self, match: LogMatch) -> Event:
        """Create an event from a log match."""
        return self.create_event(
            event_type=EventType.LOG_PATTERN_MATCH,
            severity=match.pattern.severity,
            description=f"{match.pattern.description}: {match.line[:100]}",
            raw=match.line,
            metadata={
                "pattern": match.pattern.pattern,
                "log_file": match.log_file,
                "line_number": match.line_number,
            },
        )

    def add_pattern(
        self, pattern: str, severity: str = "MEDIUM", description: str = ""
    ) -> None:
        """Add a new pattern to monitor."""
        self.patterns.append(LogPattern.from_config({
            "pattern": pattern,
            "severity": severity,
            "description": description or f"Match: {pattern}",
        }))



