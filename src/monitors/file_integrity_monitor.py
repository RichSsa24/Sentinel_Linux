"""
File integrity monitoring module.

Monitors critical files for unauthorized changes using
cryptographic hashing.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.config.logging_config import get_logger
from src.core.base_monitor import (
    BaseMonitor,
    Event,
    EventObject,
    EventType,
    Severity,
)
from src.core.exceptions import CollectionError


logger = get_logger(__name__)


@dataclass
class FileInfo:
    """Information about a monitored file."""

    path: str
    hash: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    ctime: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "hash": self.hash,
            "size": self.size,
            "mode": oct(self.mode),
            "uid": self.uid,
            "gid": self.gid,
            "mtime": datetime.fromtimestamp(self.mtime).isoformat(),
            "ctime": datetime.fromtimestamp(self.ctime).isoformat(),
        }


@dataclass
class FileChange:
    """Represents a detected file change."""

    path: str
    change_type: str  # modified, created, deleted, permission
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "change_type": self.change_type,
            "old_value": self.old_value,
            "new_value": self.new_value,
        }


@dataclass
class FileBaseline:
    """Baseline of file states."""

    files: Dict[str, FileInfo]
    created_at: datetime
    host: str
    hash_algorithm: str


class FileIntegrityMonitor(BaseMonitor):
    """
    Monitors file integrity using cryptographic hashes.

    Features:
    - Content change detection via hashing
    - Permission change detection
    - Ownership change detection
    - New file detection
    - Deleted file detection
    - Recursive directory monitoring
    """

    # Critical system files that should always be monitored
    CRITICAL_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/crontab",
    ]

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize file integrity monitor.

        Args:
            config: Monitor configuration.
        """
        super().__init__("file_integrity_monitor", config)

        self.watched_paths = config.get("watched_paths", self.CRITICAL_FILES)
        self.recursive_paths = config.get("recursive_paths", [])
        self.exclude_patterns = config.get("exclude_patterns", ["*.swp", "*~"])
        self.hash_algorithm = config.get("hash_algorithm", "sha256")

        self._baseline: Dict[str, FileInfo] = {}
        self._initialized = False

    def _initialize(self) -> None:
        """Initialize the monitor."""
        # Build initial baseline
        self._baseline = self._build_baseline()
        self._initialized = True

        logger.info(
            f"FileIntegrityMonitor initialized, monitoring {len(self._baseline)} files"
        )

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect file integrity events."""
        if not self._initialized:
            return []

        events: List[Event] = []
        current_state = self._build_baseline()

        # Check for changes
        changes = self._compare_states(self._baseline, current_state)

        for change in changes:
            event = self._create_change_event(change)
            if event:
                events.append(event)

        # Update baseline
        self._baseline = current_state

        return events

    def _build_baseline(self) -> Dict[str, FileInfo]:
        """Build a baseline of all monitored files."""
        baseline: Dict[str, FileInfo] = {}

        # Process individual files
        for path in self.watched_paths:
            if os.path.isfile(path):
                info = self._get_file_info(path)
                if info:
                    baseline[path] = info
            elif os.path.isdir(path):
                # Add directory to recursive processing
                for file_info in self._scan_directory(path, recursive=False):
                    baseline[file_info.path] = file_info

        # Process recursive directories
        for path in self.recursive_paths:
            if os.path.isdir(path):
                for file_info in self._scan_directory(path, recursive=True):
                    baseline[file_info.path] = file_info

        return baseline

    def _scan_directory(
        self, directory: str, recursive: bool = False
    ) -> List[FileInfo]:
        """Scan a directory for files."""
        files: List[FileInfo] = []

        try:
            if recursive:
                for root, dirs, filenames in os.walk(directory):
                    for filename in filenames:
                        if self._should_exclude(filename):
                            continue
                        filepath = os.path.join(root, filename)
                        info = self._get_file_info(filepath)
                        if info:
                            files.append(info)
            else:
                for entry in os.scandir(directory):
                    if entry.is_file() and not self._should_exclude(entry.name):
                        info = self._get_file_info(entry.path)
                        if info:
                            files.append(info)
        except PermissionError:
            logger.warning(f"Permission denied scanning directory: {directory}")
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")

        return files

    def _should_exclude(self, filename: str) -> bool:
        """Check if file should be excluded."""
        import fnmatch

        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def _get_file_info(self, path: str) -> Optional[FileInfo]:
        """Get information about a file."""
        try:
            stat_info = os.stat(path)
            file_hash = self._hash_file(path)

            return FileInfo(
                path=path,
                hash=file_hash,
                size=stat_info.st_size,
                mode=stat_info.st_mode,
                uid=stat_info.st_uid,
                gid=stat_info.st_gid,
                mtime=stat_info.st_mtime,
                ctime=stat_info.st_ctime,
            )
        except PermissionError:
            logger.debug(f"Permission denied reading file: {path}")
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.debug(f"Error getting file info for {path}: {e}")
            return None

    def _hash_file(self, path: str) -> str:
        """Calculate hash of a file."""
        hasher = hashlib.new(self.hash_algorithm)

        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.debug(f"Error hashing file {path}: {e}")
            return ""

    def _compare_states(
        self,
        old_state: Dict[str, FileInfo],
        new_state: Dict[str, FileInfo],
    ) -> List[FileChange]:
        """Compare two file states to detect changes."""
        changes: List[FileChange] = []

        old_paths = set(old_state.keys())
        new_paths = set(new_state.keys())

        # New files
        for path in new_paths - old_paths:
            changes.append(FileChange(
                path=path,
                change_type="created",
                new_value=new_state[path].to_dict(),
            ))

        # Deleted files
        for path in old_paths - new_paths:
            changes.append(FileChange(
                path=path,
                change_type="deleted",
                old_value=old_state[path].to_dict(),
            ))

        # Modified files
        for path in old_paths & new_paths:
            old_info = old_state[path]
            new_info = new_state[path]

            # Check content change
            if old_info.hash != new_info.hash:
                changes.append(FileChange(
                    path=path,
                    change_type="modified",
                    old_value={"hash": old_info.hash, "size": old_info.size},
                    new_value={"hash": new_info.hash, "size": new_info.size},
                ))

            # Check permission change
            elif old_info.mode != new_info.mode:
                changes.append(FileChange(
                    path=path,
                    change_type="permission",
                    old_value={"mode": oct(old_info.mode)},
                    new_value={"mode": oct(new_info.mode)},
                ))

            # Check ownership change
            elif old_info.uid != new_info.uid or old_info.gid != new_info.gid:
                changes.append(FileChange(
                    path=path,
                    change_type="ownership",
                    old_value={"uid": old_info.uid, "gid": old_info.gid},
                    new_value={"uid": new_info.uid, "gid": new_info.gid},
                ))

        return changes

    def _create_change_event(self, change: FileChange) -> Optional[Event]:
        """Create an event from a file change."""
        # Determine severity based on file and change type
        severity = self._determine_severity(change)

        # Determine event type
        event_type_map = {
            "created": EventType.FILE_CREATED,
            "deleted": EventType.FILE_DELETED,
            "modified": EventType.FILE_MODIFIED,
            "permission": EventType.FILE_PERMISSION_CHANGED,
            "ownership": EventType.FILE_PERMISSION_CHANGED,
        }
        event_type = event_type_map.get(change.change_type, EventType.FILE_MODIFIED)

        # Build description
        description = self._build_description(change)

        return self.create_event(
            event_type=event_type,
            severity=severity,
            description=description,
            raw=str(change.to_dict()),
            obj=EventObject(
                type="file",
                path=change.path,
                details={
                    "change_type": change.change_type,
                    "old_value": change.old_value,
                    "new_value": change.new_value,
                },
            ),
            metadata={
                "is_critical": change.path in self.CRITICAL_FILES,
            },
        )

    def _determine_severity(self, change: FileChange) -> Severity:
        """Determine severity based on file and change type."""
        # Critical files get higher severity
        is_critical = change.path in self.CRITICAL_FILES or any(
            change.path.startswith(p) for p in [
                "/etc/pam.d",
                "/etc/security",
                "/etc/sudoers.d",
            ]
        )

        if is_critical:
            if change.change_type in ["modified", "deleted"]:
                return Severity.CRITICAL
            elif change.change_type == "permission":
                return Severity.HIGH
            else:
                return Severity.MEDIUM

        # Regular files
        if change.change_type == "deleted":
            return Severity.MEDIUM
        elif change.change_type == "permission":
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _build_description(self, change: FileChange) -> str:
        """Build human-readable description of change."""
        if change.change_type == "created":
            return f"New file created: {change.path}"
        elif change.change_type == "deleted":
            return f"File deleted: {change.path}"
        elif change.change_type == "modified":
            return f"File content modified: {change.path}"
        elif change.change_type == "permission":
            old_mode = change.old_value.get("mode", "unknown") if change.old_value else "unknown"
            new_mode = change.new_value.get("mode", "unknown") if change.new_value else "unknown"
            return f"File permissions changed: {change.path} ({old_mode} -> {new_mode})"
        elif change.change_type == "ownership":
            return f"File ownership changed: {change.path}"
        else:
            return f"File changed: {change.path}"

    def create_baseline(self, output_path: str) -> FileBaseline:
        """
        Create and save a baseline.

        Args:
            output_path: Path to save baseline.

        Returns:
            Created baseline.
        """
        import json

        baseline_data = self._build_baseline()

        baseline = FileBaseline(
            files=baseline_data,
            created_at=datetime.now(),
            host=self.hostname,
            hash_algorithm=self.hash_algorithm,
        )

        # Save to file
        output = {
            "created_at": baseline.created_at.isoformat(),
            "host": baseline.host,
            "hash_algorithm": baseline.hash_algorithm,
            "files": {
                path: info.to_dict() for path, info in baseline.files.items()
            },
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        logger.info(f"Baseline saved to {output_path} with {len(baseline_data)} files")
        return baseline

    def check_integrity(self, baseline_path: str) -> List[FileChange]:
        """
        Check current state against a saved baseline.

        Args:
            baseline_path: Path to baseline file.

        Returns:
            List of detected changes.
        """
        import json

        with open(baseline_path, "r") as f:
            data = json.load(f)

        # Reconstruct baseline
        old_state: Dict[str, FileInfo] = {}
        for path, info in data.get("files", {}).items():
            old_state[path] = FileInfo(
                path=path,
                hash=info["hash"],
                size=info["size"],
                mode=int(info["mode"], 8),
                uid=info["uid"],
                gid=info["gid"],
                mtime=0,  # Not comparing time
                ctime=0,
            )

        current_state = self._build_baseline()
        return self._compare_states(old_state, current_state)



