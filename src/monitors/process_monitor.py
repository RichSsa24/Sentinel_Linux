"""
Process monitoring module.

Monitors running processes for anomalous behavior,
suspicious execution paths, and unauthorized binaries.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import psutil

from src.config.logging_config import get_logger
from src.core.base_monitor import (
    BaseMonitor,
    Event,
    EventObject,
    EventSubject,
    EventType,
    Severity,
)
from src.core.exceptions import CollectionError


logger = get_logger(__name__)


@dataclass
class ProcessInfo:
    """Information about a running process."""

    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: str
    create_time: datetime
    ppid: int
    status: str
    cwd: Optional[str] = None
    open_files: List[str] = field(default_factory=list)
    connections: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "username": self.username,
            "create_time": self.create_time.isoformat(),
            "ppid": self.ppid,
            "status": self.status,
            "cwd": self.cwd,
        }


@dataclass
class ProcessBaseline:
    """Baseline of expected processes."""

    processes: Dict[str, Dict[str, Any]]
    created_at: datetime
    host: str


class ProcessMonitor(BaseMonitor):
    """
    Monitors process activity for security-relevant events.

    Detects:
    - New process creation
    - Processes running from suspicious paths
    - Processes with suspicious names
    - Hidden processes
    - Resource anomalies
    """

    # Suspicious paths where legitimate binaries shouldn't execute from
    DEFAULT_SUSPICIOUS_PATHS = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/shm",
        "/home",  # User home directories
    ]

    # Common suspicious process names
    DEFAULT_SUSPICIOUS_NAMES = [
        "nc",
        "ncat",
        "netcat",
        "nmap",
        "tcpdump",
        "wireshark",
        "tshark",
        "masscan",
        "nikto",
        "hydra",
        "john",
        "hashcat",
        "mimikatz",
        "meterpreter",
        "cobalt",
    ]

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize process monitor.

        Args:
            config: Monitor configuration.
        """
        super().__init__("process_monitor", config)

        self.suspicious_paths = config.get(
            "suspicious_paths", self.DEFAULT_SUSPICIOUS_PATHS
        )
        self.suspicious_names = config.get(
            "suspicious_names", self.DEFAULT_SUSPICIOUS_NAMES
        )
        self.alert_on_new_process = config.get("alert_on_new_process", False)
        self.baseline_path = config.get("baseline_path")

        self._known_pids: Set[int] = set()
        self._baseline: Optional[ProcessBaseline] = None

    def _initialize(self) -> None:
        """Initialize the monitor."""
        # Get current processes
        for proc in psutil.process_iter(["pid"]):
            try:
                self._known_pids.add(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Load baseline if configured
        if self.baseline_path and os.path.exists(self.baseline_path):
            self._load_baseline()

        logger.info(
            f"ProcessMonitor initialized, tracking {len(self._known_pids)} processes"
        )

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect process events."""
        events: List[Event] = []
        current_pids: Set[int] = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "username", "create_time", "ppid", "status"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                # Check for new processes
                if pid not in self._known_pids:
                    proc_info = self._get_process_info(proc)
                    if proc_info:
                        new_events = self._analyze_new_process(proc_info)
                        events.extend(new_events)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Update known PIDs
        self._known_pids = current_pids

        return events

    def _get_process_info(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Get detailed information about a process."""
        try:
            with proc.oneshot():
                return ProcessInfo(
                    pid=proc.pid,
                    name=proc.name(),
                    exe=self._safe_get(proc.exe),
                    cmdline=proc.cmdline() or [],
                    username=proc.username(),
                    create_time=datetime.fromtimestamp(proc.create_time()),
                    ppid=proc.ppid(),
                    status=proc.status(),
                    cwd=self._safe_get(proc.cwd),
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _safe_get(self, func: Any) -> Optional[str]:
        """Safely call a process method that might fail."""
        try:
            return func()
        except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
            return None

    def _analyze_new_process(self, proc_info: ProcessInfo) -> List[Event]:
        """Analyze a new process for suspicious characteristics."""
        events: List[Event] = []

        # Check for suspicious executable path
        if proc_info.exe:
            for suspicious_path in self.suspicious_paths:
                if proc_info.exe.startswith(suspicious_path):
                    events.append(self._create_suspicious_event(
                        proc_info,
                        f"Process executing from suspicious path: {proc_info.exe}",
                        Severity.HIGH,
                        {"reason": "suspicious_path", "path": proc_info.exe},
                    ))
                    break

        # Check for suspicious process name
        name_lower = proc_info.name.lower()
        for suspicious_name in self.suspicious_names:
            if suspicious_name.lower() in name_lower:
                events.append(self._create_suspicious_event(
                    proc_info,
                    f"Suspicious process detected: {proc_info.name}",
                    Severity.HIGH,
                    {"reason": "suspicious_name", "matched": suspicious_name},
                ))
                break

        # Check for shell spawned by unexpected parent
        if self._is_interactive_shell(proc_info):
            parent_info = self._get_parent_info(proc_info.ppid)
            if parent_info and self._is_suspicious_shell_parent(parent_info):
                events.append(self._create_suspicious_event(
                    proc_info,
                    f"Interactive shell spawned by {parent_info.name}",
                    Severity.HIGH,
                    {"reason": "suspicious_shell", "parent": parent_info.name},
                ))

        # Check for encoded commands
        cmdline_str = " ".join(proc_info.cmdline)
        if self._has_encoded_command(cmdline_str):
            events.append(self._create_suspicious_event(
                proc_info,
                "Process with potentially encoded command detected",
                Severity.MEDIUM,
                {"reason": "encoded_command"},
            ))

        # Alert on any new process if configured
        if self.alert_on_new_process and not events:
            events.append(self.create_event(
                event_type=EventType.PROCESS_START,
                severity=Severity.INFO,
                description=f"New process: {proc_info.name} (PID: {proc_info.pid})",
                raw=str(proc_info.to_dict()),
                subject=EventSubject(
                    user=proc_info.username,
                    process=proc_info.name,
                    pid=proc_info.pid,
                ),
            ))

        return events

    def _create_suspicious_event(
        self,
        proc_info: ProcessInfo,
        description: str,
        severity: Severity,
        metadata: Dict[str, Any],
    ) -> Event:
        """Create a suspicious process event."""
        return self.create_event(
            event_type=EventType.PROCESS_SUSPICIOUS,
            severity=severity,
            description=description,
            raw=str(proc_info.to_dict()),
            subject=EventSubject(
                user=proc_info.username,
                process=proc_info.name,
                pid=proc_info.pid,
            ),
            obj=EventObject(
                type="process",
                path=proc_info.exe,
                details={
                    "cmdline": proc_info.cmdline,
                    "ppid": proc_info.ppid,
                    "cwd": proc_info.cwd,
                },
            ),
            metadata=metadata,
        )

    def _is_interactive_shell(self, proc_info: ProcessInfo) -> bool:
        """Check if process is an interactive shell."""
        shells = ["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh"]
        return proc_info.name in shells and "-i" in proc_info.cmdline

    def _get_parent_info(self, ppid: int) -> Optional[ProcessInfo]:
        """Get information about parent process."""
        try:
            parent = psutil.Process(ppid)
            return self._get_process_info(parent)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _is_suspicious_shell_parent(self, parent_info: ProcessInfo) -> bool:
        """Check if parent is suspicious for spawning a shell."""
        suspicious_parents = [
            "apache",
            "nginx",
            "httpd",
            "php",
            "python",
            "perl",
            "ruby",
            "node",
            "java",
            "tomcat",
        ]
        return any(
            sp in parent_info.name.lower() for sp in suspicious_parents
        )

    def _has_encoded_command(self, cmdline: str) -> bool:
        """Check for base64 or other encoded commands."""
        import re

        # Common encoded command patterns
        patterns = [
            r"base64\s+-d",
            r"echo\s+[A-Za-z0-9+/=]{50,}",  # Long base64 string
            r"-e\s+['\"]\\x",  # Hex encoded
            r"python.*-c.*__import__",
            r"perl.*-e.*pack",
            r"bash\s+-c\s+['\"].*\$\(",  # Command substitution
        ]

        for pattern in patterns:
            if re.search(pattern, cmdline):
                return True

        return False

    def _load_baseline(self) -> None:
        """Load process baseline from file."""
        import json

        try:
            with open(self.baseline_path, "r") as f:
                data = json.load(f)
                self._baseline = ProcessBaseline(
                    processes=data.get("processes", {}),
                    created_at=datetime.fromisoformat(data.get("created_at", "")),
                    host=data.get("host", ""),
                )
        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")

    def get_processes(self) -> List[ProcessInfo]:
        """Get list of all running processes."""
        processes: List[ProcessInfo] = []

        for proc in psutil.process_iter():
            proc_info = self._get_process_info(proc)
            if proc_info:
                processes.append(proc_info)

        return processes

    def analyze_process(self, pid: int) -> Dict[str, Any]:
        """
        Perform detailed analysis of a specific process.

        Args:
            pid: Process ID to analyze.

        Returns:
            Analysis results including risk indicators.
        """
        try:
            proc = psutil.Process(pid)
            proc_info = self._get_process_info(proc)

            if not proc_info:
                return {"error": "Process not found or access denied"}

            analysis = {
                "process_info": proc_info.to_dict(),
                "risk_indicators": [],
                "risk_score": 0.0,
            }

            # Check various risk factors
            if proc_info.exe:
                for suspicious_path in self.suspicious_paths:
                    if proc_info.exe.startswith(suspicious_path):
                        analysis["risk_indicators"].append({
                            "type": "suspicious_path",
                            "value": proc_info.exe,
                            "severity": "high",
                        })
                        analysis["risk_score"] += 0.4

            name_lower = proc_info.name.lower()
            for suspicious_name in self.suspicious_names:
                if suspicious_name.lower() in name_lower:
                    analysis["risk_indicators"].append({
                        "type": "suspicious_name",
                        "value": proc_info.name,
                        "severity": "high",
                    })
                    analysis["risk_score"] += 0.3

            # Check network connections
            try:
                connections = proc.connections()
                if connections:
                    analysis["network_connections"] = [
                        {
                            "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                            "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            "status": c.status,
                        }
                        for c in connections
                    ]
            except psutil.AccessDenied:
                pass

            # Cap risk score at 1.0
            analysis["risk_score"] = min(analysis["risk_score"], 1.0)

            return analysis

        except psutil.NoSuchProcess:
            return {"error": f"Process {pid} not found"}
        except psutil.AccessDenied:
            return {"error": f"Access denied to process {pid}"}



