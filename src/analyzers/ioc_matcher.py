"""
Indicator of Compromise (IOC) matching module.

Matches events against known malicious indicators.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from src.config.logging_config import get_logger
from src.core.base_monitor import Event
from src.core.event_handler import AnalysisResult


logger = get_logger(__name__)


@dataclass
class IOC:
    """Indicator of Compromise."""

    type: str  # ip, domain, hash, path, process
    value: str
    description: str = ""
    severity: str = "medium"
    source: str = ""
    added_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "tags": self.tags,
        }


@dataclass
class IOCMatch:
    """Result of an IOC match."""

    ioc: IOC
    matched_value: str
    context: str


class IOCMatcher:
    """
    Matches system artifacts against known IOCs.

    Supported IOC types:
    - IP addresses
    - Domain names
    - File hashes (MD5, SHA1, SHA256)
    - File paths
    - Process names
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize IOC matcher."""
        self.config = config
        self.ioc_database = config.get("ioc_database", "")

        self._ip_iocs: Set[str] = set()
        self._domain_iocs: Set[str] = set()
        self._hash_iocs: Dict[str, Set[str]] = {
            "md5": set(),
            "sha1": set(),
            "sha256": set(),
        }
        self._path_iocs: List[re.Pattern] = []
        self._process_iocs: Set[str] = set()

        self._all_iocs: List[IOC] = []

        self._load_builtin_iocs()

        if self.ioc_database and os.path.exists(self.ioc_database):
            self.load_iocs(self.ioc_database)

        logger.info(f"IOCMatcher initialized with {len(self._all_iocs)} IOCs")

    def _load_builtin_iocs(self) -> None:
        """Load built-in sample IOCs."""
        builtin = [
            IOC(
                type="process",
                value="mimikatz",
                description="Credential dumping tool",
                severity="critical",
            ),
            IOC(
                type="process",
                value="meterpreter",
                description="Metasploit payload",
                severity="critical",
            ),
            IOC(
                type="process",
                value="cobalt",
                description="Cobalt Strike beacon",
                severity="critical",
            ),
            IOC(
                type="path",
                value="/tmp/.*\\.elf$",  # nosec B108
                description="ELF in temp directory",
                severity="high",
            ),
            IOC(
                type="path",
                value="/dev/shm/.*",  # nosec B108
                description="File in shared memory",
                severity="medium",
            ),
        ]

        for ioc in builtin:
            self.add_ioc(ioc)

    def load_iocs(self, path: str) -> int:
        """
        Load IOCs from a file.

        Args:
            path: Path to IOC file (JSON).

        Returns:
            Number of IOCs loaded.
        """
        count = 0

        try:
            # Validate path to prevent path traversal
            from src.core.exceptions import ValidationError
            from src.utils.validators import validate_path

            validate_path(path, must_exist=True, must_be_file=True)
        except ValidationError as e:
            logger.error(f"Invalid IOC file path: {path} - {e}")
            return 0

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            iocs = data if isinstance(data, list) else data.get("iocs", [])

            for ioc_data in iocs:
                ioc = IOC(
                    type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    description=ioc_data.get("description", ""),
                    severity=ioc_data.get("severity", "medium"),
                    source=ioc_data.get("source", path),
                    tags=ioc_data.get("tags", []),
                )
                self.add_ioc(ioc)
                count += 1

            logger.info(f"Loaded {count} IOCs from {path}")

        except Exception as e:
            logger.error(f"Failed to load IOCs from {path}: {e}")

        return count

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC to the database."""
        self._all_iocs.append(ioc)

        if ioc.type == "ip":
            self._ip_iocs.add(ioc.value.lower())
        elif ioc.type == "domain":
            self._domain_iocs.add(ioc.value.lower())
        elif ioc.type == "hash":
            value_lower = ioc.value.lower()
            if len(value_lower) == 32:
                self._hash_iocs["md5"].add(value_lower)
            elif len(value_lower) == 40:
                self._hash_iocs["sha1"].add(value_lower)
            elif len(value_lower) == 64:
                self._hash_iocs["sha256"].add(value_lower)
        elif ioc.type == "path":
            try:
                self._path_iocs.append(re.compile(ioc.value))
            except re.error:
                self._path_iocs.append(re.compile(re.escape(ioc.value)))
        elif ioc.type == "process":
            self._process_iocs.add(ioc.value.lower())

    def analyze(self, event: Event) -> Optional[AnalysisResult]:
        """
        Analyze an event for IOC matches.

        Args:
            event: Event to analyze.

        Returns:
            AnalysisResult if IOCs matched, None otherwise.
        """
        matches: List[IOCMatch] = []

        # Check IP addresses
        ip_matches = self._check_ips(event)
        matches.extend(ip_matches)

        # Check file paths
        path_matches = self._check_paths(event)
        matches.extend(path_matches)

        # Check process names
        process_matches = self._check_processes(event)
        matches.extend(process_matches)

        # Check hashes
        hash_matches = self._check_hashes(event)
        matches.extend(hash_matches)

        if not matches:
            return None

        # Calculate threat score based on severity
        severity_scores = {"low": 0.3, "medium": 0.5, "high": 0.7, "critical": 1.0}
        max_score = max(
            severity_scores.get(m.ioc.severity, 0.5) for m in matches
        )

        return AnalysisResult(
            analyzer_name="IOCMatcher",
            threat_score=max_score,
            ioc_matches=[m.ioc.value for m in matches],
            findings=[
                f"IOC match: {m.ioc.type} - {m.ioc.value} ({m.ioc.description})"
                for m in matches
            ],
            metadata={
                "matches": [
                    {
                        "ioc": m.ioc.to_dict(),
                        "matched_value": m.matched_value,
                        "context": m.context,
                    }
                    for m in matches
                ],
            },
        )

    def _check_ips(self, event: Event) -> List[IOCMatch]:
        """Check event for malicious IPs."""
        matches: List[IOCMatch] = []

        # Check source IP
        if event.source.ip and event.source.ip.lower() in self._ip_iocs:
            ioc = self._find_ioc("ip", event.source.ip)
            if ioc:
                matches.append(IOCMatch(
                    ioc=ioc,
                    matched_value=event.source.ip,
                    context="source_ip",
                ))

        # Check metadata for IPs
        for key, value in event.metadata.items():
            if isinstance(value, str) and value.lower() in self._ip_iocs:
                ioc = self._find_ioc("ip", value)
                if ioc:
                    matches.append(IOCMatch(
                        ioc=ioc,
                        matched_value=value,
                        context=f"metadata.{key}",
                    ))

        return matches

    def _check_paths(self, event: Event) -> List[IOCMatch]:
        """Check event for malicious file paths."""
        matches: List[IOCMatch] = []

        if event.object and event.object.path:
            path = event.object.path

            for i, pattern in enumerate(self._path_iocs):
                if pattern.search(path):
                    ioc = self._all_iocs[i] if i < len(self._all_iocs) else None
                    if ioc and ioc.type == "path":
                        matches.append(IOCMatch(
                            ioc=ioc,
                            matched_value=path,
                            context="object.path",
                        ))

        return matches

    def _check_processes(self, event: Event) -> List[IOCMatch]:
        """Check event for malicious process names."""
        matches: List[IOCMatch] = []

        if event.subject and event.subject.process:
            proc_name = event.subject.process.lower()

            for ioc_name in self._process_iocs:
                if ioc_name in proc_name:
                    ioc = self._find_ioc("process", ioc_name)
                    if ioc:
                        matches.append(IOCMatch(
                            ioc=ioc,
                            matched_value=event.subject.process,
                            context="subject.process",
                        ))

        return matches

    def _check_hashes(self, event: Event) -> List[IOCMatch]:
        """Check event for malicious hashes."""
        matches: List[IOCMatch] = []

        # Check metadata for hashes
        hash_fields = ["hash", "sha256", "sha1", "md5", "file_hash"]

        for hash_field in hash_fields:
            if hash_field in event.metadata:
                hash_value = event.metadata[hash_field].lower()

                for hash_type, hash_set in self._hash_iocs.items():
                    if hash_value in hash_set:
                        ioc = self._find_ioc("hash", hash_value)
                        if ioc:
                            matches.append(IOCMatch(
                                ioc=ioc,
                                matched_value=hash_value,
                                context=f"metadata.{field}",
                            ))

        return matches

    def _find_ioc(self, ioc_type: str, value: str) -> Optional[IOC]:
        """Find an IOC by type and value."""
        value_lower = value.lower()
        for ioc in self._all_iocs:
            if ioc.type == ioc_type and ioc.value.lower() == value_lower:
                return ioc
        return None

    def check_ip(self, ip: str) -> Optional[IOC]:
        """Check if an IP is in the IOC database."""
        if ip.lower() in self._ip_iocs:
            return self._find_ioc("ip", ip)
        return None

    def check_hash(self, hash_value: str) -> Optional[IOC]:
        """Check if a hash is in the IOC database."""
        hash_lower = hash_value.lower()
        for hash_type, hash_set in self._hash_iocs.items():
            if hash_lower in hash_set:
                return self._find_ioc("hash", hash_value)
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get IOC database statistics."""
        return {
            "total_iocs": len(self._all_iocs),
            "ip_iocs": len(self._ip_iocs),
            "domain_iocs": len(self._domain_iocs),
            "hash_iocs": sum(len(s) for s in self._hash_iocs.values()),
            "path_iocs": len(self._path_iocs),
            "process_iocs": len(self._process_iocs),
        }



