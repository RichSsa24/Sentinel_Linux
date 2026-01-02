"""
Threat analysis engine.

Rule-based threat detection using Sigma-compatible rules
and custom detection logic.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.config.logging_config import get_logger
from src.core.base_monitor import Event, Severity
from src.core.event_handler import AnalysisResult


logger = get_logger(__name__)


@dataclass
class DetectionRule:
    """A detection rule for threat identification."""

    id: str
    title: str
    description: str
    severity: Severity
    detection: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    enabled: bool = True

    @classmethod
    def from_sigma(cls, data: Dict[str, Any]) -> "DetectionRule":
        """Create rule from Sigma format."""
        level_map = {
            "informational": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        # Extract MITRE techniques from tags
        techniques = []
        tags = data.get("tags", [])
        for tag in tags:
            if tag.startswith("attack.t"):
                techniques.append(tag.replace("attack.", "").upper())

        return cls(
            id=data.get("id", data.get("title", "unknown")),
            title=data.get("title", "Unnamed Rule"),
            description=data.get("description", ""),
            severity=level_map.get(data.get("level", "medium"), Severity.MEDIUM),
            detection=data.get("detection", {}),
            tags=tags,
            mitre_techniques=techniques,
            enabled=data.get("status", "experimental") != "deprecated",
        )


@dataclass
class RuleMatch:
    """Result of a rule matching an event."""

    rule: DetectionRule
    event: Event
    matched_fields: Dict[str, Any]
    confidence: float


class ThreatAnalyzer:
    """
    Rule-based threat detection engine.

    Features:
    - Sigma rule format support
    - Custom detection rules
    - Event correlation
    - Confidence scoring
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize threat analyzer."""
        self.config = config
        self.rules_path = config.get("rules_path", "")
        self.rules: List[DetectionRule] = []

        self._load_builtin_rules()

        if self.rules_path and os.path.exists(self.rules_path):
            self.load_rules(self.rules_path)

        logger.info(f"ThreatAnalyzer initialized with {len(self.rules)} rules")

    def _load_builtin_rules(self) -> None:
        """Load built-in detection rules."""
        builtin_rules = [
            {
                "id": "builtin_ssh_brute_force",
                "title": "SSH Brute Force Detection",
                "description": "Detects multiple failed SSH authentication attempts",
                "level": "high",
                "tags": ["attack.credential_access", "attack.t1110"],
                "detection": {
                    "event_type": "brute_force",
                    "metadata.service": "ssh",
                },
            },
            {
                "id": "builtin_suspicious_process",
                "title": "Suspicious Process Execution",
                "description": "Detects execution of known suspicious tools",
                "level": "high",
                "tags": ["attack.execution", "attack.t1059"],
                "detection": {
                    "event_type": "process_suspicious",
                },
            },
            {
                "id": "builtin_root_login",
                "title": "Root User Login",
                "description": "Detects direct root user login",
                "level": "medium",
                "tags": ["attack.initial_access", "attack.t1078"],
                "detection": {
                    "event_type": "user_login",
                    "subject.user": "root",
                },
            },
            {
                "id": "builtin_file_integrity",
                "title": "Critical File Modified",
                "description": "Detects modification of critical system files",
                "level": "high",
                "tags": ["attack.persistence", "attack.t1543"],
                "detection": {
                    "event_type": ["file_modified", "file_created", "file_deleted"],
                    "metadata.is_critical": True,
                },
            },
            {
                "id": "builtin_new_listener",
                "title": "New Network Listener",
                "description": "Detects new listening ports",
                "level": "medium",
                "tags": ["attack.command_and_control", "attack.t1571"],
                "detection": {
                    "event_type": "network_listener",
                },
            },
        ]

        for rule_data in builtin_rules:
            self.rules.append(DetectionRule.from_sigma(rule_data))

    def load_rules(self, path: str) -> int:
        """
        Load detection rules from a directory.

        Args:
            path: Path to rules directory.

        Returns:
            Number of rules loaded.
        """
        count = 0
        rules_path = Path(path)

        if not rules_path.exists():
            return 0

        # Load YAML rules
        for rule_file in rules_path.glob("**/*.yml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        rule = DetectionRule.from_sigma(data)
                        self.rules.append(rule)
                        count += 1
            except Exception as e:
                logger.warning(f"Failed to load rule {rule_file}: {e}")

        for rule_file in rules_path.glob("**/*.yaml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data:
                        rule = DetectionRule.from_sigma(data)
                        self.rules.append(rule)
                        count += 1
            except Exception as e:
                logger.warning(f"Failed to load rule {rule_file}: {e}")

        logger.info(f"Loaded {count} rules from {path}")
        return count

    def analyze(self, event: Event) -> Optional[AnalysisResult]:
        """
        Analyze an event for threats.

        Args:
            event: Event to analyze.

        Returns:
            AnalysisResult if threats detected, None otherwise.
        """
        matches: List[RuleMatch] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            match_result = self._match_rule(rule, event)
            if match_result:
                matches.append(match_result)

        if not matches:
            return None

        # Calculate threat score
        max_severity = max(m.rule.severity.value for m in matches)
        threat_score = min(1.0, max_severity / 4.0 + 0.2 * len(matches))

        # Collect MITRE techniques
        techniques = []
        for match in matches:
            techniques.extend(match.rule.mitre_techniques)

        return AnalysisResult(
            analyzer_name="ThreatAnalyzer",
            threat_score=threat_score,
            mitre_techniques=list(set(techniques)),
            findings=[f"Rule matched: {m.rule.title}" for m in matches],
            metadata={
                "matched_rules": [m.rule.id for m in matches],
                "max_severity": Severity(max_severity).name,
            },
        )

    def _match_rule(self, rule: DetectionRule, event: Event) -> Optional[RuleMatch]:
        """Match a rule against an event."""
        detection = rule.detection
        matched_fields: Dict[str, Any] = {}

        for detection_field, expected in detection.items():
            actual = self._get_field_value(event, detection_field)

            if actual is None:
                return None

            if isinstance(expected, list):
                if actual not in expected and str(actual) not in expected:
                    return None
            elif isinstance(expected, str):
                if expected.startswith("*") or expected.endswith("*"):
                    pattern = expected.replace("*", ".*")
                    if not re.match(pattern, str(actual)):
                        return None
                elif str(actual) != expected:
                    return None
            elif actual != expected:
                return None

            matched_fields[detection_field] = actual

        return RuleMatch(
            rule=rule,
            event=event,
            matched_fields=matched_fields,
            confidence=0.8,
        )

    def _get_field_value(self, event: Event, field: str) -> Any:
        """Get a field value from an event using dot notation."""
        parts = field.split(".")
        obj: Any = event

        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None

            if obj is None:
                return None

        # Handle EventType enum
        if hasattr(obj, "value"):
            return obj.value

        return obj

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a detection rule."""
        self.rules.append(rule)

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get list of loaded rules."""
        return [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity.name,
                "enabled": r.enabled,
                "mitre_techniques": r.mitre_techniques,
            }
            for r in self.rules
        ]



