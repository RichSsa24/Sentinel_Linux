"""
MITRE ATT&CK mapping module.

Maps detected threats to MITRE ATT&CK techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.config.logging_config import get_logger
from src.core.base_monitor import Event
from src.core.event_handler import AnalysisResult


logger = get_logger(__name__)


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique information."""

    technique_id: str
    name: str
    tactic: str
    description: str = ""
    detection: str = ""
    platforms: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)


# MITRE ATT&CK mapping for common Linux events
TECHNIQUE_MAPPING: Dict[str, List[str]] = {
    "user_login": ["T1078"],                     # Valid Accounts
    "user_logout": [],
    "user_privilege_escalation": ["T1548", "T1068"],  # Abuse Elevation, Exploitation
    "auth_failure": ["T1110"],                   # Brute Force
    "auth_success": ["T1078"],                   # Valid Accounts
    "process_start": ["T1059"],                  # Command and Scripting Interpreter
    "process_suspicious": ["T1059", "T1053"],    # Command Interpreter, Scheduled Task
    "network_connection": ["T1071", "T1095"],    # Application Layer Protocol, Non-App Protocol
    "network_listener": ["T1571"],               # Non-Standard Port
    "file_modified": ["T1565"],                  # Data Manipulation
    "file_created": ["T1105"],                   # Ingress Tool Transfer
    "file_deleted": ["T1070"],                   # Indicator Removal
    "file_permission_changed": ["T1222"],        # File and Directory Permissions
    "service_started": ["T1569"],                # System Services
    "service_stopped": ["T1489"],                # Service Stop
    "service_new": ["T1543"],                    # Create or Modify System Process
    "log_pattern_match": ["T1070"],              # Indicator Removal
    "anomaly_detected": [],
    "ioc_match": [],
    "brute_force": ["T1110"],                    # Brute Force
}


# Technique details
TECHNIQUES: Dict[str, MITRETechnique] = {
    "T1059": MITRETechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries may abuse command and script interpreters to execute commands.",
        platforms=["Linux", "macOS", "Windows"],
        sub_techniques=["T1059.001", "T1059.004", "T1059.006"],
    ),
    "T1078": MITRETechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Initial Access",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1110": MITRETechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force techniques to gain access to accounts.",
        platforms=["Linux", "macOS", "Windows"],
        sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
    ),
    "T1548": MITRETechnique(
        technique_id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation, Defense Evasion",
        description=(
            "Adversaries may circumvent mechanisms designed to control elevated privileges."
        ),
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1068": MITRETechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries may exploit software vulnerabilities to elevate privileges.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1053": MITRETechnique(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="Execution, Persistence, Privilege Escalation",
        description="Adversaries may abuse task scheduling functionality.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1071": MITRETechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversaries may communicate using application layer protocols.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1571": MITRETechnique(
        technique_id="T1571",
        name="Non-Standard Port",
        tactic="Command and Control",
        description="Adversaries may communicate using a protocol and port pairing not normally associated.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1070": MITRETechnique(
        technique_id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        description="Adversaries may delete or modify artifacts to remove evidence.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1105": MITRETechnique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Adversaries may transfer tools or other files from external systems.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1222": MITRETechnique(
        technique_id="T1222",
        name="File and Directory Permissions Modification",
        tactic="Defense Evasion",
        description="Adversaries may modify file or directory permissions/attributes.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1543": MITRETechnique(
        technique_id="T1543",
        name="Create or Modify System Process",
        tactic="Persistence, Privilege Escalation",
        description=(
            "Adversaries may create or modify system processes to execute malicious payloads."
        ),
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1569": MITRETechnique(
        technique_id="T1569",
        name="System Services",
        tactic="Execution",
        description="Adversaries may abuse system services to execute malicious commands or payloads.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1489": MITRETechnique(
        technique_id="T1489",
        name="Service Stop",
        tactic="Impact",
        description="Adversaries may stop or disable services to render them unavailable.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1565": MITRETechnique(
        technique_id="T1565",
        name="Data Manipulation",
        tactic="Impact",
        description="Adversaries may insert, delete, or manipulate data to influence outcomes.",
        platforms=["Linux", "macOS", "Windows"],
    ),
    "T1095": MITRETechnique(
        technique_id="T1095",
        name="Non-Application Layer Protocol",
        tactic="Command and Control",
        description="Adversaries may use a non-application layer protocol for communication.",
        platforms=["Linux", "macOS", "Windows"],
    ),
}


class MITREMapper:
    """
    Maps detected events to MITRE ATT&CK techniques.

    Features:
    - Automatic technique identification
    - Tactic context
    - Sub-technique mapping
    - ATT&CK Navigator export
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize MITRE mapper."""
        self.config = config
        self.include_sub_techniques = config.get("include_sub_techniques", True)

        logger.info("MITREMapper initialized")

    def analyze(self, event: Event) -> Optional[AnalysisResult]:
        """
        Map event to MITRE ATT&CK techniques.

        Args:
            event: Event to analyze.

        Returns:
            AnalysisResult with technique mappings.
        """
        techniques = self.map(event)

        if not techniques:
            return None

        return AnalysisResult(
            analyzer_name="MITREMapper",
            mitre_techniques=[t.technique_id for t in techniques],
            findings=[
                f"MITRE: {t.technique_id} - {t.name} ({t.tactic})"
                for t in techniques
            ],
            metadata={
                "techniques": [
                    {
                        "id": t.technique_id,
                        "name": t.name,
                        "tactic": t.tactic,
                    }
                    for t in techniques
                ],
            },
        )

    def map(self, event: Event) -> List[MITRETechnique]:
        """
        Map event to ATT&CK techniques.

        Args:
            event: Event to map.

        Returns:
            List of mapped techniques.
        """
        techniques: List[MITRETechnique] = []

        # Get techniques for event type
        event_type_value = event.event_type.value
        technique_ids = TECHNIQUE_MAPPING.get(event_type_value, [])

        for tech_id in technique_ids:
            if tech_id in TECHNIQUES:
                techniques.append(TECHNIQUES[tech_id])

        # Add context-specific mappings
        context_techniques = self._map_context(event)
        techniques.extend(context_techniques)

        # Remove duplicates
        seen = set()
        unique_techniques = []
        for t in techniques:
            if t.technique_id not in seen:
                seen.add(t.technique_id)
                unique_techniques.append(t)

        return unique_techniques

    def _map_context(self, event: Event) -> List[MITRETechnique]:
        """Map additional techniques based on event context."""
        techniques: List[MITRETechnique] = []

        # Check for specific patterns
        if event.subject and event.subject.process:
            proc_lower = event.subject.process.lower()

            # Shell interpreters
            if proc_lower in ["bash", "sh", "zsh", "dash"]:
                if "T1059" in TECHNIQUES:
                    techniques.append(TECHNIQUES["T1059"])

        # Check metadata for indicators
        if "encoded_command" in event.metadata:
            if "T1059" in TECHNIQUES:
                techniques.append(TECHNIQUES["T1059"])

        if event.metadata.get("is_critical"):
            if "T1070" in TECHNIQUES:
                techniques.append(TECHNIQUES["T1070"])

        return techniques

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """
        Get details for a specific technique.

        Args:
            technique_id: ATT&CK technique ID.

        Returns:
            Technique details or None.
        """
        return TECHNIQUES.get(technique_id)

    def get_all_techniques(self) -> List[Dict[str, Any]]:
        """Get all known techniques."""
        return [
            {
                "id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
            }
            for t in TECHNIQUES.values()
        ]

    def export_navigator(self, technique_ids: List[str]) -> Dict[str, Any]:
        """
        Export techniques as ATT&CK Navigator layer.

        Args:
            technique_ids: List of technique IDs.

        Returns:
            Navigator layer JSON structure.
        """
        techniques_data = []

        for tech_id in technique_ids:
            techniques_data.append({
                "techniqueID": tech_id,
                "score": 100,
                "color": "#ff6666",
                "comment": "Detected by Linux Security Monitor",
                "enabled": True,
            })

        return {
            "name": "Linux Security Monitor Detections",
            "version": "4.5",
            "domain": "enterprise-attack",
            "description": "Techniques detected by Linux Security Monitor",
            "techniques": techniques_data,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Detected", "color": "#ff6666"},
            ],
        }


