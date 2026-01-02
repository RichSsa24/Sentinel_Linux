"""
Console reporter for terminal output.

Formats alerts for human-readable terminal display with color support.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional

from src.config.logging_config import get_logger
from src.core.alert_manager import Alert
from src.core.base_monitor import Severity


logger = get_logger(__name__)


class ConsoleReporter:
    """
    Outputs alerts to the terminal with formatting.

    Features:
    - Color-coded severity
    - Structured output
    - Configurable verbosity
    """

    SEVERITY_COLORS = {
        Severity.INFO: "\033[36m",      # Cyan
        Severity.LOW: "\033[32m",       # Green
        Severity.MEDIUM: "\033[33m",    # Yellow
        Severity.HIGH: "\033[31m",      # Red
        Severity.CRITICAL: "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize console reporter."""
        config = config or {}
        self.use_color = config.get("color", True) and sys.stdout.isatty()
        self.severity_threshold = Severity[
            config.get("severity_threshold", "INFO").upper()
        ]
        self.verbose = config.get("verbose", False)

    def report(self, alert: Alert) -> None:
        """
        Output alert to console.

        Args:
            alert: Alert to display.
        """
        if alert.severity < self.severity_threshold:
            return

        output = self._format_alert(alert)
        print(output)

    def _format_alert(self, alert: Alert) -> str:
        """Format alert for console output."""
        lines = []

        # Header
        severity_str = self._colorize(
            f"[{alert.severity.name}]",
            alert.severity
        )
        timestamp = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        lines.append(f"\n{'=' * 60}")
        lines.append(f"{severity_str} {self._bold(alert.title)}")
        lines.append(f"Time: {timestamp} | Host: {alert.host}")
        lines.append(f"{'=' * 60}")

        # Description
        lines.append(f"\n{alert.description}")

        # MITRE techniques
        if alert.mitre_techniques:
            lines.append(f"\nMITRE ATT&CK: {', '.join(alert.mitre_techniques)}")

        # IOC matches
        if alert.ioc_matches:
            lines.append(f"IOC Matches: {', '.join(alert.ioc_matches)}")

        # Recommendations
        if alert.recommendations and self.verbose:
            lines.append("\nRecommendations:")
            for rec in alert.recommendations[:3]:
                lines.append(f"  - {rec}")

        # Metadata
        if self.verbose and alert.metadata:
            lines.append(f"\nMetadata: {alert.metadata}")

        lines.append("")

        return "\n".join(lines)

    def _colorize(self, text: str, severity: Severity) -> str:
        """Apply color to text based on severity."""
        if not self.use_color:
            return text
        color = self.SEVERITY_COLORS.get(severity, "")
        return f"{color}{text}{self.RESET}"

    def _bold(self, text: str) -> str:
        """Make text bold."""
        if not self.use_color:
            return text
        return f"{self.BOLD}{text}{self.RESET}"


