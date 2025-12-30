#!/usr/bin/env python3
"""
Custom alert handler example for Linux Security Monitor.

Demonstrates how to create custom alert handling logic.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.logging_config import setup_logging, get_logger
from src.core.alert_manager import Alert
from src.core.base_monitor import Severity


logger = get_logger(__name__)


class CustomAlertHandler:
    """
    Example custom alert handler.

    Demonstrates:
    - Filtering alerts by criteria
    - Custom formatting
    - Integration with external systems
    """

    def __init__(self, min_severity: Severity = Severity.MEDIUM) -> None:
        """Initialize the handler."""
        self.min_severity = min_severity
        self.alert_history: List[Alert] = []

    def handle(self, alert: Alert) -> bool:
        """
        Handle an incoming alert.

        Args:
            alert: The alert to handle.

        Returns:
            True if alert was processed.
        """
        # Filter by severity
        if alert.severity < self.min_severity:
            logger.debug(f"Skipping low-severity alert: {alert.alert_id}")
            return False

        # Log the alert
        self._log_alert(alert)

        # Store in history
        self.alert_history.append(alert)

        # Send to external system (example)
        self._send_to_external(alert)

        return True

    def _log_alert(self, alert: Alert) -> None:
        """Log alert details."""
        logger.warning(
            f"ALERT [{alert.severity.name}]: {alert.title}\n"
            f"  Host: {alert.host}\n"
            f"  Time: {alert.timestamp}\n"
            f"  Description: {alert.description}"
        )

    def _send_to_external(self, alert: Alert) -> None:
        """
        Send alert to external system.

        This is a placeholder - implement actual integration here.
        """
        # Example: Send to Slack
        # slack_webhook_url = os.environ.get("SLACK_WEBHOOK")
        # if slack_webhook_url:
        #     requests.post(slack_webhook_url, json=alert.to_dict())

        # Example: Send to email
        # send_email(
        #     to="security@example.com",
        #     subject=f"Security Alert: {alert.title}",
        #     body=alert.description,
        # )

        logger.info(f"Would send alert {alert.alert_id} to external system")

    def get_summary(self) -> dict:
        """Get summary of handled alerts."""
        severity_counts = {}
        for alert in self.alert_history:
            sev = alert.severity.name
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_alerts": len(self.alert_history),
            "by_severity": severity_counts,
        }


def main() -> None:
    """Run custom alert handler example."""
    setup_logging(level="INFO")

    # Create handler
    handler = CustomAlertHandler(min_severity=Severity.MEDIUM)

    # Create sample alerts
    alerts = [
        Alert(
            alert_id="test-001",
            timestamp=datetime.now(),
            title="SSH Brute Force Detected",
            description="Multiple failed SSH attempts from 10.0.0.1",
            severity=Severity.HIGH,
            host="server-01",
            mitre_techniques=["T1110"],
        ),
        Alert(
            alert_id="test-002",
            timestamp=datetime.now(),
            title="User Login",
            description="Normal user login",
            severity=Severity.INFO,
            host="server-01",
        ),
        Alert(
            alert_id="test-003",
            timestamp=datetime.now(),
            title="Suspicious Process",
            description="Process running from /tmp",
            severity=Severity.CRITICAL,
            host="server-02",
            mitre_techniques=["T1059"],
        ),
    ]

    # Process alerts
    for alert in alerts:
        handler.handle(alert)

    # Print summary
    summary = handler.get_summary()
    logger.info(f"Alert Summary: {summary}")


if __name__ == "__main__":
    main()



