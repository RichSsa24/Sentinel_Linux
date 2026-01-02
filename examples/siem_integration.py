#!/usr/bin/env python3
"""
SIEM integration example for Linux Security Monitor.

Demonstrates how to integrate with SIEM platforms.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.logging_config import setup_logging, get_logger
from src.core.alert_manager import Alert
from src.core.base_monitor import Severity


logger = get_logger(__name__)


class SIEMExporter:
    """
    Exports alerts in SIEM-compatible formats.

    Supports:
    - Splunk HEC format
    - Elasticsearch format
    - QRadar LEEF format
    - Generic CEF format
    """

    def to_splunk_hec(self, alert: Alert) -> Dict[str, Any]:
        """
        Format alert for Splunk HTTP Event Collector.

        Returns:
            Splunk HEC formatted event.
        """
        return {
            "time": alert.timestamp.timestamp(),
            "host": alert.host,
            "source": "Sentinel_Linux",
            "sourcetype": "lsm:alert",
            "event": {
                "alert_id": alert.alert_id,
                "severity": alert.severity.name,
                "title": alert.title,
                "description": alert.description,
                "mitre_techniques": alert.mitre_techniques,
                "ioc_matches": alert.ioc_matches,
            },
        }

    def to_elasticsearch(self, alert: Alert) -> Dict[str, Any]:
        """
        Format alert for Elasticsearch.

        Returns:
            Elasticsearch document.
        """
        return {
            "@timestamp": alert.timestamp.isoformat(),
            "host": {"name": alert.host},
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["indicator"],
                "severity": alert.severity.value,
            },
            "message": alert.description,
            "rule": {
                "name": alert.title,
            },
            "threat": {
                "technique": [
                    {"id": t} for t in alert.mitre_techniques
                ],
            },
            "labels": {
                "alert_id": alert.alert_id,
                "source": "Sentinel_Linux",
            },
        }

    def to_cef(self, alert: Alert) -> str:
        """
        Format alert as CEF (Common Event Format).

        Returns:
            CEF formatted string.
        """
        severity_map = {
            Severity.INFO: 1,
            Severity.LOW: 3,
            Severity.MEDIUM: 5,
            Severity.HIGH: 7,
            Severity.CRITICAL: 10,
        }

        cef_severity = severity_map.get(alert.severity, 5)

        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef_header = (
            f"CEF:0|LinuxSecurityMonitor|LSM|1.0|"
            f"{alert.alert_id}|{alert.title}|{cef_severity}|"
        )

        # Extension fields
        extensions = [
            f"dhost={alert.host}",
            f"msg={alert.description[:200]}",
            f"rt={int(alert.timestamp.timestamp() * 1000)}",
        ]

        if alert.mitre_techniques:
            extensions.append(f"cs1={','.join(alert.mitre_techniques)}")
            extensions.append("cs1Label=MITRETechniques")

        return cef_header + " ".join(extensions)

    def to_leef(self, alert: Alert) -> str:
        """
        Format alert as LEEF (Log Event Extended Format) for QRadar.

        Returns:
            LEEF formatted string.
        """
        # LEEF format: LEEF:Version|Vendor|Product|Version|EventID|
        leef_header = (
            f"LEEF:1.0|LinuxSecurityMonitor|LSM|1.0|{alert.alert_id}|"
        )

        # Key=Value pairs
        fields = [
            f"cat={alert.title}",
            f"sev={alert.severity.value}",
            f"src={alert.host}",
            f"msg={alert.description[:200]}",
        ]

        return leef_header + "\t".join(fields)


def main() -> None:
    """Run SIEM integration example."""
    setup_logging(level="INFO")

    # Create sample alert
    alert = Alert(
        alert_id="test-001",
        timestamp=datetime.now(),
        title="SSH Brute Force Detected",
        description="Multiple failed SSH authentication attempts detected from 10.0.0.1",
        severity=Severity.HIGH,
        host="server-01",
        mitre_techniques=["T1110", "T1078"],
        ioc_matches=["10.0.0.1"],
    )

    # Create exporter
    exporter = SIEMExporter()

    # Export in various formats
    logger.info("Splunk HEC Format:")
    print(json.dumps(exporter.to_splunk_hec(alert), indent=2))

    logger.info("\nElasticsearch Format:")
    print(json.dumps(exporter.to_elasticsearch(alert), indent=2))

    logger.info("\nCEF Format:")
    print(exporter.to_cef(alert))

    logger.info("\nLEEF Format:")
    print(exporter.to_leef(alert))


if __name__ == "__main__":
    main()



