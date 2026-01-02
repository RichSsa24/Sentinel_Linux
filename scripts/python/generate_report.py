#!/usr/bin/env python3
"""
Security report generator for Linux Security Monitor.

Generates comprehensive security reports from collected events.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Try to import from project modules, fallback to local implementations
try:
    from src.config.logging_config import setup_logging, get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)
    def setup_logging(level="INFO"):
        logging.getLogger().setLevel(getattr(logging, level))

try:
    from src.utils.system_utils import get_system_info, get_hostname
except ImportError:
    import socket
    import platform
    def get_hostname() -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
    
    def get_system_info() -> Dict[str, Any]:
        return {
            "hostname": get_hostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "architecture": platform.machine(),
        }


def load_events(
    events_file: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load events from JSON file with filtering."""
    events = []

    try:
        with open(events_file, "r") as f:
            for line in f:
                try:
                    event = json.loads(line.strip())

                    # Time filter
                    if start_time or end_time:
                        event_time = datetime.fromisoformat(
                            event.get("timestamp", "")
                        )
                        if start_time and event_time < start_time:
                            continue
                        if end_time and event_time > end_time:
                            continue

                    # Severity filter
                    if severity:
                        event_sev = event.get("severity", "INFO")
                        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                        if severity_order.index(event_sev) < severity_order.index(severity):
                            continue

                    events.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning(f"Events file not found: {events_file}")

    return events


def generate_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary statistics from events."""
    if not events:
        return {"total_events": 0}

    # Count by severity
    severity_counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}
    mitre_techniques: Dict[str, int] = {}

    for event in events:
        # Severity
        sev = event.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Event type
        etype = event.get("event_type", "unknown")
        type_counts[etype] = type_counts.get(etype, 0) + 1

        # MITRE techniques
        for tech in event.get("mitre_techniques", []):
            mitre_techniques[tech] = mitre_techniques.get(tech, 0) + 1

    return {
        "total_events": len(events),
        "by_severity": severity_counts,
        "by_type": type_counts,
        "mitre_techniques": mitre_techniques,
        "time_range": {
            "start": min(e.get("timestamp", "") for e in events),
            "end": max(e.get("timestamp", "") for e in events),
        },
    }


def generate_json_report(
    events: List[Dict[str, Any]],
    output_path: str,
) -> None:
    """Generate JSON format report."""
    report = {
        "report_generated": datetime.now().isoformat(),
        "host": get_hostname(),
        "summary": generate_summary(events),
        "events": events,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"JSON report saved to {output_path}")


def generate_text_report(
    events: List[Dict[str, Any]],
    output_path: str,
) -> None:
    """Generate text format report."""
    summary = generate_summary(events)

    lines = [
        "=" * 60,
        "  LINUX SECURITY MONITOR - SECURITY REPORT",
        "=" * 60,
        "",
        f"Generated: {datetime.now().isoformat()}",
        f"Host: {get_hostname()}",
        "",
        "-" * 60,
        "SUMMARY",
        "-" * 60,
        f"Total Events: {summary.get('total_events', 0)}",
        "",
        "By Severity:",
    ]

    for sev, count in summary.get("by_severity", {}).items():
        lines.append(f"  {sev}: {count}")

    lines.extend([
        "",
        "By Type:",
    ])

    for etype, count in list(summary.get("by_type", {}).items())[:10]:
        lines.append(f"  {etype}: {count}")

    if summary.get("mitre_techniques"):
        lines.extend([
            "",
            "MITRE ATT&CK Techniques:",
        ])
        for tech, count in list(summary.get("mitre_techniques", {}).items())[:10]:
            lines.append(f"  {tech}: {count}")

    lines.extend([
        "",
        "-" * 60,
        "HIGH/CRITICAL EVENTS",
        "-" * 60,
    ])

    high_events = [
        e for e in events
        if e.get("severity") in ["HIGH", "CRITICAL"]
    ]

    for event in high_events[:20]:
        lines.extend([
            "",
            f"[{event.get('severity')}] {event.get('timestamp', '')}",
            f"Type: {event.get('event_type', 'unknown')}",
            f"Description: {event.get('description', 'N/A')[:100]}",
        ])

    lines.append("")
    lines.append("=" * 60)

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    logger.info(f"Text report saved to {output_path}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate Security Reports")

    parser.add_argument(
        "-i", "--input",
        default="/var/log/Sentinel_Linux/events.json",
        help="Input events file",
    )
    parser.add_argument(
        "-o", "--output",
        default="security_report",
        help="Output file path (without extension)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "text", "both"],
        default="both",
        help="Output format",
    )
    parser.add_argument(
        "--start-time",
        help="Start time (ISO 8601)",
    )
    parser.add_argument(
        "--end-time",
        help="End time (ISO 8601)",
    )
    parser.add_argument(
        "--severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    setup_logging(level="INFO")
    args = parse_args()

    # Parse times
    start_time = None
    end_time = None

    if args.start_time:
        start_time = datetime.fromisoformat(args.start_time)
    if args.end_time:
        end_time = datetime.fromisoformat(args.end_time)

    # Load events
    events = load_events(
        args.input,
        start_time=start_time,
        end_time=end_time,
        severity=args.severity,
    )

    logger.info(f"Loaded {len(events)} events")

    # Generate reports
    if args.format in ["json", "both"]:
        generate_json_report(events, f"{args.output}.json")

    if args.format in ["text", "both"]:
        generate_text_report(events, f"{args.output}.txt")

    return 0


if __name__ == "__main__":
    sys.exit(main())



