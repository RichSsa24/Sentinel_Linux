#!/usr/bin/env python3
"""
Basic monitoring example for Linux Security Monitor.

Demonstrates how to set up and run basic security monitoring.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config.logging_config import setup_logging, get_logger
from src.monitors import UserMonitor, ProcessMonitor, NetworkMonitor
from src.core.event_handler import EventHandler
from src.reporters import ConsoleReporter


def main() -> None:
    """Run basic monitoring example."""
    # Set up logging
    setup_logging(level="INFO")
    logger = get_logger(__name__)

    logger.info("Starting basic monitoring example...")

    # Create monitors with default config
    monitors = [
        UserMonitor({"enabled": True, "poll_interval": 60}),
        ProcessMonitor({"enabled": True, "poll_interval": 30}),
        NetworkMonitor({"enabled": True, "poll_interval": 30}),
    ]

    # Create reporter
    reporter = ConsoleReporter({"color": True})

    # Create event handler
    handler = EventHandler()

    # Collect and process events
    for monitor in monitors:
        logger.info(f"Collecting from {monitor.name}...")

        try:
            events = monitor.collect()
            logger.info(f"Collected {len(events)} events from {monitor.name}")

            for event in events:
                processed = handler.process(event)
                logger.info(
                    f"Event: {event.event_type.value} - "
                    f"Severity: {event.severity.name}"
                )
        except Exception as e:
            logger.error(f"Error collecting from {monitor.name}: {e}")

    logger.info("Basic monitoring example complete")


if __name__ == "__main__":
    main()



