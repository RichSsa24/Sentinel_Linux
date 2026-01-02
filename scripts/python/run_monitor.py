#!/usr/bin/env python3
"""
Main entry point for Linux Security Monitor.

Usage:
    python run_monitor.py [options]

Options:
    -c, --config PATH    Configuration file path
    -v, --verbose        Enable verbose output
    -d, --debug          Enable debug mode
    --dry-run            Run without sending alerts
    --validate-config    Validate configuration and exit
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import project modules - these are required for this script
try:
    from src.config.settings import Settings, get_settings
    from src.config.logging_config import setup_logging, get_logger
    from src.core.event_handler import EventHandler
    from src.core.alert_manager import AlertManager
    from src.monitors import (
        UserMonitor,
        ProcessMonitor,
        NetworkMonitor,
        FileIntegrityMonitor,
        AuthMonitor,
        ServiceMonitor,
        LogMonitor,
    )
    from src.analyzers import (
        ThreatAnalyzer,
        AnomalyDetector,
        IOCMatcher,
        MITREMapper,
    )
    from src.reporters import (
        ConsoleReporter,
        JSONReporter,
        SyslogReporter,
        WebhookReporter,
    )
except ImportError as e:
    print(f"Error: Failed to import required modules: {e}", file=sys.stderr)
    print("This script requires the full Linux Security Monitor project to be installed.", file=sys.stderr)
    print("Please ensure you are running from the project root directory.", file=sys.stderr)
    sys.exit(1)

logger = get_logger(__name__)


class SecurityMonitor:
    """Main security monitoring orchestrator."""

    def __init__(self, settings: Settings, dry_run: bool = False) -> None:
        """Initialize the security monitor."""
        self.settings = settings
        self.dry_run = dry_run
        self.running = False

        self.monitors: List = []
        self.analyzers: List = []
        self.reporters: List = []

        self.event_handler: Optional[EventHandler] = None
        self.alert_manager: Optional[AlertManager] = None

    def setup(self) -> None:
        """Set up all components."""
        logger.info("Setting up Linux Security Monitor...")

        # Set up reporters
        self._setup_reporters()

        # Set up alert manager
        self.alert_manager = AlertManager(
            reporters=self.reporters if not self.dry_run else [],
            config=self.settings.alerting.model_dump(),
        )

        # Set up analyzers
        self._setup_analyzers()

        # Set up event handler
        self.event_handler = EventHandler(
            analyzers=self.analyzers,
            alert_manager=self.alert_manager,
        )

        # Set up monitors
        self._setup_monitors()

        logger.info(f"Setup complete: {len(self.monitors)} monitors, "
                    f"{len(self.analyzers)} analyzers, {len(self.reporters)} reporters")

    def _setup_monitors(self) -> None:
        """Initialize enabled monitors."""
        monitor_configs = self.settings.monitors

        monitor_classes = [
            (UserMonitor, monitor_configs.user_monitor),
            (ProcessMonitor, monitor_configs.process_monitor),
            (NetworkMonitor, monitor_configs.network_monitor),
            (FileIntegrityMonitor, monitor_configs.file_integrity_monitor),
            (AuthMonitor, monitor_configs.auth_monitor),
            (ServiceMonitor, monitor_configs.service_monitor),
            (LogMonitor, monitor_configs.log_monitor),
        ]

        for monitor_class, config in monitor_classes:
            if config.enabled:
                try:
                    monitor = monitor_class(config.model_dump())
                    self.monitors.append(monitor)
                    logger.debug(f"Initialized {monitor_class.__name__}")
                except Exception as e:
                    logger.error(f"Failed to initialize {monitor_class.__name__}: {e}")

    def _setup_analyzers(self) -> None:
        """Initialize enabled analyzers."""
        analyzer_configs = self.settings.analyzers

        if analyzer_configs.threat_analyzer.enabled:
            self.analyzers.append(
                ThreatAnalyzer(analyzer_configs.threat_analyzer.model_dump())
            )

        if analyzer_configs.anomaly_detector.enabled:
            self.analyzers.append(
                AnomalyDetector(analyzer_configs.anomaly_detector.model_dump())
            )

        if analyzer_configs.ioc_matcher.enabled:
            self.analyzers.append(
                IOCMatcher(analyzer_configs.ioc_matcher.model_dump())
            )

        if analyzer_configs.mitre_mapper.enabled:
            self.analyzers.append(
                MITREMapper(analyzer_configs.mitre_mapper.model_dump())
            )

    def _setup_reporters(self) -> None:
        """Initialize enabled reporters."""
        reporter_configs = self.settings.reporters

        if reporter_configs.console.enabled:
            self.reporters.append(
                ConsoleReporter(reporter_configs.console.model_dump())
            )

        if reporter_configs.json.enabled:
            self.reporters.append(
                JSONReporter(reporter_configs.json.model_dump())
            )

        if reporter_configs.syslog.enabled:
            self.reporters.append(
                SyslogReporter(reporter_configs.syslog.model_dump())
            )

        if reporter_configs.webhook.enabled:
            self.reporters.append(
                WebhookReporter(reporter_configs.webhook.model_dump())
            )

    def start(self) -> None:
        """Start all monitors."""
        logger.info("Starting Linux Security Monitor...")
        self.running = True

        for monitor in self.monitors:
            try:
                monitor.start()
                logger.info(f"Started {monitor.name}")
            except Exception as e:
                logger.error(f"Failed to start {monitor.name}: {e}")

        logger.info("All monitors started")

    def stop(self) -> None:
        """Stop all monitors."""
        logger.info("Stopping Linux Security Monitor...")
        self.running = False

        for monitor in self.monitors:
            try:
                monitor.stop()
                logger.info(f"Stopped {monitor.name}")
            except Exception as e:
                logger.error(f"Error stopping {monitor.name}: {e}")

        logger.info("All monitors stopped")

    def run(self) -> None:
        """Main monitoring loop."""
        self.setup()
        self.start()

        try:
            while self.running:
                # Collect events from monitors
                for monitor in self.monitors:
                    try:
                        events = monitor.collect()
                        for event in events:
                            self.event_handler.process(event)
                    except Exception as e:
                        logger.error(f"Error collecting from {monitor.name}: {e}")

                # Small sleep to prevent busy loop
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.stop()

    def get_status(self) -> dict:
        """Get status of all components."""
        return {
            "running": self.running,
            "monitors": [m.get_status().to_dict() for m in self.monitors],
            "event_handler": self.event_handler.get_stats() if self.event_handler else {},
            "alert_manager": self.alert_manager.get_stats() if self.alert_manager else {},
        }


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Linux Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-c", "--config",
        help="Configuration file path",
        default=None,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without sending alerts",
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration and exit",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Log level",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Determine log level
    log_level = "DEBUG" if args.debug else args.log_level
    if args.verbose:
        log_level = "DEBUG"

    # Set up logging
    setup_logging(level=log_level)

    logger.info("Linux Security Monitor starting...")

    # Load configuration
    try:
        settings = get_settings(args.config)
        logger.info(f"Configuration loaded from {args.config or 'default'}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return 1

    # Validate config only
    if args.validate_config:
        logger.info("Configuration is valid")
        return 0

    # Create and run monitor
    monitor = SecurityMonitor(settings, dry_run=args.dry_run)

    # Set up signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        monitor.running = False

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        monitor.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

    logger.info("Linux Security Monitor stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())



