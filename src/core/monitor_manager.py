"""
Monitor Manager - Orchestrates all security monitors.

Provides centralized management for:
- Monitor lifecycle (start/stop)
- Event collection and routing
- Alert generation
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from src.config.logging_config import get_logger
from src.config.settings import Settings
from src.core.event_handler import EventHandler
from src.core.alert_manager import AlertManager
from src.core.base_monitor import BaseMonitor


logger = get_logger(__name__)


class MonitorManager:
    """
    Central manager for all security monitoring components.

    Coordinates monitors, analyzers, and reporters to provide
    comprehensive security monitoring.
    """

    def __init__(self, settings: Settings, dry_run: bool = False) -> None:
        """
        Initialize the monitor manager.

        Args:
            settings: Application settings.
            dry_run: If True, don't send actual alerts.
        """
        self.settings = settings
        self.dry_run = dry_run
        self.running = False

        self.monitors: List[BaseMonitor] = []
        self.analyzers: List[Any] = []
        self.reporters: List[Any] = []

        self.event_handler: Optional[EventHandler] = None
        self.alert_manager: Optional[AlertManager] = None

    def setup(self) -> None:
        """Initialize all components."""
        logger.info("Setting up Linux Security Monitor...")

        self._setup_reporters()
        self._setup_alert_manager()
        self._setup_analyzers()
        self._setup_event_handler()
        self._setup_monitors()

        logger.info(
            f"Setup complete: {len(self.monitors)} monitors, "
            f"{len(self.analyzers)} analyzers, {len(self.reporters)} reporters"
        )

    def _setup_monitors(self) -> None:
        """Initialize enabled monitors."""
        from src.monitors import (
            UserMonitor,
            ProcessMonitor,
            NetworkMonitor,
            FileIntegrityMonitor,
            AuthMonitor,
            ServiceMonitor,
            LogMonitor,
        )

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
        from src.analyzers import (
            ThreatAnalyzer,
            AnomalyDetector,
            IOCMatcher,
            MITREMapper,
        )

        analyzer_configs = self.settings.analyzers

        if analyzer_configs.threat_analyzer.enabled:
            try:
                self.analyzers.append(
                    ThreatAnalyzer(analyzer_configs.threat_analyzer.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize ThreatAnalyzer: {e}")

        if analyzer_configs.anomaly_detector.enabled:
            try:
                self.analyzers.append(
                    AnomalyDetector(analyzer_configs.anomaly_detector.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize AnomalyDetector: {e}")

        if analyzer_configs.ioc_matcher.enabled:
            try:
                self.analyzers.append(
                    IOCMatcher(analyzer_configs.ioc_matcher.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize IOCMatcher: {e}")

        if analyzer_configs.mitre_mapper.enabled:
            try:
                self.analyzers.append(
                    MITREMapper(analyzer_configs.mitre_mapper.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize MITREMapper: {e}")

    def _setup_reporters(self) -> None:
        """Initialize enabled reporters."""
        from src.reporters import (
            ConsoleReporter,
            JSONReporter,
            SyslogReporter,
            WebhookReporter,
        )

        reporter_configs = self.settings.reporters

        if reporter_configs.console.enabled:
            try:
                self.reporters.append(
                    ConsoleReporter(reporter_configs.console.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize ConsoleReporter: {e}")

        if reporter_configs.json_reporter.enabled:
            try:
                self.reporters.append(
                    JSONReporter(reporter_configs.json_reporter.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize JSONReporter: {e}")

        if reporter_configs.syslog.enabled:
            try:
                self.reporters.append(
                    SyslogReporter(reporter_configs.syslog.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize SyslogReporter: {e}")

        if reporter_configs.webhook.enabled:
            try:
                self.reporters.append(
                    WebhookReporter(reporter_configs.webhook.model_dump())
                )
            except Exception as e:
                logger.error(f"Failed to initialize WebhookReporter: {e}")

    def _setup_alert_manager(self) -> None:
        """Initialize the alert manager."""
        reporters = [] if self.dry_run else self.reporters
        self.alert_manager = AlertManager(
            reporters=reporters,
            config=self.settings.alerting.model_dump(),
        )

    def _setup_event_handler(self) -> None:
        """Initialize the event handler."""
        self.event_handler = EventHandler(
            analyzers=self.analyzers,
            alert_manager=self.alert_manager,
        )

    def start(self) -> None:
        """Start all monitors."""
        logger.info("Starting monitors...")
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
        logger.info("Stopping monitors...")
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
            cleanup_counter = 0
            while self.running:
                for monitor in self.monitors:
                    try:
                        events = monitor.collect()
                        for event in events:
                            if self.event_handler:
                                self.event_handler.process(event)
                    except Exception as e:
                        logger.error(f"Error collecting from {monitor.name}: {e}")

                # Clean up alert cache periodically (every 60 iterations = ~1 minute)
                cleanup_counter += 1
                if cleanup_counter >= 60 and self.alert_manager:
                    try:
                        removed = self.alert_manager.cleanup_cache()
                        if removed > 0:
                            logger.debug(f"Cleaned up {removed} expired cache entries")
                    except Exception as e:
                        logger.warning(f"Error cleaning cache: {e}")
                    cleanup_counter = 0

                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.stop()

    def get_status(self) -> Dict[str, Any]:
        """Get status of all components."""
        return {
            "running": self.running,
            "monitors": [m.get_status().to_dict() for m in self.monitors],
            "analyzers": len(self.analyzers),
            "reporters": len(self.reporters),
            "event_handler": self.event_handler.get_stats() if self.event_handler else {},
            "alert_manager": self.alert_manager.get_stats() if self.alert_manager else {},
        }
