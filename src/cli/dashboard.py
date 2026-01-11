#!/usr/bin/env python3
"""
Interactive dashboard for Linux Security Monitor.

Provides real-time monitoring visualization using Rich library
for terminal-based dashboard with live updates, statistics, and alerts.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: rich library is required. Install with: pip install rich")
    sys.exit(1)

# Ensure src is in path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.config.settings import Settings, get_settings
from src.config.logging_config import get_logger
from src.core.monitor_manager import MonitorManager

logger = get_logger(__name__)


class Dashboard:
    """
    Interactive terminal dashboard for security monitoring.

    Features:
    - Real-time statistics
    - Live event stream
    - Alert summary
    - System health indicators
    - MITRE ATT&CK technique mapping
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        refresh_interval: float = 1.0,
    ) -> None:
        """
        Initialize the dashboard.

        Args:
            config_path: Path to configuration file.
            refresh_interval: Refresh interval in seconds.
        """
        self.console = Console()
        self.config_path = config_path
        self.refresh_interval = refresh_interval
        self.running = True
        self.start_time = datetime.now()

        # Statistics
        self.stats: Dict[str, Any] = {
            "events_processed": 0,
            "alerts_generated": 0,
            "alerts_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
            "mitre_techniques": {},
            "monitors_status": {},
            "recent_events": [],
            "recent_alerts": [],
        }

        # Load configuration
        try:
            self.settings = get_settings(config_path)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.console.print(f"[red]Error loading configuration: {e}[/red]")
            sys.exit(1)

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        self.console.print("\n[yellow]Shutting down dashboard...[/yellow]")
        self.running = False

    def _create_header(self) -> Panel:
        """Create dashboard header panel."""
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split(".")[0]  # Remove microseconds

        header_text = Text()
        header_text.append("🛡️  SENTINEL LINUX - Security Monitoring Dashboard", style="bold cyan")
        header_text.append("\n")
        header_text.append(f"Uptime: {uptime_str} | ", style="dim")
        header_text.append(f"Host: {self.settings.global_config.hostname or 'unknown'}", style="dim")

        return Panel(header_text, box=box.ROUNDED, style="bold blue")

    def _create_statistics_table(self) -> Table:
        """Create statistics table."""
        table = Table(title="Statistics", box=box.ROUNDED, show_header=True)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", justify="right")

        table.add_row("Events Processed", str(self.stats["events_processed"]))
        table.add_row("Alerts Generated", str(self.stats["alerts_generated"]))
        table.add_row("Active Monitors", str(len(self.stats["monitors_status"])))

        return table

    def _create_alerts_table(self) -> Table:
        """Create alerts summary table."""
        table = Table(title="Alerts by Severity", box=box.ROUNDED, show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right", style="yellow")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.stats["alerts_by_severity"].get(severity, 0)
            style_map = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "dim",
            }
            table.add_row(severity, str(count), style=style_map.get(severity, ""))

        return table

    def _create_monitors_table(self) -> Table:
        """Create monitors status table."""
        table = Table(title="Monitors Status", box=box.ROUNDED, show_header=True)
        table.add_column("Monitor", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Events", justify="right", style="green")

        if not self.stats["monitors_status"]:
            table.add_row("No monitors active", "-", "0")
        else:
            for monitor_name, status in self.stats["monitors_status"].items():
                status_icon = "✅" if status.get("enabled", False) else "❌"
                events = status.get("events", 0)
                table.add_row(monitor_name, status_icon, str(events))

        return table

    def _create_mitre_table(self) -> Table:
        """Create MITRE ATT&CK techniques table."""
        table = Table(title="MITRE ATT&CK Techniques", box=box.ROUNDED, show_header=True)
        table.add_column("Technique", style="cyan")
        table.add_column("Count", justify="right", style="yellow")

        mitre_data = self.stats["mitre_techniques"]
        if not mitre_data:
            table.add_row("No techniques detected", "0")
        else:
            # Sort by count descending
            sorted_techniques = sorted(
                mitre_data.items(), key=lambda x: x[1], reverse=True
            )[:10]  # Top 10

            for technique, count in sorted_techniques:
                table.add_row(technique, str(count))

        return table

    def _create_recent_events_panel(self) -> Panel:
        """Create recent events panel."""
        events = self.stats["recent_events"][-10:]  # Last 10 events
        if not events:
            content = Text("No recent events", style="dim")
        else:
            content = Text()
            for event in reversed(events):
                timestamp = event.get("timestamp", "unknown")
                event_type = event.get("type", "unknown")
                severity = event.get("severity", "INFO")
                content.append(f"[{timestamp}] ", style="dim")
                content.append(f"{event_type} ", style="cyan")
                content.append(f"[{severity}]", style=self._get_severity_style(severity))
                content.append("\n")

        return Panel(content, title="Recent Events", box=box.ROUNDED)

    def _create_recent_alerts_panel(self) -> Panel:
        """Create recent alerts panel."""
        alerts = self.stats["recent_alerts"][-5:]  # Last 5 alerts
        if not alerts:
            content = Text("No recent alerts", style="dim")
        else:
            content = Text()
            for alert in reversed(alerts):
                timestamp = alert.get("timestamp", "unknown")
                title = alert.get("title", "Unknown")
                severity = alert.get("severity", "INFO")
                content.append(f"[{timestamp}] ", style="dim")
                content.append(f"{title} ", style="bold")
                content.append(f"[{severity}]", style=self._get_severity_style(severity))
                content.append("\n")

        return Panel(content, title="Recent Alerts", box=box.ROUNDED)

    def _get_severity_style(self, severity: str) -> str:
        """Get style for severity level."""
        style_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }
        return style_map.get(severity.upper(), "dim")

    def _create_layout(self) -> Layout:
        """Create dashboard layout."""
        layout = Layout()

        layout.split_column(
            Layout(self._create_header(), size=3),
            Layout(name="main", ratio=1),
        )

        layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1),
        )

        layout["left"].split_column(
            Layout(self._create_statistics_table(), ratio=1),
            Layout(self._create_alerts_table(), ratio=1),
            Layout(self._create_monitors_table(), ratio=1),
        )

        layout["right"].split_column(
            Layout(self._create_mitre_table(), ratio=1),
            Layout(self._create_recent_events_panel(), ratio=1),
            Layout(self._create_recent_alerts_panel(), ratio=1),
        )

        return layout

    def update_stats(self, new_stats: Dict[str, Any]) -> None:
        """
        Update dashboard statistics.

        Args:
            new_stats: Dictionary with updated statistics.
        """
        self.stats.update(new_stats)

    def run(self) -> None:
        """Run the dashboard."""
        self.console.print("[bold green]Starting dashboard...[/bold green]")

        try:
            with Live(
                self._create_layout(),
                refresh_per_second=1.0 / self.refresh_interval,
                screen=True,
            ) as live:
                while self.running:
                    # Update layout
                    live.update(self._create_layout())

                    # Simulate data updates (in real implementation, this would
                    # come from MonitorManager or event callbacks)
                    # For now, we'll just refresh the display
                    asyncio.sleep(self.refresh_interval)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Dashboard stopped by user[/yellow]")
        except Exception as e:
            logger.error(f"Dashboard error: {e}", exc_info=True)
            self.console.print(f"[red]Error: {e}[/red]")
        finally:
            self.console.print("[bold green]Dashboard shutdown complete[/bold green]")


def main() -> int:
    """Main entry point for dashboard command."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Interactive security monitoring dashboard"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Configuration file path",
    )
    parser.add_argument(
        "--refresh",
        type=float,
        default=1.0,
        help="Refresh interval in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    try:
        dashboard = Dashboard(config_path=args.config, refresh_interval=args.refresh)
        dashboard.run()
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

