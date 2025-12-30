#!/usr/bin/env python3
"""
Main CLI entry point for Linux Security Monitor.

Provides commands for:
- Running the security monitor
- Configuration validation
- Report generation
- System audits
- Rule management
"""

from __future__ import annotations

import os
import sys
import signal
import time
from pathlib import Path
from typing import Optional

import click

# Ensure src is in path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.config.settings import Settings, get_settings, find_config_file, validate_config
from src.config.logging_config import setup_logging, get_logger


logger = get_logger(__name__)


def get_version() -> str:
    """Get package version."""
    try:
        from importlib.metadata import version
        return version("linux-security-monitor")
    except Exception:
        return "1.0.0"


@click.group(invoke_without_command=True)
@click.option("-v", "--version", is_flag=True, help="Show version and exit")
@click.option("-c", "--config", type=click.Path(exists=True), help="Configuration file path")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.pass_context
def cli(ctx: click.Context, version: bool, config: Optional[str], debug: bool) -> None:
    """Linux Security Monitor - Enterprise security monitoring for Linux systems."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["debug"] = debug

    if version:
        click.echo(f"Linux Security Monitor, version {get_version()}")
        ctx.exit(0)

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--dry-run", is_flag=True, help="Run without sending alerts")
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), default="INFO")
@click.option("--log-file", type=click.Path(), help="Log file path")
@click.pass_context
def run(ctx: click.Context, dry_run: bool, log_level: str, log_file: Optional[str]) -> None:
    """Start the security monitor daemon."""
    config_path = ctx.obj.get("config_path")
    debug = ctx.obj.get("debug", False)

    if debug:
        log_level = "DEBUG"

    setup_logging(level=log_level, log_file=log_file)
    logger.info("Starting Linux Security Monitor...")

    try:
        settings = get_settings(config_path)
    except FileNotFoundError as e:
        logger.error(f"Configuration file not found: {e}")
        ctx.exit(1)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        ctx.exit(1)

    from src.core.monitor_manager import MonitorManager

    manager = MonitorManager(settings, dry_run=dry_run)

    def signal_handler(signum: int, frame: object) -> None:
        logger.info(f"Received signal {signum}, shutting down...")
        manager.stop()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        manager.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        ctx.exit(1)


@cli.group()
def config() -> None:
    """Configuration management commands."""
    pass


@config.command("validate")
@click.option("-c", "--config", type=click.Path(exists=True), help="Configuration file to validate")
@click.pass_context
def config_validate(ctx: click.Context, config: Optional[str]) -> None:
    """Validate configuration file."""
    config_path = config or ctx.obj.get("config_path") or find_config_file()

    if not config_path:
        click.echo("No configuration file found", err=True)
        ctx.exit(1)

    click.echo(f"Validating configuration: {config_path}")

    try:
        settings = Settings.from_yaml(config_path)
        click.echo(click.style("Configuration is valid", fg="green"))

        if ctx.obj.get("debug"):
            click.echo("\nLoaded configuration:")
            click.echo(f"  Monitors enabled: {sum(1 for m in [settings.monitors.user_monitor, settings.monitors.process_monitor, settings.monitors.network_monitor, settings.monitors.file_integrity_monitor, settings.monitors.auth_monitor, settings.monitors.service_monitor, settings.monitors.log_monitor] if m.enabled)}")
            click.echo(f"  Log level: {settings.global_config.log_level}")

    except FileNotFoundError:
        click.echo(click.style(f"Configuration file not found: {config_path}", fg="red"), err=True)
        ctx.exit(1)
    except Exception as e:
        click.echo(click.style(f"Configuration validation failed: {e}", fg="red"), err=True)
        ctx.exit(1)


@config.command("show")
@click.option("-c", "--config", type=click.Path(exists=True), help="Configuration file")
@click.pass_context
def config_show(ctx: click.Context, config: Optional[str]) -> None:
    """Show current configuration."""
    import yaml

    config_path = config or ctx.obj.get("config_path") or find_config_file()

    if not config_path:
        click.echo("No configuration file found", err=True)
        ctx.exit(1)

    try:
        settings = Settings.from_yaml(config_path)
        click.echo(yaml.dump(settings.model_dump(by_alias=True), default_flow_style=False))
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        ctx.exit(1)


@config.command("init")
@click.option("-o", "--output", type=click.Path(), default="config.yaml", help="Output file path")
@click.option("--force", is_flag=True, help="Overwrite existing file")
def config_init(output: str, force: bool) -> None:
    """Create a default configuration file."""
    output_path = Path(output)

    if output_path.exists() and not force:
        click.echo(f"File already exists: {output}. Use --force to overwrite.", err=True)
        return

    settings = Settings()
    settings.to_yaml(str(output_path))
    click.echo(f"Created default configuration: {output}")


@cli.group()
def rules() -> None:
    """Detection rules management."""
    pass


@rules.command("list")
@click.option("--type", "rule_type", type=click.Choice(["sigma", "yara", "all"]), default="all")
@click.pass_context
def rules_list(ctx: click.Context, rule_type: str) -> None:
    """List available detection rules."""
    config_path = ctx.obj.get("config_path")

    try:
        settings = get_settings(config_path)
        rules_path = Path(settings.analyzers.threat_analyzer.rules_path)

        if not rules_path.exists():
            click.echo(f"Rules directory not found: {rules_path}")
            return

        click.echo(f"Rules directory: {rules_path}\n")

        if rule_type in ("sigma", "all"):
            sigma_path = rules_path / "sigma"
            if sigma_path.exists():
                sigma_files = list(sigma_path.glob("**/*.yml")) + list(sigma_path.glob("**/*.yaml"))
                click.echo(f"Sigma rules: {len(sigma_files)}")
                for f in sigma_files[:10]:
                    click.echo(f"  - {f.name}")
                if len(sigma_files) > 10:
                    click.echo(f"  ... and {len(sigma_files) - 10} more")

        if rule_type in ("yara", "all"):
            yara_path = rules_path / "yara"
            if yara_path.exists():
                yara_files = list(yara_path.glob("**/*.yar")) + list(yara_path.glob("**/*.yara"))
                click.echo(f"\nYARA rules: {len(yara_files)}")
                for f in yara_files[:10]:
                    click.echo(f"  - {f.name}")
                if len(yara_files) > 10:
                    click.echo(f"  ... and {len(yara_files) - 10} more")

    except Exception as e:
        click.echo(f"Error listing rules: {e}", err=True)


@cli.command()
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option("--format", "output_format", type=click.Choice(["json", "yaml", "html"]), default="json")
@click.option("--last", type=int, default=24, help="Hours to include in report")
@click.pass_context
def report(ctx: click.Context, output: Optional[str], output_format: str, last: int) -> None:
    """Generate a security report."""
    import json
    from datetime import datetime, timedelta

    config_path = ctx.obj.get("config_path")
    setup_logging(level="WARNING")

    click.echo(f"Generating security report (last {last} hours)...")

    try:
        settings = get_settings(config_path)

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "hostname": settings.global_config.hostname or os.uname().nodename,
            "period_hours": last,
            "summary": {
                "total_events": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0,
            },
            "top_event_types": [],
            "recommendations": [],
        }

        if output:
            output_path = Path(output)
            with open(output_path, "w") as f:
                json.dump(report_data, f, indent=2)
            click.echo(f"Report saved to: {output}")
        else:
            click.echo(json.dumps(report_data, indent=2))

    except Exception as e:
        click.echo(f"Error generating report: {e}", err=True)
        ctx.exit(1)


@cli.command()
@click.option("--profile", type=click.Choice(["basic", "cis-level1", "cis-level2"]), default="basic")
@click.option("-o", "--output", type=click.Path(), help="Output file for audit results")
@click.pass_context
def audit(ctx: click.Context, profile: str, output: Optional[str]) -> None:
    """Run a security audit on the system."""
    import json
    from datetime import datetime

    click.echo(f"Running security audit (profile: {profile})...")

    audit_results = {
        "timestamp": datetime.now().isoformat(),
        "profile": profile,
        "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
        "checks": [],
        "summary": {
            "passed": 0,
            "failed": 0,
            "warnings": 0,
        }
    }

    # Basic checks
    checks = [
        ("Root SSH login disabled", _check_root_ssh),
        ("Password authentication", _check_password_auth),
        ("Firewall enabled", _check_firewall),
        ("Automatic updates", _check_auto_updates),
        ("File permissions /etc/passwd", lambda: _check_file_perms("/etc/passwd", "644")),
        ("File permissions /etc/shadow", lambda: _check_file_perms("/etc/shadow", "640")),
    ]

    with click.progressbar(checks, label="Running checks") as bar:
        for name, check_func in bar:
            try:
                result = check_func()
                audit_results["checks"].append({
                    "name": name,
                    "status": result["status"],
                    "message": result.get("message", ""),
                })
                audit_results["summary"][result["status"]] = audit_results["summary"].get(result["status"], 0) + 1
            except Exception as e:
                audit_results["checks"].append({
                    "name": name,
                    "status": "error",
                    "message": str(e),
                })

    # Print summary
    click.echo(f"\nAudit Summary:")
    click.echo(f"  Passed:   {audit_results['summary'].get('passed', 0)}")
    click.echo(f"  Failed:   {audit_results['summary'].get('failed', 0)}")
    click.echo(f"  Warnings: {audit_results['summary'].get('warnings', 0)}")

    if output:
        with open(output, "w") as f:
            json.dump(audit_results, f, indent=2)
        click.echo(f"\nResults saved to: {output}")


def _check_root_ssh() -> dict:
    """Check if root SSH login is disabled."""
    try:
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return {"status": "warning", "message": "sshd_config not found"}

        content = sshd_config.read_text()
        if "PermitRootLogin no" in content or "PermitRootLogin prohibit-password" in content:
            return {"status": "passed", "message": "Root login disabled"}
        return {"status": "failed", "message": "Root login may be enabled"}
    except PermissionError:
        return {"status": "warning", "message": "Permission denied reading sshd_config"}


def _check_password_auth() -> dict:
    """Check password authentication settings."""
    try:
        sshd_config = Path("/etc/ssh/sshd_config")
        if not sshd_config.exists():
            return {"status": "warning", "message": "sshd_config not found"}

        content = sshd_config.read_text()
        if "PasswordAuthentication no" in content:
            return {"status": "passed", "message": "Password auth disabled"}
        return {"status": "warning", "message": "Password auth may be enabled"}
    except PermissionError:
        return {"status": "warning", "message": "Permission denied"}


def _check_firewall() -> dict:
    """Check if firewall is enabled."""
    import subprocess

    try:
        # Check iptables
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, timeout=5)
        if result.returncode == 0 and b"Chain" in result.stdout:
            return {"status": "passed", "message": "iptables configured"}
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        # Check ufw
        result = subprocess.run(["ufw", "status"], capture_output=True, timeout=5)
        if b"active" in result.stdout.lower():
            return {"status": "passed", "message": "UFW active"}
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        # Check firewalld
        result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, timeout=5)
        if b"running" in result.stdout.lower():
            return {"status": "passed", "message": "firewalld running"}
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return {"status": "warning", "message": "No active firewall detected"}


def _check_auto_updates() -> dict:
    """Check if automatic updates are configured."""
    auto_upgrade = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if auto_upgrade.exists():
        content = auto_upgrade.read_text()
        if "1" in content:
            return {"status": "passed", "message": "Auto updates enabled"}

    return {"status": "warning", "message": "Auto updates may not be configured"}


def _check_file_perms(path: str, expected: str) -> dict:
    """Check file permissions."""
    import stat

    try:
        file_path = Path(path)
        if not file_path.exists():
            return {"status": "warning", "message": f"File not found: {path}"}

        mode = oct(file_path.stat().st_mode)[-3:]
        if mode == expected:
            return {"status": "passed", "message": f"Permissions correct: {mode}"}
        return {"status": "failed", "message": f"Permissions {mode}, expected {expected}"}
    except PermissionError:
        return {"status": "warning", "message": "Permission denied"}


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show monitor status."""
    click.echo("Linux Security Monitor Status")
    click.echo("-" * 40)

    # Check if running
    pid_file = Path("/var/run/linux-security-monitor.pid")
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            if Path(f"/proc/{pid}").exists():
                click.echo(f"Status: {click.style('Running', fg='green')} (PID: {pid})")
            else:
                click.echo(f"Status: {click.style('Stale PID file', fg='yellow')}")
        except (ValueError, PermissionError):
            click.echo(f"Status: {click.style('Unknown', fg='yellow')}")
    else:
        click.echo(f"Status: {click.style('Not running', fg='red')}")

    # Show config location
    config_path = find_config_file()
    if config_path:
        click.echo(f"Config: {config_path}")
    else:
        click.echo("Config: Not found")


def main() -> int:
    """Main entry point."""
    try:
        cli(obj={})
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

