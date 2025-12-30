"""
Service monitoring module.

Monitors system services for status changes and detects
unauthorized or new services.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from src.config.logging_config import get_logger
from src.core.base_monitor import (
    BaseMonitor,
    Event,
    EventObject,
    EventType,
    Severity,
)
from src.core.exceptions import CollectionError


logger = get_logger(__name__)


@dataclass
class ServiceInfo:
    """Information about a system service."""

    name: str
    status: str  # running, stopped, failed, etc.
    enabled: bool
    description: Optional[str] = None
    pid: Optional[int] = None
    load_state: Optional[str] = None
    active_state: Optional[str] = None
    sub_state: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "enabled": self.enabled,
            "description": self.description,
            "pid": self.pid,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
        }


class ServiceMonitor(BaseMonitor):
    """
    Monitors system services for security-relevant changes.

    Features:
    - Service status change detection
    - New service detection
    - Critical service monitoring
    - Service failure alerting
    """

    # Services that should always be running
    DEFAULT_CRITICAL_SERVICES = [
        "sshd",
        "ssh",
        "firewalld",
        "iptables",
        "ufw",
        "auditd",
        "rsyslog",
        "systemd-journald",
    ]

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize service monitor.

        Args:
            config: Monitor configuration.
        """
        super().__init__("service_monitor", config)

        self.critical_services = set(
            config.get("critical_services", self.DEFAULT_CRITICAL_SERVICES)
        )
        self.alert_on_new_service = config.get("alert_on_new_service", True)

        self._known_services: Dict[str, ServiceInfo] = {}
        self._using_systemd = self._check_systemd()

    def _check_systemd(self) -> bool:
        """Check if system uses systemd."""
        try:
            result = subprocess.run(
                ["systemctl", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _initialize(self) -> None:
        """Initialize the monitor."""
        # Get current services
        for service in self.get_services():
            self._known_services[service.name] = service

        logger.info(
            f"ServiceMonitor initialized, tracking {len(self._known_services)} services"
        )

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect service events."""
        events: List[Event] = []
        current_services: Dict[str, ServiceInfo] = {}

        for service in self.get_services():
            current_services[service.name] = service

            # Check for new services
            if service.name not in self._known_services:
                if self.alert_on_new_service:
                    events.append(self._create_new_service_event(service))
            else:
                # Check for status changes
                old_service = self._known_services[service.name]
                change_events = self._check_service_changes(old_service, service)
                events.extend(change_events)

        # Check for removed services (rare but could indicate tampering)
        for name in set(self._known_services.keys()) - set(current_services.keys()):
            old_service = self._known_services[name]
            events.append(self.create_event(
                event_type=EventType.SERVICE_STOPPED,
                severity=Severity.MEDIUM,
                description=f"Service removed from system: {name}",
                obj=EventObject(
                    type="service",
                    details=old_service.to_dict(),
                ),
            ))

        # Update known services
        self._known_services = current_services

        return events

    def _check_service_changes(
        self, old: ServiceInfo, new: ServiceInfo
    ) -> List[Event]:
        """Check for changes between old and new service state."""
        events: List[Event] = []

        # Status change
        if old.status != new.status:
            is_critical = new.name in self.critical_services

            if new.status == "running" and old.status != "running":
                severity = Severity.INFO
                if is_critical:
                    severity = Severity.LOW  # Critical service coming up is good
                events.append(self.create_event(
                    event_type=EventType.SERVICE_STARTED,
                    severity=severity,
                    description=f"Service started: {new.name}",
                    obj=EventObject(
                        type="service",
                        details={
                            "old_status": old.status,
                            "new_status": new.status,
                        },
                    ),
                    metadata={"is_critical": is_critical},
                ))

            elif new.status in ["stopped", "failed"] and old.status == "running":
                severity = Severity.MEDIUM
                if is_critical:
                    severity = Severity.HIGH
                if new.status == "failed":
                    severity = Severity.HIGH if not is_critical else Severity.CRITICAL

                events.append(self.create_event(
                    event_type=EventType.SERVICE_STOPPED,
                    severity=severity,
                    description=f"Service {new.status}: {new.name}",
                    obj=EventObject(
                        type="service",
                        details={
                            "old_status": old.status,
                            "new_status": new.status,
                        },
                    ),
                    metadata={"is_critical": is_critical},
                ))

        # Enabled state change
        if old.enabled != new.enabled:
            severity = Severity.MEDIUM
            if new.name in self.critical_services:
                severity = Severity.HIGH

            action = "enabled" if new.enabled else "disabled"
            events.append(self.create_event(
                event_type=EventType.SERVICE_STARTED if new.enabled else EventType.SERVICE_STOPPED,
                severity=severity,
                description=f"Service {action} at boot: {new.name}",
                obj=EventObject(
                    type="service",
                    details={
                        "old_enabled": old.enabled,
                        "new_enabled": new.enabled,
                    },
                ),
            ))

        return events

    def _create_new_service_event(self, service: ServiceInfo) -> Event:
        """Create event for new service detection."""
        return self.create_event(
            event_type=EventType.SERVICE_NEW,
            severity=Severity.MEDIUM,
            description=f"New service detected: {service.name} (status: {service.status})",
            obj=EventObject(
                type="service",
                details=service.to_dict(),
            ),
        )

    def get_services(self) -> List[ServiceInfo]:
        """Get list of system services."""
        if self._using_systemd:
            return self._get_systemd_services()
        else:
            return self._get_sysv_services()

    def _get_systemd_services(self) -> List[ServiceInfo]:
        """Get services via systemctl."""
        services: List[ServiceInfo] = []

        try:
            # List all services
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-pager",
                    "--plain",
                    "--no-legend",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 4:
                    continue

                unit = parts[0]
                if not unit.endswith(".service"):
                    continue

                name = unit.replace(".service", "")
                load_state = parts[1] if len(parts) > 1 else "unknown"
                active_state = parts[2] if len(parts) > 2 else "unknown"
                sub_state = parts[3] if len(parts) > 3 else "unknown"

                # Determine status
                if active_state == "active":
                    status = "running" if sub_state == "running" else sub_state
                elif active_state == "failed":
                    status = "failed"
                else:
                    status = "stopped"

                # Check if enabled
                enabled = self._is_service_enabled(name)

                services.append(ServiceInfo(
                    name=name,
                    status=status,
                    enabled=enabled,
                    load_state=load_state,
                    active_state=active_state,
                    sub_state=sub_state,
                ))

        except subprocess.TimeoutExpired:
            logger.warning("Timeout getting systemd services")
        except Exception as e:
            logger.error(f"Error getting systemd services: {e}")

        return services

    def _is_service_enabled(self, name: str) -> bool:
        """Check if a service is enabled at boot."""
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", f"{name}.service"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() == "enabled"
        except Exception:
            return False

    def _get_sysv_services(self) -> List[ServiceInfo]:
        """Get services via SysV init (fallback)."""
        services: List[ServiceInfo] = []

        try:
            result = subprocess.run(
                ["service", "--status-all"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                # Format: " [ + ]  service_name" or " [ - ]  service_name"
                if "[ + ]" in line:
                    name = line.split("]")[1].strip()
                    status = "running"
                elif "[ - ]" in line:
                    name = line.split("]")[1].strip()
                    status = "stopped"
                else:
                    continue

                services.append(ServiceInfo(
                    name=name,
                    status=status,
                    enabled=True,  # Can't easily determine on SysV
                ))

        except Exception as e:
            logger.error(f"Error getting SysV services: {e}")

        return services

    def check_critical_services(self) -> Dict[str, Any]:
        """
        Check status of critical services.

        Returns:
            Dictionary with status of each critical service.
        """
        results: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "services": {},
            "issues": [],
        }

        current_services = {s.name: s for s in self.get_services()}

        for service_name in self.critical_services:
            if service_name in current_services:
                service = current_services[service_name]
                results["services"][service_name] = {
                    "status": service.status,
                    "enabled": service.enabled,
                    "healthy": service.status == "running",
                }

                if service.status != "running":
                    results["issues"].append({
                        "service": service_name,
                        "issue": f"Service is {service.status}",
                        "severity": "high",
                    })

                if not service.enabled:
                    results["issues"].append({
                        "service": service_name,
                        "issue": "Service is not enabled at boot",
                        "severity": "medium",
                    })
            else:
                results["services"][service_name] = {
                    "status": "not_found",
                    "enabled": False,
                    "healthy": False,
                }

        results["healthy"] = len(results["issues"]) == 0
        return results



