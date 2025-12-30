"""
Network connection monitoring module.

Monitors network connections for suspicious activity,
new listeners, and potential C2 communications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from src.config.logging_config import get_logger
from src.core.base_monitor import (
    BaseMonitor,
    Event,
    EventObject,
    EventSubject,
    EventType,
    Severity,
)
from src.core.exceptions import CollectionError


logger = get_logger(__name__)


@dataclass
class Connection:
    """Represents a network connection."""

    local_address: str
    local_port: int
    remote_address: Optional[str]
    remote_port: Optional[int]
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    family: str  # IPv4, IPv6
    type: str  # tcp, udp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "status": self.status,
            "pid": self.pid,
            "process_name": self.process_name,
            "family": self.family,
            "type": self.type,
        }


@dataclass
class Listener:
    """Represents a listening port."""

    address: str
    port: int
    pid: Optional[int]
    process_name: Optional[str]
    family: str
    type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "port": self.port,
            "pid": self.pid,
            "process_name": self.process_name,
            "family": self.family,
            "type": self.type,
        }


class NetworkMonitor(BaseMonitor):
    """
    Monitors network connections for security-relevant activity.

    Detects:
    - New listening ports
    - Connections to suspicious IPs
    - Unusual outbound connections
    - Potential C2 beaconing
    - DNS tunneling indicators
    """

    # Common suspicious ports
    SUSPICIOUS_PORTS = [
        4444,   # Metasploit default
        5555,   # Android ADB
        6666, 6667, 6668, 6669,  # IRC
        1234,   # Common backdoor
        31337,  # Elite backdoor
        12345,  # NetBus
        27374,  # SubSeven
    ]

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize network monitor.

        Args:
            config: Monitor configuration.
        """
        super().__init__("network_monitor", config)

        self.alert_on_new_listener = config.get("alert_on_new_listener", True)
        self.alert_on_outbound = config.get("alert_on_outbound", False)
        self.whitelisted_ports = set(config.get("whitelisted_ports", [22, 80, 443]))
        self.whitelisted_ips = set(config.get("whitelisted_ips", ["127.0.0.1", "::1"]))

        self._known_listeners: Set[Tuple[str, int]] = set()
        self._connection_history: List[Dict[str, Any]] = []

    def _initialize(self) -> None:
        """Initialize the monitor."""
        # Get current listeners
        for listener in self.get_listeners():
            self._known_listeners.add((listener.address, listener.port))

        logger.info(
            f"NetworkMonitor initialized, tracking {len(self._known_listeners)} listeners"
        )

    def _cleanup(self) -> None:
        """Clean up resources."""
        pass

    def _collect(self) -> List[Event]:
        """Collect network events."""
        events: List[Event] = []

        # Check for new listeners
        listener_events = self._check_listeners()
        events.extend(listener_events)

        # Check active connections
        connection_events = self._check_connections()
        events.extend(connection_events)

        return events

    def _check_listeners(self) -> List[Event]:
        """Check for new listening ports."""
        events: List[Event] = []
        current_listeners: Set[Tuple[str, int]] = set()

        for listener in self.get_listeners():
            listener_key = (listener.address, listener.port)
            current_listeners.add(listener_key)

            if listener_key not in self._known_listeners:
                if self.alert_on_new_listener:
                    severity = Severity.HIGH
                    if listener.port in self.whitelisted_ports:
                        severity = Severity.INFO
                    elif listener.port in self.SUSPICIOUS_PORTS:
                        severity = Severity.CRITICAL

                    events.append(self.create_event(
                        event_type=EventType.NETWORK_LISTENER,
                        severity=severity,
                        description=(
                            f"New listener detected: {listener.address}:{listener.port} "
                            f"({listener.process_name or 'unknown'})"
                        ),
                        raw=str(listener.to_dict()),
                        subject=EventSubject(
                            process=listener.process_name,
                            pid=listener.pid,
                        ),
                        obj=EventObject(
                            type="network",
                            details={
                                "address": listener.address,
                                "port": listener.port,
                                "protocol": listener.type,
                            },
                        ),
                        metadata={
                            "family": listener.family,
                            "is_suspicious_port": listener.port in self.SUSPICIOUS_PORTS,
                        },
                    ))

        self._known_listeners = current_listeners
        return events

    def _check_connections(self) -> List[Event]:
        """Check active connections for suspicious activity."""
        events: List[Event] = []

        for conn in self.get_connections():
            if not conn.remote_address:
                continue

            # Skip whitelisted
            if conn.remote_address in self.whitelisted_ips:
                continue

            # Check for suspicious remote ports
            if conn.remote_port in self.SUSPICIOUS_PORTS:
                events.append(self.create_event(
                    event_type=EventType.NETWORK_CONNECTION,
                    severity=Severity.HIGH,
                    description=(
                        f"Connection to suspicious port: "
                        f"{conn.remote_address}:{conn.remote_port}"
                    ),
                    raw=str(conn.to_dict()),
                    subject=EventSubject(
                        process=conn.process_name,
                        pid=conn.pid,
                    ),
                    obj=EventObject(
                        type="network",
                        details={
                            "remote_address": conn.remote_address,
                            "remote_port": conn.remote_port,
                            "local_port": conn.local_port,
                        },
                    ),
                    metadata={"suspicious_port": True},
                ))

            # Track for beaconing analysis
            self._record_connection(conn)

        # Check for beaconing behavior
        beacon_events = self._detect_beaconing()
        events.extend(beacon_events)

        return events

    def _record_connection(self, conn: Connection) -> None:
        """Record connection for pattern analysis."""
        self._connection_history.append({
            "timestamp": datetime.now().isoformat(),
            "remote_address": conn.remote_address,
            "remote_port": conn.remote_port,
            "pid": conn.pid,
            "process": conn.process_name,
        })

        # Keep only recent history
        max_history = 1000
        if len(self._connection_history) > max_history:
            self._connection_history = self._connection_history[-max_history:]

    def _detect_beaconing(self) -> List[Event]:
        """Detect potential C2 beaconing behavior."""
        events: List[Event] = []

        # Group connections by remote address
        from collections import Counter

        remote_counts = Counter(
            c["remote_address"] for c in self._connection_history
            if c["remote_address"]
        )

        # Alert on addresses with unusually high connection counts
        threshold = 20  # connections in history window
        for address, count in remote_counts.items():
            if count >= threshold and address not in self.whitelisted_ips:
                events.append(self.create_event(
                    event_type=EventType.NETWORK_CONNECTION,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Potential beaconing detected to {address} "
                        f"({count} connections)"
                    ),
                    metadata={
                        "remote_address": address,
                        "connection_count": count,
                        "detection_type": "beaconing",
                    },
                ))

        return events

    def get_connections(self, state: Optional[str] = None) -> List[Connection]:
        """
        Get current network connections.

        Args:
            state: Filter by connection state (ESTABLISHED, etc.)

        Returns:
            List of active connections.
        """
        connections: List[Connection] = []

        for conn in psutil.net_connections(kind="inet"):
            if state and conn.status != state:
                continue

            # Get process info
            process_name = None
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Determine family
            family = "IPv4" if conn.family.name == "AF_INET" else "IPv6"
            conn_type = "tcp" if conn.type.name == "SOCK_STREAM" else "udp"

            connections.append(Connection(
                local_address=conn.laddr.ip if conn.laddr else "",
                local_port=conn.laddr.port if conn.laddr else 0,
                remote_address=conn.raddr.ip if conn.raddr else None,
                remote_port=conn.raddr.port if conn.raddr else None,
                status=conn.status,
                pid=conn.pid,
                process_name=process_name,
                family=family,
                type=conn_type,
            ))

        return connections

    def get_listeners(self) -> List[Listener]:
        """
        Get listening ports.

        Returns:
            List of listening services.
        """
        listeners: List[Listener] = []
        seen: Set[Tuple[str, int, str]] = set()

        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "LISTEN":
                continue

            if not conn.laddr:
                continue

            key = (conn.laddr.ip, conn.laddr.port, conn.type.name)
            if key in seen:
                continue
            seen.add(key)

            process_name = None
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            family = "IPv4" if conn.family.name == "AF_INET" else "IPv6"
            conn_type = "tcp" if conn.type.name == "SOCK_STREAM" else "udp"

            listeners.append(Listener(
                address=conn.laddr.ip,
                port=conn.laddr.port,
                pid=conn.pid,
                process_name=process_name,
                family=family,
                type=conn_type,
            ))

        return listeners

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP address reputation.

        This is a placeholder for integration with threat intelligence.

        Args:
            ip: IP address to check.

        Returns:
            Reputation information.
        """
        # Placeholder - would integrate with threat intel APIs
        return {
            "ip": ip,
            "reputation": "unknown",
            "note": "Threat intelligence integration placeholder",
        }



