"""
System interaction utilities.

Provides functions for system information gathering
and interaction.
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil


def get_hostname() -> str:
    """
    Get system hostname.

    Returns:
        Hostname string.
    """
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def get_fqdn() -> str:
    """
    Get fully qualified domain name.

    Returns:
        FQDN string.
    """
    try:
        return socket.getfqdn()
    except Exception:
        return get_hostname()


def is_root() -> bool:
    """
    Check if running as root.

    Returns:
        True if running as root/Administrator.
    """
    return os.geteuid() == 0


def get_system_info() -> Dict[str, Any]:
    """
    Get comprehensive system information.

    Returns:
        Dictionary of system information.
    """
    info: Dict[str, Any] = {
        "hostname": get_hostname(),
        "fqdn": get_fqdn(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }

    # OS-specific info
    try:
        info["distro"] = get_linux_distro()
    except Exception:
        pass

    # Hardware info
    try:
        info["cpu_count"] = psutil.cpu_count()
        info["memory_total_gb"] = round(psutil.virtual_memory().total / (1024**3), 2)
    except Exception:
        pass

    # Uptime
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        info["boot_time"] = boot_time.isoformat()
        info["uptime_seconds"] = (datetime.now() - boot_time).total_seconds()
    except Exception:
        pass

    return info


def get_linux_distro() -> Dict[str, str]:
    """
    Get Linux distribution information.

    Returns:
        Dictionary with distro info.
    """
    distro_info: Dict[str, str] = {}

    # Try /etc/os-release
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    distro_info[key.lower()] = value.strip('"')
    except FileNotFoundError:
        pass

    return distro_info


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Get network interface information.

    Returns:
        List of interface info dictionaries.
    """
    interfaces: List[Dict[str, Any]] = []

    try:
        for name, addrs in psutil.net_if_addrs().items():
            iface: Dict[str, Any] = {"name": name, "addresses": []}

            for addr in addrs:
                addr_info: Dict[str, str] = {"family": addr.family.name}

                if addr.address:
                    addr_info["address"] = addr.address
                if addr.netmask:
                    addr_info["netmask"] = addr.netmask

                iface["addresses"].append(addr_info)

            interfaces.append(iface)
    except Exception:
        pass

    return interfaces


def get_disk_usage() -> List[Dict[str, Any]]:
    """
    Get disk usage information.

    Returns:
        List of disk usage info.
    """
    disks: List[Dict[str, Any]] = []

    try:
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "percent": usage.percent,
                })
            except PermissionError:
                pass
    except Exception:
        pass

    return disks


def run_command(
    command: List[str],
    timeout: int = 30,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """
    Run a system command safely.

    Args:
        command: Command and arguments.
        timeout: Timeout in seconds.
        check: Raise on non-zero exit.

    Returns:
        CompletedProcess result.
    """
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def get_users() -> List[Dict[str, Any]]:
    """
    Get logged-in users.

    Returns:
        List of user info dictionaries.
    """
    users: List[Dict[str, Any]] = []

    try:
        for user in psutil.users():
            users.append({
                "name": user.name,
                "terminal": user.terminal,
                "host": user.host,
                "started": datetime.fromtimestamp(user.started).isoformat(),
                "pid": user.pid,
            })
    except Exception:
        pass

    return users


def get_process_list(include_cmdline: bool = False) -> List[Dict[str, Any]]:
    """
    Get list of running processes.

    Args:
        include_cmdline: Include command line arguments.

    Returns:
        List of process info dictionaries.
    """
    processes: List[Dict[str, Any]] = []

    attrs = ["pid", "name", "username", "status", "create_time", "ppid"]
    if include_cmdline:
        attrs.append("cmdline")

    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            info["create_time"] = datetime.fromtimestamp(
                info["create_time"]
            ).isoformat()
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return processes



