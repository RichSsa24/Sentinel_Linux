#!/usr/bin/env python3
"""
System baseline creator for Linux Security Monitor.

Creates baseline snapshots of system state for anomaly detection.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

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
    from src.utils.system_utils import (
        get_hostname,
        get_system_info,
        get_process_list,
        get_network_interfaces,
    )
except ImportError:
    import socket
    import platform
    import psutil
    from datetime import datetime
    
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
    
    def get_process_list(include_cmdline: bool = False) -> List[Dict[str, Any]]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time', 'ppid'] + (['cmdline'] if include_cmdline else [])):
            try:
                info = proc.info
                if 'create_time' in info and info['create_time']:
                    info['create_time'] = datetime.fromtimestamp(info['create_time']).isoformat()
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes
    
    def get_network_interfaces() -> List[Dict[str, Any]]:
        interfaces = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces.append({
                    "name": iface,
                    "addresses": [addr.address for addr in addrs],
                })
        except Exception:
            pass
        return interfaces

try:
    from src.utils.crypto_utils import hash_file
except ImportError:
    import hashlib
    def hash_file(path: str, algorithm: str = "sha256") -> str:
        hasher = hashlib.new(algorithm.lower())
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()


def create_process_baseline() -> Dict[str, Any]:
    """Create baseline of running processes."""
    processes = get_process_list(include_cmdline=True)

    return {
        "timestamp": datetime.now().isoformat(),
        "process_count": len(processes),
        "processes": processes,
    }


def create_network_baseline() -> Dict[str, Any]:
    """Create baseline of network configuration."""
    import psutil

    listeners = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN":
            listeners.append({
                "address": conn.laddr.ip if conn.laddr else "",
                "port": conn.laddr.port if conn.laddr else 0,
                "pid": conn.pid,
            })

    return {
        "timestamp": datetime.now().isoformat(),
        "interfaces": get_network_interfaces(),
        "listeners": listeners,
    }


def create_file_baseline(paths: List[str]) -> Dict[str, Any]:
    """Create baseline of file hashes."""
    import os

    files = {}

    for path in paths:
        if os.path.isfile(path):
            try:
                files[path] = {
                    "hash": hash_file(path),
                    "size": os.path.getsize(path),
                    "mode": oct(os.stat(path).st_mode),
                }
            except Exception as e:
                logger.warning(f"Could not hash {path}: {e}")
        elif os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    try:
                        files[filepath] = {
                            "hash": hash_file(filepath),
                            "size": os.path.getsize(filepath),
                            "mode": oct(os.stat(filepath).st_mode),
                        }
                    except Exception:
                        pass

    return {
        "timestamp": datetime.now().isoformat(),
        "file_count": len(files),
        "files": files,
    }


def create_service_baseline() -> Dict[str, Any]:
    """Create baseline of system services."""
    import subprocess

    services = []

    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                services.append({
                    "name": parts[0].replace(".service", ""),
                    "load": parts[1],
                    "active": parts[2],
                    "sub": parts[3],
                })
    except Exception as e:
        logger.warning(f"Could not get services: {e}")

    return {
        "timestamp": datetime.now().isoformat(),
        "service_count": len(services),
        "services": services,
    }


def create_full_baseline(output_dir: str) -> None:
    """Create full system baseline."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # System info
    system_info = {
        "timestamp": datetime.now().isoformat(),
        "hostname": get_hostname(),
        "system": get_system_info(),
    }

    with open(output_path / "system_info.json", "w") as f:
        json.dump(system_info, f, indent=2)
    logger.info("Created system info baseline")

    # Processes
    process_baseline = create_process_baseline()
    with open(output_path / "processes.json", "w") as f:
        json.dump(process_baseline, f, indent=2)
    logger.info(f"Created process baseline ({process_baseline['process_count']} processes)")

    # Network
    network_baseline = create_network_baseline()
    with open(output_path / "network.json", "w") as f:
        json.dump(network_baseline, f, indent=2)
    logger.info(f"Created network baseline ({len(network_baseline['listeners'])} listeners)")

    # Files
    critical_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
    ]
    file_baseline = create_file_baseline(critical_paths)
    with open(output_path / "files.json", "w") as f:
        json.dump(file_baseline, f, indent=2)
    logger.info(f"Created file baseline ({file_baseline['file_count']} files)")

    # Services
    service_baseline = create_service_baseline()
    with open(output_path / "services.json", "w") as f:
        json.dump(service_baseline, f, indent=2)
    logger.info(f"Created service baseline ({service_baseline['service_count']} services)")

    logger.info(f"Full baseline saved to {output_dir}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Create System Baseline")

    parser.add_argument(
        "-o", "--output",
        default="/var/lib/Sentinel_Linux/baselines",
        help="Output directory",
    )
    parser.add_argument(
        "--type",
        choices=["full", "processes", "network", "files", "services"],
        default="full",
        help="Baseline type",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    setup_logging(level="INFO")
    args = parse_args()

    logger.info("Creating system baseline...")

    if args.type == "full":
        create_full_baseline(args.output)
    else:
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)

        if args.type == "processes":
            baseline = create_process_baseline()
        elif args.type == "network":
            baseline = create_network_baseline()
        elif args.type == "services":
            baseline = create_service_baseline()
        else:
            baseline = create_file_baseline(["/etc"])

        output_file = output_path / f"{args.type}.json"
        with open(output_file, "w") as f:
            json.dump(baseline, f, indent=2)
        logger.info(f"Baseline saved to {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())



