#!/usr/bin/env python3
"""
IOC database updater for Linux Security Monitor.

Updates IOC databases from various threat intelligence feeds.
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


def load_existing_iocs(path: str) -> List[Dict[str, Any]]:
    """Load existing IOCs from file."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("iocs", [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON in {path}")
        return []


def save_iocs(iocs: List[Dict[str, Any]], path: str) -> None:
    """Save IOCs to file."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "updated_at": datetime.now().isoformat(),
        "ioc_count": len(iocs),
        "iocs": iocs,
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Saved {len(iocs)} IOCs to {path}")


def add_iocs_from_file(
    existing: List[Dict[str, Any]],
    input_file: str,
) -> List[Dict[str, Any]]:
    """Add IOCs from an input file."""
    new_iocs = load_existing_iocs(input_file)

    # Deduplicate
    existing_values = {ioc["value"] for ioc in existing}
    added = 0

    for ioc in new_iocs:
        if ioc.get("value") not in existing_values:
            existing.append(ioc)
            existing_values.add(ioc["value"])
            added += 1

    logger.info(f"Added {added} new IOCs from {input_file}")
    return existing


def create_sample_iocs() -> List[Dict[str, Any]]:
    """Create sample IOC database."""
    return [
        {
            "type": "hash",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "description": "Empty file MD5 (test)",
            "severity": "low",
            "source": "sample",
        },
        {
            "type": "process",
            "value": "mimikatz",
            "description": "Credential dumping tool",
            "severity": "critical",
            "source": "sample",
        },
        {
            "type": "process",
            "value": "meterpreter",
            "description": "Metasploit payload",
            "severity": "critical",
            "source": "sample",
        },
        {
            "type": "ip",
            "value": "10.0.0.1",
            "description": "Sample malicious IP (test only)",
            "severity": "medium",
            "source": "sample",
        },
    ]


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="IOC Database Updater")

    parser.add_argument(
        "-o", "--output",
        default="/var/lib/Sentinel_Linux/ioc/iocs.json",
        help="Output IOC database path",
    )
    parser.add_argument(
        "-i", "--input",
        help="Input IOC file to merge",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize with sample IOCs",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    setup_logging(level="INFO")
    args = parse_args()

    if args.init:
        iocs = create_sample_iocs()
        save_iocs(iocs, args.output)
        return 0

    existing = load_existing_iocs(args.output)
    logger.info(f"Loaded {len(existing)} existing IOCs")

    if args.input:
        existing = add_iocs_from_file(existing, args.input)

    save_iocs(existing, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())



