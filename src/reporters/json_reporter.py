"""
JSON reporter for file output.

Writes alerts to JSON files with rotation support.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config.logging_config import get_logger
from src.core.alert_manager import Alert


logger = get_logger(__name__)


class JSONReporter:
    """
    Writes alerts to JSON files.

    Features:
    - JSON Lines format (one JSON object per line)
    - File rotation by size
    - Configurable output path
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize JSON reporter."""
        config = config or {}
        self.output_path = config.get(
            "output_path",
            "/var/log/Sentinel_Linux/events.json"
        )
        self.rotate = config.get("rotate", True)
        self.max_size_mb = config.get("max_size_mb", 100)
        self.backup_count = config.get("backup_count", 5)

        self._buffer: List[Dict[str, Any]] = []
        self._buffer_size = config.get("buffer_size", 10)

        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Ensure output directory exists."""
        try:
            Path(self.output_path).parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"Cannot create directory for {self.output_path}")

    def report(self, alert: Alert) -> None:
        """
        Write alert to JSON file.

        Args:
            alert: Alert to write.
        """
        alert_dict = alert.to_dict()
        self._buffer.append(alert_dict)

        if len(self._buffer) >= self._buffer_size:
            self.flush()

    def flush(self) -> None:
        """Write buffered alerts to file."""
        if not self._buffer:
            return

        try:
            if self.rotate:
                self._check_rotation()

            with open(self.output_path, "a", encoding="utf-8") as f:
                for alert_dict in self._buffer:
                    f.write(json.dumps(alert_dict, ensure_ascii=False) + "\n")

            self._buffer.clear()

        except PermissionError:
            logger.error(f"Permission denied writing to {self.output_path}")
        except Exception as e:
            logger.error(f"Error writing JSON: {e}")

    def _check_rotation(self) -> None:
        """Check if file rotation is needed."""
        if not os.path.exists(self.output_path):
            return

        size_mb = os.path.getsize(self.output_path) / (1024 * 1024)

        if size_mb >= self.max_size_mb:
            self._rotate_file()

    def _rotate_file(self) -> None:
        """Rotate log files."""
        base_path = self.output_path

        # Remove oldest backup if exists
        oldest = f"{base_path}.{self.backup_count}"
        if os.path.exists(oldest):
            os.remove(oldest)

        # Shift existing backups
        for i in range(self.backup_count - 1, 0, -1):
            src = f"{base_path}.{i}"
            dst = f"{base_path}.{i + 1}"
            if os.path.exists(src):
                os.rename(src, dst)

        # Rotate current file
        if os.path.exists(base_path):
            os.rename(base_path, f"{base_path}.1")

        logger.info(f"Rotated log file: {base_path}")

    def __del__(self) -> None:
        """Flush buffer on cleanup."""
        self.flush()


