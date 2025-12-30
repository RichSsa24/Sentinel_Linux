"""
Anomaly detection module.

Statistical analysis to identify deviations from baseline behavior.
"""

from __future__ import annotations

import json
import math
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config.logging_config import get_logger
from src.core.base_monitor import Event, EventType
from src.core.event_handler import AnalysisResult


logger = get_logger(__name__)


@dataclass
class MetricStats:
    """Statistics for a tracked metric."""

    count: int = 0
    sum: float = 0.0
    sum_sq: float = 0.0
    min_val: float = float("inf")
    max_val: float = float("-inf")
    last_update: datetime = field(default_factory=datetime.now)

    @property
    def mean(self) -> float:
        if self.count == 0:
            return 0.0
        return self.sum / self.count

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return (self.sum_sq - (self.sum ** 2) / self.count) / (self.count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(max(0, self.variance))

    def update(self, value: float) -> None:
        self.count += 1
        self.sum += value
        self.sum_sq += value ** 2
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)
        self.last_update = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "mean": self.mean,
            "std_dev": self.std_dev,
            "min": self.min_val if self.count > 0 else None,
            "max": self.max_val if self.count > 0 else None,
        }


class AnomalyDetector:
    """
    Statistical anomaly detection engine.

    Features:
    - Baseline learning
    - Standard deviation analysis
    - Event rate monitoring
    - Behavioral profiling
    """

    SENSITIVITY_THRESHOLDS = {
        "low": 3.0,      # 3 standard deviations
        "medium": 2.5,   # 2.5 standard deviations
        "high": 2.0,     # 2 standard deviations
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize anomaly detector."""
        self.config = config
        self.baseline_path = config.get("baseline_path", "")
        self.sensitivity = config.get("sensitivity", "medium")
        self.learning_period = config.get("learning_period", 86400)

        self.threshold = self.SENSITIVITY_THRESHOLDS.get(self.sensitivity, 2.5)

        self._metrics: Dict[str, MetricStats] = defaultdict(MetricStats)
        self._event_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._learning_start: Optional[datetime] = None
        self._is_learning = True

        self._load_baseline()
        logger.info(f"AnomalyDetector initialized (sensitivity: {self.sensitivity})")

    def _load_baseline(self) -> None:
        """Load baseline from file if exists."""
        if not self.baseline_path:
            return

        baseline_file = Path(self.baseline_path) / "anomaly_baseline.json"
        if not baseline_file.exists():
            return

        try:
            with open(baseline_file, "r") as f:
                data = json.load(f)

            for metric, stats in data.get("metrics", {}).items():
                self._metrics[metric] = MetricStats(
                    count=stats["count"],
                    sum=stats["sum"],
                    sum_sq=stats["sum_sq"],
                    min_val=stats.get("min", float("inf")),
                    max_val=stats.get("max", float("-inf")),
                )

            self._is_learning = False
            logger.info(f"Loaded baseline with {len(self._metrics)} metrics")

        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")

    def save_baseline(self) -> None:
        """Save current baseline to file."""
        if not self.baseline_path:
            return

        baseline_dir = Path(self.baseline_path)
        baseline_dir.mkdir(parents=True, exist_ok=True)

        baseline_file = baseline_dir / "anomaly_baseline.json"

        data = {
            "created_at": datetime.now().isoformat(),
            "metrics": {
                metric: {
                    "count": stats.count,
                    "sum": stats.sum,
                    "sum_sq": stats.sum_sq,
                    "min": stats.min_val,
                    "max": stats.max_val,
                }
                for metric, stats in self._metrics.items()
            },
        }

        with open(baseline_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved baseline with {len(self._metrics)} metrics")

    def analyze(self, event: Event) -> Optional[AnalysisResult]:
        """
        Analyze an event for anomalies.

        Args:
            event: Event to analyze.

        Returns:
            AnalysisResult if anomaly detected, None otherwise.
        """
        # Update metrics
        self._update_metrics(event)

        # Check learning period
        if self._is_learning:
            if self._learning_start is None:
                self._learning_start = datetime.now()

            elapsed = (datetime.now() - self._learning_start).total_seconds()
            if elapsed >= self.learning_period:
                self._is_learning = False
                self.save_baseline()
                logger.info("Anomaly detector learning period complete")

            return None

        # Detect anomalies
        anomalies = self._detect_anomalies(event)

        if not anomalies:
            return None

        # Calculate anomaly score
        max_score = max(a["score"] for a in anomalies)

        return AnalysisResult(
            analyzer_name="AnomalyDetector",
            anomaly_score=max_score,
            findings=[a["description"] for a in anomalies],
            metadata={
                "anomalies": anomalies,
                "is_learning": self._is_learning,
            },
        )

    def _update_metrics(self, event: Event) -> None:
        """Update metrics based on event."""
        # Track event type frequency
        hour_key = datetime.now().strftime("%Y%m%d%H")
        event_key = f"event_rate_{event.event_type.value}"
        self._event_counts[hour_key][event_key] += 1

        # Track severity distribution
        severity_key = f"severity_{event.severity.name}"
        self._metrics[severity_key].update(1.0)

        # Track event metadata
        if event.subject and event.subject.user:
            user_key = f"user_activity_{event.subject.user}"
            self._metrics[user_key].update(1.0)

    def _detect_anomalies(self, event: Event) -> List[Dict[str, Any]]:
        """Detect anomalies in an event."""
        anomalies: List[Dict[str, Any]] = []

        # Check event rate anomaly
        hour_key = datetime.now().strftime("%Y%m%d%H")
        event_key = f"event_rate_{event.event_type.value}"

        current_rate = self._event_counts[hour_key].get(event_key, 0)
        rate_stats = self._metrics.get(f"hourly_{event_key}")

        if rate_stats and rate_stats.count > 10:
            z_score = self._calculate_z_score(current_rate, rate_stats)
            if z_score > self.threshold:
                anomalies.append({
                    "type": "event_rate",
                    "metric": event_key,
                    "score": min(1.0, z_score / 5.0),
                    "description": f"Unusual event rate for {event.event_type.value}",
                    "z_score": z_score,
                })

        # Check user activity anomaly
        if event.subject and event.subject.user:
            user_key = f"user_activity_{event.subject.user}"
            user_stats = self._metrics.get(user_key)

            if user_stats and user_stats.count > 5:
                # User activity during unusual hours
                current_hour = datetime.now().hour
                if current_hour < 6 or current_hour > 22:
                    anomalies.append({
                        "type": "time_anomaly",
                        "metric": user_key,
                        "score": 0.5,
                        "description": f"Activity by {event.subject.user} at unusual hour",
                    })

        return anomalies

    def _calculate_z_score(self, value: float, stats: MetricStats) -> float:
        """Calculate z-score for a value."""
        if stats.std_dev == 0:
            return 0.0
        return abs(value - stats.mean) / stats.std_dev

    def get_anomaly_score(self, metric: str, value: float) -> float:
        """
        Calculate anomaly score for a specific metric.

        Args:
            metric: Metric name.
            value: Current value.

        Returns:
            Anomaly score (0.0 = normal, 1.0 = highly anomalous).
        """
        stats = self._metrics.get(metric)
        if not stats or stats.count < 5:
            return 0.0

        z_score = self._calculate_z_score(value, stats)
        return min(1.0, max(0.0, (z_score - 1.0) / 4.0))

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of tracked metrics."""
        return {
            "total_metrics": len(self._metrics),
            "is_learning": self._is_learning,
            "sensitivity": self.sensitivity,
            "threshold": self.threshold,
            "metrics": {
                name: stats.to_dict()
                for name, stats in list(self._metrics.items())[:20]
            },
        }



