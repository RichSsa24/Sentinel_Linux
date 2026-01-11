"""
Configuration settings management.

Provides a centralized configuration system with support for:
- YAML configuration files
- Environment variable overrides
- Default values
- Runtime validation
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitorConfig(BaseModel):
    """Base configuration for monitors."""

    enabled: bool = True
    poll_interval: int = Field(default=60, ge=1, le=3600)


class UserMonitorConfig(MonitorConfig):
    """Configuration for user activity monitoring."""

    auth_log_path: str = "/var/log/auth.log"
    track_commands: bool = False
    alert_on_root_login: bool = True
    alert_on_sudo: bool = True


class ProcessMonitorConfig(MonitorConfig):
    """Configuration for process monitoring."""

    poll_interval: int = 30
    baseline_path: str = "/var/lib/Sentinel_Linux/baselines/processes.json"
    alert_on_new_process: bool = False
    suspicious_paths: List[str] = Field(
        default_factory=lambda: ["/tmp", "/dev/shm", "/var/tmp"]  # nosec B108
    )
    suspicious_names: List[str] = Field(
        default_factory=lambda: ["nc", "ncat", "netcat", "nmap", "tcpdump"]
    )


class NetworkMonitorConfig(MonitorConfig):
    """Configuration for network monitoring."""

    poll_interval: int = 30
    alert_on_new_listener: bool = True
    alert_on_outbound: bool = False
    whitelisted_ports: List[int] = Field(default_factory=lambda: [22, 80, 443])
    whitelisted_ips: List[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])


class FileIntegrityMonitorConfig(MonitorConfig):
    """Configuration for file integrity monitoring."""

    poll_interval: int = 300
    watched_paths: List[str] = Field(
        default_factory=lambda: [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ]
    )
    recursive_paths: List[str] = Field(
        default_factory=lambda: ["/etc/sudoers.d", "/etc/cron.d"]
    )
    exclude_patterns: List[str] = Field(default_factory=lambda: ["*.swp", "*~"])
    hash_algorithm: str = "sha256"

    @field_validator("hash_algorithm")
    @classmethod
    def validate_hash_algorithm(cls, v: str) -> str:
        """Validate hash algorithm is supported."""
        valid_algorithms = ["md5", "sha1", "sha256", "sha512"]
        if v.lower() not in valid_algorithms:
            raise ValueError(f"Hash algorithm must be one of: {valid_algorithms}")
        return v.lower()


class AuthMonitorConfig(MonitorConfig):
    """Configuration for authentication monitoring."""

    poll_interval: int = 30
    brute_force_threshold: int = Field(default=5, ge=1)
    brute_force_window: int = Field(default=300, ge=60)
    alert_on_failed_auth: bool = True


class ServiceMonitorConfig(MonitorConfig):
    """Configuration for service monitoring."""

    critical_services: List[str] = Field(
        default_factory=lambda: ["sshd", "firewalld", "auditd"]
    )
    alert_on_new_service: bool = True


class LogMonitorConfig(MonitorConfig):
    """Configuration for log monitoring."""

    poll_interval: int = 10
    log_paths: List[str] = Field(
        default_factory=lambda: [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/secure",
        ]
    )
    patterns: List[Dict[str, str]] = Field(default_factory=list)


class MonitorsConfig(BaseModel):
    """Configuration for all monitors."""

    user_monitor: UserMonitorConfig = Field(default_factory=UserMonitorConfig)
    process_monitor: ProcessMonitorConfig = Field(default_factory=ProcessMonitorConfig)
    network_monitor: NetworkMonitorConfig = Field(default_factory=NetworkMonitorConfig)
    file_integrity_monitor: FileIntegrityMonitorConfig = Field(
        default_factory=FileIntegrityMonitorConfig
    )
    auth_monitor: AuthMonitorConfig = Field(default_factory=AuthMonitorConfig)
    service_monitor: ServiceMonitorConfig = Field(default_factory=ServiceMonitorConfig)
    log_monitor: LogMonitorConfig = Field(default_factory=LogMonitorConfig)


class ThreatAnalyzerConfig(BaseModel):
    """Configuration for threat analyzer."""

    enabled: bool = True
    rules_path: str = "/var/lib/Sentinel_Linux/rules"


class AnomalyDetectorConfig(BaseModel):
    """Configuration for anomaly detector."""

    enabled: bool = True
    baseline_path: str = "/var/lib/Sentinel_Linux/baselines"
    sensitivity: str = "medium"
    learning_period: int = Field(default=86400, ge=3600)

    @field_validator("sensitivity")
    @classmethod
    def validate_sensitivity(cls, v: str) -> str:
        """Validate sensitivity level."""
        valid_levels = ["low", "medium", "high"]
        if v.lower() not in valid_levels:
            raise ValueError(f"Sensitivity must be one of: {valid_levels}")
        return v.lower()


class IOCMatcherConfig(BaseModel):
    """Configuration for IOC matcher."""

    enabled: bool = True
    ioc_database: str = "/var/lib/Sentinel_Linux/ioc/iocs.json"
    update_interval: int = Field(default=3600, ge=300)


class MITREMapperConfig(BaseModel):
    """Configuration for MITRE mapper."""

    enabled: bool = True
    include_sub_techniques: bool = True


class AnalyzersConfig(BaseModel):
    """Configuration for all analyzers."""

    threat_analyzer: ThreatAnalyzerConfig = Field(
        default_factory=ThreatAnalyzerConfig
    )
    anomaly_detector: AnomalyDetectorConfig = Field(
        default_factory=AnomalyDetectorConfig
    )
    ioc_matcher: IOCMatcherConfig = Field(default_factory=IOCMatcherConfig)
    mitre_mapper: MITREMapperConfig = Field(default_factory=MITREMapperConfig)


class ConsoleReporterConfig(BaseModel):
    """Configuration for console reporter."""

    enabled: bool = True
    color: bool = True
    severity_threshold: str = "INFO"


class JSONReporterConfig(BaseModel):
    """Configuration for JSON reporter."""

    enabled: bool = True
    output_path: str = "/var/log/Sentinel_Linux/events.json"
    rotate: bool = True
    max_size_mb: int = Field(default=100, ge=1)
    backup_count: int = Field(default=5, ge=1)


class SyslogReporterConfig(BaseModel):
    """Configuration for syslog reporter."""

    enabled: bool = False
    host: str = "localhost"
    port: int = Field(default=514, ge=1, le=65535)
    protocol: str = "udp"
    facility: str = "LOCAL0"

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Validate syslog protocol."""
        valid_protocols = ["udp", "tcp", "tls"]
        if v.lower() not in valid_protocols:
            raise ValueError(f"Protocol must be one of: {valid_protocols}")
        return v.lower()


class WebhookReporterConfig(BaseModel):
    """Configuration for webhook reporter."""

    enabled: bool = False
    url: str = ""
    method: str = "POST"
    headers: Dict[str, str] = Field(
        default_factory=lambda: {"Content-Type": "application/json"}
    )
    template: str = ""
    retry_count: int = Field(default=3, ge=0, le=10)
    timeout: int = Field(default=10, ge=1, le=60)


class ReportersConfig(BaseModel):
    """Configuration for all reporters."""

    console: ConsoleReporterConfig = Field(default_factory=ConsoleReporterConfig)
    json_reporter: JSONReporterConfig = Field(
        default_factory=JSONReporterConfig, alias="json"
    )
    syslog: SyslogReporterConfig = Field(default_factory=SyslogReporterConfig)
    webhook: WebhookReporterConfig = Field(default_factory=WebhookReporterConfig)

    model_config = {"populate_by_name": True}


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""

    enabled: bool = True
    max_alerts_per_minute: int = Field(default=60, ge=1)


class AlertingConfig(BaseModel):
    """Configuration for alerting."""

    severity_threshold: str = "LOW"
    deduplication_window: int = Field(default=300, ge=0)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)


class GlobalConfig(BaseModel):
    """Global configuration settings."""

    hostname: str = ""
    log_level: str = "INFO"
    log_file: str = "/var/log/Sentinel_Linux/monitor.log"
    pid_file: str = "/var/run/Sentinel_Linux.pid"
    debug: bool = False

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()


class Settings(BaseSettings):
    """
    Main settings class combining all configuration sections.

    Configuration is loaded from:
    1. Default values
    2. YAML configuration file
    3. Environment variables (prefixed with LSM_)
    """

    model_config = SettingsConfigDict(
        env_prefix="LSM_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    global_config: GlobalConfig = Field(
        default_factory=GlobalConfig, alias="global"
    )
    monitors: MonitorsConfig = Field(default_factory=MonitorsConfig)
    analyzers: AnalyzersConfig = Field(default_factory=AnalyzersConfig)
    reporters: ReportersConfig = Field(default_factory=ReportersConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "Settings":
        """
        Load settings from a YAML file.

        Args:
            path: Path to YAML configuration file.

        Returns:
            Settings instance with loaded configuration.

        Raises:
            FileNotFoundError: If configuration file doesn't exist.
            ValueError: If configuration is invalid.
            ValidationError: If path is invalid (path traversal attempt).
        """
        # Validate path to prevent path traversal
        from src.core.exceptions import ValidationError as PathValidationError
        from src.utils.validators import validate_path

        try:
            validate_path(path, must_exist=True, must_be_file=True)
        except PathValidationError as e:
            raise ValueError(f"Invalid configuration file path: {e}") from e

        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f) or {}

        return cls(**config_data)

    def to_yaml(self, path: str) -> None:
        """
        Save settings to a YAML file.

        Args:
            path: Path to save configuration.
        """
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(
                self.model_dump(by_alias=True),
                f,
                default_flow_style=False,
                sort_keys=False,
            )


def find_config_file() -> Optional[str]:
    """
    Find configuration file in standard locations.

    Returns:
        Path to configuration file or None if not found.
    """
    search_paths = [
        os.environ.get("LSM_CONFIG"),
        "/etc/Sentinel_Linux/config.yaml",
        "/etc/Sentinel_Linux/config.yml",
        "./config.yaml",
        "./config.yml",
        str(Path(__file__).parent / "default_config.yaml"),
    ]

    for path in search_paths:
        if path and Path(path).exists():
            return path

    return None


@lru_cache
def get_settings(config_path: Optional[str] = None) -> Settings:
    """
    Get settings singleton.

    Args:
        config_path: Optional path to configuration file.

    Returns:
        Settings instance.
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path:
        return Settings.from_yaml(config_path)

    return Settings()


def validate_config(config: Dict[str, Any]) -> List[str]:
    """
    Validate configuration dictionary.

    Args:
        config: Configuration dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors: List[str] = []

    try:
        Settings(**config)
    except Exception as e:
        errors.append(str(e))

    return errors


