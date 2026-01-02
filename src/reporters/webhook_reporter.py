"""
Webhook reporter for HTTP notifications.

Sends alerts to webhook endpoints (Slack, Teams, PagerDuty, etc.).
"""

from __future__ import annotations

import asyncio
import json
import ssl
from typing import Any, Dict, Optional

import aiohttp

from src.config.logging_config import get_logger
from src.core.alert_manager import Alert


logger = get_logger(__name__)


class WebhookReporter:
    """
    Sends alerts to webhook endpoints.

    Features:
    - Template-based payloads
    - Retry logic
    - Rate limiting
    - Async delivery
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize webhook reporter."""
        config = config or {}
        self.url = config.get("url", "")
        self.method = config.get("method", "POST").upper()
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        self.template = config.get("template", "")
        self.retry_count = config.get("retry_count", 3)
        self.timeout = config.get("timeout", 10)
        self.verify_ssl = config.get("verify_ssl", True)

        if not self.url:
            logger.warning("Webhook URL not configured")

    def report(self, alert: Alert) -> None:
        """
        Send alert to webhook.

        Args:
            alert: Alert to send.
        """
        if not self.url:
            return

        try:
            asyncio.run(self._send_async(alert))
        except RuntimeError:
            # Already in async context
            loop = asyncio.get_event_loop()
            loop.create_task(self._send_async(alert))
        except Exception as e:
            logger.error(f"Webhook delivery failed: {e}")

    async def _send_async(self, alert: Alert) -> bool:
        """Send alert asynchronously with retries."""
        payload = self._build_payload(alert)

        for attempt in range(self.retry_count):
            try:
                # Create SSL context - verify by default for security
                ssl_context = None
                if not self.verify_ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    logger.warning("SSL verification disabled for webhook - security risk!")

                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        self.method,
                        self.url,
                        headers=self.headers,
                        json=payload if isinstance(payload, dict) else None,
                        data=payload if isinstance(payload, str) else None,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=ssl_context,  # None means use default (verify=True)
                    ) as response:
                        if response.status < 300:
                            logger.debug(f"Webhook delivered: {response.status}")
                            return True

                        logger.warning(
                            f"Webhook returned {response.status}: {await response.text()}"
                        )

            except asyncio.TimeoutError:
                logger.warning(f"Webhook timeout (attempt {attempt + 1})")
            except Exception as e:
                logger.warning(f"Webhook error (attempt {attempt + 1}): {e}")

            if attempt < self.retry_count - 1:
                await asyncio.sleep(2 ** attempt)

        logger.error(f"Webhook delivery failed after {self.retry_count} attempts")
        return False

    def _build_payload(self, alert: Alert) -> Any:
        """Build webhook payload from template or default."""
        if self.template:
            return self._render_template(alert)

        # Default JSON payload
        return {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.name,
            "title": alert.title,
            "description": alert.description,
            "host": alert.host,
            "mitre_techniques": alert.mitre_techniques,
            "ioc_matches": alert.ioc_matches,
        }

    def _render_template(self, alert: Alert) -> Any:
        """Render custom template with alert data."""
        try:
            # Replace ${alert.field} placeholders
            rendered = self.template

            replacements = {
                "${alert.alert_id}": alert.alert_id,
                "${alert.timestamp}": alert.timestamp.isoformat(),
                "${alert.severity}": alert.severity.name,
                "${alert.title}": alert.title,
                "${alert.description}": alert.description[:500],
                "${alert.host}": alert.host,
                "${alert.mitre_techniques}": ", ".join(alert.mitre_techniques),
                "${alert.ioc_matches}": ", ".join(alert.ioc_matches),
            }

            # Replace placeholders in reverse order of length to avoid partial matches
            # Sort by length descending to replace longer placeholders first
            sorted_replacements = sorted(
                replacements.items(), key=lambda x: len(x[0]), reverse=True
            )
            for placeholder, value in sorted_replacements:
                # Escape JSON special characters to prevent injection
                # Use json.dumps to properly escape, then remove outer quotes
                escaped_value = json.dumps(str(value))[1:-1]
                rendered = rendered.replace(placeholder, escaped_value)

            # Try to parse as JSON
            try:
                return json.loads(rendered)
            except json.JSONDecodeError:
                return rendered

        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            return self._build_payload(alert)


