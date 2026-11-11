"""WAFDetector - Web Application Firewall trigger detection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class RecoveryAction(str, Enum):
    NONE = "none"
    ROTATE_PROXY = "rotate_proxy"
    BACKOFF = "backoff"
    FALLBACK_FAILED = "fallback_failed"


@dataclass
class WAFTriggerResult:
    detected: bool
    action: RecoveryAction
    status_code: int | None = None
    matched_keyword: str | None = None


class WAFDetector:
    """Detects WAF (Web Application Firewall) triggers based on
    HTTP response status codes and body keywords.
    """

    def __init__(self, settings: dict[str, Any] | None = None):
        waf_config = (settings or {}).get("waf_aware", {})
        self.enabled = waf_config.get("enabled", True)
        self.trigger_status_codes: set[int] = set(
            waf_config.get("trigger_status_codes", [403, 429, 503])
        )
        self.trigger_keywords: list[str] = [
            kw.lower()
            for kw in waf_config.get(
                "trigger_response_keywords",
                ["access denied", "blocked", "captcha", "waf"],
            )
        ]

    def check_response(
        self, status_code: int, body: str = ""
    ) -> WAFTriggerResult:
        """Check if a response indicates WAF trigger.

        Args:
            status_code: HTTP status code.
            body: Response body text.

        Returns:
            WAFTriggerResult with detection result and recommended action.
        """
        if not self.enabled:
            return WAFTriggerResult(detected=False, action=RecoveryAction.NONE)

        # Check status code
        if status_code in self.trigger_status_codes:
            return WAFTriggerResult(
                detected=True,
                action=RecoveryAction.ROTATE_PROXY,
                status_code=status_code,
            )

        # Check body keywords
        body_lower = body.lower()
        for keyword in self.trigger_keywords:
            if keyword in body_lower:
                return WAFTriggerResult(
                    detected=True,
                    action=RecoveryAction.ROTATE_PROXY,
                    matched_keyword=keyword,
                )

        return WAFTriggerResult(detected=False, action=RecoveryAction.NONE)

    def get_recovery_action(
        self, rotate_attempts: int, max_rotate_attempts: int
    ) -> RecoveryAction:
        """Determine recovery action based on current state.

        Args:
            rotate_attempts: Number of proxy rotations attempted.
            max_rotate_attempts: Maximum allowed rotations.

        Returns:
            Recommended RecoveryAction.
        """
        if rotate_attempts < max_rotate_attempts:
            return RecoveryAction.ROTATE_PROXY
        return RecoveryAction.FALLBACK_FAILED
