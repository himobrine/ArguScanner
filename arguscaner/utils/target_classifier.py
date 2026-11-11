"""TargetClassifier - Detect target type (domain/IP/CIDR) and normalize targets."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class TargetClassifier:
    """Classifies scan targets as domain, IP, or CIDR range.

    Also provides safe target normalization utilities.
    """

    # IPv4/IPv6 with optional port
    _IP_PATTERN = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$"
    )
    # IPv4-like string (may be invalid octets)
    _IPV4_LIKE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    _DOMAIN_PATTERN = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\."
        r"(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
    )

    @staticmethod
    def classify(target: str) -> TargetType:
        """Classify a target string as domain, IP, or CIDR.

        Supports URLs (http://, https://, ftp://, etc.) — extracts hostname.

        Args:
            target: The target string (domain, IP, CIDR, or URL).

        Returns:
            TargetType.DOMAIN, TargetType.IP, or TargetType.CIDR.

        Raises:
            ValueError: If target is not a valid domain, IP, or CIDR.
        """
        target = target.strip()
        if not target:
            raise ValueError("目标不能为空")

        target = TargetClassifier._extract_from_url(target)

        # Strip port for detection (e.g. 1.2.3.4:8080)
        detection = target
        match = TargetClassifier._IP_PATTERN.match(target)
        if match:
            detection = match.group(1)

        # Try single IP first (ip_network would treat an IP as /32 or /128)
        try:
            ipaddress.ip_address(detection)
            return TargetType.IP
        except ValueError:
            pass

        # Try CIDR
        if "/" in detection:
            try:
                ipaddress.ip_network(detection, strict=False)
                return TargetType.CIDR
            except ValueError:
                pass

        # If it looks like an IPv4 but ip_address failed, it's invalid
        if TargetClassifier._IPV4_LIKE.match(detection):
            raise ValueError(
                f"'{target}' 看起来是 IPv4 地址但无效"
            )

        # Try domain - require at least one dot for a meaningful base domain
        if "." in detection and TargetClassifier._DOMAIN_PATTERN.match(detection):
            return TargetType.DOMAIN

        raise ValueError(
            f"'{target}' 不是有效的域名、IP 地址或 CIDR 范围"
        )

    @staticmethod
    def is_domain(target: str) -> bool:
        """Check if target is a domain name."""
        try:
            return TargetClassifier.classify(target) == TargetType.DOMAIN
        except ValueError:
            return False

    @staticmethod
    def is_ip(target: str) -> bool:
        """Check if target is an IP address."""
        try:
            return TargetClassifier.classify(target) == TargetType.IP
        except ValueError:
            return False

    @staticmethod
    def is_cidr(target: str) -> bool:
        """Check if target is a CIDR range."""
        try:
            return TargetClassifier.classify(target) == TargetType.CIDR
        except ValueError:
            return False

    @staticmethod
    def strip_www(target: str) -> str:
        """Remove leading 'www.' prefix safely.

        Uses removeprefix (not lstrip) to avoid mangling domain names.
        """
        target = target.strip().lower()
        target = target.removeprefix("www.")
        return target

    @staticmethod
    def normalize_domain(target: str) -> str:
        """Normalize a domain: lowercase, strip trailing dot."""
        return TargetClassifier.strip_www(target).rstrip(".")

    @staticmethod
    def _extract_from_url(target: str) -> str:
        """Extract hostname/IP from a URL, or return as-is if not a URL.

        Handles: http://127.0.0.1/, https://example.com:8443/path, ftp://10.0.0.1
        """
        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                return hostname
        return target

    @staticmethod
    def parse_targets(raw: str) -> list[str]:
        """Parse a raw target string into a list of individual targets.

        Splits on commas, newlines, and semicolons. Strips whitespace.
        Filters out empty strings.
        """
        import re as _re
        parts = _re.split(r'[,\n;]+', raw)
        return [p.strip() for p in parts if p.strip()]
