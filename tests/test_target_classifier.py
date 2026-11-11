"""Tests for the target classifier."""

from __future__ import annotations

import pytest

from arguscaner.utils.target_classifier import TargetClassifier, TargetType


class TestTargetClassifierClassify:

    @pytest.mark.parametrize("target", [
        "example.com",
        "www.example.com",
        "sub.domain.example.com",
        "EXAMPLE.COM",
        "example.co.uk",
    ])
    def test_domain(self, target):
        assert TargetClassifier.classify(target) == TargetType.DOMAIN

    @pytest.mark.parametrize("target", [
        "192.168.1.1",
        "8.8.8.8",
        "10.0.0.1",
        "172.16.0.5",
        "127.0.0.1",
        "2001:db8::1",
    ])
    def test_ip(self, target):
        assert TargetClassifier.classify(target) == TargetType.IP

    @pytest.mark.parametrize("target", [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "2001:db8::/32",
    ])
    def test_cidr(self, target):
        assert TargetClassifier.classify(target) == TargetType.CIDR

    @pytest.mark.parametrize("target", [
        "192.168.1.1:8080",
        "8.8.8.8:443",
    ])
    def test_ip_with_port(self, target):
        assert TargetClassifier.classify(target) == TargetType.IP

    @pytest.mark.parametrize("target", [
        "",
        "   ",
        "not a valid target",
        "example_domain",
        "123.456.789.999",
    ])
    def test_invalid(self, target):
        with pytest.raises(ValueError):
            TargetClassifier.classify(target)


class TestTargetClassifierPredicates:

    def test_is_domain(self):
        assert TargetClassifier.is_domain("example.com")
        assert not TargetClassifier.is_domain("192.168.1.1")
        assert not TargetClassifier.is_domain("invalid")

    def test_is_ip(self):
        assert TargetClassifier.is_ip("8.8.8.8")
        assert not TargetClassifier.is_ip("example.com")

    def test_is_cidr(self):
        assert TargetClassifier.is_cidr("10.0.0.0/8")
        assert not TargetClassifier.is_cidr("10.0.0.1")


class TestTargetClassifierStripWww:

    def test_normal_domain(self):
        assert TargetClassifier.strip_www("example.com") == "example.com"

    def test_with_www(self):
        assert TargetClassifier.strip_www("www.example.com") == "example.com"

    def test_mixed_case(self):
        assert TargetClassifier.strip_www("WWW.Example.COM") == "example.com"

    def test_lstrip_bug_fixed(self):
        # lstrip("www.") would mangle these; removeprefix must not
        assert TargetClassifier.strip_www("waffle.com") == "waffle.com"
        assert TargetClassifier.strip_www("web.example.com") == "web.example.com"
        assert TargetClassifier.strip_www("apple.com") == "apple.com"

    def test_normalize_domain(self):
        assert TargetClassifier.normalize_domain("www.Example.COM.") == "example.com"


class TestTargetClassifierUrl:

    @pytest.mark.parametrize("target,expected", [
        ("http://127.0.0.1/", TargetType.IP),
        ("https://127.0.0.1/", TargetType.IP),
        ("https://example.com/path", TargetType.DOMAIN),
        ("http://10.0.0.1:8080/api", TargetType.IP),
        ("ftp://192.168.1.1/file", TargetType.IP),
        ("https://sub.domain.example.com:443/", TargetType.DOMAIN),
    ])
    def test_url_parsing(self, target, expected):
        assert TargetClassifier.classify(target) == expected

    def test_url_strips_port(self):
        assert TargetClassifier.classify("http://8.8.8.8:8080/") == TargetType.IP

    def test_plain_still_works(self):
        assert TargetClassifier.classify("example.com") == TargetType.DOMAIN
        assert TargetClassifier.classify("192.168.1.1") == TargetType.IP


class TestTargetClassifierParseTargets:

    def test_single_target(self):
        assert TargetClassifier.parse_targets("example.com") == ["example.com"]

    def test_comma_separated(self):
        result = TargetClassifier.parse_targets("example.com,192.168.1.1,10.0.0.1")
        assert result == ["example.com", "192.168.1.1", "10.0.0.1"]

    def test_newline_separated(self):
        result = TargetClassifier.parse_targets("example.com\n192.168.1.1\n10.0.0.1")
        assert result == ["example.com", "192.168.1.1", "10.0.0.1"]

    def test_mixed_separators(self):
        result = TargetClassifier.parse_targets("example.com, 192.168.1.1\n10.0.0.1")
        assert result == ["example.com", "192.168.1.1", "10.0.0.1"]

    def test_with_urls(self):
        result = TargetClassifier.parse_targets("http://127.0.0.1, https://example.com")
        assert result == ["http://127.0.0.1", "https://example.com"]

    def test_empty_input(self):
        assert TargetClassifier.parse_targets("") == []
        assert TargetClassifier.parse_targets("   ") == []
        assert TargetClassifier.parse_targets(",\n;") == []

    def test_semicolon_separated(self):
        result = TargetClassifier.parse_targets("example.com;192.168.1.1")
        assert result == ["example.com", "192.168.1.1"]
