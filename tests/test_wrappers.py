"""Tests for tool wrappers — rate limiter, nmap parser, etc."""

import asyncio
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.wrappers as wrappers
from core.scoring import score_vulnerability
from tools.wrappers import parse_nmap_output
from tools.wrappers import RateLimiter, configure_http_limiter, configure_http_session


class TestParseNmapOutput:
    def test_empty_input(self):
        result = parse_nmap_output("")
        assert result["hosts"] == []

    def test_single_host(self):
        text = (
            "Nmap scan report for example.com (93.184.216.34)\n"
            "22/tcp open  ssh     OpenSSH 8.0\n"
            "80/tcp open  http    Apache 2.4\n"
        )
        result = parse_nmap_output(text)
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["hostname"] == "example.com (93.184.216.34)"
        assert len(host["ports"]) == 2

    def test_multiple_hosts_last_appended(self):
        text = (
            "Nmap scan report for host1 (10.0.0.1)\n"
            "22/tcp open  ssh\n"
            "Nmap scan report for host2 (10.0.0.2)\n"
            "80/tcp open  http\n"
            "443/tcp open https\n"
        )
        result = parse_nmap_output(text)
        assert len(result["hosts"]) == 2
        assert result["hosts"][1]["hostname"] == "host2 (10.0.0.2)"
        assert len(result["hosts"][1]["ports"]) == 2


class TestRateLimiter:
    def test_configure(self):
        configure_http_limiter(max_concurrent=10, max_per_minute=30)
        configure_http_limiter(max_concurrent=5, max_per_minute=60)

    def test_limiter_attrs(self):
        limiter = RateLimiter(max_concurrent=3, max_per_minute=50)
        assert limiter._max_per_minute == 50
        assert limiter._semaphore._value == 3

    def test_configure_http_session_merges_auth(self):
        configure_http_session({
            "auth": {
                "headers": {"X-Test": "1"},
                "cookies": {"sid": "abc"},
                "bearer_token": "tok",
            }
        })
        merged = wrappers._merge_session_headers({"X-Test": "2"})
        assert merged["X-Test"] == "2"
        assert merged["Cookie"] == "sid=abc"
        assert merged["Authorization"] == "Bearer tok"
        configure_http_session({})


class TestFreeApiWrappers:
    def test_score_vulnerability_weights(self):
        score = score_vulnerability(cvss=9.8, epss=0.7, kev=True, exposure=1.0)
        assert score >= 85

    def test_extract_domain_hosts(self):
        hosts = wrappers._extract_domain_hosts(
            "api.example.com cdn.example.com evil-example.com",
            "example.com",
        )
        assert hosts == ["api.example.com", "cdn.example.com"]

    def test_anubisdb_filters_scope(self, monkeypatch):
        async def fake_curl_json(url, **kwargs):
            return ["api.example.com", "other.test", "*.cdn.example.com"]

        monkeypatch.setattr(wrappers, "curl_json", fake_curl_json)
        result = asyncio.run(wrappers.anubisdb("example.com"))
        assert result == ["api.example.com", "cdn.example.com"]

    def test_epss_score_maps_cves(self, monkeypatch):
        async def fake_curl_json(url, **kwargs):
            return {
                "data": [
                    {
                        "cve": "CVE-2024-0001",
                        "epss": "0.42",
                        "percentile": "0.91",
                        "date": "2026-01-01",
                    }
                ]
            }

        monkeypatch.setattr(wrappers, "curl_json", fake_curl_json)
        result = asyncio.run(wrappers.epss_score(["CVE-2024-0001", "bad"]))
        assert result["CVE-2024-0001"]["epss"] == 0.42
