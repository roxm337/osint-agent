"""Tests for DNS takeover classification."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.dns_takeover import classify_takeover_risk


def test_classifies_provider_cname_without_a_records_as_risky():
    result = classify_takeover_risk(
        ["old-site.s3.amazonaws.com."],
        [],
    )

    assert result["risk"] is True
    assert result["provider"] == "aws_s3"


def test_provider_cname_with_a_records_is_not_risky():
    result = classify_takeover_risk(
        ["project.github.io."],
        ["185.199.108.153"],
    )

    assert result["risk"] is False
    assert result["provider"] == "github_pages"


def test_untracked_cname_is_not_risky():
    result = classify_takeover_risk(
        ["www.example.net."],
        [],
    )

    assert result["risk"] is False
