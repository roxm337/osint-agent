"""Tests for P6/P7 identity, secrets, and submission modules."""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validators import extract_secrets, redact_secret, validate_secret
from modules.bounty_submission import BountySubmission
from modules.secret_validation import SecretValidation
from modules.social_osint import SocialOSINT
from state.manager import StateManager


def test_secret_validators_extract_and_redact():
    secrets = extract_secrets("token = ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")

    assert secrets[0]["type"] == "github_pat"
    assert secrets[0]["redacted"].startswith("ghp_")
    assert validate_secret("aws_access_key", "AKIAABCDEFGHIJKLMNOP")["verdict"] == "structurally_valid"
    assert redact_secret("abcdefghi") == "abcd...fghi"


def test_secret_validation_reads_evidence_files():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    evidence_id = state.add_evidence(
        "js_analysis",
        "javascript",
        "https://example.com/app.js",
        {"body": "const token = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ';"},
    )
    assert evidence_id == "EVIDENCE-0001"

    result = asyncio.run(
        SecretValidation(state, {"target": {"domain": "example.com"}}).run()
    )

    assert result == "done"
    assert state.get_assets_by_type("secret_candidate")
    assert state.findings["findings"][0]["title"].startswith("Structurally Valid Secret")


def test_social_osint_skips_without_identity_seeds():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))

    result = asyncio.run(SocialOSINT(state, {"target": {"domain": ""}}).run())

    assert result == "skipped"


def test_bounty_submission_writes_files():
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_finding(
        title="Example High Finding",
        severity="HIGH",
        confidence="FIRM",
        category="Credential Exposure",
        description="A token was exposed.",
        evidence=["token redacted"],
        remediation="Rotate token.",
        risk_score=88,
    )

    result = asyncio.run(
        BountySubmission(state, {"target": {"domain": "example.com"}}).run()
    )

    assert result == "done"
    index = tmpdir / "run" / "example.com" / "submissions" / "INDEX.md"
    assert index.exists()
    assert "Example High Finding" in index.read_text()
