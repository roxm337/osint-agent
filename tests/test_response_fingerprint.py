"""Tests for core/response_fingerprint.py and the fast_exposure_scan fix.

Context, because the shape of these tests is not obvious: against OWASP Juice
Shop, `fast_exposure_scan` filed 7 CRITICAL and 4 HIGH findings. Every one was
the same document. Juice Shop is an Express app serving an Angular SPA, so
`/.env`, `/wp-config.php`, `/actuator/env` and `/backup.sql` all returned the
9393-byte index.html that `/` returns — byte-identical, same md5.

The old `_path_finding` had exactly one body check, `len(body.strip()) < 20`.
A 9393-byte shell sails past that, so a 200 was treated as proof of exposure.

These tests encode that real response, so the regression cannot come back.
"""

import pytest

from core.response_fingerprint import (
    Baseline,
    content_matches,
    establish_baseline,
    fingerprint,
)
from modules.fast_exposure_scan import FastExposureScan

# What Juice Shop actually served for every one of those paths, and for /.
JUICE_SHELL = ("<!doctype html><html lang=\"en\"><head><title>OWASP Juice Shop"
               "</title></head><body class=\"bluegrey-lightgreen-theme\">"
               "<app-root></app-root></body></html>")
JUICE_LEN = 9393


def _juice_body():
    """The shell, padded to the real observed length."""
    pad = " " * max(0, JUICE_LEN - len(JUICE_SHELL))
    return JUICE_SHELL + pad


# --- fingerprinting -----------------------------------------------------

def test_same_document_different_whitespace_is_the_same_page():
    a = fingerprint(200, "<html>  <body>hello</body>\n</html>")
    b = fingerprint(200, "<html><body>hello</body></html>")
    assert a.body_hash == b.body_hash


def test_volatile_numbers_do_not_make_a_new_document():
    a = fingerprint(200, "<p>id 1234567 created 20260101</p>")
    b = fingerprint(200, "<p>id 7654321 created 20261231</p>")
    assert a.body_hash == b.body_hash


def test_genuinely_different_documents_differ():
    a = fingerprint(200, "<html>index</html>")
    b = fingerprint(200, "<html>admin panel, users table</html>")
    assert a.body_hash != b.body_hash


def test_content_type_is_compared_without_parameters():
    a = fingerprint(200, "x", "text/html; charset=utf-8")
    b = fingerprint(200, "x", "text/html")
    assert a.content_type == b.content_type


# --- catch-all detection ------------------------------------------------

def _baseline_with(root_body, control_body=None):
    control_body = control_body if control_body is not None else root_body
    b = Baseline()
    b.root = fingerprint(200, root_body, "text/html")
    b.control_paths = 3
    for _ in range(3):
        b.dominant[fingerprint(200, control_body, "text/html").body_hash] += 1
    return b


def test_response_identical_to_root_is_a_catch_all():
    """This is the Juice Shop case, exactly."""
    body = _juice_body()
    b = _baseline_with(body)
    assert b.catch_all(fingerprint(200, body, "text/html")) is True


def test_response_different_from_root_is_not_a_catch_all():
    b = _baseline_with(_juice_body())
    env = "DB_PASSWORD=hunter2\nSECRET_KEY=abc123\n"
    assert b.catch_all(fingerprint(200, env, "text/plain")) is False


def test_dominant_group_is_detected_even_when_root_differs():
    b = Baseline()
    b.root = fingerprint(200, "<html>a different root</html>", "text/html")
    b.control_paths = 4
    for _ in range(4):
        b.dominant[fingerprint(200, "<html>catchall</html>", "text/html").body_hash] += 1
    assert b.catch_all(fingerprint(200, "<html>catchall</html>", "text/html")) is True


def test_a_single_control_path_is_not_enough_to_claim_a_catch_all():
    """One 404 is not proof of a catch-all; three agreeing responses are."""
    b = Baseline()
    b.root = fingerprint(200, "<html>root</html>", "text/html")
    b.control_paths = 1
    b.dominant[fingerprint(404, "nope", "text/html").body_hash] += 1
    assert b.catch_all(fingerprint(404, "nope", "text/html")) is False


def test_empty_baseline_never_claims_a_catch_all():
    b = Baseline()
    assert b.catch_all(fingerprint(200, "anything")) is False


# --- content assertions -------------------------------------------------

@pytest.mark.parametrize("rule,body,expected", [
    (r"/\.env", "DB_PASSWORD=hunter2\nAPI_KEY=xyz", True),
    (r"/\.env", "<html>not an env file</html>", False),
    (r"/\.git/(config|HEAD)", "[core]\n\trepositoryformatversion = 0", True),
    (r"/\.git/(config|HEAD)", "<html>spa shell</html>", False),
    (r"backup\.sql", "-- MySQL dump 10.13\nCREATE TABLE users", True),
    (r"backup\.sql", "<html>spa shell</html>", False),
    (r"phpinfo|info\.php", "phpinfo()\nPHP Version 8.2.0", True),
    (r"phpinfo|info\.php", "<html>spa shell</html>", False),
    (r"phpmyadmin|adminer", "<title>phpMyAdmin</title>", True),
    (r"phpmyadmin|adminer", "<html>spa shell</html>", False),
    (r"graphql|graphiql", '{"data":{"user":null}}', True),
    (r"graphql|graphiql", "<html>spa shell</html>", False),
    (r"actuator/(env|heapdump)", '{"_links":{"self":{"href":"/actuator"}}}', True),
    (r"actuator/(env|heapdump)", "<html>spa shell</html>", False),
])
def test_content_assertions(rule, body, expected):
    assert content_matches(rule, body) is expected


def test_unknown_rule_is_unverified_rather_than_rejected():
    """A new rule must not be silently disabled by a missing assertion."""
    assert content_matches(r"/something/new", "whatever") is True


# --- the module-level regression ----------------------------------------

def _item(path, body, status=200):
    return {"path": path, "status": status, "body": body,
            "sig": fingerprint(status, body, "text/html")}


def _verdict(path, body, baseline, status=200):
    mod = FastExposureScan.__new__(FastExposureScan)
    return mod._path_finding("http://t", _item(path, body, status), baseline)


@pytest.mark.parametrize("path,title", [
    ("/.env", "Exposed Environment File"),
    ("/.git/config", "Exposed Git Metadata"),
    ("/wp-config.php", "Exposed WordPress Configuration"),
    ("/actuator/env", "Sensitive Spring Boot Actuator Exposed"),
    ("/backup.sql", "Database Backup Exposed"),
    ("/phpmyadmin/", "Database Admin Interface Exposed"),
])
def test_the_spa_shell_produces_no_finding(path, title):
    """The 22 false positives from the Juice Shop run, pinned one by one."""
    body = _juice_body()
    verdict, finding = _verdict(path, body, _baseline_with(body))
    assert finding is None, f"{path} was reported as {finding and finding['title']}"
    assert verdict == "catch_all"


def test_a_real_exposed_env_file_is_still_reported():
    body = _juice_body()
    env = "DB_PASSWORD=hunter2\nJWT_SECRET=s3cr3t\n"
    verdict, finding = _verdict("/.env", env, _baseline_with(body))
    assert finding is not None
    assert finding["title"] == "Exposed Environment File"
    assert finding["severity"] == "CRITICAL"
    assert finding["confidence"] == "CONFIRMED"


def test_a_novel_200_without_the_expected_content_is_not_reported():
    """Serving 200 is not evidence; serving the artifact is."""
    body = _juice_body()
    verdict, finding = _verdict(
        "/backup.sql", "<html>brand new page, but not a SQL dump</html>",
        _baseline_with(body))
    assert finding is None
    assert verdict == "no_content_match"


def test_a_403_no_longer_claims_critical_exposure():
    body = _juice_body()
    verdict, finding = _verdict("/.env", "Forbidden", _baseline_with(body), status=403)
    assert finding is not None
    assert finding["severity"] == "INFO", "access denied discloses nothing"
    assert finding["title"].endswith("(access denied)")


# --- baseline establishment --------------------------------------------

def test_establish_baseline_uses_the_callers_fetch():
    import asyncio
    calls = []

    async def fetch(path):
        calls.append(path)
        return 200, _juice_body(), "text/html"

    b = asyncio.run(establish_baseline(fetch, "http://t"))
    assert calls[0] == "/"
    assert len(calls) == 5, "root plus the control paths"
    assert b.root is not None
    assert b.catch_all(fingerprint(200, _juice_body(), "text/html")) is True


def test_establish_baseline_survives_a_fetch_that_raises():
    import asyncio
    async def fetch(path):
        if path == "/":
            raise RuntimeError("connection refused")
        return 200, "x", "text/html"

    b = asyncio.run(establish_baseline(fetch, "http://t"))
    assert b.root is None
    assert b.catch_all(fingerprint(200, "x", "text/html")) is False
