"""Tests for external tool parsers."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import external

from modules.content_discovery import classify_content_hit
from modules.exploit_lookup import build_search_terms
from tools.external import (
    extract_parameters_from_urls,
    parse_arjun_json,
    parse_dalfox_jsonl,
    parse_ffuf_json,
    parse_maigret_json,
    parse_nuclei_jsonl,
    parse_searchsploit_json,
    parse_sqlmap_text,
    parse_cms_text_findings,
)


def test_parse_searchsploit_json():
    text = """
    {
      "RESULTS_EXPLOIT": [
        {"Title": "Example CMS RCE", "EDB-ID": "12345", "Path": "exploits/x.py"}
      ]
    }
    """

    results = parse_searchsploit_json(text)

    assert results[0]["title"] == "Example CMS RCE"
    assert results[0]["edb_id"] == "12345"


def test_parse_ffuf_json():
    text = """
    {
      "results": [
        {"url": "https://example.com/admin", "status": 403, "length": 10}
      ]
    }
    """

    results = parse_ffuf_json(text)

    assert results[0]["url"].endswith("/admin")
    assert results[0]["status"] == 403


def test_build_search_terms_from_webapp_assets():
    terms = build_search_terms([
        {
            "attrs": {
                "cms": "WordPress 6.4",
                "server": "nginx",
                "plugins": ["elementor"],
            }
        }
    ])

    assert "WordPress 6.4" in terms
    assert "wordpress elementor" in terms


def test_classify_content_hit():
    # "served" replaced the old "interesting" label: a 200 on a sensitive-looking
    # name is served without a redirect to a login, which is the case worth
    # reporting. A 403 stays "protected" — the resource exists, access control
    # held. See tests/test_content_discovery.py for the full grading.
    assert classify_content_hit({"url": "https://e.com/admin", "status": 200}) == "served"
    assert classify_content_hit({"url": "https://e.com/private", "status": 403}) == "protected"
    assert classify_content_hit({"url": "https://e.com/login", "status": 302}) == "redirected"


def test_parse_nuclei_jsonl():
    text = (
        '{"template-id":"test-template","info":{"name":"Test Finding",'
        '"severity":"medium","tags":["test"]},"matched-at":"https://example.com"}\n'
    )

    results = parse_nuclei_jsonl(text)

    assert results[0]["template_id"] == "test-template"
    assert results[0]["severity"] == "MEDIUM"


def test_extract_parameters_from_urls():
    results = extract_parameters_from_urls([
        "https://example.com/search?q=test&page=1",
        "https://example.com/search?q=again",
    ])

    assert {item["parameter"] for item in results} == {"q", "page"}


def test_parse_arjun_json():
    results = parse_arjun_json('{"https://example.com": ["id", "next"]}')

    assert results == [
        {"url": "https://example.com", "parameter": "id", "source": "arjun"},
        {"url": "https://example.com", "parameter": "next", "source": "arjun"},
    ]


def test_parse_dalfox_jsonl():
    results = parse_dalfox_jsonl(
        '{"type":"v","data":"https://example.com/?q=x","payload":"<x>"}\n'
    )

    assert results[0]["type"] == "v"
    assert results[0]["payload"] == "<x>"


def test_parse_sqlmap_text():
    results = parse_sqlmap_text("GET parameter 'id' is vulnerable. Do you want to keep testing?")

    assert results[0]["evidence"].startswith("GET parameter")


def test_parse_sqlmap_text_keeps_the_target_url():
    """The URL is what lets an out-of-band callback be attributed to the one
    request that caused it, so the parser has to recover it from sqlmap's
    connection line rather than dropping it."""
    text = (
        "[12:00:01] testing connection to the target URL: https://t/api/x?id=1\n"
        "[12:00:02] GET parameter 'id' is vulnerable. Do you want to keep testing?\n"
    )
    results = parse_sqlmap_text(text)

    assert results == [{
        "url": "https://t/api/x?id=1",
        "evidence": "[12:00:02] GET parameter 'id' is vulnerable. "
                    "Do you want to keep testing?",
    }]


def test_parse_sqlmap_text_survives_a_url_with_a_colon_in_the_path():
    text = "testing connection to the target URL: https://t:8443/a:b?id=1\n"
    text += "GET parameter 'id' is vulnerable.\n"
    assert parse_sqlmap_text(text)[0]["url"] == "https://t:8443/a:b?id=1"


def test_parse_sqlmap_text_without_a_connection_line_keeps_no_url():
    assert parse_sqlmap_text("POST parameter 'q' is injectable")[0]["url"] == ""


def test_parse_sqlmap_text_ignores_lines_that_reject_the_parameter():
    """The four CRITICAL findings this parser produced on the benchmark target.

    The rule used to be "the line mentions a GET or POST parameter", which is
    most of what sqlmap prints while deciding a parameter is *not* worth
    testing. All four lines below came from one run against `to` on
    `/redirect` — sqlmap rejecting it — and each was filed as FIRM SQL
    injection.
    """
    text = "\n".join([
        "[14:34:14] [INFO] testing if GET parameter 'to' is dynamic",
        "[14:34:14] [WARNING] GET parameter 'to' does not appear to be dynamic",
        "[14:34:14] [WARNING] heuristic (basic) test shows that GET "
        "parameter 'to' might not be injectable",
        "[14:34:14] [INFO] skipping GET parameter 'to'",
    ])

    assert parse_sqlmap_text(text) == []


def test_parse_sqlmap_text_still_reports_a_real_hit_amid_the_noise():
    text = "\n".join([
        "[14:34:14] [INFO] testing if GET parameter 'q' is dynamic",
        "[14:34:14] [INFO] GET parameter 'q' is vulnerable",
        "[14:34:14] [INFO] skipping GET parameter 'to'",
    ])

    results = parse_sqlmap_text(text)

    assert [r["evidence"] for r in results] == \
        ["[14:34:14] [INFO] GET parameter 'q' is vulnerable"]


def test_sqlmap_scan_leaves_oast_off_by_default(monkeypatch):
    """No interactsh server, no behaviour change: the argv must be identical to
    what it was before OAST existed, or every existing run shifts under it."""
    captured = {}

    async def fake_run_command(args, timeout=None):
        captured["args"] = args
        return {"stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setattr(external, "run_command", fake_run_command)
    result = asyncio.run(external.sqlmap_scan("https://t/api/x?id=1"))

    assert "--oast" not in captured["args"]
    assert "--interactsh-url" not in captured["args"]
    assert result["oast"] is False


def test_sqlmap_scan_enables_oast_when_a_server_is_given(monkeypatch):
    captured = {}

    async def fake_run_command(args, timeout=None):
        captured["args"] = args
        return {"stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setattr(external, "run_command", fake_run_command)
    asyncio.run(external.sqlmap_scan("https://t/api/x?id=1",
                                     interactsh_url="https://oast.test"))

    assert "--oast" in captured["args"]
    assert captured["args"][captured["args"].index("--interactsh-url") + 1] == \
           "https://oast.test"


@pytest.mark.parametrize("line,expected", [
    ("[+] interactsh OOB: the target resolved our host", True),
    ("[+] OAST confirmed blind injection", True),
    ("[+] the parameter is injectable, out-of-band data exfiltrated", True),
    ("GET parameter 'id' is vulnerable", False),
    ("[12:00:01] testing connection to the target URL: https://t/api/x?id=1", False),
])
def test_oast_marker_detection(monkeypatch, line, expected):
    async def fake_run_command(args, timeout=None):
        return {"stdout": line, "stderr": "", "exit_code": 0}

    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setattr(external, "run_command", fake_run_command)
    result = asyncio.run(external.sqlmap_scan("https://t/api/x?id=1",
                                              interactsh_url="https://oast.test"))

    assert result["oast"] is expected


def test_parse_maigret_json():
    results = parse_maigret_json(
        '{"GitHub":{"name":"GitHub","url_user":"https://github.com/example",'
        '"status":{"status":"Claimed"}}}'
    )

    assert results[0]["site"] == "GitHub"


def test_parse_cms_text_findings():
    results = parse_cms_text_findings("Outdated version detected\nNo issue here")

    assert results == [{"evidence": "Outdated version detected"}]

