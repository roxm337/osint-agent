"""Tests for external tool parsers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    assert classify_content_hit({"url": "https://e.com/admin", "status": 200}) == "interesting"
    assert classify_content_hit({"url": "https://e.com/private", "status": 403}) == "protected"


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


def test_parse_maigret_json():
    results = parse_maigret_json(
        '{"GitHub":{"name":"GitHub","url_user":"https://github.com/example",'
        '"status":{"status":"Claimed"}}}'
    )

    assert results[0]["site"] == "GitHub"


def test_parse_cms_text_findings():
    results = parse_cms_text_findings("Outdated version detected\nNo issue here")

    assert results == [{"evidence": "Outdated version detected"}]

