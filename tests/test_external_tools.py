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


def test_docker_ready_falls_back_to_qualified_reference(monkeypatch):
    """Some Docker Desktop releases resolve short names for run/pull but
    not for `image inspect` — the short form then reports a present
    image as missing. The check must try docker.io/library/ next."""
    import subprocess as _subprocess
    import tools.external as external

    seen = []

    class _Proc:
        def __init__(self, rc, out=""):
            self.returncode = rc
            self.stdout = out

    def fake_run(args, **kwargs):
        seen.append(args[-1])
        if args[-1] == "osint-tools:latest":
            return _Proc(1)
        return _Proc(0)

    monkeypatch.setattr(_subprocess, "run", fake_run)
    external._DOCKER_OK = None
    external._BACKEND["image"] = "osint-tools:latest"

    try:
        assert external._docker_ready() is True
    finally:
        external._DOCKER_OK = None
        external.configure_tool_backend({})
    assert seen[0] == "osint-tools:latest"
    assert "docker.io/library/osint-tools:latest" in seen


def test_parse_dalfox_jsonl():
    results = parse_dalfox_jsonl(
        '{"type":"v","data":"https://example.com/?q=x","payload":"<x>"}\n'
    )

    assert results[0]["type"] == "v"
    assert results[0]["payload"] == "<x>"


def test_parse_dalfox_jsonl_v3_shape():
    """v3 lines carry type tiers, inject_type and a url field instead of
    data; the parser must keep them without dropping the v2 shape above."""
    results = parse_dalfox_jsonl(
        '{"type":"V","type_description":"Vulnerable - exploitable",'
        '"inject_type":"inHTML","method":"GET",'
        '"url":"https://example.com/?q=x","payload":"<svg>"}\n'
        '{"type":"R","inject_type":"inHTML-HPP",'
        '"url":"https://example.com/?p=y"}\n'
        '{"level":"info","message":"scan complete"}\n'
    )

    assert len(results) == 2
    assert results[0]["type"] == "V"
    assert results[0]["url"] == "https://example.com/?q=x"
    assert results[0]["inject_type"] == "inHTML"
    assert results[0]["evidence"] == "Vulnerable - exploitable"
    assert results[1]["type"] == "R"


def test_dalfox_scan_uses_v3_flags(monkeypatch):
    """v3 renamed the format flag, retired --skip-bav, and reports
    findings on exit 1 — the invocation must match the new CLI."""
    import tools.external as external

    calls = {}

    async def fake_run(args, timeout=120, stdin_data=""):
        calls["args"] = args
        calls["stdin"] = stdin_data
        return {"stdout": "", "stderr": "", "exit_code": 1, "error": None}

    monkeypatch.setattr(external, "run_command", fake_run)
    monkeypatch.setattr(external, "tool_available", lambda name: True)

    result = asyncio.run(external.dalfox_scan(
        ["https://example.com/?q=x"], timeout=60,
        blind="http://cb.oob/x", blind_oob=False, rate_limit=5))

    args = calls["args"]
    assert args[:2] == ["dalfox", "pipe"]
    assert "-f" in args and "jsonl" in args
    assert "--format" not in args and "--skip-bav" not in args
    assert "--blind" in args and "http://cb.oob/x" in args
    assert "--blind-oob" not in args
    assert "--rate-limit" in args and "5" in args
    assert calls["stdin"] == "https://example.com/?q=x"
    assert result["available"] is True
    assert result["exit_code"] == 1  # findings, not failure


def test_dalfox_scan_blind_oob_flag(monkeypatch):
    import tools.external as external

    calls = {}

    async def fake_run(args, timeout=120, stdin_data=""):
        calls["args"] = args
        return {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(external, "run_command", fake_run)
    monkeypatch.setattr(external, "tool_available", lambda name: True)

    asyncio.run(external.dalfox_scan(["https://example.com/"], blind_oob=True))

    assert "--blind-oob" in calls["args"]
    assert "--blind" not in calls["args"]


def test_parse_kiterunner_json():
    from tools.external import parse_kiterunner_json

    text = (
        '{"level":"info","message":"scan options"}\n'
        '{"method":"GET","target":"https://h.test","path":"/api",'
        '"responses":[{"uri":"","sc":200,"len":123}]}\n'
        '{"method":"POST","target":"https://h.test/","path":"v1/login",'
        '"responses":[{"uri":"","sc":403,"len":9}]}\n'
        '{"level":"info","results":0,"message":"scan complete"}\n'
        "not json at all\n"
    )
    hits = parse_kiterunner_json(text)

    assert hits == [
        {"url": "https://h.test/api", "method": "GET",
         "status": 200, "length": 123},
        {"url": "https://h.test/v1/login", "method": "POST",
         "status": 403, "length": 9},
    ]


def test_kiterunner_scan_builds_bounded_args(monkeypatch):
    import tools.external as external

    calls = []

    async def fake_run(args, timeout=120, stdin_data=""):
        calls.append(args)
        return {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(external, "run_command", fake_run)
    monkeypatch.setattr(external, "tool_available", lambda name: True)

    result = asyncio.run(external.kiterunner_scan(
        ["https://a.test", "https://b.test"],
        wordlist="apiroutes-260227", max_routes=50000, timeout=60))

    assert len(calls) == 2  # one invocation per target
    assert calls[0][:3] == ["kr", "brute", "https://a.test"]
    assert "-A" in calls[0]
    # max_routes clamps at 20000 so a typo cannot schedule millions.
    assert "apiroutes-260227:20000" in calls[0]
    assert "-o" in calls[0] and "json" in calls[0]
    assert result["available"] is True
    assert result["targets"] == ["https://a.test", "https://b.test"]


def test_semgrep_scan_parses_rule_hits(monkeypatch):
    import json as _json
    import tools.external as external

    async def fake_run(args, timeout=120, stdin_data=""):
        assert args[0] == "semgrep"
        assert "--metrics" in args and "off" in args
        assert "--disable-version-check" in args
        payload = {
            "results": [{
                "check_id": "rules.js-eval-call",
                "path": "tmp/bundle-0.js",
                "start": {"line": 42},
                "extra": {"severity": "WARNING",
                          "message": "Direct eval()",
                          "lines": "eval(x)"},
            }],
            "errors": [],
        }
        return {"stdout": _json.dumps(payload), "stderr": "",
                "exit_code": 0, "error": None}

    monkeypatch.setattr(external, "run_command", fake_run)
    monkeypatch.setattr(external, "tool_available", lambda name: True)

    result = asyncio.run(external.semgrep_scan(
        {"https://h.test/app.js": "var x = 1; eval(x); " * 10}))

    assert result["available"] is True
    assert result["scanned"] == 1
    assert result["results"] == [{
        "rule": "js-eval-call",
        "severity": "WARNING",
        "message": "Direct eval()",
        "source": "https://h.test/app.js",
        "line": 42,
        "snippet": "eval(x)",
    }]


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



# ── Docker tool backend ──────────────────────────────────────────

def test_backend_defaults_to_local(monkeypatch):
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    assert external.configure_tool_backend({}) == "local"
    assert external.configure_tool_backend(None) == "local"


def test_backend_reads_config_and_env(monkeypatch):
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    assert external.configure_tool_backend(
        {"tools": {"backend": "docker", "image": "custom:1"}}) == "docker"
    assert external._BACKEND["image"] == "custom:1"
    monkeypatch.setenv("OSINT_TOOLS_BACKEND", "local")
    assert external.configure_tool_backend(
        {"tools": {"backend": "docker"}}) == "local"
    monkeypatch.setenv("OSINT_TOOLS_BACKEND", "docker")
    monkeypatch.setenv("OSINT_TOOLS_IMAGE", "img:2")
    assert external.configure_tool_backend({}) == "docker"
    assert external._BACKEND["image"] == "img:2"
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    external.configure_tool_backend({})


def test_docker_run_args_rewrites_repo_paths(monkeypatch):
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    import os
    external.configure_tool_backend(
        {"tools": {"backend": "docker", "image": "img:t"}})
    cwd = os.getcwd()
    args = external.docker_run_args(
        ["ffuf", "-u", "https://t/FUZZ", "-o", f"{cwd}/reports/x.json",
         "-w", "/usr/share/seclists/rockyou.txt"], stdin=False)
    assert args[:3] == ["docker", "run", "--rm"]
    assert "-i" not in args
    assert f"{cwd}:/work" in args
    assert f"/work/reports/x.json" in args
    # Outside the repo: passed through untouched.
    assert "/usr/share/seclists/rockyou.txt" in args
    assert "https://t/FUZZ" in args
    args_in = external.docker_run_args(["nuclei", "-l", "t.txt"], stdin=True)
    assert "-i" in args_in
    external.configure_tool_backend({})


def test_run_command_routes_through_docker(monkeypatch):
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    external.configure_tool_backend(
        {"tools": {"backend": "docker", "image": "img:t"}})
    monkeypatch.setattr(external, "_docker_ready", lambda: True)
    seen = {}

    async def fake_exec(*args, **kwargs):
        seen["args"] = args
        class P:
            returncode = 0
            async def communicate(self, input=None):
                return (b"out", b"")
        return P()

    monkeypatch.setattr(external.asyncio, "create_subprocess_exec", fake_exec)
    result = asyncio.run(external.run_command(["nuclei", "-version"]))
    assert seen["args"][0] == "docker"
    assert "img:t" in seen["args"]
    assert result["stdout"] == "out"
    external.configure_tool_backend({})


def test_run_command_stays_local_for_unknown_binaries(monkeypatch):
    external.configure_tool_backend(
        {"tools": {"backend": "docker", "image": "img:t"}})
    monkeypatch.setattr(external, "_docker_ready", lambda: True)
    seen = {}

    async def fake_exec(*args, **kwargs):
        seen["args"] = args
        class P:
            returncode = 0
            async def communicate(self, input=None):
                return (b"out", b"")
        return P()

    monkeypatch.setattr(external.asyncio, "create_subprocess_exec", fake_exec)
    asyncio.run(external.run_command(["definitely-not-a-tool-zzz", "x"]))
    assert seen["args"][0] == "definitely-not-a-tool-zzz"
    external.configure_tool_backend({})


def test_tool_available_uses_image_presence_in_docker_mode(monkeypatch):
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    external.configure_tool_backend(
        {"tools": {"backend": "docker", "image": "img:t"}})
    monkeypatch.setattr(external, "_docker_ready", lambda: True)
    assert external.tool_available("nuclei") is True
    monkeypatch.setattr(external, "_docker_ready", lambda: False)
    assert external.tool_available("nuclei") is False
    # Non-baked binaries still resolve locally.
    assert external.tool_available("definitely-not-a-tool-zzz") is False
    external.configure_tool_backend({})


def test_docker_wrap_shell_passthrough_and_wrap(monkeypatch):
    monkeypatch.delenv("OSINT_TOOLS_BACKEND", raising=False)
    monkeypatch.delenv("OSINT_TOOLS_IMAGE", raising=False)
    external.configure_tool_backend({})
    assert external.docker_wrap_shell("echo hello") == "echo hello"
    external.configure_tool_backend(
        {"tools": {"backend": "docker", "image": "img:t"}})
    monkeypatch.setattr(external, "_docker_ready", lambda: True)
    wrapped = external.docker_wrap_shell(
        "echo 'a' | httpx -silent -json 2>/dev/null")
    assert wrapped.startswith("printf %s ")
    assert "docker run --rm -i" in wrapped
    assert "img:t sh" in wrapped
    # Round-trips byte-identically through base64.
    import base64
    payload = wrapped.split("printf %s ", 1)[1].split(" | base64", 1)[0]
    assert base64.b64decode(payload).decode() == \
        "echo 'a' | httpx -silent -json 2>/dev/null"
    # Non-tool commands pass through even in docker mode.
    assert external.docker_wrap_shell("whoami") == "whoami"
    external.configure_tool_backend({})


# ── Tier-1 hunt tools: jsluice + graphql-cop ─────────────────────

def test_new_tools_in_docker_contract():
    assert {"jsluice", "gxss", "uro", "gitleaks", "graphql-cop"} <= set(
        external.DOCKER_TOOLS)


def test_jsluice_extracts_urls_from_bundle(monkeypatch):
    async def fake_run(args, timeout=None, stdin_data=""):
        assert args[:2] == ["jsluice", "urls"]
        return {"stdout": '{"url":"https://t/api/users"}\n/api/auth/login\n',
                "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setattr(external, "run_command", fake_run)
    found = asyncio.run(external.jsluice_urls("var x=fetch('/api/a');"))
    assert found == ["https://t/api/users", "/api/auth/login"]


def test_jsluice_missing_binary_returns_empty(monkeypatch):
    monkeypatch.setattr(external, "tool_available", lambda name: False)
    assert asyncio.run(external.jsluice_urls("x")) == []


def test_graphql_cop_parses_json(monkeypatch):
    async def fake_run(args, timeout=None, stdin_data=""):
        assert args == ["graphql-cop", "-t", "https://t/graphql",
                        "-o", "json"]
        return {"stdout": '{"introspection": true}',
                "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setattr(external, "run_command", fake_run)
    result = asyncio.run(
        external.graphql_cop_scan("https://t/graphql"))
    assert result["available"] is True
    assert result["results"] == {"introspection": True}


def test_graphql_cop_missing_binary_skips(monkeypatch):
    monkeypatch.setattr(external, "tool_available", lambda name: False)
    result = asyncio.run(external.graphql_cop_scan("https://t/graphql"))
    assert result == {"available": False, "results": {},
                      "error": "missing"}


# ── Public interactsh sessions (Option A) ────────────────────────

def test_parse_interactsh_session_line():
    parse = external._parse_interactsh_session_line
    assert parse('{"url":"https://c1234.interactsh.com"}') == \
        "c1234.interactsh.com"
    assert parse('Your domain: https://abc.oast.live/ here') == \
        "abc.oast.live"
    # Bare INF line against the session's own server domains.
    assert parse('[INF] db37mgc7c1618oadidqgprgsosbn3b7gz.oast.pro',
                 ("oast.pro", "oast.live")) == \
        "db37mgc7c1618oadidqgprgsosbn3b7gz.oast.pro"
    # Banner hostnames from other domains never match.
    assert parse('projectdiscovery.io', ("oast.pro",)) == ""
    assert parse('c1234.evil.example listening', ("oast.pro",)) == ""
    assert parse('') == ""
    assert parse('listening for interactions...') == ""


def test_poll_interactsh_log_reads_incrementally(tmp_path):
    log = tmp_path / "sess.jsonl"
    log.write_text(
        '{"full-id":"aaa.oast/x","raw-request":"GET /x"}\n'
        'noise line\n'
        '{"full-id":"aaa.oast/y","raw-request":"GET /y"}\n')
    hits, offset = external._poll_interactsh_log(str(log), 0)
    assert len(hits) == 2
    assert offset > 0
    hits2, _ = external._poll_interactsh_log(str(log), offset)
    assert hits2 == []
    assert external._poll_interactsh_log("/nonexistent.jsonl", 0) == ([], 0)


def test_public_client_callback_url_shapes():
    client = external.PublicInteractshClient()
    assert client.callback_url("abc.oast.com", "/xss") == \
        "https://abc.oast.com/xss"
    assert client.callback_url("", "/x") == \
        "http://unregistered.oob.invalid/x"
    assert client.callback_url("http://h/o", "p") == "http://h/o/p"


def test_interactsh_session_reuses_live_process(monkeypatch):
    class FakeProc:
        returncode = None
    external._PUBLIC_SESSION["https://s.test"] = {
        "proc": FakeProc(), "url": "abc.s.test", "log": "/tmp/x",
        "offset": 3}
    try:
        out = asyncio.run(external.interactsh_session("https://s.test"))
        assert out["available"] is True
        assert out["url"] == "abc.s.test"
        assert out["reused"] is True
    finally:
        external._PUBLIC_SESSION.pop("https://s.test", None)


def test_interactsh_session_missing_binary(monkeypatch):
    monkeypatch.setattr(external, "tool_available", lambda name: False)
    out = asyncio.run(external.interactsh_session("https://s.test"))
    assert out == {"available": False, "error": "missing"}


def test_oob_public_mode_returns_public_client():
    from modules.base import BaseModule
    from state.manager import StateManager
    import tempfile
    state = StateManager(tempfile.mkdtemp())
    module = BaseModule(
        state, {"target": {"domain": "example.test"},
                "oob": {"mode": "public"}})
    client = module.oob()
    assert isinstance(client, external.PublicInteractshClient)


def test_oob_unconfigured_returns_none():
    from modules.base import BaseModule
    from state.manager import StateManager
    import tempfile
    state = StateManager(tempfile.mkdtemp())
    module = BaseModule(state, {"target": {"domain": "example.test"}})
    assert module.oob() is None


def test_nuclei_templates_info_parses_probe(monkeypatch):
    import time as _time
    import tools.wrappers as wrappers

    mtime = int(_time.time()) - 10 * 86400

    async def fake_bash(command, timeout=120):
        assert "NUCLEI_TEMPLATES_DIR" in command
        return {"stdout": f"{mtime}|/root/nuclei-templates|14036\n",
                "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(wrappers, "bash", fake_bash)
    monkeypatch.setattr(external, "tool_available", lambda name: True)
    # Force local execution: a docker _BACKEND left over from an earlier
    # test would route past the fake into a real container run.
    monkeypatch.setitem(external._BACKEND, "mode", "local")

    out = asyncio.run(external.nuclei_templates_info())

    assert out["available"] is True
    assert out["dir"] == "/root/nuclei-templates"
    assert out["templates"] == 14036
    assert 9.0 <= out["age_days"] <= 11.0


def test_nuclei_templates_info_no_dir(monkeypatch):
    import tools.wrappers as wrappers

    async def fake_bash(command, timeout=120):
        return {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

    monkeypatch.setattr(wrappers, "bash", fake_bash)
    monkeypatch.setattr(external, "tool_available", lambda name: True)
    monkeypatch.setitem(external._BACKEND, "mode", "local")

    out = asyncio.run(external.nuclei_templates_info())

    assert out["available"] is True
    assert out["age_days"] is None
    assert "no template directory" in out["error"]


def test_nuclei_templates_info_missing_binary(monkeypatch):
    monkeypatch.setattr(external, "tool_available", lambda name: False)

    out = asyncio.run(external.nuclei_templates_info())

    assert out == {"available": False, "dir": "", "age_days": None,
                   "templates": 0}


def test_nuclei_update_templates_runs_explicitly(monkeypatch):
    calls = {}

    async def fake_run(args, timeout=120, stdin_data=""):
        calls["args"] = args
        return {"stdout": "updated", "stderr": "", "exit_code": 0,
                "error": None}

    monkeypatch.setattr(external, "run_command", fake_run)
    monkeypatch.setattr(external, "tool_available", lambda name: True)

    out = asyncio.run(external.nuclei_update_templates(timeout=60))

    assert calls["args"][:2] == ["nuclei", "-update-templates"]
    assert "-silent" in calls["args"]
    assert out["exit_code"] == 0


def test_nuclei_stale_templates_warn_but_scan(monkeypatch):
    """Stale templates warn; they never become a finding — old sets
    miss things, they do not invent them."""
    import tempfile
    import modules.nuclei_scan as nuclei_module
    from modules.nuclei_scan import NucleiScan
    from state.manager import StateManager

    async def stale():
        return {"available": True, "dir": "/t", "age_days": 90.0,
                "templates": 100}

    async def fail_update(timeout=600):
        raise AssertionError("refresh must be opt-in")

    monkeypatch.setattr(nuclei_module, "nuclei_templates_info", stale)
    monkeypatch.setattr(nuclei_module, "nuclei_update_templates", fail_update)
    logged = []
    state = StateManager(tempfile.mkdtemp())
    module = NucleiScan(state, {"target": {"domain": "example.com"},
                                "nuclei": {}})
    module.log = logged.append

    out = asyncio.run(module._template_freshness({}))

    assert out["age_days"] == 90.0
    assert any("stale" in line for line in logged)


def test_nuclei_refresh_opt_in_updates_first(monkeypatch):
    import tempfile
    import modules.nuclei_scan as nuclei_module
    from modules.nuclei_scan import NucleiScan
    from state.manager import StateManager

    calls = []

    async def old():
        calls.append("info")
        if len(calls) == 1:
            return {"available": True, "dir": "/t", "age_days": 90.0,
                    "templates": 100}
        return {"available": True, "dir": "/t", "age_days": 0.0,
                "templates": 200}

    async def update(timeout=600):
        calls.append("update")
        return {"available": True, "exit_code": 0, "error": None,
                "tail": ""}

    monkeypatch.setattr(nuclei_module, "nuclei_templates_info", old)
    monkeypatch.setattr(nuclei_module, "nuclei_update_templates", update)
    state = StateManager(tempfile.mkdtemp())
    module = NucleiScan(state, {"target": {"domain": "example.com"},
                                "nuclei": {"update_templates": True}})

    out = asyncio.run(module._template_freshness(
        {"update_templates": True}))

    assert calls == ["info", "update", "info"]
    assert out["refreshed"] is True
    assert out["age_days"] == 0.0
