"""Does a catch-all site actually stay silent?

`tests/test_response_fingerprint.py` proves the shared primitive works and
`tests/test_no_blind_trust.py` proves modules call it. Neither proves a module
still reports nothing when the target answers 200 to everything — a module can
keep the call, keep the import, and pass both suites while returning a
critical finding on every path, because the shape is right and the behaviour is
wrong.

So these tests run the real modules against a fake server that behaves like the
one that produced the original findings: one page, served with 200, for every
path. The expectation is silence. Then the same module is pointed at a server
that genuinely serves `/.env`, and the expectation is a critical finding —
because a gate that suppresses everything is not a fix, it is a mute button.
"""

import asyncio
import tempfile
from pathlib import Path

from modules.misconfig import MisconfigProbes
from modules.rest_api import RestAPIAudit
from state.manager import StateManager

# What a modern SPA returns: long enough to pass every length heuristic anyone
# has ever written, and identical for every path.
SPA_SHELL = (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>App</title><base href=\"/\"></head><body><app-root></app-root>"
    + "<script src=\"runtime.js\" defer></script>" * 40
    + "</body></html>"
)

REAL_ENV = (
    "APP_KEY=base64:s3cr3t\n"
    "DB_PASSWORD=hunter2\n"
    "JWT_SECRET=aVeryLongSecretValueThatIsDefinitelyNotASample\n"
    "STRIPE_KEY=sk_live_51H8xQ2eZvKYlo2C\n"
)


def _misconfig_config():
    return {
        "target": {"domain": "example.com"},
        "misconfig": {
            "concurrency": 4, "timeout": 1, "max_paths": 40,
            "max_consecutive_empty": 40, "progress_every": 100,
        },
        "wordlists": {
            "misconfig_paths": [
                "/.env", "/.env.production", "/.env.backup", "/.git/config",
                "/.git/HEAD", "/.ssh/id_rsa", "/wp-config.php",
                "/wp-config.php.bak", "/actuator/env", "/actuator/heapdump",
                "/phpinfo.php", "/api-docs", "/swagger.json", "/graphql",
                "/backup.sql", "/dump.sql", "/phpmyadmin/", "/adminer.php",
            ],
        },
    }


def _run_misconfig(monkeypatch, handler):
    import modules.misconfig as misconfig_module
    from core.site_profile import clear_profiles

    clear_profiles()  # profiles are cached per origin across tests
    monkeypatch.setattr(misconfig_module, "curl_with_status", handler)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    asyncio.run(MisconfigProbes(state, _misconfig_config()).run())
    return state.findings["findings"]



def test_a_catch_all_site_produces_no_misconfig_findings(monkeypatch):
    """The exact shape that produced seven criticals and four highs."""
    findings = _run_misconfig(monkeypatch, _catch_all_handler)
    assert findings == [], (
        f"a server returning one 200 page for every path produced "
        f"{len(findings)} finding(s): "
        f"{[f['title'] for f in findings]}"
    )


def test_a_real_exposed_env_is_still_reported(monkeypatch):
    """The gate must not be a mute button."""
    findings = _run_misconfig(monkeypatch, _env_server_handler)
    titles = [f["title"] for f in findings]
    assert "Exposed Environment File" in titles, (
        f"a genuinely served .env was not reported; got {titles}"
    )
    env = [f for f in findings if f["title"] == "Exposed Environment File"][0]
    assert env["severity"] == "CRITICAL"


def test_a_catch_all_server_does_not_manufacture_critical_findings(monkeypatch):
    """Every finding from a catch-all site would be a false positive.

    Worth stating as its own test because it is the property that matters: the
    number is not "we report fewer", it is "nothing on a silent server".
    """
    findings = _run_misconfig(monkeypatch, _catch_all_handler)
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    assert critical == []


def test_a_git_config_with_core_section_is_reported(monkeypatch):
    """Content gating must be specific enough to let real things through."""
    findings = _run_misconfig(monkeypatch, _git_server_handler)
    titles = [f["title"] for f in findings]
    assert any("Git" in t for t in titles), f"real .git/config missed; got {titles}"


# ── handlers ──────────────────────────────────────────────────────────────

async def _catch_all_handler(url, **kwargs):
    """Every path returns 200 with the same body. The original failure mode."""
    return {"status": 200, "body": SPA_SHELL, "content_type": "text/html"}


async def _env_server_handler(url, **kwargs):
    """Serves the SPA everywhere except `/.env`, which is a real `.env`."""
    if url.endswith("/.env"):
        return {"status": 200, "body": REAL_ENV,
                "content_type": "text/plain"}
    return {"status": 200, "body": SPA_SHELL, "content_type": "text/html"}


async def _git_server_handler(url, **kwargs):
    if url.endswith("/.git/config"):
        return {"status": 200, "body": "[core]\n\trepositoryformatversion = 0\n",
                "content_type": "text/plain"}
    return {"status": 200, "body": SPA_SHELL, "content_type": "text/html"}


# ── rest_api ───────────────────────────────────────────────────────────────

def _run_rest_api(monkeypatch, handler, wp_root=None):
    import modules.rest_api as rest_module
    from core.site_profile import clear_profiles

    clear_profiles()
    monkeypatch.setattr(rest_module, "curl_with_status", handler)

    async def json_handler(url, **kwargs):
        return wp_root

    # Must be mocked: unmocked it reaches the real network, fails, and the
    # module exits before the code under test is ever reached — which is how
    # this test passed while the gate was doing nothing.
    monkeypatch.setattr(rest_module, "curl_json", json_handler)
    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    asyncio.run(RestAPIAudit(state, {"target": {"domain": "example.com"}}).run())
    return state


def _confirmed_api_endpoints(state):
    return [n for n in state.assets["nodes"]
            if n.get("type") == "api_endpoint"
            and n.get("confidence") == "CONFIRMED"]


def _generic_api_endpoints(state):
    """Assets whose confidence came from a status code rather than content.

    `/wp-json/` is excluded on purpose: it is CONFIRMED because the response
    parsed as a WordPress root with namespaces in it, which is evidence. The
    generic probes are the ones that used to read FIRM off a bare 200.
    """
    return [n for n in state.assets["nodes"]
            if n.get("type") == "api_endpoint"
            and n.get("attrs", {}).get("type") == "rest"]


def test_rest_api_does_not_confirm_endpoints_on_a_catch_all_site(monkeypatch):
    """A catch-all origin must not yield CONFIRMED api_endpoint assets.

    These assets feed the attack graph, so a confirmed endpoint that does not
    exist becomes a chain target later — the false positive propagates into
    the exploitation stage, which is worse than a noisy report.
    """
    async def handler(url, **kwargs):
        return {"status": 200, "body": SPA_SHELL, "content_type": "text/html"}

    state = _run_rest_api(monkeypatch, handler)
    confirmed = _confirmed_api_endpoints(state)
    assert confirmed == [], (
        f"{len(confirmed)} api_endpoint assets confirmed against a site that "
        f"answers 200 to everything: {[n['key'] for n in confirmed][:5]}"
    )


def test_catch_all_api_probes_are_downgraded_to_tentative(monkeypatch):
    """The specific regression: `FIRM if status == 200`.

    Every generic probe gets the same 200 and the same body, so every one of
    them must land on TENTATIVE. This asserts TENTATIVE specifically rather
    than "not CONFIRMED", because the grades this code path uses are FIRM and
    TENTATIVE — checking for the absence of CONFIRMED would pass whether or
    not the gate worked.
    """
    async def handler(url, **kwargs):
        return {"status": 200, "body": SPA_SHELL, "content_type": "text/html"}

    state = _run_rest_api(monkeypatch, handler)
    probes = _generic_api_endpoints(state)
    assert probes, (
        "no generic api_endpoint assets were created, so this test is vacuous "
        "— the module exited before reaching the graded code path"
    )
    wrong = [n["key"] for n in probes if n["confidence"] != "TENTATIVE"]
    assert wrong == [], (
        f"probes on a catch-all origin graded higher than TENTATIVE: {wrong[:5]}"
    )


def test_the_rest_api_test_actually_reaches_the_code_under_test(monkeypatch):
    """Guard against the vacuous case: a test that passes because nothing ran.

    This one caught a real problem — `curl_json` was unmocked, so the module
    made a real network call, exited early, and the CONFIRMED assertions above
    passed against code that never executed.
    """
    async def handler(url, **kwargs):
        return {"status": 200, "body": SPA_SHELL, "content_type": "text/html"}

    state = _run_rest_api(monkeypatch, handler,
                          wp_root={"namespaces": ["wp/v2"], "routes": {}})
    any_endpoint = [n for n in state.assets["nodes"]
                    if n.get("type") == "api_endpoint"]
    assert any_endpoint, (
        "no api_endpoint assets were created at all, so the CONFIRMED "
        "assertions in this module are vacuous — the module exited early"
    )
