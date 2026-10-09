"""Config doctor — warn when the loaded config predates known features.

Every key the engine reads has a code default (`.get(..., default)`), so a
stale config never crashes: it silently runs Tier-2 tools on defaults the
operator cannot see or tune. `doctor()` lists what the file does not say,
with the default that applies and one line on why it matters. `--check-config`
prints the full coverage; normal runs print only the warnings.
"""

from __future__ import annotations


# dotted path -> (default, why it matters). Keep this to operator-facing
# switches, not every wordlist: the point is surfacing invisible behavior.
KNOWN_KEYS: tuple[tuple[str, object, str], ...] = (
    ("tools.backend", "local",
     "local uses host binaries, docker runs the toolchain image instead"),
    ("tools.image", "osint-tools:latest",
     "image the docker backend executes tool binaries in"),
    ("semgrep.enabled", True,
     "SAST over downloaded JS bundles (repo-local rules, offline)"),
    ("semgrep.rules", "rules/semgrep",
     "rule directory semgrep scans with"),
    ("modules.content_discovery.kiterunner.enabled", True,
     "API-route brute force over assetnote wordlists"),
    ("modules.content_discovery.kiterunner.wordlist", "apiroutes-260227",
     "remote list name (`kr wordlist list` shows current names)"),
    ("modules.content_discovery.kiterunner.max_routes", 1500,
     "routes tried per target (cap 20000)"),
    ("modules.content_discovery.kiterunner.max_targets", 2,
     "base URL plus api_endpoint origins (cap 10)"),
    ("modules.content_discovery.kiterunner.delay_ms", 100,
     "delay between requests to one host (1000+ for live scopes)"),
    ("modules.content_discovery.kiterunner.connections", 3,
     "parallel connections per host (1 for live scopes)"),
    ("xss.dalfox_blind_oob", False,
     "dalfox runs its own interactsh session (findings stay FIRM)"),
    ("xss.dalfox_rate_limit", 0,
     "global outbound cap for dalfox in requests/second (0 = unlimited)"),
    ("modules.sqli_scan.oast", True,
     "hands sqlmap an interactsh server so blind injections get proof"),
    ("modules.ssrf_scan.enabled", True,
     "generic SSRF: OOB-graded probes of URL-bearing parameters"),
    ("modules.ssrf_scan.max_points", 6,
     "URL parameters probed per run (cap 30)"),
    ("crawl.browser.enabled", True,
     "rendered crawling, one context per verified identity"),
    ("crawl.browser.depth", 1,
     "same-origin link-following depth (cap 3)"),
    ("crawl.browser.max_identities", 2,
     "verified identities rendered per run (cap 5)"),
    ("modules.business_logic.enabled", True,
     "own-account logic flaws: surface recon plus cart tamper probes"),
    ("modules.business_logic.max_probes", 12,
     "hostile values sent per run (cap 40)"),
    ("nuclei.max_age_days", 30,
     "warn past this template age; stale sets miss CVEs"),
    ("nuclei.update_templates", False,
     "refresh templates before scanning (downloads, opt-in)"),
    ("oob.mode", "",
     "empty stays dormant, public uses the free interactsh mesh, "
     "wrapper uses a self-hosted shim"),
    ("oob.enabled", True,
     "off disables OOB everywhere without deleting the settings"),
)


def _lookup(config: dict, dotted: str) -> tuple[bool, object]:
    """(present, value) for a dotted path; non-dict hops mean absent."""
    node: object = config if isinstance(config, dict) else {}
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def doctor(config: dict) -> list[str]:
    """Human-readable warnings for known keys missing from the config."""
    warnings = []
    for dotted, default, why in KNOWN_KEYS:
        present, _ = _lookup(config or {}, dotted)
        if not present:
            warnings.append(f"{dotted} (default {default!r}): {why}")
    return warnings


def coverage(config: dict) -> list[tuple[str, bool, object, str]]:
    """(dotted, present, effective value, why) for every known key."""
    rows = []
    for dotted, default, why in KNOWN_KEYS:
        present, value = _lookup(config or {}, dotted)
        rows.append((dotted, present, value if present else default, why))
    return rows
