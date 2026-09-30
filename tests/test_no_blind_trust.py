"""Fails the build if any module re-learns that a 200 is proof.

This is the structural half of the fix. `core/site_profile.py` makes the
correct judgement available in one place, but availability is not enforcement:
ten modules already had a working fix sitting in `content_discovery` and none
of them used it. So this test reads the module sources and fails when it finds
the old shortcut, which is the failure mode that actually occurred.

What it looks for: a module that inspects a response status and files a
severity-bearing finding without routing through `grade_path_exposure` or
`SiteProfile`. That is a code-shape check rather than a behavioural one, which
is normally a smell — but the behaviour is already covered by
`test_response_fingerprint.py`, and this test covers the thing behavioural
tests cannot see: a module that does not ask the question at all.

Modules that legitimately never judge a raw status are allowlisted below, with
the reason, so the exception is visible rather than accumulating silently.
"""

import ast
import re
from pathlib import Path

import pytest

MODULES_DIR = Path(__file__).resolve().parents[1] / "modules"

# status literals that mean "the server answered"
STATUS_TOKENS = {"200", "206", "401", "403"}

# Modules allowed to branch on a raw status, with the reason. Every entry here
# is a debt, not an approval.
ALLOWLIST = {
    "cors_audit.py": "grades ACAO/ACAC headers, not bare status",
    "idor_differ.py": "requires a 200 and a body difference; the oracle decides",
    "http_smuggling.py": "needs two raw responses compared to each other",
    "base.py": "framework plumbing, not a detector",
    "visual_recon.py": "screenshot comparison, not HTTP status",
    "social_media.py": "probes third-party APIs, not the target site",
    "waf_module.py": "presence/absence of a WAF header is the whole signal",
    "tech_detect.py": "fingerprints headers, not path exposure",
    "login_enum.py": "compares response bodies across credentials, not status",
    "content_discovery.py": "predates the shared primitive; already has its own "
                            "dominant-group rejection",
    "deep_crawl.py": "same as content_discovery",
    "tls_audit.py": "TLS handshake, not HTTP status",
    "cms_deep_scan.py": "uses dropescan fingerprints, not raw status",
    "nuclei_scan.py": "delegates to nuclei, which does its own verification",
    "port_scan_module.py": "TCP connect, not HTTP",
    # The oracle is not the status — it is a before/after comparison, so a 200
    # is a precondition rather than the evidence. Gating these on a catch-all
    # check would be wrong: a SPA shell is a perfectly good baseline for
    # "did this field get written".
    "mass_assignment.py": "oracle is before/after body diff on an accepted field",
    "prototype_pollution.py": "oracle is whether pollution manifests in the response",
    # Discovery-only 200s: the status is used to decide what to fetch next, and
    # no finding is filed on its strength.
    "js_analysis.py": "200 means 'here is a JS file to analyse', not an exposure",
    "mobile_assets.py": "200 means 'here is a manifest', not an exposure",
    "graphql_module.py": "already requires an is_graphql content marker, "
                         "not a bare status",
    # Third-party hosts with their own handlers: a 200 from S3 is the bucket
    # answering, and a per-origin catch-all baseline does not apply.
    "cloud_enum.py": "probes provider-owned hosts (S3/GCS/Azure); a 200 is "
                     "the bucket responding, body is then checked for provider XML",
}

# A finding being filed is the thing that must be gated.
FILES_FINDING = re.compile(r"add_finding\s*\(")

# The shared decision point, and the primitive it is built from. Both count: a
# module may call `grade_path_exposure` directly, or establish a SiteProfile
# and compare against its baseline, which is the same gate reached a different
# way. Matching on the import alone would let an unused import satisfy this,
# so the AST is checked too.
USES_DECISION_POINT = re.compile(
    r"grade_path_exposure\s*\(|get_profile\s*\(|establish_baseline\s*\(|"
    r"baseline\.catch_all\s*\(|content_matches\s*\("
)


def _calls_decision_point(tree: ast.AST) -> bool:
    """A real call, not a mention. An import alone does not count."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("grade_path_exposure", "get_profile",
                        "establish_baseline", "catch_all", "content_matches"):
                return True
    return False


def _module_files():
    return sorted(
        p for p in MODULES_DIR.glob("*.py")
        if not p.name.startswith("__")
    )


def _branches_on_status(tree: ast.AST) -> bool:
    """Does this module compare a status against a 200-literal anywhere?"""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for side in (node.left, *node.comparators):
            if isinstance(side, ast.Constant) and str(side.value) in STATUS_TOKENS:
                return True
    return False


def _files_finding(source: str) -> bool:
    return bool(FILES_FINDING.search(source))


@pytest.mark.parametrize("path", _module_files(), ids=lambda p: p.name)
def test_module_does_not_trust_a_bare_status(path):
    if path.name in ALLOWLIST:
        pytest.skip(f"allowlisted: {ALLOWLIST[path.name]}")
    source = path.read_text()
    if not _files_finding(source):
        pytest.skip("files no findings")
    tree = ast.parse(source)
    if _calls_decision_point(tree):
        return
    assert not _branches_on_status(tree), (
        f"{path.name} compares a response status to a 200-literal and files "
        "findings without going through core.site_profile. A 200 is not proof "
        "that a path exists: a server that answers everything answers 200 to "
        "everything. Use grade_path_exposure() so the catch-all check and the "
        "content check both run, or add the module to ALLOWLIST in this file "
        "with the reason."
    )


def test_the_allowlist_is_small_and_each_entry_is_justified():
    """An allowlist that grows to cover every module proves nothing."""
    modules = {p.name for p in _module_files()}
    unknown = set(ALLOWLIST) - modules
    assert not unknown, f"allowlist names modules that do not exist: {unknown}"
    assert len(ALLOWLIST) <= len(modules) // 2, (
        f"{len(ALLOWLIST)} of {len(modules)} modules are allowlisted; the "
        "exceptions have become the rule"
    )
    for name, reason in ALLOWLIST.items():
        assert len(reason) > 20, f"{name} needs a real reason, not a stub"


def test_every_allowlisted_module_still_exists():
    """Renaming a module must not silently re-enable the check for it."""
    modules = {p.name for p in _module_files()}
    for name in ALLOWLIST:
        assert name in modules, f"allowlisted module {name} was removed or renamed"
