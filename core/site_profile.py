"""One place that decides whether an HTTP response is an exposure.

Every path-probing module in this tool needs the same judgement: I requested
`/.env`, I got a 200, is that a critical finding or does this server just serve
the same page for everything? Ten modules answered that question independently
and ten of them got it wrong, which is how a modern Angular SPA on Express
produced seven CRITICAL findings for `.git`, `.env`, `wp-config.php` and
Spring Boot Actuator — all of them the same 9393-byte `index.html` that `/`
returns.

The pattern that keeps failing: a status code is treated as proof of
existence. It is not. `200` means the server chose to answer, and a server
that answers everything answers `200` for everything.

So this module is the only place allowed to make that call. It owns:

  * the `SiteProfile` — what this origin serves when nothing matches,
    established once per origin from `/` plus control paths, and cached,
  * the path rules and their severity,
  * the content assertions — what the named artifact must actually contain.

A module that wants to report a path exposure calls `grade_path_exposure` and
files whatever it is handed. It cannot forget the differential check, because
there is nowhere else to get the answer. `tests/test_no_blind_trust.py` fails
the build if a module reintroduces the old shortcut.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from core.response_fingerprint import (
    Baseline,
    content_matches,
    establish_baseline,
    fingerprint,
)

# Path -> (severity when genuinely exposed, title). The severity is a ceiling,
# not a promise: it only ever applies once the differential and the content
# check have both passed.
PATH_RULES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"/\.env"), "CRITICAL", "Exposed Environment File"),
    (re.compile(r"/\.git/(config|HEAD|refs)"), "CRITICAL", "Exposed Git Metadata"),
    (re.compile(r"/\.svn/(entries|wc.db)"), "CRITICAL", "Exposed SVN Metadata"),
    (re.compile(r"/\.DS_Store"), "LOW", "Exposed Directory Listing Metadata"),
    (re.compile(r"/\.aws/credentials"), "CRITICAL", "Exposed AWS Credentials File"),
    (re.compile(r"/\.ssh/id_(rsa|dsa|ecdsa)"), "CRITICAL", "Exposed Private Key"),
    (re.compile(r"wp-config"), "CRITICAL", "Exposed WordPress Configuration"),
    (re.compile(r"debug\.log|error_log|server-status"), "HIGH",
     "Sensitive Diagnostic Endpoint Exposed"),
    (re.compile(r"phpinfo|info\.php"), "MEDIUM", "phpinfo Page Exposed"),
    (re.compile(r"actuator/(env|heapdump|configprops|threaddump)"), "CRITICAL",
     "Sensitive Spring Boot Actuator Exposed"),
    (re.compile(r"swagger|api-docs|openapi\.json"), "MEDIUM",
     "API Documentation Exposed"),
    (re.compile(r"graphql|graphiql"), "MEDIUM", "GraphQL Endpoint Accessible"),
    (re.compile(r"phpmyadmin|adminer"), "HIGH", "Database Admin Interface Exposed"),
    (re.compile(r"backup\.sql|\.sql\.gz|dump\.sql"), "CRITICAL",
     "Database Backup Exposed"),
    (re.compile(r"\.zip$|\.tar\.gz$|\.tgz$"), "MEDIUM", "Archive File Exposed"),
    (re.compile(r"id_rsa|\.pem$|\.key$|\.p12$|\.pfx$"), "HIGH",
     "Exposed Key Material"),
    (re.compile(r"/(?:config|configuration)\.(json|ya?ml|ini|xml)$"), "MEDIUM",
     "Exposed Configuration File"),
    (re.compile(r"adminer|/admin\.php|/admin/console"), "MEDIUM",
     "Admin Console Exposed"),
    (re.compile(r"/metrics$|/metrics/"), "MEDIUM",
     "Exposed Prometheus Metrics"),
    (re.compile(r"/\.well-known/security\.txt$"), "LOW",
     "Security Policy Exposed"),
    (re.compile(r"\.md\.bak$|\.bak$|\.backup$|\.old$"), "HIGH",
     "Backup File Exposed"),
    (re.compile(r"/\.terraform/|\.tfstate$|docker-compose\.ya?ml$"), "HIGH",
     "IaC State Exposed"),
    (re.compile(r"^/ftp/"), "LOW",
     "Exposed File Drop"),
]

# Verdicts, in the order a module should care about them.
VERDICT_EXPOSED = "exposed"
VERDICT_CATCH_ALL = "catch_all"      # identical to the site's own answer
VERDICT_NO_CONTENT = "no_content"    # novel response, wrong content for the path
VERDICT_DENIED = "denied"            # exists, not readable
VERDICT_UNINTERESTING = "uninteresting"


@dataclass
class SiteProfile:
    """What one origin serves, plus a cache so it is established once."""
    origin: str
    baseline: Baseline
    probes: int = 0
    exposures: int = 0
    catch_all_hits: int = 0
    _extra: dict = field(default_factory=dict)

    def record(self, verdict: str) -> None:
        self.probes += 1
        if verdict == VERDICT_EXPOSED:
            self.exposures += 1
        elif verdict == VERDICT_CATCH_ALL:
            self.catch_all_hits += 1

    def coverage(self) -> dict:
        """What fraction of probed paths could actually be judged.

        A scan that probed 20 paths and could distinguish none of them has not
        tested anything, and should not be able to say otherwise.
        """
        judged = self.probes - self.catch_all_hits
        return {
            "origin": self.origin,
            "probed": self.probes,
            "judged": judged,
            "judgable_pct": round(100.0 * judged / self.probes, 1) if self.probes else 0.0,
            "exposures": self.exposures,
            "catch_all": self.catch_all_hits,
        }

    def as_asset_attrs(self) -> dict:
        return self.coverage()


_PROFILES: dict[str, SiteProfile] = {}


def clear_profiles() -> None:
    """Drop cached profiles. Tests and long engagements both need this."""
    _PROFILES.clear()


async def get_profile(origin: str,
                      fetch: Callable,
                      control_paths: Optional[Iterable[str]] = None) -> SiteProfile:
    """Establish (or reuse) the profile for one origin.

    `fetch` is the caller's own HTTP coroutine, `async (path) -> (status, body,
    content_type)`. Reusing the caller's client means the profile cannot drift
    out of sync with how the module actually requests pages.
    """
    key = origin.rstrip("/")
    existing = _PROFILES.get(key)
    if existing is not None:
        return existing
    baseline = await establish_baseline(fetch, key, control_paths)
    profile = SiteProfile(origin=key, baseline=baseline)
    _PROFILES[key] = profile
    return profile


def grade_path_exposure(path: str, status: int, body: str, content_type: str,
                        profile: Optional[SiteProfile],
                        rules: Optional[list] = None) -> tuple[str, Optional[dict]]:
    """The single decision point for "is this path an exposure?".

    Returns (verdict, finding) where finding is None unless the verdict is
    `exposed` or `denied`. A module files what it gets; it does not get to
    decide for itself.

    Two independent gates stand between a 200 and a finding, and both must pass:

      1. The response must be distinguishable from the site's catch-all.
         Without this, any server that answers 200 to everything manufactures
         one critical finding per rule.
      2. The body must contain what the named artifact would contain. A path
         is a guess about content; the content is the evidence.
    """
    rules = rules if rules is not None else PATH_RULES
    body = str(body or "")

    matched = next(((p, sev, title) for p, sev, title in rules if p.search(path)),
                   None)
    if matched is None:
        return VERDICT_UNINTERESTING, None
    pattern, severity, title = matched
    rule_key = pattern.pattern

    if status in (401, 403):
        # The resource exists and is protected. That is a real observation and a
        # weak one: nothing is disclosed, so it must never inherit the severity
        # of the rule it matched.
        return VERDICT_DENIED, {
            "title": f"{title} (access denied)",
            "severity": "INFO",
            "confidence": "FIRM",
            "category": "Information Disclosure",
            "description": (
                f"{path} returns HTTP {status}, so the resource appears to exist "
                "but is not publicly readable. Nothing is disclosed."
            ),
            "evidence": [f"Path: {path}", f"Status: {status}"],
            "remediation": (
                "No action required unless the resource should not exist at all."
            ),
        }

    if status not in (200, 206):
        return VERDICT_UNINTERESTING, None

    if status == 200 and len(body.strip()) < 20:
        return VERDICT_UNINTERESTING, None

    sig = fingerprint(status, body, content_type)
    if profile is not None and profile.baseline.catch_all(sig):
        return VERDICT_CATCH_ALL, None

    if not content_matches(rule_key, body, content_type):
        return VERDICT_NO_CONTENT, None

    return VERDICT_EXPOSED, {
        "title": title,
        "severity": severity,
        "confidence": "CONFIRMED",
        "category": "Information Disclosure",
        "description": (
            f"{path} is publicly readable and its contents match the expected "
            f"form of {title.lower()}. The response is distinguishable from the "
            "site's own default page, so this is a real resource and not a "
            "catch-all handler."
        ),
        "evidence": [
            f"Path: {path}",
            f"Status: {status}",
            f"Content matched expected {title.lower()}",
            f"Content-Type: {content_type or '<absent>'}",
            f"Body length: {len(body)}",
            f"Preview: {body[:200]}",
        ],
        "remediation": (
            "Remove the exposed resource, or require authentication and restrict "
            "it at the network edge."
        ),
    }
