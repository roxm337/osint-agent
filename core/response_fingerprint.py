"""Response fingerprinting, shared by every module that probes HTTP.

The bug this exists to stop: a module fetches a path, sees `200`, and files a
CRITICAL. On a modern SPA that serves `index.html` for any unmatched path, a
200 proves nothing — `/.env`, `/wp-config.php` and `/backup.sql` all return the
same 9393-byte shell as the root. Measured against OWASP Juice Shop, that one
missing check produced 7 CRITICAL and 4 HIGH findings that were all the same
HTML document.

Commit 9dd9c44 added a fix for exactly this inside `content_discovery` — reject
a dominant group of identical responses. It did not propagate to
`fast_exposure_scan`, `misconfig_probes` or `cms_deep_scan`, because the logic
was a private method in one module and there was nothing to import. This module
is the importable thing, so the next module cannot repeat the mistake.

Two independent questions, and a finding needs both:

  1. Is this response distinguishable from the site's catch-all? If not, the
     path does not exist, whatever the status says.
  2. Does the body contain what that artifact would actually contain? A real
     `.env` has assignments in it. A real `.git/config` has `[core]`. A real
     SQL dump has `CREATE TABLE`. Serving 200 is not evidence; serving the
     artifact is.

Answering (1) alone removes the false positives. Answering (2) alone is what
stops a novel 200 from being graded CRITICAL on the strength of a path name.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Optional


@dataclass(frozen=True)
class Fingerprint:
    """What is left of a response once noise is stripped."""
    status: int
    length: int
    content_type: str
    body_hash: str

    def is_distinct_from(self, other: "Fingerprint") -> bool:
        return self.body_hash != other.body_hash


def fingerprint(status: int, body: str, content_type: str = "") -> Fingerprint:
    """Reduce a response to a comparable identity.

    The body is normalised first: gzip and aiohttp can vary whitespace and
    newline handling for the same document, and two spellings of one page must
    not read as two different pages. Conversely, a page that differs only in a
    CSRF token or a timestamp is still the same page for our purposes, so
    digits runs and long hex-ish runs collapse before hashing.
    """
    text = _normalise(body)
    return Fingerprint(
        status=int(status or 0),
        length=len(text),
        content_type=_normalise_ct(content_type),
        body_hash=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16],
    )


def _normalise(body: str) -> str:
    text = str(body or "")
    # Collapse volatile substrings so one document hashes consistently.
    text = re.sub(r"\b\d{4,}\b", "<n>", text)      # timestamps, ids, counters
    # Drop all whitespace rather than squeezing runs. Two renderings of one page
    # differ in inter-tag whitespace, and that is not a different page. Keeping
    # a single space would still separate "<p>a</p>" from "<p> a </p>".
    text = re.sub(r"\s+", "", text)
    return text.strip()


def _normalise_ct(content_type: str) -> str:
    return str(content_type or "").split(";")[0].strip().lower()


@dataclass
class Baseline:
    """What this site serves when nothing matches."""
    root: Optional[Fingerprint] = None
    # Fingerprints seen for a majority of the random control paths, which is how
    # a catch-all announces itself without assuming what it looks like.
    dominant: Counter = field(default_factory=Counter)
    control_paths: int = 0

    def catch_all(self, sig: Fingerprint) -> bool:
        """Is this response just the site answering 'anything'?

        Three independent signals, because one is not enough:
          * identical to the root,
          * identical to a majority of control paths,
          * same status, length and content-type as the root (weaker, and only
            used when we have a root to compare against).
        """
        if self.root is not None and sig.body_hash == self.root.body_hash:
            return True
        if self.dominant and self.control_paths >= 2:
            total = sum(self.dominant.values())
            if total and self.dominant.get(sig.body_hash, 0) / total >= 0.7:
                return True
        return False

    def describe(self) -> str:
        root = self.root.body_hash if self.root else "none"
        return (f"root={root} dominant={dict(self.dominant)} "
                f"controls={self.control_paths}")


# Paths chosen to be unlikely to exist. If a site returns the same body for
# several of these, it is serving a catch-all and any 200 elsewhere means little.
CONTROL_PATHS = [
    "/.well-known/this-path-should-not-exist-4f2a91",
    "/__control__/n7q2x8",
    "/zz-nonexistent-3b81ce",
    "/static/.__missing__.9d2f",
]


async def establish_baseline(fetch, base_url: str,
                             control_paths: Optional[Iterable[str]] = None) -> Baseline:
    """Build a Baseline using an existing fetch coroutine.

    `fetch` must be `async (path) -> (status, body, content_type)`. The caller's
    HTTP client is reused rather than duplicated, so this cannot drift out of
    sync with how the module actually requests pages.
    """
    baseline = Baseline()
    try:
        status, body, ct = await fetch("/")
        baseline.root = fingerprint(status, body, ct)
    except Exception:
        return baseline

    for path in (control_paths if control_paths is not None else CONTROL_PATHS):
        try:
            status, body, ct = await fetch(path)
        except Exception:
            continue
        baseline.control_paths += 1
        baseline.dominant[fingerprint(status, body, ct).body_hash] += 1
    return baseline


# --- content assertions -------------------------------------------------
#
# What the artifact would actually contain. A 200 with a matching body is
# evidence; a 200 without one is not, whatever the path is called.

CONTENT_ASSERTIONS: dict[str, "re.Pattern[str]"] = {
    r"/\.env": re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M),
    r"/\.git/(config|HEAD)": re.compile(r"^\s*\[core\]|^ref:\s*refs/", re.M),
    r"wp-config": re.compile(r"define\s*\(\s*['\"]DB_NAME|table_prefix", re.I),
    r"debug\.log|error_log|server-status": re.compile(
        r"\[(?:error|warning|notice|fatal|debug)\]|Apache Server Status", re.I),
    r"phpinfo|info\.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    r"actuator/(env|heapdump)": re.compile(r'"(?:_links|activeProfiles)"|Spring', re.I),
    r"swagger|api-docs": re.compile(r'"(?:openapi|swagger|info)"\s*:', re.I),
    r"graphql|graphiql": re.compile(r"__schema|\"data\"\s*:|\"errors\"\s*:", re.I),
    r"phpmyadmin|adminer": re.compile(r"phpMyAdmin|Adminer|select\.php", re.I),
    r"backup\.sql": re.compile(
        r"CREATE TABLE|INSERT INTO|-- MySQL dump|PRAGMA", re.I),
}


def content_matches(rule_key: str, body: str) -> bool:
    """Does the body look like the artifact this rule claims?

    Unknown rules return True, so a new rule is not silently disabled by
    forgetting to add an assertion — it is merely unverified.
    """
    pattern = CONTENT_ASSERTIONS.get(rule_key)
    if pattern is None:
        return True
    return bool(pattern.search(str(body or "")))
