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

        Two independent signals, because one is not enough:

          * identical body to the root,
          * matching the fingerprint that a majority of control paths produced,
            which catches a catch-all that serves something other than its own
            homepage.

        The majority check needs at least two control paths before it will
        claim anything: a single unlucky 404 must not be able to condemn every
        real finding on the site.

        Status and content type are deliberately not part of the comparison.
        A real 404 and a real 200 often share both, so including them would
        make distinct resources look identical and suppress true findings.
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
    r"/\.git/(config|HEAD|refs)": re.compile(r"^\s*\[core\]|^ref:\s*refs/", re.M),
    r"/\.svn/(entries|wc\.db)": None,          # wc.db is binary; see below
    r"/\.DS_Store": None,                       # binary; see below
    r"/\.aws/credentials": re.compile(
        r"\[default\]|aws_access_key_id|aws_secret_access_key", re.I),
    r"/\.ssh/id_(rsa|dsa|ecdsa)": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    r"wp-config": re.compile(r"define\s*\(\s*['\"]DB_NAME|table_prefix", re.I),
    r"debug\.log|error_log|server-status": re.compile(
        r"\[(?:error|warning|notice|fatal|debug)\]|Apache Server Status", re.I),
    r"phpinfo|info\.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    r"actuator/(env|heapdump|configprops|threaddump)": re.compile(
        r'"(?:_links|activeProfiles|beans)"|Spring', re.I),
    r"swagger|api-docs|openapi\.json": re.compile(r'"(?:openapi|swagger|info)"\s*:', re.I),
    r"graphql|graphiql": re.compile(r"__schema|\"data\"\s*:|\"errors\"\s*:", re.I),
    r"phpmyadmin|adminer": re.compile(r"phpMyAdmin|Adminer|select\.php", re.I),
    r"backup\.sql|\.sql\.gz|dump\.sql": re.compile(
        r"CREATE TABLE|INSERT INTO|-- MySQL dump|PRAGMA", re.I),
    r"\.zip$|\.tar\.gz$|\.tgz$": re.compile(r"PK\x03\x04|\x1f\x8b", re.I),
    r"id_rsa|\.pem$|\.key$|\.p12$|\.pfx$": re.compile(
        r"-----BEGIN|\x30\x82", re.I),
    r"/(?:config|configuration)\.(json|ya?ml|ini|xml)$": re.compile(
        r"^\s*[\[{]|^[\w.-]+\s*[:=]", re.M),
    r"adminer|/admin\.php|/admin/console": re.compile(
        r"Adminer|admin_console|<title>.*[Aa]dmin", re.I),
}


class _Binary:
    """Sentinel: the matched artifact is binary, so assert on content type."""
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<binary artifact>"


BINARY = _Binary()

_NOTHING = object()


def _resolve(rule_or_path: str):
    """Find the content assertion that governs this rule or path.

    An exact key wins, so a caller that already knows its rule is never
    second-guessed. Otherwise the input is treated as a path and every known
    key is tried as a regex against it. The path fallback exists because
    key-based lookup alone meant a renamed rule group silently stopped
    verifying — an unrecognised key fell through to "assume fine", which is
    the same failure this module exists to prevent, one level up.
    """
    if rule_or_path in CONTENT_ASSERTIONS:
        pattern = CONTENT_ASSERTIONS[rule_or_path]
        return BINARY if pattern is None else pattern

    fallback = _NOTHING
    for key, pattern in CONTENT_ASSERTIONS.items():
        try:
            hit = re.search(key, rule_or_path)
        except re.error:
            continue
        if not hit:
            continue
        if pattern is None:
            # Binary artifact. Keep looking for a text assertion that is more
            # specific to this path, but remember this one as a fallback.
            if fallback is _NOTHING:
                fallback = BINARY
        else:
            return pattern
    return fallback


def content_matches(rule_or_path: str, body: str, content_type: str = "") -> bool:
    """Does the body look like the artifact this rule or path claims?

    Two kinds of answer:

      * a text assertion — the body must contain what the artifact contains.
      * `BINARY` — a text pattern cannot help (`wc.db`, `.DS_Store`), so the
        signal is the content type. A binary file served as `text/html` is not
        a binary file, it is the server answering with its default page.

    Nothing matched, so the rule is unverified, and returns True: the
    catch-all gate still applies, so this is a missing assertion rather than a
    missing check. Silence here is recorded, not assumed away.
    """
    resolved = _resolve(str(rule_or_path or ""))
    if resolved is BINARY:
        return _is_not_html(content_type)
    if resolved is _NOTHING:
        return True
    return bool(resolved.search(str(body or "")))


def _is_not_html(content_type: str) -> bool:
    """For binary artifacts: is this plausibly not a rendered HTML page?

    An absent content type gives us nothing, so we do not claim a match.
    """
    ct = _normalise_ct(content_type)
    if not ct:
        return False
    return ct not in ("text/html", "application/xhtml+xml")
