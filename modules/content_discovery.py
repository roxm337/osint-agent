"""Stage 4: Authorized content discovery via ffuf.

The previous version reported one finding: "Interesting Web Paths Discovered",
MEDIUM/CONFIRMED, for any ffuf hit that was not a plain 200-discovered path.
That graded three different situations identically, and one of them backwards:

  403 Forbidden   reported as a vulnerability, because `classify_content_hit`
                  called it "protected" and anything that was not "discovered"
                  fed the MEDIUM finding. A 403 is the access control working
                  as intended. It is reported here as INFO and framed as
                  "exists, access-controlled" — which is the useful fact.

  200 on a
  sensitive-looking name
                  genuinely worth a MEDIUM, because a 200 on /admin or
                  /backup means the resource is served without a redirect to a
                  login. This is the case the finding was named for, and it was
                  being outranked by the 403s.

  200 on anything else
                  a discovery, recorded as an asset and not raised as a finding.

Two other problems are fixed here. ffuf was run without `-ac`, so a site that
returns 200 for every path (a SPA catch-all, or a misconfigured soft-404)
produced a hit for the entire wordlist and the module had no way to tell a real
page from a catch-all. And ffuf's own status filter already excluded 404, so a
baseline request is what distinguishes a genuine 200 from a wildcard.

Severity here is a statement about exposure, not about vulnerability: none of
these are bugs in the application, and a 200 on /login is the expected shape of
a login page.
"""

from urllib.parse import urlparse

from modules.base import BaseModule
from tools.external import ffuf, parse_ffuf_json, tool_available


INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}

# Names that, when served with 200, suggest the resource is reachable without
# authentication. A 200 on any of these is worth a look.
SENSITIVE_TOKENS = (
    "admin", "backup", "bak", "debug", "config", "dump", "sql", "env",
    "credentials", "password", "secret", "private", "internal", "staging",
    "phpmyadmin", "wp-config", ".git", ".env", ".sql", ".bak", ".old",
    ".swp", ".zip", ".tar", "test", "temp", "upload",
)

# Redirects point at a login in almost every case, which is the intended shape.
REDIRECT_STATUSES = {301, 302, 307, 308}

# High-value paths no generic wordlist carries. Merged with configured
# words in run(): file drops, well-known disclosures, consoles.
HIGH_VALUE_SEEDS = (
    "ftp",
    ".well-known/security.txt",
    ".well-known/change-password",
    "server-status",
    "metrics",
)


def classify_content_hit(hit: dict) -> str:
    """What a single hit actually establishes.

    "served"      200 on a name that suggests a resource that should not be
                  public — the only case that is a MEDIUM.
    "protected"   401/403 — the resource exists, access control held.
    "redirected"  a 3xx, which normally means a login or a canonical move.
    "discovered"  a 200 on an unremarkable name. Just an asset.
    """
    status = int(hit.get("status") or 0)
    # Match on the path only. Testing the whole URL would match the token
    # "test" or "internal" against a hostname like example.test and mark every
    # path on the host as sensitive.
    url = urlparse(str(hit.get("url", ""))).path.lower()
    if status in (401, 403):
        return "protected"
    if status in REDIRECT_STATUSES:
        return "redirected"
    if status in (200, 204) and any(token in url for token in SENSITIVE_TOKENS):
        return "served"
    return "discovered"


class ContentDiscovery(BaseModule):
    id = "content_discovery"
    name = "Content Discovery"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        self.log("Running ffuf content discovery...")
        if not tool_available("ffuf"):
            self.state.skip_module(self.id, "ffuf not installed")
            return "skipped"

        base_url = self.base_url
        words = self.config.get("wordlists", {}).get("content_discovery", [])
        if not words:
            self.state.skip_module(self.id, "no content discovery wordlist")
            return "skipped"
        # High-value paths no generic wordlist carries, plus operator and
        # lab-pack additions (packs merge into the configured wordlist).
        # Merged under the same cap discipline as configured words.
        words = list(words) + [w for w in HIGH_VALUE_SEEDS if w not in words]

        run_dir = self.state.state_dir / "tool-output"
        run_dir.mkdir(exist_ok=True)
        wordlist_path = run_dir / "ffuf-content.txt"
        output_path = run_dir / "ffuf-content.json"
        wordlist_path.write_text("\n".join(w.strip("/") for w in words if w) + "\n")

        result = await ffuf(
            f"{base_url}/FUZZ",
            str(wordlist_path),
            str(output_path),
            rate=self.config.get("rate_limits", {}).get("scan", {}).get("per_minute", 10),
            timeout=240,
            # Calibrate against a random path, otherwise a catch-all site
            # returns a "hit" for every word in the list.
            extra_args=["-ac"],
        )
        if not result.get("available", True):
            self.state.skip_module(self.id, "ffuf not installed")
            return "skipped"

        output_text = output_path.read_text() if output_path.exists() else "{}"
        hits = [
            hit for hit in parse_ffuf_json(output_text)
            if int(hit.get("status") or 0) in INTERESTING_STATUSES
        ]

        wildcard = self._wildcard_group(hits)
        real_hits = [h for h in hits if str(h.get("url", "")) not in wildcard]
        filtered = len(wildcard)

        evidence_id = self.state.add_evidence(
            self.id,
            "ffuf",
            base_url,
            {
                "command": "ffuf",
                "url_template": f"{base_url}/FUZZ",
                "word_count": len(words),
                "autocalibrated": True,
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
                "filtered_as_wildcard": sorted(wildcard)[:50],
                "results": real_hits,
            },
        )

        categories = {url: classify_content_hit(hit)
                      for url, hit in ((h["url"], h) for h in real_hits)}
        for hit in real_hits:
            self.state.add_asset(
                "web_path",
                f"web_path:{hit['url']}",
                hit["url"],
                # The status and length came from a request we made, so the
                # path's existence is confirmed even where the classification
                # is only a guess about what the path is.
                confidence="CONFIRMED",
                sources=["ffuf"],
                attrs={**hit, "category": categories[hit["url"]]},
            )

        served = [h for h in real_hits if categories[h["url"]] == "served"]
        protected = [h for h in real_hits if categories[h["url"]] == "protected"]
        redirected = [h for h in real_hits if categories[h["url"]] == "redirected"]

        if served:
            self.state.add_finding(
                title=f"{len(served)} sensitive path(s) served with 200",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="Content Discovery",
                description=(
                    f"{len(served)} paths with names suggesting they should not be "
                    f"public on {self.domain} were served with HTTP 200 rather "
                    "than redirecting to a login or returning 403: "
                    f"{', '.join(h['url'] for h in served[:10])}. The path exists "
                    "and is reachable; whether the response body is sensitive is "
                    "the next thing to check. None of these are a vulnerability "
                    "on their own — a 200 on /login is the expected shape of a "
                    "login page."
                ),
                evidence=[
                    f"{h['status']} {h['url']} ({h.get('length', 0)} bytes)"
                    for h in served[:15]
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"web_path:{h['url']}" for h in served[:10]],
                remediation=(
                    "Confirm what each path returns. If the body is a directory "
                    "listing, a config file, or a database dump, treat it as a "
                    "disclosure. Otherwise confirm the page requires "
                    "authentication before serving it."
                ),
            )

        if protected:
            self.state.add_finding(
                title=f"{len(protected)} protected path(s) confirmed to exist",
                severity="INFO",
                confidence="CONFIRMED",
                category="Content Discovery",
                description=(
                    f"{len(protected)} paths returned 401 or 403 on {self.domain}. "
                    "The resource exists and access control is being enforced, "
                    "which is the expected behaviour and is recorded here so the "
                    "existence of the path is not rediscovered later. This is not "
                    "a weakness; it is reported at INFO deliberately."
                ),
                evidence=[
                    f"{h['status']} {h['url']}" for h in protected[:15]
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"web_path:{h['url']}" for h in protected[:10]],
                remediation=(
                    "No action required unless the path itself should not exist "
                    "at all. If it should, remove it rather than relying on a "
                    "403."
                ),
            )

        if redirected:
            self.log(f"  {len(redirected)} redirected path(s), recorded as assets")

        self.state.add_asset(
            "content_discovery",
            f"content_discovery:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["ffuf"],
            attrs={
                "hits": len(real_hits),
                "served": len(served),
                "protected": len(protected),
                "redirected": len(redirected),
                "discovered": len(real_hits) - len(served) - len(protected)
                - len(redirected),
                "filtered_as_wildcard": filtered,
                "output": str(output_path),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"ffuf hits: {len(real_hits)} real "
            f"({len(served)} served, {len(protected)} protected, "
            f"{len(redirected)} redirected, {filtered} filtered as wildcard)"
        )
        return "done"

    def _wildcard_group(self, hits: list) -> set:
        """URLs that look like the site's catch-all, so they can be discarded.

        ffuf filters 404s itself, so a 200 that reaches us may still be a
        soft-404 or a SPA serving index.html for unknown paths. The tell is
        that a large share of the wordlist comes back as the *same* response.

        Keyed on status, word count and body length together, so three
        different pages that happen to share a word count are not mistaken for
        one repeated response.

        An earlier version picked a single hit as the baseline and compared the
        rest against it. That was wrong in a way worth recording: when the
        dominant group is genuine, the chosen baseline was itself filtered out
        as a wildcard, so a real page was discarded. Discarding the dominant
        group as a unit cannot do that.
        """
        if not hits:
            return set()
        groups = {}
        for hit in hits:
            key = (int(hit.get("status") or 0), int(hit.get("words") or 0),
                   int(hit.get("length") or 0))
            groups.setdefault(key, set()).add(str(hit.get("url", "")))
        best = max(groups.values(), key=len)
        # Require a clear majority. A soft-404 site returns the catch-all for
        # nearly the whole wordlist, so the threshold is deliberately high:
        # discarding a real page is a false negative, and a spurious hit costs
        # only a glance. Needing both a ratio and a floor of three keeps a
        # handful of coincidentally equal responses from being thrown away.
        if len(best) < max(3, len(hits) * 0.7):
            return set()
        return best

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
