"""Stage 5: Generic server-side request forgery via OOB callbacks.

Actions know SSRF (`web.ssrf.oob_detect`) and one WordPress endpoint has
its own proof (`rest_api._check_file_size_ssrf`), but no stage module
looked for the primitive across a target: parameters that take URLs.
This module closes that gap.

The rule is the Yoast one, generalised: a URL parameter is a *candidate*,
and only a callback distinguishes a server that fetches from one that
merely stores or reflects. Grades:

  HTTP callback   the server fetched our URL (path-tagged per probe):
                  HIGH/CONFIRMED, verified, method oob_callback.
  DNS-only        the resolver asked for our domain but no HTTP arrived:
                  the server initiates outbound requests without proving
                  a full fetch: MEDIUM/FIRM.
  fetch error     the response names our domain next to a fetch failure
                  (getaddrinfo, ENOTFOUND, failed to fetch, timed out):
                  the server attempted the request: MEDIUM/FIRM.
  silence         no callback, no error: the parameter stays a candidate.
                  One aggregate LOW/TENTATIVE finding lists them instead
                  of N unproven findings.

Two safety rules:

- The target is only ever asked to fetch OUR callback URL. Cloud
  metadata (169.254.169.254 and friends) is never requested: proving
  the fetch primitive via our own infrastructure establishes the bug
  without touching instance credentials, which would land secrets in
  evidence on a hit.
- Without an OOB channel nothing is probed at all. Guessing from
  parameter names alone is how "url=" became a finding without a
  request ever leaving the scanner; the aggregate LOW says untested
  and means it.
"""

from __future__ import annotations

import asyncio as _asyncio
import json as _json

from core.validators import inject_param
from modules.base import BaseModule
from tools.wrappers import curl


# Parameter names that conventionally carry a URL the server fetches.
# A name match makes a candidate, never a finding.
SSRF_PARAMS = (
    "url", "uri", "u", "src", "source", "file", "path", "folder",
    "redirect", "redirect_url", "next", "dest", "destination", "target",
    "link", "image", "img", "avatar", "photo", "picture", "fetch",
    "feed", "proxy", "proxy_url", "callback", "webhook", "hook",
    "site", "domain", "host", "server", "api_url", "endpoint",
)

# Response text showing the server tried to resolve or fetch our URL.
# Matched against the lowercased body (our domain must appear nearby —
# a generic "timeout" on a slow page is not an attempt).
FETCH_ERROR_MARKERS = (
    "getaddrinfo", "enotfound", "econnrefused", "econnreset",
    "failed to fetch", "fetch failed", "could not fetch",
    "could not resolve", "name resolution", "dns error",
    "connection refused", "connection timed out", "timed out",
    "no such host", "unknown host", "invalid url", "unsupported url",
)


class SSRFScan(BaseModule):
    id = "ssrf_scan"
    name = "SSRF Scan"
    stage = 5
    detectability = "high"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        names = tuple(
            str(n).lower() for n in (cfg.get("params") or SSRF_PARAMS))
        try:
            max_points = max(1, min(30, int(cfg.get("max_points", 6))))
        except (TypeError, ValueError):
            max_points = 6

        points = [p for p in self._candidate_points(names)][:max_points]
        if not points:
            self.state.skip_module(self.id, "no URL-bearing parameters")
            return "skipped"

        oob_client = self.oob()
        probed: list[dict] = []
        if oob_client is None:
            self.log("  no OOB channel — parameters recorded untested, "
                     "nothing probed")
            self.state.add_finding(
                title=f"{len(points)} URL parameter(s) accept arbitrary "
                      f"URLs (untested, no OOB channel)",
                severity="LOW",
                confidence="TENTATIVE",
                category="SSRF",
                description=(
                    f"{len(points)} parameter(s) conventionally carry a URL "
                    f"the server may fetch "
                    f"({', '.join(sorted({p['param'] for p in points})[:10])}). "
                    f"No OOB channel is configured, so server-side fetching "
                    f"is unproven and nothing was sent. Configure oob.mode "
                    f"(public needs no infrastructure) to test them."
                ),
                evidence=[
                    f"{p['param']} on {p['url']}" for p in points[:15]
                ],
                remediation="Validate any server-fetched URL against an "
                            "allowlist; block instance-metadata addresses.",
            )
            self.state.complete_module(self.id)
            return "done"

        for index, point in enumerate(points):
            outcome = await self._probe_point(oob_client, point, index)
            probed.append(outcome)

        confirmed = [p for p in probed if p["grade"] == "confirmed"]
        egress = [p for p in probed if p["grade"] == "egress"]
        attempted = [p for p in probed if p["grade"] == "attempted"]
        silent = [p for p in probed if p["grade"] == "silent"]

        evidence_id = self.state.add_evidence(
            self.id,
            "ssrf_scan",
            self.domain,
            {
                "points_tested": len(probed),
                "confirmed": len(confirmed),
                "dns_egress": len(egress),
                "attempted": len(attempted),
                "silent": len(silent),
                "results": probed,
            },
        )

        for item in confirmed:
            self.state.add_finding(
                title="Blind SSRF Confirmed via OOB Callback",
                severity="HIGH",
                confidence="CONFIRMED",
                category="SSRF",
                description=(
                    f"Parameter {item['param']} on {item['url']} made the "
                    f"server issue an HTTP request to an out-of-band URL: "
                    f"attacker-supplied destinations are fetched "
                    f"server-side."
                ),
                evidence=[
                    f"URL: {item['url']}",
                    f"Parameter: {item['param']}",
                    f"OOB HTTP callback received ({item['corr'][:8]})",
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"url:{item['url']}"],
                remediation="Validate any server-fetched URL against an "
                            "allowlist; block instance-metadata and internal "
                            "addresses at the egress layer.",
                verified=True,
                verification={"method": "oob_callback",
                              "url": item["url"],
                              "param": item["param"]},
            )

        for item in egress:
            self.state.add_finding(
                title="Server-Side DNS Egress via URL Parameter",
                severity="MEDIUM",
                confidence="FIRM",
                category="SSRF",
                description=(
                    f"Parameter {item['param']} on {item['url']} made server-"
                    f"side infrastructure resolve an out-of-band domain, "
                    f"but no HTTP fetch arrived: outbound requests are "
                    f"initiated without proving a full fetch."
                ),
                evidence=[
                    f"URL: {item['url']}",
                    f"Parameter: {item['param']}",
                    f"OOB DNS interaction received ({item['corr'][:8]})",
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"url:{item['url']}"],
                remediation="Treat as an SSRF primitive with DNS exfiltration "
                            "impact; confirm whether full fetches complete.",
            )

        for item in attempted:
            self.state.add_finding(
                title="Server Attempted Fetch of Attacker URL",
                severity="MEDIUM",
                confidence="FIRM",
                category="SSRF",
                description=(
                    f"Parameter {item['param']} on {item['url']} answered "
                    f"with a fetch failure naming the probe domain: the "
                    f"server tried to resolve or retrieve it, but no "
                    f"callback arrived."
                ),
                evidence=[
                    f"URL: {item['url']}",
                    f"Parameter: {item['param']}",
                    f"Fetch error: {item['marker'][:150]}",
                ],
                evidence_refs=[evidence_id],
                asset_keys=[f"url:{item['url']}"],
                remediation="Same as confirmed SSRF until a callback proves "
                            "otherwise: allowlist fetched URLs.",
            )

        if silent:
            self.state.add_finding(
                title=f"{len(silent)} URL parameter(s) showed no server-"
                      f"side fetch",
                severity="LOW",
                confidence="TENTATIVE",
                category="SSRF",
                description=(
                    f"{len(silent)} parameter(s) accepted a callback URL and "
                    f"produced neither an interaction nor a fetch error. "
                    f"Not vulnerable by this test — kept so the negative "
                    f"result is auditable rather than rediscovered."
                ),
                evidence=[
                    f"{p['param']} on {p['url']}" for p in silent[:15]
                ],
                evidence_refs=[evidence_id],
                remediation="No action; retest if the endpoint changes.",
            )

        self.state.complete_module(self.id)
        self.log(
            f"SSRF: {len(confirmed)} confirmed | {len(egress)} dns-egress | "
            f"{len(attempted)} attempted | {len(silent)} silent"
        )
        return "done"

    async def _probe_point(self, oob_client, point: dict,
                           index: int) -> dict:
        """One parameter, one path-tagged callback, bounded poll."""
        tag = f"/ssrf-{index}-{point['param']}"
        try:
            corr_id = await oob_client.register_callback(
                f"ssrf:{self.domain}:{point['param']}:{index}")
            callback = oob_client.callback_url(corr_id, tag)
        except Exception as exc:
            self.log(f"  OOB registration failed: {exc}")
            return {**point, "grade": "silent", "corr": "", "marker": ""}
        if not corr_id or "invalid" in callback:
            return {**point, "grade": "silent", "corr": "", "marker": ""}

        probe_url = inject_param(point["url"], point["param"], callback)
        # Drain stale session lines first: DNS hits carry no path, so a
        # previous probe's late interaction must not be attributed here.
        try:
            await oob_client.poll(corr_id)
        except Exception:
            pass
        body = ""
        try:
            result = await curl(probe_url, output="full", timeout=15)
            body = str(result.get("body", "") or "")[:20000]
        except Exception:
            pass

        path_hits, dns_hits = await self._poll_path(oob_client, corr_id,
                                                    tag)
        if any(str(h.get("protocol", "") or "").lower() != "dns"
               for h in path_hits):
            return {**point, "grade": "confirmed", "corr": corr_id,
                    "marker": ""}
        if path_hits or dns_hits:
            return {**point, "grade": "egress", "corr": corr_id,
                    "marker": ""}
        marker = self._fetch_error_marker(body, callback)
        if marker:
            return {**point, "grade": "attempted", "corr": corr_id,
                    "marker": marker}
        return {**point, "grade": "silent", "corr": corr_id, "marker": ""}

    async def _poll_path(self, oob_client, corr_id: str,
                         tag: str) -> tuple[list, list]:
        """(path hits, session DNS hits) for this probe, bounded.

        The public client multiplexes one session per scan, so every
        probe shares the domain and paths distinguish them — for HTTP,
        whose request line carries the path. DNS interactions have no
        path, so they are attributed by window: the caller drains before
        probing, and any DNS hit observed after is this probe's egress.
        The poll timeout is clamped: the oob default (30s) times the
        module timeout on an all-silent run.
        """
        try:
            oob_client.poll_timeout = min(
                float(getattr(oob_client, "poll_timeout", 8) or 8), 8.0)
        except (TypeError, ValueError):
            pass
        needle = tag.lower()
        path_hits: list = []
        dns_hits: list = []
        for _ in range(3):
            try:
                items = await oob_client.poll(corr_id)
            except Exception:
                items = []
            for item in items or []:
                try:
                    dump = _json.dumps(item).lower()
                except (TypeError, ValueError):
                    continue
                if needle in dump:
                    path_hits.append(item)
                elif str(item.get("protocol", "") or "").lower() == "dns":
                    dns_hits.append(item)
            if path_hits:
                break
            try:
                await _asyncio.sleep(float(
                    getattr(oob_client, "poll_interval", 2) or 2))
            except (TypeError, ValueError):
                await _asyncio.sleep(2)
        return path_hits, dns_hits

    @staticmethod
    def _fetch_error_marker(body: str, callback: str) -> str:
        """A fetch-failure snippet naming our domain, or "".

        The domain requirement is what separates an attempt from a slow
        page: a generic "timeout" proves nothing, but a timeout next to
        the hostname we just supplied means the server chewed on it.
        """
        text = (body or "").lower()
        if not text:
            return ""
        domain = callback.split("://", 1)[-1].split("/", 1)[0].lower()
        if not domain or domain not in text:
            return ""
        for marker in FETCH_ERROR_MARKERS:
            if marker in text:
                start = max(0, text.find(marker) - 60)
                return text[start:start + 220].strip()
        return ""

    def _candidate_points(self, names: tuple) -> list[dict]:
        from core.probe_targets import iter_probe_points
        points = []
        seen = set()
        for point in iter_probe_points(self.state, self.base_url,
                                       self.domain):
            if point.get("method", "GET") != "GET":
                continue
            param = str(point.get("param", "") or "").lower()
            if param not in names:
                continue
            key = (point.get("url", ""), param)
            if key in seen:
                continue
            seen.add(key)
            points.append({"url": point["url"], "param": point["param"]})
        return points

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
