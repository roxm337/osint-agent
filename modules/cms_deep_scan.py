"""Stage 5: CMS-specific scanning, graded per finding.

The previous version merged four scanners into one `HIGH/FIRM` line: "CMS Deep
Scan Findings: 12". A WordPress core version disclosure and a known-exploitable
plugin RCE arrived as the same object, so triage meant opening all of them.

Each scanner's output is normalised to a component-level signal and graded on
what was actually established:

  known CVE on a named component   HIGH   the scanner matched a specific vuln
                                    CRITICAL if CISA KEV lists it
  named vuln, no CVE               MEDIUM real signal, no identifier to track
  version detected                 INFO   fingerprinting, not a vulnerability
  scraped line, component unknown  TENTATIVE  we could not attribute it

That last grade is the important one. joomscan and cmseek are scraped line by
line for the words "vulnerab", "outdated", "version" and "admin", which is why a
line reading "Found: /wp-admin/" used to reach a HIGH finding. A line that says
nothing attributable is now recorded as unverified rather than promoted.

CVE identifiers extracted from WPScan's structured output are cross-referenced
against the CISA KEV catalog, so a plugin bug that is being exploited in the wild
is separated from one that merely has a CVE.
"""

import json
import re

from modules.base import BaseModule
from modules.exploit_lookup import check_cisa_kev
from tools.external import (
    cmseek_scan,
    droopescan_scan,
    joomscan_scan,
    tool_available,
    wpscan,
)
from tools.wrappers import epss_score

# The words parse_cms_text_findings keys on. "admin" is the one that misfires:
# a discovered admin path is a route, not a vulnerability.
_SIGNAL_WORDS = ("vulnerab", "outdated", "version", "cve-", "exploit")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

TOOLS = ("wpscan", "joomscan", "droopescan", "cmseek")


def _cves_in(value) -> list:
    """CVE identifiers anywhere in a blob, deduplicated and uppercased."""
    if isinstance(value, str):
        found = _CVE_RE.findall(value)
    elif isinstance(value, dict):
        found = [c for item in value.values() for c in _cves_in(item)]
    elif isinstance(value, (list, tuple)):
        found = [c for item in value for c in _cves_in(item)]
    else:
        found = []
    return sorted({c.upper() for c in found})


def wpscan_signals(result: dict) -> list:
    """Pull (component, kind, title, cves) out of WPScan's JSON.

    WPScan is the only one of the four that returns structure: it knows which
    plugin or theme a CVE belongs to, which is what makes a per-component grade
    possible at all.
    """
    data = result.get("results", {}) if isinstance(result, dict) else {}
    if not isinstance(data, dict):
        return []
    signals = []

    def collect(section, component):
        for vuln in (section or {}).get("vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            title = str(vuln.get("title", "")).strip()
            if not title:
                continue
            signals.append({
                "component": component,
                "kind": "vulnerability",
                "title": title,
                "cves": _cves_in(vuln),
                "fixed_in": str(vuln.get("fixed_in", "") or ""),
                "source": "wpscan",
                "attributed": True,
            })

    collect(data.get("version", {}), "wordpress core")
    theme = data.get("main_theme", {}) or {}
    collect(theme, f"theme:{theme.get('name') or 'unknown'}")
    for name, item in (data.get("plugins", {}) or {}).items():
        collect(item if isinstance(item, dict) else {}, f"plugin:{name}")

    # Version fingerprints, which are information and not vulnerabilities.
    core_version = (data.get("version", {}) or {}).get("number", "")
    if core_version:
        signals.append({
            "component": "wordpress core", "kind": "version",
            "title": f"WordPress {core_version} identified",
            "cves": [], "source": "wpscan", "attributed": True,
        })
    for name, item in (data.get("plugins", {}) or {}).items():
        version = (item or {}).get("version") or ""
        if version and not isinstance(version, (dict, list)):
            signals.append({
                "component": f"plugin:{name}", "kind": "version",
                "title": f"{name} {version} identified",
                "cves": [], "source": "wpscan", "attributed": True,
            })
    return signals


def droopescan_signals(result: dict, cms: str = "") -> list:
    """Normalise droopescan's output.

    Two things are true here that the old code got wrong. The result was never
    appended to the findings list at all, so a Drupal site scanned with
    droopescan installed reported clean. And the result is a *dict* parsed from
    droopescan's stdout, not a list — appending it directly would have iterated
    its keys. The exact layout differs between droopescan releases, so this
    accepts both a component mapping and a flat line list rather than assuming
    one shape.
    """
    data = result.get("results") if isinstance(result, dict) else None
    signals = []
    core = f"{cms.lower()} core" if cms else "cms core"

    def component_entry(name, value):
        if isinstance(value, dict):
            version = value.get("version") or value.get("Version") or ""
            for ref in (value.get("references", []) or []) + \
                       (value.get("vulnerabilities", []) or []):
                title = str(ref if isinstance(ref, str)
                            else ref.get("title", "")).strip()
                if title:
                    signals.append({
                        "component": name, "kind": "vulnerability",
                        "title": title, "cves": _cves_in(ref),
                        "source": "droopescan", "attributed": True,
                    })
            if version and not signals:
                signals.append({
                    "component": name, "kind": "version",
                    "title": f"{name} {version} identified",
                    "cves": [], "source": "droopescan", "attributed": True,
                })
        elif isinstance(value, str) and value.strip():
            signals.append({
                "component": name, "kind": "version",
                "title": f"{name} {value.strip()} identified",
                "cves": _cves_in(value), "source": "droopescan",
                "attributed": True,
            })

    if isinstance(data, dict):
        for key, value in data.items():
            if key in ("stdout", "stderr", "exit_code", "error"):
                continue
            lowered = str(key).lower()
            if lowered in ("plugins", "modules", "themes", "components"):
                if isinstance(value, dict):
                    for name, item in value.items():
                        component_entry(f"{lowered[:-1]}:{name}", item)
                continue
            # A top-level version/framework entry describes the CMS itself, not
            # an extension, and naming it "Version" would be meaningless in a
            # report.
            component_entry(core if lowered in (
                "version", "core", "framework", "server") else str(key), value)
    elif isinstance(data, list):
        for item in data:
            line = str((item or {}).get("evidence", item)).strip()
            if line:
                signals.append(_scraped_signal(line, "droopescan"))
    elif isinstance(data, str):
        for line in data.splitlines():
            if line.strip():
                signals.append(_scraped_signal(line.strip(), "droopescan"))
    return signals


def _scraped_signal(line: str, source: str) -> dict:
    """A line that was matched by keyword, so we know nothing certain about it."""
    cves = _cves_in(line)
    lowered = line.lower()
    attributed = False
    if any(cve in lowered for cve in ("cve-", "exploit")) or cves:
        attributed = bool(cves)
    return {
        "component": "unknown",
        "kind": "vulnerability" if (cves or "vulnerab" in lowered) else "info",
        "title": line,
        "cves": cves,
        "source": source,
        # A keyword match is not an attribution. Without a CVE or a named
        # component we cannot say which part of the install is affected.
        "attributed": attributed,
    }


def scraped_signals(result: dict, source: str) -> list:
    """Normalise a line-scraped scanner result.

    `parse_cms_text_findings` keys on "admin" as well as the words below, so a
    discovered `/administrator/` path is returned as a candidate finding. Note
    that "admin" is deliberately absent from `_SIGNAL_WORDS`: the single filter
    here is what stops an admin URL from becoming a vulnerability, and keeping
    it in the word list would be the bug rather than the fix.
    """
    data = result.get("results", []) if isinstance(result, dict) else []
    if isinstance(data, dict):
        data = [str(v) for v in data.values()]
    signals = []
    for item in data or []:
        line = str((item or {}).get("evidence", item)).strip()
        if not line:
            continue
        if not any(word in line.lower() for word in _SIGNAL_WORDS):
            continue
        signals.append(_scraped_signal(line, source))
    return signals


class CMSDeepScan(BaseModule):
    id = "cms_deep_scan"
    name = "CMS Deep Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [(self.base_url, "")]

        if not any(tool_available(name) for name in TOOLS):
            self.state.skip_module(self.id, "CMS scanners not installed")
            return "skipped"

        limit = int(cfg.get("max_targets", 5) or 5)
        signals = []
        for target, cms in targets[:limit]:
            signals.extend(await self._scan(target, cms))

        if not signals:
            self.state.complete_module(self.id)
            self.log("CMS deep scan: nothing identified")
            return "done"

        kev = await self._kev_index(signals)
        reported = 0
        for finding in self._grade(signals, kev, targets):
            await self._attach_epss(finding)
            self.state.add_finding(**finding)
            reported += 1

        self.state.add_asset(
            "cms_inventory",
            f"cms_inventory:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=sorted({s["source"] for s in signals}),
            attrs={
                "components": sorted({
                    f"{s['component']} ({s['title']})"
                    for s in signals if s["kind"] == "version"
                })[:50],
                "cves": sorted({c for s in signals for c in s["cves"]}),
                "kev_cves": sorted(kev),
            },
        )

        self.state.complete_module(self.id)
        self.log(f"cms deep scan: {reported} finding(s) from {len(signals)} signal(s)")
        return "done"

    async def _scan(self, target: str, cms: str) -> list:
        """Run whichever scanners fit this target. Each one that runs has its
        output normalised and returned — including droopescan, whose results
        used to be written to the evidence file and then dropped."""
        cms_lower = cms.lower()
        signals = []

        if "wordpress" in cms_lower and tool_available("wpscan"):
            result = await wpscan(target, timeout=300)
            signals.extend(wpscan_signals(result))
            self.state.add_evidence(self.id, "wpscan", target, result)

        if "joomla" in cms_lower and tool_available("joomscan"):
            result = await joomscan_scan(target, timeout=300)
            signals.extend(scraped_signals(result, "joomscan"))
            self.state.add_evidence(self.id, "joomscan", target, result)

        if any(name in cms_lower for name in
               ("drupal", "joomla", "wordpress")) and tool_available("droopescan"):
            cms_name = ("drupal" if "drupal" in cms_lower else
                        "joomla" if "joomla" in cms_lower else "wordpress")
            result = await droopescan_scan(target, cms=cms_name, timeout=300)
            signals.extend(droopescan_signals(result, cms=cms_name))
            self.state.add_evidence(self.id, "droopescan", target, result)

        if tool_available("cmseek"):
            result = await cmseek_scan(target, timeout=300)
            signals.extend(scraped_signals(result, "cmseek"))
            self.state.add_evidence(self.id, "cmseek", target, result)

        return [s for s in signals if s.get("title")]

    async def _kev_index(self, signals: list) -> set:
        """CVE identifiers that CISA lists as known-exploited.

        Matched on the CVE id rather than the product name, because
        check_cisa_kev is keyword-driven and a product keyword would match
        every KEV entry for that product regardless of which CVE we found.
        """
        cves = sorted({c for s in signals for c in s["cves"]})
        if not cves:
            return set()
        try:
            matches = await check_cisa_kev(cves)
        except Exception as exc:  # a network hiccup must not lose the findings
            self.log(f"KEV lookup failed: {exc}")
            return set()
        return {str(m.get("cve", "")).upper() for m in matches if m.get("cve")} & set(cves)

    def _grade(self, signals: list, kev: set, targets: list) -> list:
        """One finding per component, carrying only that component's signals."""
        by_component = {}
        for signal in signals:
            key = (signal["component"], signal["kind"] == "version")
            by_component.setdefault(key, []).append(signal)

        host = self._host(targets)
        findings = []
        for (component, is_version), group in sorted(
                by_component.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            finding = self._grade_component(component, group, is_version, kev, host)
            if finding:
                findings.append(finding)
        return findings

    def _grade_component(self, component: str, group: list, is_version: bool,
                         kev: set, host: str) -> dict:
        if is_version:
            # Fingerprinting. Useful, and not a vulnerability.
            return {
                "title": f"{component}: version identified",
                "severity": "INFO",
                "confidence": "FIRM",
                "category": "CMS Fingerprinting",
                "description": (
                    f"Version information exposed for {component} on {host}: "
                    f"{'; '.join(s['title'] for s in group)}. This is an "
                    "information disclosure that tells an attacker which "
                    "published CVEs to try against this install. It is not a "
                    "vulnerability in itself."
                ),
                "evidence": [s["title"] for s in group[:10]],
                "asset_keys": [f"url:{host}"],
                "remediation": (
                    "Remove version strings from responses, generator meta tags "
                    "and static assets."
                ),
                # Fingerprinted by a scanner, not replayed by us.
                "verified": False,
            }

        cves = sorted({c for s in group for c in s["cves"]})
        in_kev = sorted(set(cves) & kev)
        attributed = all(s["attributed"] for s in group)

        if in_kev:
            severity, confidence = "CRITICAL", "FIRM"
            headline = (
                f"{component}: {len(in_kev)} known-exploited CVE(s) "
                f"({', '.join(in_kev)})"
            )
            detail = (
                f"CISA lists {', '.join(in_kev)} for this component as known "
                "exploited in the wild, so exploitation does not need a novel "
                "attack. "
            )
        elif cves and attributed:
            severity, confidence = "HIGH", "FIRM"
            headline = f"{component}: {len(cves)} known CVE(s) — {', '.join(cves[:5])}"
            detail = (
                "The scanner matched these published CVEs against the version "
                "it detected. The version is fingerprint-derived, so confirm "
                "the running build before treating it as confirmed — but the "
                "component and the CVE are both named, which is more than a "
                "keyword match. "
            )
        elif attributed:
            severity, confidence = "MEDIUM", "FIRM"
            headline = f"{component}: {len(group)} reported vulnerability(ies)"
            detail = (
                "The scanner reported the following for this component without "
                "attaching a CVE identifier, so there is nothing to track to a "
                "fix. "
            )
        else:
            severity, confidence = "LOW", "TENTATIVE"
            headline = f"{component}: unverified scanner signal"
            detail = (
                "This line was matched by keyword and the scanner did not say "
                "which component it refers to, so it cannot be attributed to "
                "anything in particular. Treat it as a lead to chase, not a "
                "finding. "
            )

        return {
            "title": headline,
            "severity": severity,
            "confidence": confidence,
            "category": "CMS Vulnerability",
            "description": (
                f"{detail}Reported against {host} for {component} by "
                f"{', '.join(sorted({s['source'] for s in group}))}."
            ),
            "evidence": [json.dumps({
                "component": component, "title": s["title"], "cves": s["cves"],
                "source": s["source"], "fixed_in": s.get("fixed_in", ""),
            }) for s in group[:10]],
            "asset_keys": [f"url:{host}"],
            "remediation": (
                "Update the component to a fixed release, remove it if unused, "
                "and re-run to confirm the version no longer matches. For the "
                "unattributed signals, identify the component first — a "
                "keyword match on its own is not a reportable finding."
            ),
            # A scanner matched; we did not replay it, so nothing here is
            # self-verified. `confidence` carries the grader's assessment and
            # `verified` records that the claim is second-hand.
            "verified": False,
        }

    def _host(self, targets: list) -> str:
        return targets[0][0] if targets else self.base_url

    async def _attach_epss(self, finding: dict) -> None:
        """Attach FIRST EPSS exploit-probability to a graded finding.

        KEV says "exploited now"; EPSS says "likely next". A HIGH with
        EPSS 0.9 outranks a HIGH with EPSS 0.01 at triage time. Network
        failure degrades to nothing — the graded finding stands alone.
        """
        cves = _cves_in([finding.get("title", ""),
                         finding.get("description", "")]
                        + list(finding.get("evidence", []) or []))
        if not cves:
            return
        try:
            scores = await epss_score(cves[:10])
        except Exception:
            return
        if not scores:
            return
        top_cve = max(scores, key=lambda c: scores[c].get("epss", 0.0))
        top = scores[top_cve]
        finding.setdefault("evidence", []).append(
            f"EPSS {top_cve}: {top.get('epss', 0.0):.3f} "
            f"(percentile {top.get('percentile', 0.0):.2f})")
        verification = finding.setdefault("verification", {})
        verification["epss"] = {cve: scores[cve].get("epss", 0.0)
                               for cve in sorted(scores)}

    def _targets(self) -> list:
        targets = []
        for asset in self.state.get_assets_by_type("webapp"):
            value = str(asset.get("value", "")).strip()
            cms = str((asset.get("attrs") or {}).get("cms", ""))
            if value.startswith(("http://", "https://")):
                targets.append((value, cms))
        return targets

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
