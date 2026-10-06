"""Stage 3: Passive threat intelligence enrichment."""

from datetime import datetime, timezone
from urllib.parse import urlparse

from modules.base import BaseModule
from tools.wrappers import ip_api, threatfox_ioc, urlhaus_host

# IOCs older than this are history, not current compromise evidence.
FRESH_DAYS = 365


class ThreatIntel(BaseModule):
    id = "threat_intel"
    name = "Threat Intelligence"
    stage = 3
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        from core.validators import is_public_target
        if not is_public_target(self.domain):
            self.state.skip_module(self.id, "reputation feeds cover the public internet only")
            return "skipped"
        self.log("Checking passive threat intelligence sources...")

        hostnames = {self.domain} if self.domain else set()
        for asset_type in ("domain", "subdomain", "webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                host = _host_from_value(value)
                if host:
                    hostnames.add(host)

        ips = {
            str(asset.get("value", "")).strip()
            for asset in self.state.get_assets_by_type("ip")
            if str(asset.get("value", "")).strip()
        }

        if not hostnames and not ips:
            self.state.skip_module(self.id, "no indicators")
            return "skipped"

        evidence_refs = []
        urlhaus_hits = []
        threatfox_hits = []
        geo_asn = {}

        for host in sorted(hostnames)[:50]:
            urlhaus = await urlhaus_host(host)
            evidence_refs.append(
                self.state.add_evidence(self.id, "urlhaus_host", host, urlhaus)
            )
            if _has_urlhaus_hit(urlhaus):
                fresh, lines = _describe_urlhaus_hit(host, urlhaus)
                urlhaus_hits.append({"indicator": host, "result": urlhaus,
                                     "fresh": fresh, "detail": lines[0] if lines else host,
                                     "lines": lines})

            threatfox = await threatfox_ioc(host)
            evidence_refs.append(
                self.state.add_evidence(self.id, "threatfox_ioc", host, threatfox)
            )
            if _has_threatfox_hit(threatfox):
                fresh, lines = _describe_threatfox_hit(host, threatfox)
                threatfox_hits.append({"indicator": host, "result": threatfox,
                                       "fresh": fresh,
                                       "detail": lines[0] if lines else host,
                                       "lines": lines})

        for ip in sorted(ips)[:50]:
            enrich = await ip_api(ip)
            evidence_refs.append(self.state.add_evidence(self.id, "ip_api", ip, enrich))
            if enrich.get("status") == "success":
                geo_asn[ip] = {
                    "as": enrich.get("as", ""),
                    "asname": enrich.get("asname", ""),
                    "country": enrich.get("countryCode", ""),
                    "org": enrich.get("org", ""),
                    "reverse": enrich.get("reverse", ""),
                }
            threatfox = await threatfox_ioc(ip)
            evidence_refs.append(
                self.state.add_evidence(self.id, "threatfox_ioc", ip, threatfox)
            )
            if _has_threatfox_hit(threatfox):
                fresh, lines = _describe_threatfox_hit(ip, threatfox)
                threatfox_hits.append({"indicator": ip, "result": threatfox,
                                       "fresh": fresh,
                                       "detail": lines[0] if lines else ip,
                                       "lines": lines})

        if urlhaus_hits:
            fresh = [hit for hit in urlhaus_hits if hit.get("fresh")]
            stale = [hit for hit in urlhaus_hits if not hit.get("fresh")]
            if fresh:
                self.state.add_finding(
                    title=f"URLHaus Reputation Hits: {len(fresh)} Indicator(s)",
                    severity="HIGH",
                    confidence="FIRM",
                    category="Threat Intelligence",
                    description=(
                        "URLHaus returned recent abuse or malware URL history for "
                        "in-scope indicators. Validate ownership and current "
                        "compromise state."
                    ),
                    evidence=[line for hit in fresh[:5] for line in hit.get("lines", [])][:10],
                    evidence_refs=evidence_refs,
                    remediation="Review affected hosts for compromise, redirects, and stale DNS.",
                )
            if stale:
                self.state.add_finding(
                    title=f"URLHaus Stale IOC History: {len(stale)} Indicator(s)",
                    severity="INFO",
                    confidence="FIRM",
                    category="Threat Intelligence",
                    description=(
                        "URLHaus has only aged-out entries for these indicators "
                        f"(nothing seen in {FRESH_DAYS} days). History, not "
                        "current compromise evidence."
                    ),
                    evidence=[line for hit in stale[:5] for line in hit.get("lines", [])][:10],
                    evidence_refs=evidence_refs,
                    remediation="No action unless fresh activity appears.",
                )

        if threatfox_hits:
            fresh = [hit for hit in threatfox_hits if hit.get("fresh")]
            stale = [hit for hit in threatfox_hits if not hit.get("fresh")]
            if fresh:
                self.state.add_finding(
                    title=f"ThreatFox IOC Hits: {len(fresh)} Indicator(s)",
                    severity="HIGH",
                    confidence="FIRM",
                    category="Threat Intelligence",
                    description=(
                        "ThreatFox returned recent IOC matches for in-scope indicators. "
                        "Treat as priority triage until ownership and freshness "
                        "are confirmed."
                    ),
                    evidence=[line for hit in fresh[:5] for line in hit.get("lines", [])][:10],
                    evidence_refs=evidence_refs,
                    remediation="Confirm IOC freshness and inspect affected infrastructure.",
                )
            if stale:
                self.state.add_finding(
                    title=f"ThreatFox Stale IOC History: {len(stale)} Indicator(s)",
                    severity="INFO",
                    confidence="FIRM",
                    category="Threat Intelligence",
                    description=(
                        "ThreatFox has only aged-out entries for these indicators. "
                        "History, not current compromise evidence."
                    ),
                    evidence=[line for hit in stale[:5] for line in hit.get("lines", [])][:10],
                    evidence_refs=evidence_refs,
                    remediation="No action unless fresh activity appears.",
                )

        self.state.add_asset(
            "threat_intel",
            f"threat_intel:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id, "urlhaus", "threatfox", "ip-api"],
            attrs={
                "hostnames_checked": sorted(hostnames),
                "ips_checked": sorted(ips),
                "urlhaus_hits": len(urlhaus_hits),
                "threatfox_hits": len(threatfox_hits),
                "geo_asn": geo_asn,
                "evidence_refs": evidence_refs,
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"Threat intel: {len(urlhaus_hits)} URLHaus hit(s), "
            f"{len(threatfox_hits)} ThreatFox hit(s)"
        )
        return "done"


def _host_from_value(value: str) -> str:
    if not value:
        return ""
    # Values are written by every module that records an asset, so one
    # malformed string must not take the whole run down: CPython 3.14's
    # `urlparse` raises "Invalid IPv6 URL" for a netloc whose brackets do not
    # pair, and `http://host:3000 [exchange_owa]` was stored verbatim.
    candidate = value.split()[0]
    try:
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        host = parsed.hostname or ""
    except ValueError:
        host = candidate.split("://", 1)[-1].split("/", 1)[0]
    host = host or value
    return host.strip().lower().strip(".")


def _parse_ioc_date(value: str):
    """Parse abuse.ch date shapes; None when unparseable."""
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _fresh_enough(dates: list, max_age_days: int = FRESH_DAYS) -> tuple:
    """(fresh, newest): anything seen within the window?"""
    newest = None
    for value in dates:
        parsed = _parse_ioc_date(value)
        if parsed and (newest is None or parsed > newest):
            newest = parsed
    if newest is None:
        return False, ""
    age_days = (datetime.now(timezone.utc) - newest).days
    return age_days <= max_age_days, newest.strftime("%Y-%m-%d")


def _describe_urlhaus_hit(indicator: str, result: dict) -> tuple:
    """(fresh, lines): one evidence line per dated URL, fresh-first."""
    lines = []
    fresh_any = False
    for entry in (result.get("urls") or [])[:10]:
        if not isinstance(entry, dict):
            continue
        dates = [entry.get("lastseen", ""), entry.get("date_added", "")]
        fresh, newest = _fresh_enough([d for d in dates if d])
        fresh_any = fresh_any or fresh
        threat = entry.get("threat", "") or ",".join(entry.get("tags", [])[:3])
        reporter = entry.get("reporter", "")
        lines.append((fresh, newest,
                      f"{indicator}: {threat or 'malware URL'} "
                      f"(reporter {reporter or 'unknown'}, "
                      f"last seen {newest or 'unknown date'})"))
    if not lines:
        return False, [f"{indicator}: {result.get('query_status', 'hit')} (no dated entries)"]
    lines.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return fresh_any, [line for _fresh, _newest, line in lines]


def _describe_threatfox_hit(indicator: str, result: dict) -> tuple:
    """(fresh, lines): one evidence line per dated IOC, fresh-first."""
    lines = []
    fresh_any = False
    for entry in (result.get("data") or [])[:10]:
        if not isinstance(entry, dict):
            continue
        dates = [entry.get("last_seen", ""), entry.get("first_seen", "")]
        fresh, newest = _fresh_enough([d for d in dates if d])
        fresh_any = fresh_any or fresh
        family = (entry.get("malware_printable", "")
                  or entry.get("malware_alias", "")
                  or entry.get("threat_type", ""))
        confidence = entry.get("confidence_level", "")
        lines.append((fresh, newest,
                      f"{indicator}: {family or 'IOC match'} "
                      f"(confidence {confidence or 'unknown'}, "
                      f"last seen {newest or 'unknown date'})"))
    if not lines:
        return False, [f"{indicator}: {result.get('query_status', 'hit')} (no dated entries)"]
    lines.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return fresh_any, [line for _fresh, _newest, line in lines]


def _has_urlhaus_hit(result: dict) -> bool:
    status = str(result.get("query_status", "")).lower()
    if not status or status in {"no_results", "no_result", "not_found", "invalid_host"}:
        return False
    return bool(result.get("urls")) or status in {"ok", "found"}


def _has_threatfox_hit(result: dict) -> bool:
    status = str(result.get("query_status", "")).lower()
    if not status or status in {"no_result", "no_results", "not_found", "invalid_ioc"}:
        return False
    return bool(result.get("data")) or status in {"ok", "found"}
