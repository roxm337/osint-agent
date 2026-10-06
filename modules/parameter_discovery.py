"""Stage 4: Parameter discovery from archives, crawls, and optional tools."""

import asyncio

from modules.base import BaseModule
from tools.external import (
    arjun_scan,
    extract_parameters_from_urls,
    paramspider_scan,
    tool_available,
)
from tools.wrappers import curl

# When crawls and archives yield zero parameters (clean-URL apps like
# Next.js), injection modules all skip and the active phase loses its
# targets. Seeding probes a bounded set of live pages with inert marker
# values under common names; a page that reflects the marker is a real
# reflection point, which is exactly what XSS/SQLi/open-redirect need.
# The marker is alphanumeric noise — no payload, no special characters —
# so seeding detects reflection without testing any vulnerability.
SEED_MARKER = "zxqseed9k2"
SEED_PARAM_NAMES = (
    "q", "s", "search", "query", "keyword", "id", "page", "lang",
    "redirect", "url", "next", "return", "callback", "debug",
)


class ParameterDiscovery(BaseModule):
    id = "parameter_discovery"
    name = "Parameter Discovery"
    stage = 4
    detectability = "medium"
    depends_on = ["wayback_machine"]

    async def run(self) -> str:
        urls = self._known_urls()
        parameters = extract_parameters_from_urls(urls)
        evidence_refs = []

        if tool_available("paramspider"):
            result = await paramspider_scan(self.domain, timeout=180)
            parameters.extend(result.get("parameters", []))
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "paramspider",
                    self.domain,
                    {
                        "available": result.get("available"),
                        "url_count": len(result.get("urls", [])),
                        "parameter_count": len(result.get("parameters", [])),
                        "stderr": result.get("stderr", ""),
                    },
                )
            )

        if tool_available("arjun"):
            run_dir = self.state.state_dir / "tool-output"
            run_dir.mkdir(exist_ok=True)
            for target in self._scan_targets()[:5]:
                output_file = run_dir / f"arjun-{len(evidence_refs) + 1}.json"
                result = await arjun_scan(target, str(output_file), timeout=240)
                parameters.extend(result.get("results", []))
                evidence_refs.append(
                    self.state.add_evidence(
                        self.id,
                        "arjun",
                        target,
                        {
                            "available": result.get("available"),
                            "parameter_count": len(result.get("results", [])),
                            "exit_code": result.get("exit_code"),
                            "stderr": result.get("stderr", ""),
                        },
                    )
                )

        unique = _dedupe_parameters(parameters)
        if not unique:
            seeded = await self._seed_reflection_params()
            unique = _dedupe_parameters(seeded)
        if not unique:
            self.state.skip_module(self.id, "no parameters discovered")
            return "skipped"

        sensitive = []
        for item in unique:
            key = f"param:{item['url']}:{item['parameter']}"
            self.state.add_asset(
                "parameter",
                key,
                item["parameter"],
                confidence="FIRM",
                sources=[self.id],
                attrs=item,
            )
            if _sensitive_parameter(item["parameter"]) and not item.get("seeded"):
                sensitive.append(item)

        if sensitive:
            self.state.add_finding(
                title="Sensitive Parameter Names Discovered",
                severity="MEDIUM",
                confidence="FIRM",
                category="Parameter Discovery",
                description=(
                    "Parameter mining found names commonly associated with secrets, "
                    "redirects, authorization, or object references."
                ),
                evidence=[
                    f"{item['url']} -> {item['parameter']}"
                    for item in sensitive[:15]
                ],
                evidence_refs=evidence_refs,
                remediation="Review handlers for authorization, validation, and secret leakage.",
            )

        self.state.add_asset(
            "parameter_inventory",
            f"params:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "parameters": len(unique),
                "sensitive": len(sensitive),
                "top": unique[:50],
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Parameters: {len(unique)} discovered")
        return "done"

    def _known_urls(self) -> list[str]:
        urls = []
        for asset_type in ("url", "api_endpoint", "web_path", "js_file"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")):
                    urls.append(value)
        return urls

    def _scan_targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        if not targets:
            targets.append(self.base_url)
        return targets

    async def _seed_reflection_params(self) -> list[dict]:
        """Probe live pages for reflection under common parameter names.

        Bounded and inert: at most a dozen pages times a dozen names, one
        GET each, marker value is noise. Anything reflecting the marker
        becomes a `parameter` asset so the injection modules have targets
        instead of skipping the whole active phase.
        """
        cfg = self.config.get("modules", {}).get(self.id, {})
        if isinstance(cfg, dict) and cfg.get("seed_when_empty") is False:
            return []
        names = list(SEED_PARAM_NAMES)
        if isinstance(cfg, dict) and cfg.get("seed_params"):
            names = [str(p) for p in cfg["seed_params"] if p][:24]
        pages = []
        for page in [self.base_url] + self._scan_targets():
            clean = str(page or "").split("?")[0].rstrip("/") or str(page or "")
            if clean.startswith(("http://", "https://")) and clean not in pages:
                pages.append(clean)
        max_pages = int(cfg.get("seed_targets", 10)) if isinstance(cfg, dict) else 10
        pages = pages[:max(1, max_pages)]
        self.log(f"  No parameters from crawl — seeding reflection on "
                 f"{len(pages)} page(s) x {len(names)} names...")

        semaphore = asyncio.Semaphore(8)

        async def probe(page: str, name: str):
            from urllib.parse import urlencode, urlparse, urlunparse
            parsed = urlparse(page)
            query = urlencode({name: SEED_MARKER})
            url = urlunparse(parsed._replace(query=query))
            async with semaphore:
                try:
                    result = await curl(url, output="full",
                                        follow_redirects=False, timeout=10)
                except Exception:
                    return None
            body = result.get("body", "") or ""
            if SEED_MARKER in body:
                return {"url": page, "parameter": name,
                        "example_value": SEED_MARKER,
                        "sources": ["reflection_seed"],
                        "source": "reflection_seed",
                        "seeded": True,
                        "status": result.get("status", 0)}
            return None

        probed = await asyncio.gather(
            *(probe(page, name) for page in pages for name in names),
            return_exceptions=True,
        )
        seeded = [p for p in probed if isinstance(p, dict)]
        self.log(f"  Reflection seeding: {len(seeded)} reflecting "
                 f"(page, param) pairs from {len(pages) * len(names)} probes")
        if seeded:
            self.state.add_evidence(
                self.id,
                "reflection_seed",
                self.domain,
                {"pages": pages, "names": names, "marker": SEED_MARKER,
                 "reflecting": len(seeded),
                 "pairs": [(p["url"], p["parameter"]) for p in seeded[:50]]},
            )
        return seeded


def _dedupe_parameters(items: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in items:
        url = str(item.get("url", "")).strip()
        parameter = str(item.get("parameter", "")).strip()
        if not url or not parameter:
            continue
        key = (url, parameter)
        if key in seen:
            continue
        seen.add(key)
        unique.append({
            "url": url,
            "parameter": parameter,
            "example_value": item.get("example_value", ""),
            "sources": item.get("sources", []),
            "source": item.get("source", ""),
            "seeded": bool(item.get("seeded")),
        })
    return unique


def _sensitive_parameter(name: str) -> bool:
    lowered = str(name).lower()
    tokens = (
        "token", "key", "secret", "redirect", "url", "next", "return",
        "id", "user", "account", "file", "path", "debug", "admin",
    )
    return any(token in lowered for token in tokens)
