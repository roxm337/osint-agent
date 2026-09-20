"""Stage 4: Parameter discovery from archives, crawls, and optional tools."""

from modules.base import BaseModule
from tools.external import (
    arjun_scan,
    extract_parameters_from_urls,
    paramspider_scan,
    tool_available,
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
                if not self.scope.check(target).allowed:
                    continue
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
            if _sensitive_parameter(item["parameter"]):
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
            targets.append(f"https://{self.domain}")
        return targets


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
        })
    return unique


def _sensitive_parameter(name: str) -> bool:
    lowered = str(name).lower()
    tokens = (
        "token", "key", "secret", "redirect", "url", "next", "return",
        "id", "user", "account", "file", "path", "debug", "admin",
    )
    return any(token in lowered for token in tokens)
