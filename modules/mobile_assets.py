"""Stage 4: Passive Android/iOS asset association discovery."""

from __future__ import annotations

import json

from modules.base import BaseModule
from tools.wrappers import curl_with_status


class MobileAssets(BaseModule):
    id = "mobile_assets"
    name = "Mobile Asset Discovery"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = f"https://{self.domain}"
        self.log("Discovering Android/iOS app associations...")

        android_apps = []
        ios_apps = []
        related_apps = []
        evidence_refs = []

        for path in ("/.well-known/assetlinks.json", "/assetlinks.json"):
            result = await curl_with_status(f"{base_url}{path}")
            if result.get("status") != 200:
                continue
            apps = _parse_assetlinks(result.get("body", ""))
            if apps:
                android_apps.extend(apps)
                evidence_refs.append(self._record_evidence(f"{base_url}{path}", result, apps))

        for path in ("/.well-known/apple-app-site-association", "/apple-app-site-association"):
            result = await curl_with_status(f"{base_url}{path}")
            if result.get("status") != 200:
                continue
            apps = _parse_apple_app_site_association(result.get("body", ""))
            if apps:
                ios_apps.extend(apps)
                evidence_refs.append(self._record_evidence(f"{base_url}{path}", result, apps))

        manifest = await curl_with_status(f"{base_url}/manifest.json")
        if manifest.get("status") == 200:
            apps = _parse_manifest_related_apps(manifest.get("body", ""))
            if apps:
                related_apps.extend(apps)
                evidence_refs.append(self._record_evidence(f"{base_url}/manifest.json", manifest, apps))

        for app in _dedupe(android_apps, "package_name"):
            self.state.add_asset(
                "mobile_app",
                f"android:{app['package_name']}",
                app["package_name"],
                confidence="FIRM",
                sources=[self.id],
                attrs={**app, "platform": "android"},
            )
            self.state.add_edge(f"domain:{self.domain}", f"android:{app['package_name']}", "android_asset_link")

        for app in _dedupe(ios_apps, "app_id"):
            self.state.add_asset(
                "mobile_app",
                f"ios:{app['app_id']}",
                app["app_id"],
                confidence="FIRM",
                sources=[self.id],
                attrs={**app, "platform": "ios"},
            )
            self.state.add_edge(f"domain:{self.domain}", f"ios:{app['app_id']}", "ios_app_site_association")

        for app in related_apps[:50]:
            key = f"related_app:{app.get('platform', 'unknown')}:{app.get('id') or app.get('url')}"
            self.state.add_asset(
                "mobile_app_reference",
                key,
                app.get("id") or app.get("url") or "",
                confidence="TENTATIVE",
                sources=[self.id],
                attrs=app,
            )

        total = len(android_apps) + len(ios_apps) + len(related_apps)
        if total:
            self.state.add_finding(
                title=f"Mobile App Associations Discovered: {total}",
                severity="INFO",
                confidence="FIRM",
                category="Mobile Attack Surface",
                description=(
                    "The target publishes mobile application association metadata "
                    "that identifies Android/iOS app assets for follow-up testing."
                ),
                evidence=[
                    f"Android: {app['package_name']}" for app in _dedupe(android_apps, "package_name")[:8]
                ] + [
                    f"iOS: {app['app_id']}" for app in _dedupe(ios_apps, "app_id")[:8]
                ] + [
                    f"Related: {app.get('platform')} {app.get('id') or app.get('url')}"
                    for app in related_apps[:8]
                ],
                evidence_refs=evidence_refs,
                remediation="Include the associated mobile apps in authorized mobile testing scope.",
            )

        self.state.add_asset(
            "mobile_assets_summary",
            f"mobile_assets:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "android_apps": len(_dedupe(android_apps, "package_name")),
                "ios_apps": len(_dedupe(ios_apps, "app_id")),
                "related_apps": len(related_apps),
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Mobile assets: {total}")
        return "done"

    def _record_evidence(self, url: str, result: dict, apps: list[dict]) -> str:
        return self.state.add_evidence(
            self.id,
            "mobile_association",
            url,
            {
                "url": url,
                "status": result.get("status"),
                "apps": apps[:50],
                "body_preview": str(result.get("body", ""))[:2000],
            },
        )


def _parse_assetlinks(text: str) -> list[dict]:
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    apps = []
    for entry in data if isinstance(data, list) else []:
        target = entry.get("target", {}) if isinstance(entry, dict) else {}
        if target.get("namespace") != "android_app":
            continue
        package_name = target.get("package_name")
        if package_name:
            apps.append({
                "package_name": package_name,
                "sha256_cert_fingerprints": target.get("sha256_cert_fingerprints", []),
                "relations": entry.get("relation", []),
            })
    return apps


def _parse_apple_app_site_association(text: str) -> list[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    apps = []
    applinks = data.get("applinks", {}) if isinstance(data, dict) else {}
    details = applinks.get("details", [])
    if isinstance(details, dict):
        details = [details]
    for detail in details if isinstance(details, list) else []:
        app_ids = detail.get("appIDs") or ([detail.get("appID")] if detail.get("appID") else [])
        for app_id in app_ids:
            apps.append({"app_id": app_id, "paths": detail.get("paths", []), "components": detail.get("components", [])})
    return apps


def _parse_manifest_related_apps(text: str) -> list[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    related = data.get("related_applications", []) if isinstance(data, dict) else []
    return [item for item in related if isinstance(item, dict)]


def _dedupe(items: list[dict], key: str) -> list[dict]:
    seen = set()
    result = []
    for item in items:
        value = item.get(key)
        if value and value not in seen:
            seen.add(value)
            result.append(item)
    return result
