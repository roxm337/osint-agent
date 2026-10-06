"""Stage 5: File-upload audit — type confusion, XXE, stored script.

Upload handlers fail in three repeatable ways: they trust the extension
while serving the content (stored XSS via SVG), they parse XML with
entity expansion (XXE), and they gate types client-side only. Every
probe below is inert by construction: SVG carries a text marker, never
an exfiltrating payload; XXE entities resolve to a canary string or an
OOB callback, never to /etc/passwd; nothing executes on the target.
"""

import re
import secrets

from core.probe_targets import iter_probe_points
from modules.base import BaseModule
from tools.wrappers import curl


UPLOAD_PATH_SEEDS = (
    "/file-upload", "/upload", "/api/upload", "/rest/file-upload",
    "/api/file-upload", "/files/upload", "/attachments", "/media/upload",
)

XXE_CANARY = "XXE_PROBE_CANARY_7f3a"

XXE_PROBE_BODY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe "' + XXE_CANARY + '">]>'
    "<r>&xxe;</r>"
)


class UploadAudit(BaseModule):
    id = "upload_audit"
    name = "File Upload Audit"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        endpoints = self._upload_endpoints()
        if not endpoints:
            self.state.skip_module(self.id, "no upload endpoints discovered")
            return "skipped"

        import time as _time_guard
        try:
            _guard_deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _guard_deadline = 300.0
        _stop_at = _time_guard.monotonic() + max(60.0, _guard_deadline - 30.0)
        cfg = self._cfg()
        self._auth_headers = self._session_headers()
        reported = 0
        for endpoint in endpoints[:10]:
            if _time_guard.monotonic() >= _stop_at:
                break
            if await self._audit_endpoint(endpoint, cfg):
                reported += 1

        self.state.complete_module(self.id)
        self.log(f"Upload audit: {reported} issue(s) across {len(endpoints[:10])} endpoint(s)")
        return "done"

    def _session_headers(self) -> dict:
        """Captured sessions, so authenticated upload paths (profile
        images, complaints) are tested as the user, not as anonymous.
        First confirmed identity wins."""
        for asset in self.state.get_assets_by_type("identity_credential"):
            token = str((asset.get("attrs", {}) or {}).get("token", "") or "")
            if token and not token.startswith("cookie:"):
                return {"Authorization": f"Bearer {token}"}
        return {}

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    def _upload_endpoints(self) -> list:
        """Seed paths that answer POST/PUT plus swagger POST operations."""
        found = []
        for asset in self.state.get_assets_by_type("api_endpoint"):
            attrs = asset.get("attrs", {}) or {}
            methods = [m.upper() for m in (attrs.get("methods") or [])]
            value = str(asset.get("value", "") or "")
            if any(m in ("POST", "PUT", "PATCH") for m in methods):
                if value not in found:
                    found.append(value)
        for path in UPLOAD_PATH_SEEDS:
            url = f"{self.base_url}{path}"
            if url not in found:
                found.append(url)
        return found

    async def _audit_endpoint(self, url: str, cfg: dict) -> bool:
        """SVG upload, XXE probes, type confusion. True if anything filed."""
        filed = False
        marker = f"upl{secrets.token_hex(4)}"

        # 1. SVG with script-shaped content: stored XSS if served as-is.
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" onload="document.body.append('
               f"'{marker}')\">"
               f"<text>{marker}</text></svg>")
        location = await self._multipart(
            url, "probe.svg", svg.encode(), "image/svg+xml")
        if location:
            served = await self._fetch_text(location)
            if served and marker in served and "<svg" in served.lower():
                self.state.add_finding(
                    title=f"Stored Script via SVG Upload: {url}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="Stored XSS",
                    description=(
                        f"SVG uploaded to {url} is served back with script "
                        f"content intact at {location}: attacker markup "
                        f"executes in victims' browsers."),
                    evidence=[f"Upload: {url}", f"Served at: {location}",
                              f"Marker reflected: {marker}"],
                    remediation="Re-encode uploads to inert formats, serve "
                                "user files with Content-Disposition: attachment "
                                "and a non-executing content type.",
                    asset_keys=[f"url:{url}"],
                    verified=True,
                    verification={"method": "svg_served_intact", "url": location},
                )
                return True

        # 2. XXE canary: entity expansion without touching the filesystem.
        for content_type in ("application/xml", "text/xml"):
            try:
                result = await curl(
                    url, method="POST",
                    headers={"Content-Type": content_type,
                             **self._auth_headers},
                    data=XXE_PROBE_BODY.encode(),
                    output="full", timeout=15)
            except Exception:
                continue
            body = result.get("body", "") or ""
            status = result.get("status", 0)
            if status in (400, 405, 415):
                continue
            if XXE_CANARY in body and "&xxe;" not in body:
                self.state.add_finding(
                    title=f"XXE Entity Expansion: {url}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    category="XXE",
                    description=(
                        f"XML accepted at {url} expanded an external-style "
                        f"entity to the canary string: the parser resolves "
                        f"entities, which is the XXE primitive. File "
                        f"content was not read; that step needs an OOB "
                        f"channel or manual follow-up."),
                    evidence=[f"URL: {url}",
                              f"Canary expanded: {XXE_CANARY}"],
                    remediation="Disable DTDs and external entities in the XML "
                                "parser; prefer JSON or a hardened parser.",
                    asset_keys=[f"url:{url}"],
                    verified=True,
                    verification={"method": "xxe_canary_expansion",
                                  "url": url},
                )
                return True

        # 3. Type confusion: XML content where documents are expected.
        xml_name = f"probe-{marker}.xml"
        location = await self._multipart(
            url, xml_name,
            XXE_PROBE_BODY.encode(), "application/xml")
        if location and location != url:
            served = await self._fetch_text(location)
            if served and ("<?xml" in served or XXE_CANARY in served
                           or "&xxe;" in served):
                self.state.add_finding(
                    title=f"Unrestricted File Type Upload: {url}",
                    severity="MEDIUM",
                    confidence="FIRM",
                    category="File Upload",
                    description=(
                        f"{url} stored {xml_name} and serves it back with "
                        f"XML content intact: extension and content-type "
                        f"gates are client-side or absent."),
                    evidence=[f"Upload: {url}", f"Served at: {location}"],
                    remediation="Allowlist extensions AND content types "
                                "server-side; re-encode or sandbox uploads.",
                    asset_keys=[f"url:{url}"],
                )
                return True
        return filed

    async def _multipart(self, url: str, filename: str, content: bytes,
                         content_type: str) -> str:
        """One multipart upload; returns the served location or ''."""
        import uuid
        boundary = f"----osint{uuid.uuid4().hex[:12]}"
        payload = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
        try:
            result = await curl(
                url, method="POST",
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                         **self._auth_headers},
                data=payload,
                output="full", timeout=20)
        except Exception:
            return ""
        if result.get("status", 0) not in (200, 201):
            return ""
        body = result.get("body", "") or ""
        match = re.search(r'"(?:location|url|path|file)"\s*:\s*"([^"]+)"', body)
        if match:
            location = match.group(1)
            if location.startswith("/"):
                from urllib.parse import urlparse
                base = urlparse(url)
                return f"{base.scheme}://{base.netloc}{location}"
            if location.startswith(("http://", "https://")):
                return location
        # No location advertised: the upload URL itself may serve it, or
        # a conventional path. Only return something fetchable.
        return ""

    async def _fetch_text(self, url: str) -> str:
        try:
            result = await curl(url, output="body", timeout=15)
        except Exception:
            return ""
        if result.get("status", 0) not in (200, 201):
            return ""
        return result.get("body", "") or ""
