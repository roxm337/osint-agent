"""Stage 4: Cloud Bucket Enumeration — S3, GCS, Azure, DigitalOcean Spaces."""

import asyncio
import time

from modules.base import BaseModule
from tools.wrappers import curl


PROVIDER_TEMPLATES = {
    "s3":               "https://{name}.s3.amazonaws.com",
    "gcs":              "https://storage.googleapis.com/{name}",
    "azure":            "https://{name}.blob.core.windows.net",
    "do_nyc3":          "https://{name}.nyc3.digitaloceanspaces.com",
    "do_ams3":          "https://{name}.ams3.digitaloceanspaces.com",
    "firebase":         "https://{name}.firebaseio.com/.json",
    "firebase_storage": "https://firebasestorage.googleapis.com/v0/b/{name}.appspot.com/o",
}

_BUCKET_TIMEOUT = 5

# File/word markers that upgrade a public bucket from MEDIUM to CRITICAL.
_SENSITIVE_MARKERS = (
    ".env", ".sql", ".bak", ".backup", ".old", ".tar", ".zip",
    "backup", "dump", "secret", "password", "credential", "private_key",
    "id_rsa", ".pem", ".key", "config.json", "settings.py",
    "connectionstring", "database_url", "apikey", "api_key",
    ".git/", ".ssh/",
)


class CloudEnum(BaseModule):
    id = "cloud_enum"
    name = "Cloud Bucket Enumeration"
    stage = 4
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log("Enumerating cloud buckets...")

        candidates = self._generate_candidates()
        self.log(f"  Testing {len(candidates)} name candidates across "
                 f"{len(PROVIDER_TEMPLATES)} providers...")

        results = {p: [] for p in PROVIDER_TEMPLATES}
        public_count = 0
        critical_count = 0
        exists_count = 0

        semaphore = asyncio.Semaphore(20)
        total_tasks = len(candidates) * len(PROVIDER_TEMPLATES)
        completed = 0

        async def test_bucket(name, provider, url_template):
            url = url_template.format(name=name)
            async with semaphore:
                r = await curl(url, output="status", follow_redirects=False,
                               timeout=_BUCKET_TIMEOUT)
            status = r.get("status", 0)
            body = ""
            if status == 200:
                rb = await curl(url, output="body", follow_redirects=False,
                                timeout=_BUCKET_TIMEOUT)
                body = rb.get("body", "")
            return name, provider, url, status, body

        tasks = [
            test_bucket(name, provider, template)
            for name in candidates
            for provider, template in PROVIDER_TEMPLATES.items()
        ]

        batch_size = 200
        task_results = []
        # Dead names cost the full 5s curl timeout each, so a few hundred
        # candidates across seven providers can outlast the module deadline
        # and die with zero buckets recorded. Findings already land per
        # bucket above, so stopping early keeps the partial coverage.
        try:
            deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            deadline = 300.0
        stop_at = time.monotonic() + max(60.0, deadline - 45.0)
        time_boxed = False
        for i in range(0, len(tasks), batch_size):
            if time.monotonic() >= stop_at:
                time_boxed = True
                self.log(f"  Time-box hit at {completed}/{total_tasks} probes — "
                         "keeping the buckets found so far")
                break
            batch = tasks[i:i + batch_size]
            batch_out = await asyncio.gather(*batch, return_exceptions=True)
            task_results.extend(batch_out)
            completed += len(batch)
            self.log(f"  Progress: {completed}/{total_tasks} probes done")

        for result in task_results:
            if isinstance(result, Exception):
                continue
            name, provider, url, status, body = result

            if status == 0:
                continue

            if status == 200:
                listing = self._classify_listing(provider, body)
                keys = self._extract_keys(provider, body)
                # Markers count in object KEYS, not in the raw body: SDK
                # bundles and docs pages contain words like "config.json"
                # and "password" without exposing anything. Body-only
                # mentions are context, never a severity bump.
                sensitive = self._find_sensitive_markers(keys)
                body_mentions = self._find_sensitive_markers(
                    [body[:5000]]) if not sensitive else []
                proven, proof = False, []

                if sensitive:
                    proven, proof = await self._prove_key_readable(
                        provider, url, keys, sensitive)
                    if proven:
                        severity = "CRITICAL"
                        critical_count += 1
                        classification = "Sensitive data exposed and readable"
                    else:
                        severity = "HIGH"
                        classification = ("Sensitive object names listed "
                                          "(objects not directly readable)")
                elif listing:
                    severity = "MEDIUM"
                    classification = "Public directory listing"
                else:
                    severity = "LOW"
                    classification = "Public object, not listable"

                public_count += 1
                public_note = (
                    f"{classification}. {len(keys)} object(s) visible."
                    if keys else classification
                )

                self.state.add_finding(
                    title=f"Public Cloud Bucket: {name} ({provider.upper().split('_')[0]})",
                    severity=severity,
                    confidence="CONFIRMED",
                    category="Cloud Exposure",
                    description=(
                        f"Bucket '{name}' on {provider} returns HTTP 200 for "
                        f"unauthenticated requests. {public_note}"
                    ),
                    evidence=[
                        f"URL: {url}",
                        f"Status: {status}",
                        f"Listing: {listing}",
                        f"Objects visible: {len(keys)}",
                        f"Sample keys: {keys[:15]}",
                        f"Sensitive markers: {sensitive[:10]}" if sensitive else "",
                        f"Body-only mentions (not object names): "
                        f"{body_mentions[:5]}" if body_mentions else "",
                        f"Preview: {body[:200]}",
                    ] + [f"Key readability proof: {line}" for line in proof[:3]],
                    remediation=(
                        "Apply bucket ACL to block public access. Enable Block "
                        "Public Access settings. Rotate any credentials present "
                        "in exposed files." if sensitive else
                        "Apply bucket ACL to block public access. Enable Block "
                        "Public Access settings."
                    ),
                    verified=severity == "CRITICAL",
                    verification={
                        "method": ("sensitive_object_readable_unauthenticated"
                                   if severity == "CRITICAL"
                                   else "http_200_unauthenticated"),
                        "listing_detected": listing,
                        "keys_visible": len(keys),
                        "sensitive_markers": sensitive,
                    },
                )
                results[provider].append({
                    "name": name, "url": url, "status": status,
                    "listing": listing, "keys": len(keys),
                    "sensitive": sensitive,
                })

            elif status == 403:
                exists_count += 1
                results[provider].append({
                    "name": name, "url": url, "status": 403, "private": True,
                })
                self.state.add_asset(
                    "bucket", f"bucket:{provider}:{name}", name,
                    confidence="FIRM", sources=["cloud enumeration"],
                    attrs={"provider": provider, "url": url, "status": 403, "private": True},
                )

            elif status in (301, 302):
                exists_count += 1
                self.state.add_asset(
                    "bucket", f"bucket:{provider}:{name}", name,
                    confidence="TENTATIVE", sources=["cloud enumeration"],
                    attrs={"provider": provider, "url": url, "status": status},
                )

            if "firebase" in provider and status == 200 and '"rules"' not in body:
                self.state.add_finding(
                    title=f"Firebase Database Publicly Readable: {name}",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    category="Cloud Exposure",
                    description=f"Firebase Realtime Database at {url} is publicly readable.",
                    evidence=[f"URL: {url}", f"Response preview: {body[:300]}"],
                    remediation="Set Firebase security rules to deny read/write by default.",
                    verified=True,
                    verification={"method": "firebase_open_read"},
                )

        total = sum(len(v) for v in results.values())
        self.state.add_asset(
            "cloud_enum", f"cloud_enum:{self.domain}", self.domain,
            confidence="CONFIRMED", sources=["cloud enumeration"],
            attrs={
                "total_found": total,
                "public": public_count,
                "public_critical": critical_count,
                "private": exists_count - public_count,
                "providers_checked": list(PROVIDER_TEMPLATES.keys()),
                "candidates_tested": len(candidates),
                "probes_completed": completed,
                "time_boxed": time_boxed,
            },
        )

        self.state.complete_module(self.id)
        self.log(
            f"Cloud: {total} buckets found ({public_count} public, "
            f"{critical_count} critical content, {exists_count} total exists)"
        )
        return "done"

    def _classify_listing(self, provider: str, body: str) -> bool:
        if not body:
            return False
        if provider.startswith("s3") or provider.startswith("do_"):
            return "<ListBucketResult" in body and "<Contents>" in body
        if provider == "gcs":
            return (
                "<ListBucketResult" in body
                or '"items"' in body
                or ("<Contents>" in body and "<Key>" in body)
            )
        if provider == "azure":
            return "<EnumerationResults" in body
        if provider.startswith("firebase"):
            return body.strip() not in ("", "null", "{}")
        return "<Contents>" in body or "<Key>" in body

    def _extract_keys(self, provider: str, body: str) -> list:
        import re
        keys = re.findall(r"<Key>([^<]+)</Key>", body)
        if not keys:
            # GCS JSON: {"items": [{"name": "..."}]}
            keys = re.findall(r'"name"\s*:\s*"([^"]+)"', body)
        return keys[:200]

    def _find_sensitive_markers(self, texts: list) -> list:
        """Marker substrings in object names (never the raw body alone)."""
        found = []
        haystack = " ".join(texts).lower()
        for marker in _SENSITIVE_MARKERS:
            if marker in haystack:
                found.append(marker)
        return found

    async def _prove_key_readable(self, provider: str, bucket_url: str,
                                  keys: list, sensitive: list
                                  ) -> tuple[bool, list[str]]:
        """GET one sensitive-named key to prove readability, read-only.

        A listed name is a claim; a fetched body is proof. Only object
        stores with unambiguous key URLs are attempted (S3/GCS/Spaces);
        Azure needs a container segment and Firebase is JSON-shaped, so
        those keep the HIGH "names listed" verdict.
        """
        if provider.startswith("azure") or provider.startswith("firebase"):
            return False, ["provider needs container context — not attempted"]
        target_key = ""
        for key in keys:
            lowered = str(key).lower()
            if any(marker in lowered for marker in sensitive):
                target_key = str(key).strip()
                break
        if not target_key:
            return False, []
        key_url = bucket_url.rstrip("/") + "/" + target_key.lstrip("/")
        try:
            response = await curl(key_url, output="body",
                                  follow_redirects=False, timeout=8)
        except Exception as exc:
            return False, [f"key fetch failed: {exc}"]
        body = response.get("body", "") or ""
        if response.get("status") == 200 and len(body) > 0:
            preview = body[:160].replace("\n", " ")
            return True, [f"GET {key_url} -> HTTP 200, {len(body)} bytes",
                          f"preview: {preview}"]
        return False, [f"GET {key_url} -> HTTP {response.get('status', 0)}"]

    def _generate_candidates(self) -> list:
        prefixes = self.config.get("wordlists", {}).get("bucket_prefixes", [""])
        suffixes = self.config.get("wordlists", {}).get("bucket_suffixes", [""])

        domain_parts = self.domain.replace("-", ".").split(".")
        base_names = []
        for i in range(len(domain_parts) - 1):
            part = domain_parts[i]
            if len(part) > 2:
                base_names.append(part)
        base_names.append("-".join(domain_parts[:-1]))
        base_names.append(self.domain.replace(".", "-"))
        base_names = list(dict.fromkeys(b for b in base_names if b))

        candidates = set()
        for base in base_names:
            candidates.add(base)
            for prefix in prefixes[:8]:
                for suffix in suffixes[:8]:
                    name = f"{prefix}{base}{suffix}".strip("-").strip(".")
                    if name:
                        candidates.add(name.lower())

        # Bucket names the target itself advertises: storage hosts inside
        # discovered URLs, API endpoints and JS files. A bucket referenced
        # by the app outranks the thousandth domain permutation.
        candidates.update(self._candidates_from_assets())

        return sorted(candidates)[:300]

    def _candidates_from_assets(self) -> set:
        """Derive bucket names from storage URLs already in state."""
        import re
        found = set()
        patterns = (
            (re.compile(r"https?://([a-z0-9.-]+?)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.I), 1),
            (re.compile(r"https?://storage\.googleapis\.com/([a-z0-9._-]+)", re.I), 1),
            (re.compile(r"https?://([a-z0-9-]+)\.blob\.core\.windows\.net", re.I), 1),
            (re.compile(r"https?://([a-z0-9.-]+)\.digitaloceanspaces\.com", re.I), 1),
            (re.compile(r"https?://([a-z0-9-]+)\.firebaseio\.com", re.I), 1),
        )
        for asset_type in ("url", "api_endpoint", "js_file", "web_path"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "") or "")
                for pattern, _group in patterns:
                    for match in pattern.finditer(value):
                        name = match.group(1).strip(".").lower()
                        if name and len(name) >= 3:
                            found.add(name)
        return found