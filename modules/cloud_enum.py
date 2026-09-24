"""Stage 4: Cloud Bucket Enumeration — S3, GCS, Azure, DigitalOcean Spaces."""

import asyncio
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
        for i in range(0, len(tasks), batch_size):
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
                sensitive = self._find_sensitive_markers(keys, body)

                if sensitive:
                    severity = "CRITICAL"
                    critical_count += 1
                    classification = "Sensitive data exposed"
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
                        f"Preview: {body[:200]}",
                    ],
                    remediation=(
                        "Apply bucket ACL to block public access. Enable Block "
                        "Public Access settings. Rotate any credentials present "
                        "in exposed files." if sensitive else
                        "Apply bucket ACL to block public access. Enable Block "
                        "Public Access settings."
                    ),
                    verified=True,
                    verification={
                        "method": "http_200_unauthenticated",
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

    def _find_sensitive_markers(self, keys: list, body: str) -> list:
        found = []
        haystack = (" ".join(keys) + " " + body[:5000]).lower()
        for marker in _SENSITIVE_MARKERS:
            if marker in haystack:
                found.append(marker)
        return found

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

        return sorted(candidates)[:200]