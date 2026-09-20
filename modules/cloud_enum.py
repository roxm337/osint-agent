"""Stage 4: Cloud Bucket Enumeration — S3, GCS, Azure, DigitalOcean Spaces."""

import asyncio
from modules.base import BaseModule
from tools.wrappers import curl


# Core providers checked by default.  S3 multi-region variants are resolved by
# the global S3 endpoint so we only probe the canonical URL.
PROVIDER_TEMPLATES = {
    "s3":              "https://{name}.s3.amazonaws.com",
    "gcs":             "https://storage.googleapis.com/{name}",
    "azure":           "https://{name}.blob.core.windows.net",
    "do_nyc3":         "https://{name}.nyc3.digitaloceanspaces.com",
    "do_ams3":         "https://{name}.ams3.digitaloceanspaces.com",
    "firebase":        "https://{name}.firebaseio.com/.json",
    "firebase_storage":"https://firebasestorage.googleapis.com/v0/b/{name}.appspot.com/o",
}

# Per-bucket request timeout.  These are third-party storage endpoints; a
# non-existent bucket 404s in <1s.  Anything slower is a real hit.
_BUCKET_TIMEOUT = 5


class CloudEnum(BaseModule):
    id = "cloud_enum"
    name = "Cloud Bucket Enumeration"
    stage = 4
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log("Enumerating cloud buckets...")

        candidates = self._generate_candidates()
        self.log(f"  Testing {len(candidates)} name candidates across {len(PROVIDER_TEMPLATES)} providers...")

        results = {p: [] for p in PROVIDER_TEMPLATES}
        public_count = 0
        exists_count = 0

        # Use a dedicated semaphore — bucket probes hit third-party CDN endpoints,
        # not the target, so they bypass the global HTTP rate limiter intentionally.
        # 20 concurrent × 5s timeout → 200 cands × 7 providers ≈ 70 requests/slot
        # worst-case wall time ~35s.
        semaphore = asyncio.Semaphore(20)
        total_tasks = len(candidates) * len(PROVIDER_TEMPLATES)
        completed = 0

        async def test_bucket(name, provider, url_template):
            url = url_template.format(name=name)
            async with semaphore:
                # status-only first pass; cheap and fast
                r = await curl(url, output="status", follow_redirects=False,
                               timeout=_BUCKET_TIMEOUT)
            status = r.get("status", 0)
            body = ""
            if status == 200:
                # Fetch body only for confirmed hits to detect directory listings
                rb = await curl(url, output="body", follow_redirects=False,
                                timeout=_BUCKET_TIMEOUT)
                body = rb.get("body", "")
            return name, provider, url, status, body

        tasks = [
            test_bucket(name, provider, template)
            for name in candidates
            for provider, template in PROVIDER_TEMPLATES.items()
        ]

        # Process in batches of 200 so progress is visible and memory stays flat
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

            # Public bucket (directory listing or direct access)
            if status == 200:
                is_listing = (
                    "ListBucketResult" in body
                    or "<?xml" in body
                    or '"items"' in body  # GCS JSON
                    or "Contents" in body
                )
                severity = "CRITICAL" if is_listing else "HIGH"
                public_count += 1

                self.state.add_finding(
                    title=f"Public Cloud Bucket: {name} ({provider.upper().split('_')[0]})",
                    severity=severity,
                    confidence="CONFIRMED",
                    category="Cloud Exposure",
                    description=(
                        f"Cloud bucket '{name}' on {provider} is publicly accessible. "
                        + ("Directory listing enabled — all contents enumerable."
                           if is_listing else "Direct access allowed.")
                    ),
                    evidence=[
                        f"URL: {url}",
                        f"Status: {status}",
                        f"Listing: {is_listing}",
                        f"Preview: {body[:300]}" if body else "",
                    ],
                    remediation="Apply bucket ACL to block public access. Enable Block Public Access settings.",
                )
                results[provider].append({
                    "name": name, "url": url, "status": status,
                    "listing": is_listing,
                })

            elif status == 403:
                # Bucket exists but is private
                exists_count += 1
                results[provider].append({
                    "name": name, "url": url, "status": 403, "private": True
                })
                self.state.add_asset(
                    "bucket",
                    f"bucket:{provider}:{name}",
                    name,
                    confidence="FIRM",
                    sources=["cloud enumeration"],
                    attrs={
                        "provider": provider,
                        "url": url,
                        "status": 403,
                        "private": True,
                    },
                )

            elif status == 301 or status == 302:
                # Redirect — may indicate bucket exists in another region
                exists_count += 1
                self.state.add_asset(
                    "bucket",
                    f"bucket:{provider}:{name}",
                    name,
                    confidence="TENTATIVE",
                    sources=["cloud enumeration"],
                    attrs={"provider": provider, "url": url, "status": status},
                )

            # Firebase-specific: open database
            if "firebase" in provider and status == 200 and '"rules"' not in body:
                self.state.add_finding(
                    title=f"Firebase Database Publicly Readable: {name}",
                    severity="CRITICAL",
                    confidence="CONFIRMED",
                    category="Cloud Exposure",
                    description=(
                        f"Firebase Realtime Database at {url} is publicly readable. "
                        f"All database contents may be accessible."
                    ),
                    evidence=[f"URL: {url}", f"Response preview: {body[:300]}"],
                    remediation="Set Firebase security rules to deny read/write by default.",
                )

        total = sum(len(v) for v in results.values())
        self.state.add_asset(
            "cloud_enum",
            f"cloud_enum:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["cloud enumeration"],
            attrs={
                "total_found": total,
                "public": public_count,
                "private": exists_count - public_count,
                "providers_checked": list(PROVIDER_TEMPLATES.keys()),
                "candidates_tested": len(candidates),
            },
        )

        self.state.complete_module(self.id)
        self.log(f"Cloud: {total} buckets found ({public_count} public, "
                 f"{exists_count} total exists)")
        return "done"

    def _generate_candidates(self) -> list:
        """Generate bucket name candidates from domain + wordlist permutations."""
        prefixes = self.config.get("wordlists", {}).get("bucket_prefixes", [""])
        suffixes = self.config.get("wordlists", {}).get("bucket_suffixes", [""])

        # Base names from domain
        domain_parts = self.domain.replace("-", ".").split(".")
        base_names = []
        for i in range(len(domain_parts) - 1):
            # "example" from "example.com"
            part = domain_parts[i]
            if len(part) > 2:
                base_names.append(part)
        # Also try full domain without TLD: "example-co" from "example.co.uk"
        base_names.append("-".join(domain_parts[:-1]))
        # Full domain slug
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
