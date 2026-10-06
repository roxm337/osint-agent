"""Stage 4: Read-only Git exposure triage."""

import re

from core.response_fingerprint import (
    establish_baseline,
    fingerprint,
)
from core.validators import extract_secrets
from modules.base import BaseModule


GIT_PATHS = ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD"]

# What each of these is supposed to look like. `/.git/HEAD` answers with a
# single ref line; `config` with an INI file. Without this, a target that
# serves one 9393-byte index.html for every path passes on `len(body) > 20`
# and the module reports a CRITICAL with `200 /.git/config` as its only
# evidence — a finding that is false in every particular and looks
# authoritative in every particular.
CONTENT_HINTS: dict[str, "re.Pattern[str]"] = {
    "/.git/HEAD": re.compile(r"^ref:\s*refs/", re.M),
    "/.git/config": re.compile(r"^\s*\[(?:core|remote|branch)\]", re.M),
    "/.git/index": re.compile(r"^DIRC", re.M),
    "/.git/logs/HEAD": re.compile(r"^[0-9a-f]{40}\s", re.M),
}


def grade_git_severity(exposed: list[dict]) -> str:
    """Grade by what was actually readable, not by which paths answered.

    An exposed `HEAD` is real source exposure: it names the branch, and paired
    with `objects/` it walks the whole history. An exposed `config` whose only
    content is `[core] repositoryformatversion = 0` discloses nothing useful,
    and CRITICAL for it spends a triager's credibility. A `config` carrying a
    remote URL — especially one with credentials in it — is the real thing.
    """
    paths = {item["path"] for item in exposed}

    if "/.git/HEAD" in paths or "/.git/logs/HEAD" in paths:
        return "HIGH"                       # repo layout and history walkable

    for item in exposed:
        if item["path"] != "/.git/config":
            continue
        body = item.get("preview", "")
        # Credentials in the remote URL are CRITICAL. A bare URL is not: it
        # names the host, the org and the repository, which is real
        # reconnaissance, but it hands over no secret.
        if re.search(r"^\s*(?:url\s*=\s*)?(?:https?|git|ssh|ssh)://"
                     r"[^\s/@]+:[^\s/@]+@", body, re.M):
            return "CRITICAL"
        if re.search(r"^\s*\[remote", body, re.M):
            return "HIGH"
    return "MEDIUM"


class GitExposure(BaseModule):
    id = "git_exposure"
    name = "Git Exposure"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = self.base_url
        exposed = []
        evidence_refs = []
        secrets = []
        rejected = []

        async def probe(path: str):
            result = await self.http_get(f"{base_url}{path}", output="full")
            ct = ""
            for line in str(result.get("headers", "")).splitlines():
                if line.lower().startswith("content-type:"):
                    ct = line.split(":", 1)[1].strip()
                    break
            return (int(result.get("status", 0) or 0),
                    str(result.get("body", "") or ""),
                    ct)

        baseline = await establish_baseline(probe, base_url)
        self.log(f"  baseline: {baseline.describe()}")

        for path in GIT_PATHS:
            status, body, ct = await probe(path)
            if status not in (200, 206):
                continue

            hint = CONTENT_HINTS.get(path)
            if hint is not None and not hint.search(body):
                rejected.append(f"{path}: status {status} but no {path} content")
                continue

            # The catch-all gate. A site that answers every path with the same
            # page has no `.git` directory, whatever the status says.
            if status == 200 and baseline.root is not None:
                if baseline.catch_all(fingerprint(status, body, ct)):
                    rejected.append(f"{path}: status {status} but matches the site default")
                    continue

            exposed.append({"path": path, "status": status, "preview": body[:500]})
            secrets.extend(extract_secrets(body))

        if rejected:
            self.log("  [content-gate] " + "; ".join(rejected))

        if not exposed:
            self.state.skip_module(self.id, "no exposed git metadata")
            return "skipped"

        # Never persist full secret values: evidence files are shared with
        # reports, and a live credential in a JSON artifact is a second
        # exposure. Redacted form only.
        redacted_secrets = [
            {k: v for k, v in secret.items() if k != "value"}
            for secret in secrets
        ]
        evidence_refs.append(
            self.state.add_evidence(
                self.id,
                "git_exposure",
                base_url,
                {"paths": exposed, "secrets": redacted_secrets, "rejected": rejected},
            )
        )

        self.state.add_finding(
            title="Exposed Git Metadata",
            severity=grade_git_severity(exposed),
            confidence="CONFIRMED",
            category="Source Exposure",
            description=(
                "Public .git metadata is accessible. This can allow source reconstruction "
                "or disclosure of repository remotes and commit history."
            ),
            # The preview, not the status. "200 /.git/config" is what a server
            # says when it answers anything; the first line of what it answered
            # is what the reader needs in order to believe this.
            evidence=[
                f"{item['status']} {base_url}{item['path']}: "
                f"{item['preview'].strip().splitlines()[0][:100] if item['preview'].strip() else '(empty)'}"
                for item in exposed
            ]
            + ([f"Rejected as not-{p}: {len(rejected)} path(s) answered but served the "
                "site's own page" for p in ("git",) if rejected]),
            evidence_refs=evidence_refs,
            asset_keys=[f"webapp:{base_url}"],
            remediation="Remove .git from the web root and deny all dot-directory access at the web server.",
            verified=True,
            verification={"method": "git_metadata_content",
                          "url": f"{base_url}{exposed[0]['path']}" if exposed else base_url},
        )

        if secrets:
            from modules.secret_validation import _grade
            plausible = any(
                _grade(secret.get("type", ""), secret.get("value", ""),
                       secret.get("validation", {}))[0] == "plausible"
                for secret in secrets
            )
            # Real-shaped strings inside public git history are HIGH triage,
            # not CRITICAL: nothing here proves a credential works. Docs and
            # example keys are MEDIUM.
            self.state.add_finding(
                title=f"Potential Secrets in Git Metadata: {len(secrets)}",
                severity="HIGH" if plausible else "MEDIUM",
                confidence="FIRM",
                category="Credential Exposure",
                description="Secret patterns were found in publicly accessible Git metadata.",
                evidence=[f"{item['type']}: {item['redacted']}" for item in secrets[:10]],
                evidence_refs=evidence_refs,
                remediation="Rotate exposed credentials and remove secret material from repository history.",
            )

        self.state.add_asset(
            "git_exposure",
            f"git_exposure:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=[self.id],
            attrs={"paths": exposed, "secrets": len(secrets)},
        )
        self.state.complete_module(self.id)
        self.log(f"Git exposure paths: {len(exposed)}")
        return "done"
