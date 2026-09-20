"""Stage 4: Read-only Git exposure triage."""

from core.validators import extract_secrets
from modules.base import BaseModule


GIT_PATHS = ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD"]


class GitExposure(BaseModule):
    id = "git_exposure"
    name = "Git Exposure"
    stage = 4
    detectability = "medium"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = f"https://{self.domain}"
        exposed = []
        evidence_refs = []
        secrets = []

        for path in GIT_PATHS:
            url = f"{base_url}{path}"
            if not self.scope.check(url).allowed:
                continue
            result = await self.http_get(url, output="full")
            status = result.get("status", 0)
            body = result.get("body", "")
            if status in (200, 206) and (path.endswith("HEAD") or len(body) > 20):
                exposed.append({"path": path, "status": status, "preview": body[:500]})
                secrets.extend(extract_secrets(body))

        if not exposed:
            self.state.skip_module(self.id, "no exposed git metadata")
            return "skipped"

        evidence_refs.append(
            self.state.add_evidence(
                self.id,
                "git_exposure",
                base_url,
                {"paths": exposed, "secrets": secrets},
            )
        )

        self.state.add_finding(
            title="Exposed Git Metadata",
            severity="CRITICAL" if any(item["path"] == "/.git/config" for item in exposed) else "HIGH",
            confidence="CONFIRMED",
            category="Source Exposure",
            description=(
                "Public .git metadata is accessible. This can allow source reconstruction "
                "or disclosure of repository remotes and commit history."
            ),
            evidence=[f"{item['status']} {base_url}{item['path']}" for item in exposed],
            evidence_refs=evidence_refs,
            asset_keys=[f"webapp:{base_url}"],
            remediation="Remove .git from the web root and deny all dot-directory access at the web server.",
        )

        if secrets:
            self.state.add_finding(
                title=f"Potential Secrets in Git Metadata: {len(secrets)}",
                severity="CRITICAL",
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
