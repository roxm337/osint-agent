"""Stage 4: DNS Takeover — dangling CNAMEs with 30+ provider fingerprints."""

from modules.base import BaseModule
from tools.wrappers import dig, curl_with_status


TAKEOVER_PROVIDERS = {
    "aws_s3": {
        "patterns": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": "NoSuchBucket",
        "severity": "HIGH",
    },
    "aws_elastic_beanstalk": {
        "patterns": ["elasticbeanstalk.com"],
        "fingerprint": "NXDOMAIN",
        "severity": "HIGH",
    },
    "aws_cloudfront": {
        "patterns": ["cloudfront.net"],
        "fingerprint": "The request could not be satisfied",
        "severity": "MEDIUM",
    },
    "azure_websites": {
        "patterns": ["azurewebsites.net"],
        "fingerprint": "404 Web Site not found",
        "severity": "HIGH",
    },
    "azure_cloudapp": {
        "patterns": ["cloudapp.net", "cloudapp.azure.com"],
        "fingerprint": "NXDOMAIN",
        "severity": "HIGH",
    },
    "azure_trafficmanager": {
        "patterns": ["trafficmanager.net"],
        "fingerprint": "NXDOMAIN",
        "severity": "HIGH",
    },
    "azure_blob": {
        "patterns": ["blob.core.windows.net"],
        "fingerprint": "The specified container does not exist",
        "severity": "HIGH",
    },
    "github_pages": {
        "patterns": ["github.io"],
        "fingerprint": "There isn't a GitHub Pages site here",
        "severity": "HIGH",
    },
    "heroku": {
        "patterns": ["herokuapp.com", "herokudns.com"],
        "fingerprint": "no-such-app.html",
        "severity": "HIGH",
    },
    "netlify": {
        "patterns": ["netlify.app", "netlify.com"],
        "fingerprint": "Not Found - Request ID",
        "severity": "HIGH",
    },
    "vercel": {
        "patterns": ["vercel.app", "now.sh"],
        "fingerprint": "The deployment you're looking for doesn't exist",
        "severity": "HIGH",
    },
    "shopify": {
        "patterns": ["myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable",
        "severity": "MEDIUM",
    },
    "zendesk": {
        "patterns": ["zendesk.com"],
        "fingerprint": "Oops, this help center no longer exists",
        "severity": "MEDIUM",
    },
    "surge": {
        "patterns": ["surge.sh"],
        "fingerprint": "project not found",
        "severity": "HIGH",
    },
    "unbounce": {
        "patterns": ["unbouncepages.com"],
        "fingerprint": "The requested URL was not found",
        "severity": "MEDIUM",
    },
    "ghost": {
        "patterns": ["ghost.io"],
        "fingerprint": "Failed to resolve DNS",
        "severity": "MEDIUM",
    },
    "tumblr": {
        "patterns": ["tumblr.com"],
        "fingerprint": "Whatever you were looking for doesn't currently exist",
        "severity": "MEDIUM",
    },
    "wordpress_com": {
        "patterns": ["wordpress.com"],
        "fingerprint": "Do you want to register",
        "severity": "MEDIUM",
    },
    "bitbucket": {
        "patterns": ["bitbucket.io"],
        "fingerprint": "Repository not found",
        "severity": "MEDIUM",
    },
    "fastly": {
        "patterns": ["fastly.net"],
        "fingerprint": "Fastly error: unknown domain",
        "severity": "MEDIUM",
    },
    "pantheon": {
        "patterns": ["pantheon.io", "pantheonsite.io"],
        "fingerprint": "404 error unknown site",
        "severity": "HIGH",
    },
    "kinsta": {
        "patterns": ["kinsta.cloud", "kinsta.app"],
        "fingerprint": "No Site For Domain",
        "severity": "HIGH",
    },
    "wix": {
        "patterns": ["wixsite.com"],
        "fingerprint": "Error ConnectYourDomain",
        "severity": "MEDIUM",
    },
    "squarespace": {
        "patterns": ["squarespace.com"],
        "fingerprint": "No Such Account",
        "severity": "MEDIUM",
    },
    "webflow": {
        "patterns": ["webflow.io"],
        "fingerprint": "The page you are looking for doesn't exist",
        "severity": "MEDIUM",
    },
    "readme_io": {
        "patterns": ["readme.io"],
        "fingerprint": "Project doesnt exist",
        "severity": "MEDIUM",
    },
    "helpjuice": {
        "patterns": ["helpjuice.com"],
        "fingerprint": "We could not find what you're looking for",
        "severity": "MEDIUM",
    },
    "desk_com": {
        "patterns": ["desk.com"],
        "fingerprint": "Please try again or try Desk.com free",
        "severity": "MEDIUM",
    },
    "statuspage_io": {
        "patterns": ["statuspage.io"],
        "fingerprint": "You are being redirected",
        "severity": "MEDIUM",
    },
    "intercom": {
        "patterns": ["custom.intercom.help"],
        "fingerprint": "This page is reserved for artistic",
        "severity": "MEDIUM",
    },
    "campaignmonitor": {
        "patterns": ["createsend.com"],
        "fingerprint": "Double check the URL",
        "severity": "MEDIUM",
    },
    "acquia": {
        "patterns": ["acquia-sites.com"],
        "fingerprint": "The site you are looking for could not be found",
        "severity": "HIGH",
    },
    "fly_io": {
        "patterns": ["fly.dev", "fly.io"],
        "fingerprint": "404 Not Found",
        "severity": "MEDIUM",
    },
    "render": {
        "patterns": ["onrender.com"],
        "fingerprint": "Page not found",
        "severity": "MEDIUM",
    },
}


def classify_takeover_risk(cname_answers: list, a_answers: list,
                            body: str = "") -> dict:
    """Classify takeover risk with CNAME + body fingerprint matching."""
    normalized = [str(a).strip().lower().rstrip(".") for a in cname_answers]
    provider = ""
    matched_cname = ""
    fingerprint_matched = False

    for cname in normalized:
        for name, info in TAKEOVER_PROVIDERS.items():
            if any(pattern in cname for pattern in info["patterns"]):
                provider = name
                matched_cname = cname

                # Check body fingerprint if available
                fp = info.get("fingerprint", "")
                if fp and fp.lower() in body.lower():
                    fingerprint_matched = True
                elif fp == "NXDOMAIN" and not a_answers:
                    fingerprint_matched = True

                break
        if provider:
            break

    if not provider:
        return {"risk": False, "provider": "", "matched": "", "reason": ""}

    severity = TAKEOVER_PROVIDERS.get(provider, {}).get("severity", "HIGH")

    if fingerprint_matched:
        return {
            "risk": True,
            "severity": severity,
            "provider": provider,
            "matched": matched_cname,
            "reason": "CNAME + response body fingerprint match",
            "confidence": "HIGH",
        }

    if not a_answers:
        return {
            "risk": True,
            "severity": severity,
            "provider": provider,
            "matched": matched_cname,
            "reason": "Provider CNAME with no A records — likely dangling",
            "confidence": "MEDIUM",
        }

    return {
        "risk": False,
        "provider": provider,
        "matched": matched_cname,
        "reason": "Provider CNAME resolves — not vulnerable",
    }


class DNSTakeover(BaseModule):
    id = "dns_takeover"
    name = "DNS Takeover Checks"
    stage = 4
    detectability = "low"
    depends_on = ["subdomain_enum"]

    async def run(self) -> str:
        self.log("Checking dangling CNAME takeover risk...")

        subdomains = self.state.get_assets_by_type("subdomain")
        candidates = sorted({asset["value"] for asset in subdomains})
        if not candidates:
            self.state.skip_module(self.id, "no subdomains")
            return "skipped"

        checked = 0
        risky = []

        for host in candidates:
            if not self.scope.check(host).allowed:
                continue

            cname = await dig("CNAME", host)
            cname_answers = cname.get("answers", [])
            if not cname_answers:
                continue

            a_result = await dig("A", host)
            a_answers = a_result.get("answers", [])
            checked += 1

            # Fetch body for fingerprint-based detection
            body = ""
            if not a_answers:
                r = await curl_with_status(f"http://{host}")
                body = r.get("body", "")

            risk = classify_takeover_risk(cname_answers, a_answers, body)

            evidence_id = self.state.add_evidence(
                self.id,
                "dns",
                host,
                {
                    "host": host,
                    "cname": cname_answers,
                    "a": a_answers,
                    "body_preview": body[:500],
                    "risk": risk,
                },
            )

            if risk["risk"]:
                risky.append(host)
                self.state.add_finding(
                    title=f"Subdomain Takeover: {host} ({risk['provider']})",
                    severity=risk.get("severity", "HIGH"),
                    confidence="CONFIRMED" if risk.get("confidence") == "HIGH" else "FIRM",
                    category="DNS Exposure",
                    description=(
                        f"{host} has a CNAME pointing to {risk['matched']} "
                        f"({risk['provider']}) which appears unclaimed. "
                        f"Reason: {risk['reason']}"
                    ),
                    evidence=[
                        f"CNAME: {', '.join(cname_answers)}",
                        f"A records: {a_answers or 'none'}",
                        f"Confidence: {risk.get('confidence', 'MEDIUM')}",
                    ],
                    evidence_refs=[evidence_id],
                    remediation=(
                        "Remove the dangling DNS CNAME record, or claim/configure the "
                        "provider resource before an attacker does."
                    ),
                    asset_keys=[f"sub:{host}"],
                )

        self.state.add_asset(
            "dns_takeover_scan",
            f"dns_takeover:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=["dns takeover checks"],
            attrs={
                "checked": checked,
                "risky": len(risky),
                "vulnerable_hosts": risky,
                "providers_checked": len(TAKEOVER_PROVIDERS),
            },
        )
        self.state.complete_module(self.id)
        self.log(
            f"DNS takeover: {len(risky)} vulnerable of {checked} CNAME hosts "
            f"({len(TAKEOVER_PROVIDERS)} providers checked)"
        )
        return "done"
