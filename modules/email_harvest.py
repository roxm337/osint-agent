"""Stage 2: Email Harvesting — page scrape + keyed sources + pattern derivation."""

import re

from modules.base import BaseModule
from tools.external import theharvester_scan, tool_available
from tools.wrappers import curl

# Word-char email regexes match foo@bar.png and version strings. Anchor the
# TLD and deny static-asset tails, example/documentation domains, and
# non-routable names instead of playing suffix whack-a-mole per format.
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
NAME_RE = re.compile(
    r"(?:^|[\s>(])"
    r"([A-Z][a-zéèêëàâäùûüôöîïç]{2,}"
    r"(?:\s[A-Z][a-zéèêëàâäùûüôöîïç-]+){1,2})"
    r"(?=[\s<.,;:()\"]|$)"
)
PHONE_RE = re.compile(r"\+?(?:\d[\s\-.()]?){9,15}\d")

_DENY_TAILS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
    ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
)
_DENY_DOMAINS = (
    # Never legitimate mail hosts. Note: example.* is deliberately NOT
    # here — deny-lists must not contain domains that can themselves be
    # targets; placeholder filtering is a confidence problem.
    "localhost", "local", "invalid", "test", "sentry.io",
    "w3.org", "schema.org", "xml.org",
)
# Version strings the regex admits as locals ("v1.2@", "2.0@").
_VERSION_LOCAL_RE = re.compile(r"^v?\d+(?:\.\d+)+$")
_ROLE_ACCOUNTS = {
    "info", "contact", "support", "sales", "admin", "hello", "team",
    "privacy", "legal", "careers", "jobs", "press", "presse", "media",
    "marketing", "office", "mail", "webmaster", "postmaster", "abuse",
    "security", "noreply", "no-reply", "donotreply", "newsletter",
}

# Cheap, high-yield pages beyond the homepage. Bounded and passive.
_CONTACT_PATHS = (
    "/contact", "/contact-us", "/about", "/about-us", "/team",
    "/imprint", "/impressum", "/legal-notice", "/mentions-legales",
)


class EmailHarvest(BaseModule):
    id = "email_harvest"
    name = "Email Harvest"
    stage = 2
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        self.log(f"Harvesting emails from {self.domain}")

        # 1. Scrape homepage, known webapps, and contact-family pages.
        urls_to_scrape = [self.base_url]
        for asset in self.state.get_assets_by_type("webapp"):
            value = str(asset.get("value", "")).strip()
            if value.startswith(("http://", "https://")) \
                    and value not in urls_to_scrape:
                urls_to_scrape.append(value)
        base = self.base_url.rstrip("/")
        for path in _CONTACT_PATHS:
            candidate = f"{base}{path}"
            if candidate not in urls_to_scrape:
                urls_to_scrape.append(candidate)

        all_emails: dict[str, set[str]] = {}
        all_names: set[str] = set()
        all_phones: set[str] = set()
        for url in urls_to_scrape[:12]:
            try:
                result = await curl(url, output="body", timeout=15)
            except Exception:
                continue
            body = result.get("body", "") or ""
            if result.get("status", 0) not in (200,):
                continue
            for email in _clean_emails(EMAIL_RE.findall(body)):
                all_emails.setdefault(email, set()).add("page scrape")
            for name in NAME_RE.findall(body):
                cleaned = " ".join(name.split())
                if 4 <= len(cleaned) <= 40 and "@" not in cleaned:
                    all_names.add(cleaned)
            for phone in PHONE_RE.findall(body):
                digits = re.sub(r"\D", "", phone)
                if 9 <= len(digits) <= 15:
                    all_phones.add(phone.strip())

        # 2. WP REST API authors/pages when WordPress is in play.
        for path in ("/wp-json/wp/v2/users?per_page=100",
                     "/wp-json/wp/v2/pages?per_page=100"):
            try:
                result = await curl(f"{base}{path}", output="body", timeout=15)
            except Exception:
                continue
            for email in _clean_emails(EMAIL_RE.findall(result.get("body", "") or "")):
                all_emails.setdefault(email, set()).add("wp-json")

        # 3. theHarvester when installed (Bing/DuckDuckGo/crt.sh in one shot).
        if tool_available("theHarvester"):
            try:
                result = await theharvester_scan(self.domain, timeout=180)
            except Exception as exc:
                self.log(f"  theHarvester failed: {exc}")
                result = {"available": False, "emails": [], "hosts": []}
            self.state.add_evidence(
                self.id, "theharvester", self.domain,
                {"available": result.get("available"),
                 "emails": len(result.get("emails", [])),
                 "hosts": len(result.get("hosts", []))},
            )
            for email in _clean_emails(result.get("emails", [])):
                all_emails.setdefault(email, set()).add("theHarvester")
            for host in result.get("hosts", [])[:100]:
                host = str(host).strip().lower()
                if host.endswith(self.domain.lower()):
                    self.state.add_asset(
                        "subdomain", f"sub:{host}", host,
                        confidence="TENTATIVE",
                        sources=["theHarvester"],
                        attrs={"source": "theharvester"},
                    )

        # 4. Hunter.io domain search when keyed: corroborated, often with
        # names and deliverability scores.
        hunter_confirmed: set[str] = set()
        hunter_key = (self.keys.get("hunter") or self.keys.get("hunterio") or "")
        if hunter_key:
            from tools.wrappers import hunter_domain
            try:
                result = await hunter_domain(self.domain, hunter_key)
            except Exception as exc:
                self.log(f"  hunter.io failed: {exc}")
                result = {}
            found = _parse_hunter(result)
            self.state.add_evidence(
                self.id, "hunter", self.domain,
                {"emails": len(found),
                 "pattern": (result.get("data") or {}).get("pattern", "")},
            )
            for email in _clean_emails([item["email"] for item in found]):
                all_emails.setdefault(email, set()).add("hunter.io")
                hunter_confirmed.add(email)

        # 5. Pattern derivation from apex-domain mails only (learning it
        # from third-party senders is how the old code inverted the logic).
        apex = self.domain.lower()
        pattern = _derive_pattern(
            [e for e in all_emails if e.endswith("@" + apex)], apex)

        # 6. Store. Hunter/theHarvester corroboration lifts TENTATIVE scrapes
        # to FIRM; role accounts are still people-adjacent but flagged.
        for email in sorted(all_emails):
            local, _, domain_part = email.partition("@")
            if not domain_part:
                continue
            sources = sorted(all_emails[email])
            confidence = "FIRM" if (
                email in hunter_confirmed or len(sources) > 1
            ) else "TENTATIVE"
            self.state.add_asset(
                "email",
                f"email:{email}",
                email,
                confidence=confidence,
                sources=sources,
                attrs={"domain": domain_part, "local": local,
                       "role_account": local in _ROLE_ACCOUNTS},
            )
            self.state.add_edge(
                f"email:{email}",
                f"domain:{self.domain}",
                "RELATED_TO",
            )

        for name in sorted(all_names)[:50]:
            self.state.add_asset(
                "person", f"person:{name.lower()}", name,
                confidence="TENTATIVE",
                sources=["page scrape"],
                attrs={"source": "team page scrape"},
            )
        for phone in sorted(all_phones)[:30]:
            self.state.add_asset(
                "phone", f"phone:{re.sub(r'\\D', '', phone)}", phone,
                confidence="TENTATIVE",
                sources=["page scrape"],
                attrs={},
            )

        email_domain = _derive_email_domain(list(all_emails))
        self.state.add_asset(
            "email_pattern",
            f"email_pattern:{self.domain}",
            self.domain,
            confidence="FIRM" if pattern != "unknown" else "TENTATIVE",
            sources=["email harvest"],
            attrs={
                "total_emails": len(all_emails),
                "primary_domain": email_domain,
                "pattern": pattern,
                "sample_emails": sorted(list(all_emails))[:20],
            },
        )

        self.state.complete_module(self.id)
        self.log(f"Emails: {len(all_emails)} found | Domain: {email_domain} | "
                 f"Pattern: {pattern} | People: {len(all_names)}")
        return "done"


def _clean_emails(raw: list) -> list:
    """Lowercase, de-duplicate, and drop non-addresses the regex admits."""
    cleaned = []
    seen = set()
    for candidate in raw:
        email = str(candidate or "").lower().strip().strip(".,;:'\"()[]<>")
        if not email or email in seen or "@" not in email:
            continue
        local, _, domain = email.partition("@")
        if not local or not domain or "." not in domain:
            continue
        if _VERSION_LOCAL_RE.match(local):
            continue
        if email.endswith(_DENY_TAILS):
            continue
        if domain in _DENY_DOMAINS or domain.endswith(".local"):
            continue
        seen.add(email)
        cleaned.append(email)
    return cleaned


def _parse_hunter(result: dict) -> list:
    """Pull (email, deliverability) pairs from a Hunter domain-search."""
    if not isinstance(result, dict):
        return []
    data = result.get("data") or {}
    emails = data.get("emails") or []
    found = []
    for entry in emails:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("value", "") or entry.get("email", "")).strip()
        if "@" in address:
            found.append({"email": address,
                          "confidence": entry.get("confidence", 0)})
    return found


def _derive_email_domain(emails: list) -> str:
    """Find the most common email domain."""
    domains = {}
    for email in emails:
        _, _, domain = email.partition("@")
        if domain:
            domains[domain] = domains.get(domain, 0) + 1
    if domains:
        return max(domains, key=domains.get)
    return ""


def _derive_pattern(emails: list, apex_domain: str = "") -> str:
    """Derive the address pattern from apex-domain, non-role mails.

    Needs at least two agreeing samples: one jdoe@ is a data point, two
    are a pattern. Role accounts (info@, support@) carry no pattern.
    """
    votes: dict[str, int] = {}
    for email in emails:
        local, _, domain = email.partition("@")
        if apex_domain and domain.lower() != apex_domain.lower():
            continue
        if not local or local in _ROLE_ACCOUNTS:
            continue
        candidate = _classify_local(local)
        if candidate:
            votes[candidate] = votes.get(candidate, 0) + 1
    if not votes:
        return "unknown"
    best, count = max(votes.items(), key=lambda item: (item[1], item[0]))
    # A pattern needs at least two agreeing samples. One jdoe@ is a data
    # point the email asset already records; calling it a pattern overstates.
    if count < 2:
        return "unknown"
    return best


def _classify_local(local: str) -> str:
    """Map one local part to a pattern name, or '' if it fits none."""
    if "." in local:
        parts = local.split(".")
        if len(parts) == 2 and all(parts) and len(parts[0]) > 1:
            return "{first}.{last}"
    if "-" in local:
        parts = local.split("-")
        if len(parts) == 2 and all(parts):
            return "{first}-{last}"
    if "_" in local:
        parts = local.split("_")
        if len(parts) == 2 and all(parts):
            return "{first}_{last}"
    if len(local) > 2 and local[0].isalpha() and local.isalnum():
        return "{first_initial}{last}"
    return ""
