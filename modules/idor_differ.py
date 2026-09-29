"""Broken object-level authorisation differ (IDOR / BOLA).

This is the highest-yield bug class in bug bounty and it was structurally
unreachable before: every other module here runs unauthenticated, so no
module could hold two sessions at once and compare what each one is allowed
to see. `core/auth_harness` supplies the sessions; this module supplies the
comparison.

The design problem is that "200 OK" proves nothing. Endpoints return 200 for
login pages, for empty shells, for soft-deleted records, and for objects that
are genuinely public. Reporting a bare status code produces findings that die
in triage, so every candidate here must survive three independent gates:

  1. ACCESS      — the victim account is denied, or the object is anonymous.
  2. LEAK        — the attacker account's response is distinguishable from
                   both "object missing" and "generic error page".
  3. ATTRIBUTION — the leaked payload demonstrably contains data belonging to
                   the victim, via markers recovered from the victim's own
                   authorised response.

Gate 3 is what separates a report from a guess. Without it, a 200 on
`/api/invoice/1042` looks identical whether the object leaked or not.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qsl, quote_plus, urlparse, urlunparse

from core.auth_harness import AuthHarness, Identity, fingerprint_body
from modules.base import BaseModule

# Statuses that mean "the server actually enforced authorisation".
DENIED_STATUSES = {401, 403}
# Statuses that mean "no such object" — the good outcome.
ABSENT_STATUSES = {404, 410}

# Query parameter names that conventionally carry an object reference.
_ID_PARAM_HINTS = (
    "id", "uid", "user", "userid", "user_id", "username", "account", "accountid",
    "account_id", "order", "orderid", "order_id", "invoice", "invoiceid",
    "project", "projectid", "ticket", "ticketid", "doc", "docid", "file",
    "fileid", "record", "recordid", "item", "itemid", "org", "orgid", "team",
    "teamid", "customer", "customerid", "sub", "subid", "group", "groupid",
    "workspace", "workspaceid", "session", "sessionid", "key", "apikey",
)

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)
_NUMERIC_RE = re.compile(r"^\d{1,12}$")
# Long opaque tokens (slugs, hashes) that are plausible object references.
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

# Keys whose values in a JSON object tend to identify whose data it is.
_OWNER_KEY_HINTS = (
    "email", "e_mail", "username", "user_name", "login", "handle",
    "full_name", "fullname", "first_name", "last_name", "display_name",
    "phone", "ssn", "address", "owner", "owner_id", "user_id", "account_id",
    "customer_email", "billing_email", "contact_email",
)

DEFAULT_PATHS = [
    "/api/v1/users/me", "/api/v1/orders", "/api/v1/invoices",
    "/api/v1/projects", "/api/v1/tickets", "/api/v1/documents",
    "/api/users/me", "/api/orders", "/api/invoices", "/api/profile",
    "/api/me", "/api/v1/me", "/api/v1/account", "/api/account",
]


@dataclass
class ObjectTemplate:
    """A URL shape with one or more replaceable object references.

    `samples` maps each discovered reference to a concrete URL that contains
    it. Storing one representative URL is not enough: sibling references often
    arrive from different crawled URLs, and a reference that is absent from the
    representative has no reachable URL to request.
    """

    url: str
    samples: dict = field(default_factory=dict)   # ref -> concrete URL
    kind: str = "unknown"          # "numeric" | "uuid" | "opaque"
    source: str = "discovered"     # discovered | configured

    @property
    def id_values(self) -> set:
        return set(self.samples)

    def url_for(self, ref: str) -> Optional[str]:
        return self.samples.get(ref)

    @property
    def key(self) -> str:
        return _template_key(self.url)


@dataclass
class CrossResult:
    """The outcome of one cross-account access attempt."""

    template: ObjectTemplate
    attacker: str
    victim: str
    object_ref: str
    status: int
    leak_detected: bool
    attributed: bool
    shared_markers: list = field(default_factory=list)
    notes: str = ""


def _template_key(url: str) -> str:
    """Collapse an object reference to a placeholder so sibling IDs group."""
    parsed = urlparse(url)
    path = parsed.path
    for match in sorted(_UUID_RE.findall(path)):
        path = path.replace(match, "{uuid}")
    path = re.sub(r"/\d{1,12}(?=/|$)", "/{id}", path)
    path = re.sub(r"/[A-Za-z0-9_-]{16,64}(?=/|$)", "/{id}", path)

    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _looks_like_id(value) or _is_id_param(key):
            query.append((key, "{id}"))
        else:
            query.append((key, value))

    # urlencode would escape the braces into %7Bid%7D, which stops sibling
    # URLs from grouping under one key, so the string is built by hand.
    rendered = "&".join(
        f"{key}={value}" if value == "{id}" else f"{key}={quote_plus(str(value))}"
        for key, value in query
    )

    return urlunparse(parsed._replace(
        path=path, query=rendered, fragment="",
    ))


def _is_id_param(name: str) -> bool:
    low = name.lower().replace("-", "_")
    return low in _ID_PARAM_HINTS or low.endswith("_id") or low.endswith("id")


def _looks_like_id(value: str) -> bool:
    if not value or len(value) > 64:
        return False
    return bool(
        _NUMERIC_RE.match(value)
        or _UUID_RE.fullmatch(value)
        or _OPAQUE_RE.match(value)
    )


def _id_kind(value: str) -> str:
    if _NUMERIC_RE.match(value):
        return "numeric"
    if _UUID_RE.fullmatch(value):
        return "uuid"
    return "opaque"


def _swap_id(url: str, old: str, new: str) -> Optional[str]:
    """Return `url` with every occurrence of `old` replaced by `new`.

    Substring replacement is deliberate: the same reference often appears in
    both a path segment and a query parameter, and a partial swap would test
    a URL the application never serves.
    """
    if not old or old not in url:
        return None
    swapped = url.replace(old, new)
    return swapped if swapped != url else None


def _identity_markers(body: str) -> set:
    """Values in a response that plausibly identify whose data it is.

    Only markers that are *specific* count. Generic values like a status
    string or a currency code would match every response and turn the
    attribution gate into noise.
    """
    markers: set = set()

    for email in set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", body or "")):
        markers.add(email.lower())

    payload = _maybe_json(body)
    for key, value in _walk_identifiers(payload):
        markers.add(str(value).strip().lower())

    # Drop values too generic to be evidence of ownership.
    generic = {"", "null", "none", "true", "false", "0", "1", "admin", "user",
               "active", "pending", "usd", "eur", "gbp", "test", "demo"}
    return {m for m in markers if m and len(m) > 3 and m not in generic}


def _walk_identifiers(node: Any, key_hint: str = ""):
    """Yield (key, value) pairs whose key looks ownership-related."""
    if isinstance(node, dict):
        for key, value in node.items():
            low = str(key).lower().replace("-", "_")
            interesting = (
                low in _OWNER_KEY_HINTS
                or any(hint in low for hint in ("email", "name", "owner", "account"))
            )
            if interesting and isinstance(value, (str, int, float)):
                if str(value).strip():
                    yield key, value
            yield from _walk_identifiers(value, low)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_identifiers(item, key_hint)


def _maybe_json(text: str):
    stripped = (text or "").strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None


def _collection_candidates(url: str) -> list:
    """URLs likely to list the caller's own objects.

    Dropping the final path segment is the standard move: `/api/v1/orders/1042`
    implies `/api/v1/orders` lists them. Note that the resource name itself is
    not an object reference, so it must not be trimmed as well — that would
    walk the path all the way back to the root and find nothing.
    """
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    if len(segments) < 2:
        return []

    parent = segments[:-1]
    candidates = [
        urlunparse(parsed._replace(path="/" + "/".join(parent), query="", fragment=""))
    ]
    # For a nested resource such as /orders/1042/items/88 the parent is still
    # an object URL, so the collection above it is worth trying too.
    if len(parent) >= 2 and _looks_like_id(parent[-1]):
        candidates.append(
            urlunparse(parsed._replace(
                path="/" + "/".join(parent[:-1]), query="", fragment=""))
        )
    return candidates


class IdorDiffer(BaseModule):
    id = "idor_differ"
    name = "IDOR / BOLA Differentiator"
    stage = 5
    detectability = "medium"
    depends_on = ["subdomain_enum"]
    active = True

    async def run(self) -> str:
        self.log("Loading identity sessions...")
        harness = AuthHarness(self.config)
        if not harness.identities:
            self.log("No identities in auth.identities — nothing to compare.")
            return "skipped"

        await harness.establish_all(self.domain)
        usable = harness.usable
        for identity in harness.identities.values():
            marker = "verified" if identity.verified else "UNVERIFIED"
            self.log(f"  {identity.name}: {marker} — {identity.verification_note}")

        if not usable:
            self.log("No session survived verification; refusing to guess.")
            return "skipped"

        templates = await self._collect_templates(harness)
        if not templates:
            self.log("No object-reference endpoints found.")
            return "skipped"

        self.log(f"Testing {len(templates)} object endpoint(s) across {len(usable)} account(s)")

        owned = await self._enumerate_owned(harness, templates)
        total_refs = sum(len(v) for v in owned.values())
        self.log(f"Attributed {total_refs} object reference(s) to known accounts")
        if not owned:
            self.log("No account-owned objects discovered — cannot attribute a leak.")
            return "done"

        results: list[CrossResult] = []
        for template in templates:
            results.extend(await self._test_template(harness, template, owned))

        reported = await self._report(results, harness)
        self.log(f"{reported} finding(s) from {len(results)} cross-account probe(s)")
        return "done"

    # ── Phase 1: endpoint discovery ──────────────────────────────

    async def _collect_templates(self, harness: AuthHarness) -> list:
        templates: dict[str, ObjectTemplate] = {}

        def add(url: str, source: str = "discovered"):
            for value in _extract_refs(url):
                key = _template_key(url)
                entry = templates.get(key)
                if entry is None:
                    entry = ObjectTemplate(url=url, kind=_id_kind(value), source=source)
                    templates[key] = entry
                # Keep the first URL seen for a reference so a test always
                # requests a URL the target was actually observed to serve.
                entry.samples.setdefault(value, url)

        for asset in self.state.get_assets_by_type("api_endpoint"):
            add(str(asset.get("value", "")), "state")

        configured = self.module_config.get("idor", {}).get("endpoints", [])
        for url in configured:
            if isinstance(url, str) and url.startswith("http"):
                add(url, "configured")

        # Seed from paths that name a resource, so a run with no prior
        # js_analysis still has something to test.
        base = f"https://{self.domain}"
        for path in DEFAULT_PATHS:
            url = f"{base}{path}"
            if path.endswith("/me") or path.endswith("/account"):
                continue
            add(url, "seeded")

        # A URL with no ID in it is a collection, not an object. Keep it only
        # as a source of ownership evidence, handled in _enumerate_owned.
        return [t for t in templates.values() if t.id_values]

    # ── Phase 2: ownership mapping ───────────────────────────────

    async def _enumerate_owned(self, harness: AuthHarness,
                               templates: list) -> dict:
        """Map each account to the object references it can legitimately see.

        A reference is only useful as a cross-account target if it is known to
        belong to someone. Enumerating each account's own view is what
        produces that mapping, and it is why the harness needs two sessions.
        """
        owned: dict = {i.name: set() for i in harness.usable}

        # Collection endpoints are derived from the object templates, which
        # keeps the request count proportional to what was actually found.
        # The broad path list is a fallback for when nothing was discovered.
        seeds: list = []
        for template in templates:
            seeds.extend(_collection_candidates(template.url))
        if not seeds:
            seeds = [f"https://{self.domain}{p}" for p in DEFAULT_PATHS]

        # Collections that serve no account can never yield an owned
        # reference, so probing them wastes the rate-limit budget.
        seeds = [u for u in _dedupe(seeds) if u not in
                 {t.url for t in templates}]

        for identity in harness.usable:
            for url in seeds:
                result = await self._fetch(harness, identity, url)
                if result.get("status") in DENIED_STATUSES or \
                        result.get("status") in ABSENT_STATUSES or \
                        result.get("status") == 0:
                    continue
                body = result.get("body", "") or ""
                # Never treat a login page as an inventory of the account.
                if fingerprint_body(body)["has_login_form"]:
                    continue
                owned[identity.name].update(_extract_object_ids(body))

        return owned

    # ── Phase 3: cross-account testing ───────────────────────────

    async def _test_template(self, harness: AuthHarness, template: ObjectTemplate,
                             owned: dict) -> list:
        results: list[CrossResult] = []

        for attacker in harness.usable:
            attacker_own = owned.get(attacker.name, set())
            for victim in harness.usable:
                if victim.name == attacker.name:
                    continue
                victim_own = owned.get(victim.name, set())
                # Only test references that are demonstrably the victim's.
                candidates = sorted((victim_own - attacker_own))
                if not candidates:
                    continue

                for ref in candidates[: self._cap()]:
                    target = template.url_for(ref)
                    if not target:
                        continue
                    results.append(await self._cross_fetch(
                        harness, attacker, victim, target, ref,
                    ))
        return results

    async def _cross_fetch(self, harness: AuthHarness, attacker: Identity,
                           victim: Identity, url: str, ref: str) -> CrossResult:
        result = await self._fetch(harness, attacker, url)
        status = result.get("status", 0)
        body = result.get("body", "") or ""

        # Establish what "no access" looks like for this endpoint, so a 200
        # can be told apart from a soft failure that happens to return one.
        absent_url = _swap_id(url, ref, "0")
        absent = await self._fetch(harness, attacker, absent_url or url)
        absent_body = absent.get("body", "") or ""
        absent_shape = _shape(absent_body, absent.get("status", 0))
        absent_markers = _identity_markers(absent_body)

        def make(leak: bool, attributed: bool, shared=(), note="") -> CrossResult:
            return CrossResult(
                ObjectTemplate(url), attacker.name, victim.name, ref, status,
                leak_detected=leak, attributed=attributed,
                shared_markers=list(shared)[:12], notes=note,
            )

        if status in DENIED_STATUSES:
            return make(False, False, note="access denied")
        if status in ABSENT_STATUSES or status == 0:
            return make(False, False, note="no object exposed")

        if fingerprint_body(body)["has_login_form"]:
            return make(False, False, note="200 was a login page")

        # Gate 2: the response must differ from the absent-object response,
        # otherwise a uniform "not found" 200 would read as a leak.
        leak = status < 400 and _shape(body, status) != absent_shape

        # Gate 3: prove the payload carries the victim's own data. Markers the
        # attacker also sees on the absent-object page are excluded, since
        # they belong to the error page rather than to the leaked record.
        victim_view = await self._fetch(harness, victim, url)
        victim_markers = _identity_markers(victim_view.get("body", "") or "")
        leaked = _identity_markers(body)
        shared = sorted((victim_markers & leaked) - absent_markers)

        if not shared:
            return make(leak, False, note="response differs but is unattributed")
        return make(True, True, shared, "attributed to victim")

    # ── Phase 4: reporting ───────────────────────────────────────

    async def _report(self, results: list, harness: AuthHarness) -> int:
        reported = 0
        seen: set = set()

        for result in results:
            if not result.leak_detected:
                continue
            # Attribution is what makes this reportable. A 200 with no proof
            # of whose data it is is logged as evidence, not raised.
            if not result.attributed:
                self.state.add_evidence(
                    self.id, "idor_unattributed",
                    result.template.url,
                    {"attacker": result.attacker, "victim": result.victim,
                     "object": result.object_ref, "status": result.status},
                )
                continue

            dedupe = (result.template.key, result.object_ref)
            if dedupe in seen:
                continue
            seen.add(dedupe)

            self.state.add_evidence(
                self.id, "idor_cross_account",
                f"{result.attacker}->{result.victim}:{result.object_ref}",
                {
                    "url": result.template.url,
                    "status": result.status,
                    "victim_markers_leaked": result.shared_markers,
                    "attacker": result.attacker,
                    "victim": result.victim,
                },
            )

            self.state.add_finding(
                title=(
                    f"IDOR: {result.attacker} can read {result.victim}'s object "
                    f"via {result.object_ref}"
                ),
                severity="high",
                confidence="CONFIRMED" if result.attributed else "TENTATIVE",
                category="broken-access-control",
                description=(
                    f"Requesting {result.template.url} as '{result.attacker}' "
                    f"returned HTTP {result.status} containing data owned by "
                    f"'{result.victim}'. Shared identifying markers: "
                    f"{', '.join(result.shared_markers[:6])}. The account that owns "
                    f"the object is not consulted during authorisation."
                ),
                evidence=[f"idor_cross_account:{result.object_ref}"],
                remediation=(
                    "Authorise the object against the authenticated principal on "
                    "every request rather than trusting the identifier in the path."
                ),
                verified=result.attributed,
            )
            reported += 1
        return reported

    # ── Helpers ──────────────────────────────────────────────────

    def _cap(self) -> int:
        return int(self.module_config.get("idor", {}).get("max_probes_per_template", 15))

    async def _fetch(self, harness: AuthHarness, identity: Identity, url: str) -> dict:
        result = await harness.request(identity.name, url, output="body")
        if result.get("status", 0) in DENIED_STATUSES:
            self.state.record_waf_block(url, result["status"])
        return result


def _dedupe(items) -> list:
    """Order-preserving unique."""
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _shape(body: str, status: int) -> str:
    """A coarse identity for "kind of page", used to spot soft failures."""
    fp = fingerprint_body(body)
    return f"{status}|{fp['digest']}"


def _extract_refs(url: str) -> list:
    """Object references present in a URL's path or query."""
    refs = []
    parsed = urlparse(url)
    for segment in parsed.path.split("/"):
        if _looks_like_id(segment):
            refs.append(segment)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_id_param(key) and _looks_like_id(value):
            refs.append(value)
        elif _looks_like_id(value):
            refs.append(value)
    return refs


def _extract_object_ids(body: str) -> list:
    """Object references visible inside a response body.

    JSON is parsed structurally so `{"order_id": "1042"}` is found reliably;
    a regex alone would also match version strings and timestamps.
    """
    found = set()
    payload = _maybe_json(body)

    if payload is not None:
        for key, value in _walk_ids(payload):
            found.add(value)
    else:
        for match in _UUID_RE.findall(body or ""):
            found.add(match)
        for match in re.findall(r"[?&](?:id|\w*_id|\w*Id)=([^&\s\"'<>]+)", body or ""):
            if _looks_like_id(match):
                found.add(match)

    return [f for f in found if _looks_like_id(f)]


_ID_FIELD_RE = re.compile(r"^(.*_)?(id|uuid|slug|token|ref|number|no)$", re.I)


def _walk_ids(node: Any):
    if isinstance(node, dict):
        for key, value in node.items():
            if _ID_FIELD_RE.match(str(key)) and isinstance(value, (str, int)):
                text = str(value).strip()
                if _looks_like_id(text):
                    yield key, text
            yield from _walk_ids(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_ids(item)
