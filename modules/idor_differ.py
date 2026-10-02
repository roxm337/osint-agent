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
from urllib.parse import parse_qsl, quote_plus, urlencode, urlparse, urlunparse

from core.auth_harness import AuthHarness, Identity, fingerprint_body
from modules.base import BaseModule

# Statuses that mean "the server actually enforced authorisation".
DENIED_STATUSES = {401, 403}
# Statuses that mean "no such object" — the good outcome.
ABSENT_STATUSES = {404, 410}

# Query parameter names that conventionally carry an object reference.
#
# `order` is absent on purpose: `?order=asc` is a sort direction, while
# `?order_id=` carries a reference. Matching the bare word turned every
# sorted listing into a phantom object endpoint.
_ID_PARAM_HINTS = (
    "id", "uid", "user", "userid", "user_id", "username", "account", "accountid",
    "account_id", "orderid", "order_id", "invoice", "invoiceid", "invoice_id",
    "project", "projectid", "project_id", "ticket", "ticketid", "ticket_id",
    "doc", "docid", "doc_id", "file", "fileid", "file_id", "record", "recordid",
    "record_id", "item", "itemid", "item_id", "org", "orgid", "org_id", "team",
    "teamid", "team_id", "customer", "customerid", "customer_id", "sub", "subid",
    "group", "groupid", "group_id", "workspace", "workspaceid", "workspace_id",
    "session", "sessionid", "session_id", "key", "apikey", "api_key",
    "object_id", "ref", "reference", "uuid", "slug", "code", "number", "refno",
)

# Parameters that never identify an object, whatever their value looks like.
# Without this denylist, `?page=2` and `?limit=50` are mined as object
# references and every one of them becomes a wasted cross-account probe.
_NON_ID_PARAMS = frozenset({
    "page", "pagesize", "page_size", "per_page", "perpage", "limit", "offset",
    "cursor", "start", "count", "size", "from", "to", "since", "until", "after",
    "before", "sort", "order", "orderby", "order_by", "direction", "dir",
    "fields", "include", "expand", "select", "format", "type", "kind", "q",
    "query", "search", "term", "filter", "filters", "where", "sort_by",
    "group_by", "lang", "locale", "callback", "jsonp", "_", "t", "v", "r",
    "nocache", "cachebuster", "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content", "ref_", "source", "version", "v", "debug",
    "verbose", "pretty", "callback_url", "redirect", "next", "return",
})

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

# Resource names probed when reconnaissance found no object URL to derive a
# collection from. Kept to resources that hold per-user data, because that is
# what cross-account testing needs; a public blog post is not worth a probe.
DEFAULT_RESOURCES = (
    "users", "accounts", "orders", "invoices", "payments",
    "subscriptions", "projects", "tasks", "tickets", "documents", "files",
    "reports", "contracts", "customers", "contacts", "leads", "messages",
    "notifications", "workspaces", "organizations", "teams", "members",
    "transactions", "refunds", "shipments", "addresses", "cards", "sessions",
    "devices", "keys", "tokens", "webhooks", "jobs", "assets", "records",
)


@dataclass
class ObjectTemplate:
    """A URL shape with one or more replaceable object references.

    `samples` maps each discovered reference to a concrete URL that contains
    it. Storing one representative URL is not enough: sibling references often
    arrive from different crawled URLs, and a reference that is absent from the
    representative has no reachable URL to request.
    """

    url: str
    url_template: str = ""        # same shape with the reference as `{id}`
    samples: dict = field(default_factory=dict)   # ref -> concrete URL
    kind: str = "unknown"          # "numeric" | "uuid" | "opaque"
    source: str = "discovered"     # discovered | configured | collection

    @property
    def id_values(self) -> set:
        return set(self.samples)

    def url_for(self, ref: str) -> Optional[str]:
        """A concrete URL for `ref`, or None when the shape cannot hold it.

        A sample collected from real traffic is preferred because it carries
        whatever query parameters and casing the application actually serves.
        Failing that, the `{id}` placeholder is filled in directly — without
        this, a reference seen only in a collection body, or a template built
        from `/api/invoices`, could never be probed.
        """
        known = self.samples.get(ref)
        if known:
            return known
        shape = self.url_template or self.url
        if "{id}" in shape:
            return shape.replace("{id}", str(ref))
        return None

    @property
    def key(self) -> str:
        return _template_key(self.url)


@dataclass
class CrossResult:
    """The outcome of one access attempt against an object reference."""

    template: ObjectTemplate
    attacker: str
    victim: str
    object_ref: str
    status: int
    leak_detected: bool
    attributed: bool
    shared_markers: list = field(default_factory=list)
    notes: str = ""
    kind: str = "read"      # read | write | anonymous

    @property
    def severity(self) -> str:
        # A write the server accepted is a data-integrity problem, not just a
        # confidentiality one, and the two are triaged differently.
        if self.kind == "write":
            return "critical"
        if self.kind == "anonymous":
            return "critical" if self.attributed else "medium"
        return "high"


def _describe(result: "CrossResult") -> tuple:
    """Turn a probe outcome into a title, severity, and report body."""
    url = result.template.url
    markers = ", ".join(result.shared_markers[:6]) or "no owner markers present"

    if result.kind == "anonymous":
        return (
            f"Object exposed without authentication: {url}",
            result.severity,
            f"{url} returns HTTP {result.status} to a request carrying no session "
            f"at all. Identifiers present in the response: {markers}. No "
            f"authentication is required to read this record.",
        )

    if result.kind == "write":
        verb = result.notes.split()[0] if result.notes else "Write"
        return (
            f"Cross-account {verb} accepted: {result.attacker} can modify "
            f"{result.victim}'s object via {result.object_ref}",
            result.severity,
            f"{verb} {url} as '{result.attacker}' returned HTTP {result.status} "
            f"for an object owned by '{result.victim}'. The server accepted a "
            f"mutating request against another account's record, so authorisation "
            f"is not enforced on this verb.",
        )

    if result.victim == "unknown":
        return (
            f"IDOR: {result.attacker} can read an unowned record via "
            f"{result.object_ref}",
            result.severity,
            f"Requesting {url} as '{result.attacker}' returned HTTP "
            f"{result.status} for reference {result.object_ref}, which is not "
            f"present in that account's own records. Identifying values in the "
            f"response that belong to neither the requesting account nor the "
            f"error baseline: {markers}. The object belongs to an account that "
            f"was not part of this test, and it was disclosed regardless.",
        )

    return (
        f"IDOR: {result.attacker} can read {result.victim}'s object via "
        f"{result.object_ref}",
        result.severity,
        f"Requesting {url} as '{result.attacker}' returned HTTP {result.status} "
        f"containing data owned by '{result.victim}'. Shared identifying "
        f"markers: {markers}. The account that owns the object is not consulted "
        f"during authorisation.",
    )


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
        if _is_non_id_param(key):
            query.append((key, value))
        elif _looks_like_id(value) and (_is_id_param(key) or _looks_like_opaque(value)):
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
    if low in _NON_ID_PARAMS:
        return False
    return low in _ID_PARAM_HINTS or low.endswith("_id") or low.endswith("id")


def _is_non_id_param(name: str) -> bool:
    return name.lower().replace("-", "_") in _NON_ID_PARAMS


def _looks_like_id(value: str) -> bool:
    if not value or len(value) > 64:
        return False
    return bool(
        _NUMERIC_RE.match(value)
        or _UUID_RE.fullmatch(value)
        or _OPAQUE_RE.match(value)
    )


def _looks_like_opaque(value: str) -> bool:
    """True for a reference too distinctive to be a page number.

    A bare numeric value under an unrecognised parameter name is ambiguous —
    it is far more often a cursor or an offset than an object ID — so it is
    only accepted when it is a UUID or a long opaque token.
    """
    return bool(_UUID_RE.fullmatch(value) or _OPAQUE_RE.match(value))


def _id_kind(value: str) -> str:
    if _NUMERIC_RE.match(value):
        return "numeric"
    if _UUID_RE.fullmatch(value):
        return "uuid"
    return "opaque"


def _swap_id(url: str, old: str, new: str) -> Optional[str]:
    """Return `url` with the object reference `old` replaced by `new`.

    Only the path segment and query value that *are* the reference are
    touched. A blind substring replace is wrong: with `old="7"` it would also
    rewrite the version in `/api/v7/orders/7` and the year in
    `/reports/2017/7`, producing URLs the application never serves and
    poisoning every result that came from them.
    """
    if not old:
        return None

    parsed = urlparse(url)
    segments = parsed.path.split("/")
    changed = False
    for index, segment in enumerate(segments):
        if segment == old:
            segments[index] = new
            changed = True

    pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if value == old and not _is_non_id_param(key):
            pairs.append((key, new))
            changed = True
        else:
            pairs.append((key, value))

    if not changed:
        return None

    query = urlencode(pairs)
    swapped = urlunparse(parsed._replace(path="/".join(segments), query=query))
    return swapped if swapped != url else None


def _absent_ref(ref: str) -> str:
    """A reference of the same shape that is very unlikely to exist.

    Using 0 is not safe: plenty of real datasets own a row with ID 0, and
    comparing against a real object makes a protected endpoint look like it
    leaked. A far-out value of the same kind keeps the comparison honest.
    """
    if _UUID_RE.fullmatch(ref):
        # Reserved values: the nil UUID is a legal identifier that some
        # schemas do hand out, and the max UUID is used as a broadcast
        # address. Both are vanishingly unlikely to be a real record, and
        # either one must never collide with the reference under test.
        nil = "00000000-0000-0000-0000-000000000000"
        if ref == nil:
            return "ffffffff-ffff-ffff-ffff-ffffffffffff"
        return nil
    if _NUMERIC_RE.match(ref):
        return "999999999998" if len(ref) < 12 else "9" * len(ref)
    # Opaque token: same alphabet and length, no realistic collision.
    return ("z" * len(ref))[:64]


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

        await harness.establish_all(self._base_url())
        usable = harness.usable
        for identity in harness.identities.values():
            marker = "verified" if identity.verified else "UNVERIFIED"
            self.log(f"  {identity.name}: {marker} — {identity.verification_note}")

        if not usable:
            self.log("No session survived verification; refusing to guess.")
            return "skipped"

        templates = await self._collect_templates()
        self.log(f"Testing {len(templates)} object endpoint(s) across "
                 f"{len(usable)} account(s)")

        # Ownership first: a cross-account target is only meaningful once we
        # know which references belong to whom.
        collections = await self._discover_collections(harness, templates)
        owned = await self._enumerate_owned(harness, collections)
        total = sum(len(v) for v in owned.values())
        self.log(f"Discovered {len(collections)} collection endpoint(s); "
                 f"attributed {total} object reference(s) to known accounts")

        if not templates:
            # Reconnaissance never surfaced a single object URL, but a
            # collection we just found proves the objects exist. Sibling
            # references are synthesised from the collection path so the run
            # does not return nothing after doing the hard part.
            templates = self._templates_from_collections(collections)
            if templates:
                self.log(f"Synthesised {len(templates)} object endpoint(s) "
                         f"from discovered collections")
            else:
                self.log("No object-reference endpoints found.")
                return "skipped"
        else:
            # Collection-derived shapes are *added*, not held in reserve. The
            # bundle gave 12 object references, which made this branch skip
            # entirely — and the collections the sessions actually enumerate
            # are where the cross-account records live. `/rest/basket/{id}` is
            # never named in the bundle, and it is exactly the one that leaks
            # another account's basket. 1191 references were attributed to
            # known accounts and then never tested, because the only template
            # that could address them had been suppressed.
            extra = self._templates_from_collections(collections)
            if extra:
                seen = {t.url_template or t.url for t in templates}
                added = [t for t in extra
                         if (t.url_template or t.url) not in seen]
                if added:
                    templates = templates + added
                    self.log(f"Added {len(added)} collection-derived object "
                             f"endpoint(s) to {len(seen)} from the bundle")

        # Kept for _self_markers(), which needs a page describing the caller.
        self._templates = list(templates)

        results: list[CrossResult] = []
        for template in templates:
            results.extend(await self._test_reads(harness, template, owned))
        if self._cfg().get("test_anonymous"):
            # Opt-in, and the gate is load-bearing: without it every run
            # quietly starts hitting the target with no credentials at all,
            # which is a different test than the one that was asked for.
            results.extend(await self._test_anonymous(harness, templates, owned))
        if self._write_enabled():
            results.extend(await self._test_writes(harness, templates, owned))

        reported = await self._report(results, harness)
        self.log(f"{reported} finding(s) from {len(results)} probe(s)")
        return "done"

    # ── Phase 1: endpoint discovery ──────────────────────────────

    async def _collect_templates(self) -> list:
        templates: dict[str, ObjectTemplate] = {}

        def add(url: str, source: str = "discovered"):
            for value in _extract_refs(url):
                key = _template_key(url)
                entry = templates.get(key)
                if entry is None:
                    entry = ObjectTemplate(url=url, kind=_id_kind(value), source=source)
                    # A shape with the reference turned back into `{id}`. Without
                    # it, a reference that was only ever seen in a *collection*
                    # body has no reachable URL: reconnaissance commonly observes
                    # `/invoices` but never `/invoices/200`, and every
                    # cross-account probe for that record would be silently
                    # dropped rather than attempted.
                    entry.url_template = _swap_id(url, value, "{id}") or url
                    templates[key] = entry
                # Keep the first URL seen for a reference so a test always
                # requests a URL the target was actually observed to serve.
                entry.samples.setdefault(value, url)

        for asset in self.state.get_assets_by_type("api_endpoint"):
            add(str(asset.get("value", "")), "state")

        for asset in self.state.get_assets_by_type("url"):
            add(str(asset.get("value", "")), "state")

        for url in self._cfg().get("endpoints", []) or []:
            if isinstance(url, str) and url.startswith("http"):
                add(url, "configured")

        # Object-reference templates assembled from a bundle's service classes
        # (`/api/Users/{id}`) carry no observed id, so `add` skips them and the
        # module found nothing to test on a target whose entire
        # access-control surface is of that shape. `url_for` fills `{id}`
        # directly, so a template needs no sample to be probeable.
        for asset in self.state.get_assets_by_type("endpoint"):
            attrs = asset.get("attrs") or {}
            if not attrs.get("object_ref"):
                continue
            template = str(attrs.get("template") or "")
            url = str(asset.get("value") or "")
            if "{id}" not in template or not url.startswith(("http://", "https://")):
                continue
            key = _template_key(template)
            if key in templates:
                continue
            templates[key] = ObjectTemplate(
                url=url, kind="numeric", source="bundle-template",
                url_template=url,
            )

        # A URL with no ID in it is a collection, not an object, so these
        # seeds do not become templates; they feed collection discovery.
        return list(templates.values())

    async def _discover_collections(self, harness: AuthHarness,
                                    templates: list) -> list:
        """Find endpoints that list the caller's own objects.

        Deriving collections only from known object URLs was the module's
        biggest blind spot: when reconnaissance found `/api/v1/invoices` but
        never `/api/v1/invoices/1042`, there was no template to derive it
        from and the run silently produced nothing. Collections are therefore
        sourced three ways — derived from object URLs, derived from every
        known endpoint asset, and probed from a resource wordlist.
        """
        candidates: list = []

        for template in templates:
            candidates.extend(_collection_candidates(template.url))

        for asset in self.state.get_assets_by_type("api_endpoint"):
            candidates.extend(_collection_candidates(str(asset.get("value", ""))))

        base = self._base_url()
        if base:
            candidates.extend(f"{base}{p}" for p in self._cfg().get("collection_paths", []))

        # Probe a bounded resource wordlist so a target whose object URLs were
        # never observed still gets its collections found.
        if self._wordlist_enabled():
            for resource in self._resources():
                for prefix in self._prefixes():
                    candidates.append(f"{base}{prefix}/{resource}")

        object_urls = {t.url for t in templates}
        candidates = [u for u in _dedupe(candidates) if u and u not in object_urls]
        return candidates[: self._collection_cap()]

    def _templates_from_collections(self, collections: list) -> list:
        """Object templates implied by collections that listed real records.

        Only collections that actually returned references are used, so an
        empty, denied, or 404 collection cannot invent an endpoint to probe.
        """
        templates: dict[str, ObjectTemplate] = {}
        for url in collections:
            if not self._owned_by_collection.get(url):
                continue
            url_template = f"{url.rstrip('/')}/{{id}}"
            key = _template_key(url_template)
            if key in templates:
                continue
            templates[key] = ObjectTemplate(
                url=url_template, source="collection",
            )
        return list(templates.values())

    async def _enumerate_owned(self, harness: AuthHarness,
                               collections: list) -> dict:
        """Map each account to the object references it can legitimately see.

        A reference is only useful as a cross-account target if it is known to
        belong to someone. Enumerating each account's own view is what
        produces that mapping, and it is why the harness needs two sessions.
        """
        self._owned_by_collection: dict[str, set] = {}
        owned: dict = {i.name: set() for i in harness.usable}

        # One account's view is enough to start; the second confirms the
        # reference really is private before anything is reported.
        primary = harness.usable[0]

        for url in collections:
            result = await self._fetch(harness, primary, url)
            status = result.get("status", 0)
            if status in DENIED_STATUSES or status in ABSENT_STATUSES or status == 0:
                continue
            body = result.get("body", "") or ""
            # Never treat a login page as an inventory of the account.
            if fingerprint_body(body)["has_login_form"]:
                continue
            refs = _extract_object_ids(body)
            if refs:
                owned[primary.name].update(refs)
                self._owned_by_collection[url] = refs
                self.state.add_asset("idor_collection", f"idor_coll:{url}", url,
                                     confidence="TENTATIVE",
                                     sources=[self.id])

        # Enumerate the remaining accounts too: their references are the
        # cross-account targets, and the difference proves privacy.
        for identity in harness.usable[1:]:
            for url in collections:
                result = await self._fetch(harness, identity, url)
                status = result.get("status", 0)
                if status in DENIED_STATUSES or status in ABSENT_STATUSES or status == 0:
                    continue
                body = result.get("body", "") or ""
                if fingerprint_body(body)["has_login_form"]:
                    continue
                owned[identity.name].update(_extract_object_ids(body))

        return owned

    # ── Phase 3: cross-account testing ───────────────────────────

    async def _test_reads(self, harness: AuthHarness, template: ObjectTemplate,
                          owned: dict) -> list:
        """Cross-account reads, plus bounded probing of unknown references."""
        results: list[CrossResult] = []

        for attacker in harness.usable:
            attacker_own = owned.get(attacker.name, set())
            for victim in harness.usable:
                if victim.name == attacker.name:
                    continue
                victim_own = owned.get(victim.name, set())
                # Only test references that are demonstrably the victim's.
                candidates = sorted(victim_own - attacker_own)
                for ref in candidates[: self._cap()]:
                    target = template.url_for(ref)
                    if not target:
                        continue
                    results.append(await self._cross_fetch(
                        harness, attacker, victim, target, ref,
                    ))

        results.extend(await self._probe_unknown(harness, template, owned))
        return results

    async def _probe_unknown(self, harness: AuthHarness, template: ObjectTemplate,
                             owned: dict) -> list:
        """Test references that belong to no account we control.

        Most real IDOR cannot be shown with two accounts: the interesting
        object belongs to a customer who never agreed to be tested, so no
        reference for it can ever be enumerated. Sequential identifier
        probing covers that case, and attribution works differently here —
        the response must carry ownership markers that belong to neither the
        requester nor the missing-object baseline, which is enough to prove a
        third party's record was disclosed without knowing who they are.

        Disabled by default: it reaches records outside the two supplied
        accounts, so it is opt-in and bounded.
        """
        probing = self._cfg().get("id_probing") or {}
        if not isinstance(probing, dict) or not probing.get("enabled"):
            return []
        if template.kind != "numeric":
            # Sequential arithmetic is meaningless for UUIDs and slugs.
            return []

        attacker = harness.usable[0]
        own = sorted(owned.get(attacker.name, set()), key=_numeric_or_zero)
        if not own:
            return []

        radius = max(0, int(probing.get("radius", 3)))
        budget = max(0, int(probing.get("max", 20)))
        already = {ref for values in owned.values() for ref in values}

        results: list[CrossResult] = []
        for ref in own:
            base_value = int(ref)
            for step in range(1, radius + 1):
                if len(results) >= budget:
                    return results
                for candidate in (base_value + step, base_value - step):
                    text = str(candidate)
                    if candidate < 1 or text in already:
                        continue
                    target = template.url_for(text) or _swap_id(template.url, ref, text)
                    if not target:
                        continue
                    already.add(text)
                    results.append(
                        await self._cross_fetch(harness, attacker, None, target, text)
                    )
        return results

    async def _test_anonymous(self, harness: AuthHarness, templates: list,
                              owned: dict) -> list:
        """Objects readable with no session at all.

        A broken access check is a broken access check regardless of who asks,
        and the no-session case is both the cheapest to test and the most
        damaging. The harness already had a way to issue a sessionless
        request; nothing was calling it.
        """
        results: list[CrossResult] = []
        for template in templates:
            for identity in harness.usable:
                for ref in sorted(owned.get(identity.name, set()))[: self._cap()]:
                    target = template.url_for(ref)
                    if not target:
                        continue
                    result = await self._probe_anonymous(harness, target, ref)
                    if result is not None:
                        results.append(result)
        return results

    async def _probe_anonymous(self, harness: AuthHarness, url: str,
                               ref: str) -> Optional[CrossResult]:
        anonymous = await harness.request_anonymous(url, output="body")
        status = anonymous.get("status", 0)
        body = anonymous.get("body", "") or ""

        if status in DENIED_STATUSES or status in ABSENT_STATUSES or status == 0:
            return None
        if status >= 400:
            return None
        if fingerprint_body(body)["has_login_form"]:
            return None

        absent_url = _swap_id(url, ref, _absent_ref(ref)) or url
        absent = await harness.request_anonymous(absent_url, output="body")
        absent_body = absent.get("body", "") or ""
        if _shape(body, status) == _shape(absent_body, absent.get("status", 0)):
            return None

        markers = sorted(_identity_markers(body) - _identity_markers(absent_body))
        if not markers:
            # Unauthenticated but no personal data in the payload: worth
            # recording, but not a data-disclosure claim.
            return CrossResult(ObjectTemplate(url), "anonymous", "unknown", ref,
                               status, True, False, [],
                               notes="readable unauthenticated, no owner markers",
                               kind="anonymous")

        return CrossResult(ObjectTemplate(url), "anonymous", "unknown", ref,
                           status, True, True, markers[:12],
                           notes="readable with no session", kind="anonymous")

    async def _test_writes(self, harness: AuthHarness, templates: list,
                           owned: dict) -> list:
        """Cross-account write authorisation.

        Reading another user's invoice is bad; overwriting or deleting it is
        worse, and plenty of applications check access on GET but not on the
        mutating verbs. Opt-in, because a successful probe has already changed
        someone's data.
        """
        results: list[CrossResult] = []
        methods = [m.upper() for m in (self._cfg().get("write_methods")
                                       or ["PATCH", "PUT", "DELETE"])]
        attacker = harness.usable[0]
        others = [i for i in harness.usable if i.name != attacker.name]
        attacker_own = owned.get(attacker.name, set())

        for template in templates:
            for victim in others:
                for ref in sorted(owned.get(victim.name, set()) - attacker_own):
                    target = template.url_for(ref)
                    if not target:
                        continue
                    for method in methods:
                        outcome = await self._probe_write(
                            harness, attacker, victim, target, ref, method,
                        )
                        if outcome is not None:
                            results.append(outcome)
                    if not self._destructive_allowed():
                        # Without explicit consent the loop stops probing a
                        # real record after the first verb.
                        break
        return results

    async def _probe_write(self, harness: AuthHarness, attacker: Identity,
                           victim: Identity, url: str, ref: str,
                           method: str) -> Optional[CrossResult]:
        """One mutating verb against a reference the attacker does not own."""
        # PATCH and PUT echo the victim's current representation back, so a
        # successful authorisation check still leaves the record's contents
        # unchanged. DELETE cannot be made safe, so it is only sent when the
        # operator has explicitly allowed destructive testing.
        body = None
        if method in ("PATCH", "PUT"):
            current = await self._fetch(harness, victim, url)
            if current.get("status", 0) >= 400 or not current.get("body"):
                return None
            body = current["body"]
        elif method == "DELETE" and not self._destructive_allowed():
            return None

        kwargs: dict = {"output": "body"}
        if body is not None:
            kwargs["data"] = body
            kwargs["headers"] = {"Content-Type": "application/json"}

        result = await self._fetch_with(harness, attacker.name, url,
                                        method=method, **kwargs)
        status = result.get("status", 0)
        if status in DENIED_STATUSES or status >= 400 or status == 0:
            return None

        # A 200 that is really the login page is a session failure, not access.
        if fingerprint_body(result.get("body", "") or "")["has_login_form"]:
            return None

        return CrossResult(ObjectTemplate(url), attacker.name, victim.name, ref,
                           status, True, True, [],
                           notes=f"{method} accepted on another account's object",
                           kind="write")

    async def _self_markers(self, harness: AuthHarness, identity: Identity) -> set:
        """Identity markers that belong to the requesting account itself.

        Needed to attribute a leak to a third party: without the requester's
        own email and name, any identifier in the response looks like another
        account's data, and that includes identifiers the server simply echoed
        back. Sourced from the account's own object views when no profile
        endpoint is available.
        """
        verify_url = identity.verify_url or self._cfg().get("account_endpoint", "")
        if verify_url:
            result = await self._fetch_with(harness, identity.name, verify_url)
            markers = _identity_markers(result.get("body", "") or "")
            if markers:
                return markers

        for template in getattr(self, "_templates", []) or []:
            result = await self._fetch_with(harness, identity.name, template.url)
            markers = _identity_markers(result.get("body", "") or "")
            if markers:
                return markers
        return set()

    async def _cross_fetch(self, harness: AuthHarness, attacker: Identity,
                           victim: Optional[Identity], url: str,
                           ref: str) -> CrossResult:
        """Test one reference as `attacker` when it belongs to `victim`.

        `victim` is None when the reference belongs to nobody we control — the
        sequential-probing case. Attribution then works against the requester's
        own identity instead: any owner marker in the payload that is not the
        requester's proves a third party's record came back.
        """
        result = await self._fetch(harness, attacker, url)
        status = result.get("status", 0)
        body = result.get("body", "") or ""
        victim_name = victim.name if victim is not None else "unknown"

        # Establish what "no access" looks like for this endpoint, so a 200
        # can be told apart from a soft failure that happens to return one.
        absent_url = _swap_id(url, ref, _absent_ref(ref)) or url
        absent = await self._fetch_with(harness, attacker.name, absent_url)
        absent_body = absent.get("body", "") or ""
        absent_shape = _shape(absent_body, absent.get("status", 0))
        absent_markers = _identity_markers(absent_body)

        def make(leak: bool, attributed: bool, shared=(), note="") -> CrossResult:
            return CrossResult(
                ObjectTemplate(url), attacker.name, victim_name, ref, status,
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
        if not leak:
            return make(False, False, note="indistinguishable from missing object")

        leaked = _identity_markers(body) - absent_markers

        if victim is None:
            # Unknown owner: any owner marker that is not the requester's own
            # belongs to somebody else, which is the disclosure itself. The
            # requester's own identity has to come from a page that describes
            # the *requester* — refetching the unknown object here would
            # compare the response with itself and always find nothing.
            self_markers = await self._self_markers(harness, attacker)
            third_party = sorted(leaked - self_markers)
            if not third_party:
                return make(True, False, note="differs from baseline, no third-party data")
            return make(True, True, third_party,
                        note="discloses another account's object")

        # Gate 3: prove the payload carries the victim's own data. Markers the
        # attacker also sees on the absent-object page are excluded, since
        # they belong to the error page rather than to the leaked record.
        victim_view = await self._fetch(harness, victim, url)
        victim_markers = _identity_markers(victim_view.get("body", "") or "")
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

            dedupe = (result.template.key, result.object_ref, result.kind)
            if dedupe in seen:
                continue
            seen.add(dedupe)

            self.state.add_evidence(
                self.id, f"idor_{result.kind}",
                f"{result.attacker}->{result.victim}:{result.object_ref}",
                {
                    "url": result.template.url,
                    "status": result.status,
                    "kind": result.kind,
                    "notes": result.notes,
                    "victim_markers_leaked": result.shared_markers,
                    "attacker": result.attacker,
                    "victim": result.victim,
                },
            )

            title, severity, description = _describe(result)
            self.state.add_finding(
                title=title,
                severity=severity,
                confidence="CONFIRMED" if result.attributed else "TENTATIVE",
                category="broken-access-control",
                description=description,
                evidence=[f"idor_{result.kind}:{result.object_ref}"],
                remediation=(
                    "Authorise the object against the authenticated principal on "
                    "every request rather than trusting the identifier in the path. "
                    "The same check must run for every HTTP verb, not only GET."
                ),
                verified=result.attributed,
            )
            reported += 1
        return reported

    # ── Helpers ──────────────────────────────────────────────────

    def _base_url(self) -> str:
        """The target's root URL, with a scheme.

        `target.domain` is a bare host by design, and the rest of the toolkit
        hardcodes `https://` around it. Handing that bare host straight to the
        auth harness made every identity fail verification with an
        unparseable-URL error, so the module then reported nothing at all
        without saying why. A configured `base_url` or `scheme` wins, and
        http is used when the target is a bare address such as 127.0.0.1.
        """
        # `raw_url` is what the orchestrator actually dialled, scheme and port
        # included. The fallback below rebuilds the root from `target.domain`,
        # which is host-only by design, so it produced `http://localhost` — port
        # 80, connection refused — and every identity came back UNVERIFIED with
        # the module then declining to guess. Two sessions against
        # `localhost:3000` were impossible until this read `raw_url`.
        #
        # The fallback is still needed: a fixture may configure only
        # `target.domain` as `127.0.0.1:9001`, where there is no scheme at all
        # and https would simply fail to connect.
        for key in ("base_url", "raw_url"):
            configured = str(self.target.get(key) or "").strip()
            if "://" in configured:
                return configured.rstrip("/")

        host = str(self.domain or "").strip().rstrip("/")
        if not host:
            return ""
        if host.startswith(("http://", "https://")):
            return host
        scheme = str(self.target.get("scheme") or "").strip()
        if scheme:
            return f"{scheme}://{host}"
        # A bare IP or localhost is almost always a local fixture, where
        # https would simply fail to connect.
        bare_host = host.split(":")[0]
        if bare_host in ("127.0.0.1", "localhost", "0.0.0.0") or \
                bare_host.replace(".", "").isdigit():
            return f"http://{host}"
        return f"https://{host}"

    def _cap(self) -> int:
        return int(self._cfg().get("max_probes_per_template", 15))

    def _cfg(self) -> dict:
        block = self.module_config.get("idor")
        return block if isinstance(block, dict) else {}

    def _write_enabled(self) -> bool:
        return bool(self._cfg().get("test_write_methods"))

    def _destructive_allowed(self) -> bool:
        return bool(self._cfg().get("allow_destructive"))

    def _wordlist_enabled(self) -> bool:
        return self._cfg().get("probe_collections", True) is not False

    def _collection_cap(self) -> int:
        return int(self._cfg().get("max_collections", 60))

    def _prefixes(self) -> list:
        configured = self._cfg().get("api_prefixes")
        if configured:
            return [str(p) for p in configured]
        return ["/api", "/api/v1", "/api/v2", "/v1", "/rest", ""]

    def _resources(self) -> list:
        """Resource names to try when no collection endpoint is known yet."""
        configured = self._cfg().get("resources")
        if configured:
            return [str(r).strip("/") for r in configured if str(r).strip("/")]
        return list(DEFAULT_RESOURCES)

    async def _fetch(self, harness: AuthHarness, identity: Identity, url: str) -> dict:
        return await self._fetch_with(harness, identity.name, url)

    async def _fetch_with(self, harness: AuthHarness, identity_name: str,
                           url: str, method: str = "GET", **kwargs) -> dict:
        """One request, with telemetry recorded against the right codes.

        A 401 or 403 here is the authorisation layer working as designed, not
        a WAF block. Recording it as one floods the WAF counters with the
        ordinary traffic of a protected API, so the codes that actually
        indicate a WAF (429, 503, and whatever is configured) are the only
        ones counted.
        """
        kwargs.setdefault("output", "body")
        result = await harness.request(identity_name, url, method=method, **kwargs)
        if result.get("status", 0) in self._waf_codes():
            self.state.record_waf_block(url, result["status"])
        return result

    def _waf_codes(self) -> set:
        codes = self.waf_config.get("block_codes") or [429, 503]
        try:
            return {int(c) for c in codes}
        except (TypeError, ValueError):
            return {429, 503}


def _numeric_or_zero(value: str) -> int:
    """Sort key that orders integers numerically and everything else first.

    Sequential probing compares differences between references, so 9 must sort
    before 10 rather than after it.
    """
    return int(value) if str(value).isdigit() else -1


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
    """Object references present in a URL's path or query.

    A query value is only a reference when its *name* says it identifies
    something. Treating every numeric value as a reference mines `?page=2`
    and `?offset=100` as objects, and each one then becomes a cross-account
    probe that can never succeed.
    """
    refs = []
    parsed = urlparse(url)
    for segment in parsed.path.split("/"):
        if _looks_like_id(segment):
            refs.append(segment)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_non_id_param(key):
            continue
        if _looks_like_id(value) and (_is_id_param(key) or _looks_like_opaque(value)):
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


# Field names that identify a record. Deliberately excludes bare `no` and
# `number`: those are as likely to be a line number or an invoice sequence
# that maps to nothing fetchable, and each false reference becomes a probe
# that can only ever 404.
_ID_FIELD_RE = re.compile(r"^(.*_)?(id|uuid|slug|token|ref)$", re.I)


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
