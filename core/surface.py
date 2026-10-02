"""Find the attack surface when nothing has told us where it is.

`--pentest` builds its graph from whatever recon left behind, so on a fresh
target it starts from an empty graph, finds no chains, and reports zero
findings — while looking for all the world like a target with nothing on it.
That is the same "nothing attempted looks like nothing found" failure the probe
planner already had to be taught to avoid, one level up.

A modern single-page application does not advertise its API in HTML links. It
ships one JavaScript bundle, several hundred kilobytes of it, with every
endpoint and query parameter the frontend can reach written into the code. The
target therefore declares its own attack surface; this reads that declaration
rather than guessing at common paths.

Bounded on three axes, because an unbounded crawler over someone else's
JavaScript is both slow and impolite: a script count, a script size, and a
total surface cap.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

# `rest/products/${id}` in a bundle is a path with a hole in it. Kept as a
# literal so it can still be probed, but marked so nothing treats it as a
# confirmed endpoint.
TEMPLATE_VAR = re.compile(r"\$\{[^}]*\}|\{\{[^}]*\}\}")

# A path segment that looks like a route rather than an asset.
API_PATH = re.compile(
    r"""(?P<path>
        (?:rest|api|graphql|graphiql)/        # conventional API prefixes
        [A-Za-z0-9][A-Za-z0-9/_\-.${}]{2,80}
    )""",
    re.VERBOSE,
)

# `?q=${...}`, `?id=1`, `?fields=` — a parameter the frontend actually sends.
QUERY_PARAM = re.compile(
    r"""\?(?P<name>[a-zA-Z_][a-zA-Z0-9_]{0,24})=(?:\$|\{|"|'|\d)""",
)

# `params:{challenge:e}` — a query parameter named in an options object next
# to the path it belongs to. Angular's HttpClient writes its parameters this
# way, and minified code keeps the literal key.
NAMED_PARAMS_OBJECT = re.compile(
    r"""params\s*:\s*\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_]{0,24})\s*:""",
)

# `{params:e}` — the path takes query parameters, but they arrive as a
# variable, so no name is recoverable here. Recorded, because "this endpoint
# is parameterised and I cannot see the names" is a materially different fact
# from "this endpoint takes no parameters", and only the first one justifies
# sending a parameter-discovery module at it.
ANONYMOUS_PARAMS_OBJECT = re.compile(r"""params\s*:\s*(?!\{)""")

# A service's base path, assigned in a class field:
#   host=this.hostServer+`/api/Users`
SERVICE_BASE = re.compile(
    r"""(?P<ident>[A-Za-z_$][A-Za-z0-9_$]{0,20})\s*=\s*(?:this\.)?[A-Za-z0-9_$.\s]{0,24}?\+?\s*"""
    r"""[`"'](?P<path>/(?:rest|api|graphql)[A-Za-z0-9_\-/]*)[`"']""",
)

# ...and the object reference built from it in a sibling method:
#   `${this.host}/${e}`  ->  /api/Users/{id}
#
# The tail runs to the closing quote, not just past the first interpolation.
# `${this.host}/${e}/x/${i}` used to match only `${this.host}/${e}`, which
# yielded `/rest/chat/{id}` — a URL the application never requests. Every
# surface that is invented rather than read costs precision, and this one
# would have shipped a phantom endpoint in the report.
TEMPLATE_OVER_BASE = re.compile(
    r"""\$\{\s*this\.(?P<ident>[A-Za-z_$][A-Za-z0-9_$]{0,20})\s*\}"""
    r"""(?P<tail>[^`'"\\]*)""",
)

# A path segment that is safe to carry through verbatim.
_PLAIN_SEGMENT = re.compile(r"[A-Za-z0-9_.~\-]+")


def _tail_to_path(tail: str) -> str | None:
    """The object-reference path spliced onto a service base, or None.

    Each interpolated segment becomes `{id}`; literal segments are kept. A
    query string is dropped, because it is not part of the reference — the
    endpoint still identifies one object with or without it.
    """
    tail = tail.split("?", 1)[0]
    out: list[str] = []
    for raw in tail.split("/"):
        if not raw:
            continue
        if raw.startswith("${") and raw.endswith("}"):
            out.append("{id}")
        elif _PLAIN_SEGMENT.fullmatch(raw):
            out.append(raw)
        else:
            return None
    return "/" + "/".join(out) if out else None

SCRIPT_SRC = re.compile(
    r"""<script[^>]+src=["'](?P<src>[^"']+\.js)["']""", re.IGNORECASE
)

# Not routes. Bundlers, polyfills, and the favicon are large and say nothing
# about the API.
SKIP_SCRIPTS = re.compile(
    r"(polyfills?|runtime|vendor|chunk|styles?|main\.[0-9a-f]{8,})\.js$",
    re.IGNORECASE,
)


@dataclass
class SurfaceSeed:
    """What the target's own assets said about its attack surface."""
    scripts: list[str] = field(default_factory=list)
    scripts_skipped: list[str] = field(default_factory=list)
    paths: set[str] = field(default_factory=set)
    templated: set[str] = field(default_factory=set)
    query_params: set[str] = field(default_factory=set)
    path_params: dict[str, set[str]] = field(default_factory=dict)
    # Object-reference templates reassembled across a service class body, e.g.
    # `/api/Users/{id}` from `host=…/api/Users` plus `${this.host}/${e}`.
    # These are inferences rather than literals, so they are kept apart from
    # `paths` and carry their provenance. They are the entire broken-access-
    # control surface: without them a target exposes only collections.
    object_templates: set[str] = field(default_factory=set)
    # Paths the frontend calls with query parameters whose names are not in the
    # bundle (`{params:e}`). Not injectable by name, but proof that the
    # endpoint takes parameters at all.
    parameterised_unknown: set[str] = field(default_factory=set)
    truncated: bool = False

    def urls(self, base_url: str, limit: int = 60) -> list[str]:
        """Absolute URLs to probe, most parameterised first.

        Sorted deliberately: a path with a query parameter is a testable
        injection surface, and a bare REST path is much less so. Probing
        `/rest/products/{id}` tells you much less than probing
        `/rest/products/search?q=`.
        """
        scored: list[tuple[int, str]] = []
        for path in self.paths:
            has_param = any(f"{path}?{p}=" for p in self.query_params)
            scored.append((0 if has_param else 1, path))
        scored.sort()
        out: list[str] = []
        for _rank, path in scored[:limit]:
            out.append(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
        return out

    def seeded_params(self, base_url: str) -> list[tuple[str, str, str]]:
        """(url, param, source) triples for paths that declare a parameter.

        Only pairs the bundle actually wrote down. Every path here was found
        next to its own parameter in the same string literal, so the probe is
        aimed at an endpoint the frontend really calls with a value it really
        controls.
        """
        pairs: list[tuple[str, str, str]] = []
        for path, params in sorted(self.path_params.items()):
            if path in self.templated:
                continue
            for param in sorted(params):
                pairs.append((
                    urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
                    param,
                    f"declared in bundle: {path}?{param}=",
                ))
        return pairs

    def object_refs(self, base_url: str, limit: int = 40) -> list[tuple[str, str]]:
        """`(url, template)` for every derived object reference.

        `{id}` is left in the URL deliberately. A placeholder is a claim that
        something is differentiated here; substituting a guessed `1` turns that
        into a claim about a specific record, which is a different and much
        stronger thing to assert. The consumer fills the hole with an id it
        has reason to believe exists.
        """
        out: list[tuple[str, str]] = []
        for tpl in sorted(self.object_templates)[:limit]:
            out.append((urljoin(base_url.rstrip("/") + "/", tpl.lstrip("/")), tpl))
        return out

    def summary(self) -> dict:
        return {
            "scripts_fetched": len(self.scripts),
            "scripts_skipped": len(self.scripts_skipped),
            "api_paths": len(self.paths),
            "templated_paths": len(self.templated),
            "injectable_params": sorted(
                {f"{p}?{q}=" for p, ps in self.path_params.items() for q in ps}
            ),
            "object_templates": sorted(self.object_templates),
            "parameterised_names_unknown": sorted(self.parameterised_unknown),
            "truncated": self.truncated,
        }


def derive_from_service_bases(source: str) -> tuple[set[str], set[str]]:
    """Object-reference templates assembled across a class body.

    A minified Angular service does not write the object URL in one piece. It
    stores a base in a field and splices the identifier on in a method:

        class o{host=this.hostServer+`/api/Users`;
                get(e){return this.http.get(`${this.host}/${e}`)}}

    Read literally, that yields two fragments the extractor can do nothing
    with: the collection path `/api/Users`, and an id with no path attached.
    So the whole of the object-reference surface — the one class that matters
    most for broken access control — is invisible, and every endpoint looks
    like a collection with nothing to differentiate.

    Returns `(derived_templates, parameterised_paths)`. A derived template is
    an inference, not a literal, and is labelled as one by the caller rather
    than mixed in with paths the bundle wrote down.
    """
    # The identifier is not unique. Every minified service class names its own
    # field `host`, so a dict keyed on the identifier collapses twenty classes
    # into whichever was assigned last, and `/api/Users` disappears behind
    # `/rest/chat`. Scope by position instead: a class field is assigned
    # before the methods that use it, so the nearest preceding assignment of
    # the same name is the one this template belongs to.
    bases: list[tuple[int, str, str]] = sorted(
        (m.start(), m.group("ident"), m.group("path").rstrip("/"))
        for m in SERVICE_BASE.finditer(source)
    )
    by_ident: dict[str, list[tuple[int, str]]] = {}
    for pos, ident, path in bases:
        by_ident.setdefault(ident, []).append((pos, path))

    derived: set[str] = set()
    if not bases:
        return derived, set()

    def base_for(pos: int, ident: str) -> str | None:
        candidates = by_ident.get(ident, [])
        chosen = None
        for apos, apath in candidates:
            if apos < pos:
                chosen = apath
            else:
                break
        return chosen

    # Every occurrence of `${this.<ident>}` spliced with at least one further
    # segment is an object reference against that service's collection.
    for match in TEMPLATE_OVER_BASE.finditer(source):
        base = base_for(match.start(), match.group("ident"))
        if base is None:
            continue
        suffix = _tail_to_path(match.group("tail"))
        if suffix is None or suffix == "/":
            # `${this.host}` alone is just the collection, not a reference.
            continue
        derived.add(base + suffix)

    # `{params:e}` next to a base path: parameterised, names not recoverable.
    parameterised: set[str] = set()
    for pos, ident, path in bases:
        window = source[pos:pos + 400]
        if ANONYMOUS_PARAMS_OBJECT.search(window):
            parameterised.add(path)

    return derived, parameterised


def extract_from_script(source: str) -> tuple[set[str], set[str], dict[str, set[str]]]:
    """Paths and their declared query parameters, from one JavaScript bundle.

    Returns `(paths, templated_paths, path_params)`. The association is kept
    per path rather than pooled, because a pooled parameter list cannot say
    which endpoint accepts it.

    Templated paths are split out because `/rest/basket/${e}` and
    `/rest/basket/1` are not the same endpoint, and only the second is a claim
    worth probing.
    """
    paths: set[str] = set()
    templated: set[str] = set()
    path_params: dict[str, set[str]] = {}

    for match in API_PATH.finditer(source):
        path = match.group("path").rstrip(".,;'\"")
        if TEMPLATE_VAR.search(path):
            templated.add(path)
            continue
        paths.add(path)
        found = _params_in_same_literal(source, match.end())
        if found:
            path_params.setdefault(path, set()).update(found)

    return paths, templated, path_params


def _params_in_same_literal(source: str, from_pos: int, window: int = 160) -> set[str]:
    """Query parameters declared alongside one API path, in the same literal.

    The naive reading — collect every `?name=` in the bundle, then offer them
    to every path — is how a tool ends up claiming it can inject into
    `/rest/captcha?q=`. That combination was never written by anybody; it is
    two unrelated fragments of a minified bundle counted together.

    A frontend writes an endpoint and its parameters in one string literal:
    `"/rest/products/search?q=${term}"`. So the association is read from that
    literal, and the search stops at the boundary that ends it. A parameter
    seen somewhere else in the file is not attributed to this path, because
    there is no evidence that it is.
    """
    out: set[str] = set()
    end = min(len(source), from_pos + window)
    for match in QUERY_PARAM.finditer(source, from_pos, end):
        # Stop at anything that ends the string literal. A `?` in a following
        # expression belongs to a different URL, not to this one.
        between = source[from_pos:match.start()]
        if any(boundary in between for boundary in ('"', "'", "`", ";", "\n")):
            break
        out.add(match.group("name"))
    return out


def script_urls_from_html(html: str, base_url: str) -> list[str]:
    """Every script the page actually loads, in document order."""
    out: list[str] = []
    for match in SCRIPT_SRC.finditer(html):
        out.append(urljoin(base_url, match.group("src")))
    return out


async def seed_surface(fetch_text, home_url: str, *,
                       max_scripts: int = 4,
                       max_script_bytes: int = 4_000_000,
                       max_paths: int = 120) -> SurfaceSeed:
    """Read the surface out of the target's own assets.

    `fetch_text` is `async (url) -> (status, body)`, so the caller keeps its
    own HTTP client and the seeder cannot drift from how the rest of the
    engagement reaches the target. A `fetch_text` that raises is treated as a
    failed fetch rather than a fatal error: a target that serves a broken
    bundle should degrade to "no surface found", not to a crash.
    """
    seed = SurfaceSeed()

    try:
        status, html = await fetch_text(home_url)
    except Exception:  # noqa: BLE001 - seeding is best-effort by design
        return seed
    if status != 200 or not html:
        return seed

    candidates = script_urls_from_html(html, home_url)
    for url in candidates:
        if SKIP_SCRIPTS.search(urlparse(url).path):
            seed.scripts_skipped.append(url)
            continue
        if len(seed.scripts) >= max_scripts:
            seed.truncated = True
            continue
        try:
            status, body = await fetch_text(url)
        except Exception:  # noqa: BLE001
            continue
        if status != 200 or not body:
            continue
        if len(body) > max_script_bytes:
            seed.truncated = True
            continue
        seed.scripts.append(url)
        paths, templated, path_params = extract_from_script(body)
        seed.paths |= paths
        seed.templated |= templated
        for path, params in path_params.items():
            seed.path_params.setdefault(path, set()).update(params)
            seed.query_params |= params

        objects, param_unknown = derive_from_service_bases(body)
        seed.object_templates |= objects
        seed.parameterised_unknown |= param_unknown

    if len(seed.paths) > max_paths:
        # Keep the shortest paths: they are the leaves, and a leaf is
        # something you can actually request. `/rest/admin/users` beats
        # `/rest/admin/users/2fa/setup/disable` when you can only afford one.
        seed.paths = set(sorted(seed.paths, key=len)[:max_paths])
        seed.templated = set(sorted(seed.templated, key=len)[:max_paths])
        seed.truncated = True

    if len(seed.object_templates) > max_paths:
        seed.object_templates = set(sorted(seed.object_templates, key=len)[:max_paths])
        seed.truncated = True

    return seed
