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

    def summary(self) -> dict:
        return {
            "scripts_fetched": len(self.scripts),
            "scripts_skipped": len(self.scripts_skipped),
            "api_paths": len(self.paths),
            "templated_paths": len(self.templated),
            "injectable_params": sorted(
                {f"{p}?{q}=" for p, ps in self.path_params.items() for q in ps}
            ),
            "truncated": self.truncated,
        }


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

    if len(seed.paths) > max_paths:
        # Keep the shortest paths: they are the leaves, and a leaf is
        # something you can actually request. `/rest/admin/users` beats
        # `/rest/admin/users/2fa/setup/disable` when you can only afford one.
        seed.paths = set(sorted(seed.paths, key=len)[:max_paths])
        seed.templated = set(sorted(seed.templated, key=len)[:max_paths])
        seed.truncated = True

    return seed
