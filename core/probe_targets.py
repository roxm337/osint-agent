"""Shared injection-point builder for testing modules.

Every active module used to mine its own points from its own favourite
asset types, which is how sqlmap ended up testing youtube.com and
`localhost:/8094` while `/rest/products/search?q=` sat untested in a
different asset table. One builder, one scope rule, every module.

A point is {"url", "param", "method", "source", "json_body"}. `url` may
carry an `{id}` path placeholder — `inject_param` fills those in place.
`json_body` lists body parameter names for POST/PUT/PATCH endpoints;
modules that only speak query strings ignore it.
"""

from urllib.parse import parse_qsl, urlparse

from core.validators import is_public_target


# Marker fragments our own probes leave in URLs. Crawlers record every
# URL they visit — including the ones earlier modules injected payloads
# into — and without this filter the graph treats a DOM-XSS probe URL
# as discovered attack surface and proposes probing the probe.
PROBE_MARKERS = (
    "osintxss", "hxprobe", "domxss", "redirect-probe", "hopefully404",
    "zz74x74zz", "zzz_no_such", "zxqseed9k", "onload=", "onerror=",
    "javascript:", "<svg", "<iframe", "%60", "`",
)


def is_probe_garbage(url: str) -> bool:
    """Was this URL manufactured by our own testing, not discovered?"""
    lowered = str(url or "").lower()
    if "${" in lowered:
        return True
    return any(marker in lowered for marker in PROBE_MARKERS)


def _scope_hosts(base_url: str, domain: str) -> tuple:
    """(hosts, port_or_None): what counts as the same app."""
    try:
        parsed = urlparse(base_url)
        base_host = (parsed.hostname or "").lower()
        base_port = parsed.port
    except ValueError:
        return set(), None
    hosts = {h for h in (base_host, domain.lower()) if h}
    return hosts, base_port


def in_scope_url(url: str, base_url: str, domain: str) -> bool:
    """Same app, parseable, no third-party embeds or misbuilds."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return False
    if not host:
        return False
    hosts, base_port = _scope_hosts(base_url, domain)
    if host not in hosts and not any(
            host == h or host.endswith("." + h) for h in hosts if h):
        return False
    if not is_public_target(domain) and base_port is not None:
        scheme_default = 443 if parsed.scheme == "https" else 80
        if (port or scheme_default) != base_port:
            return False
    return True


def iter_probe_points(state, base_url: str, domain: str,
                      max_points: int = 200) -> list:
    """Yield deduplicated (url, param, method, source, json_body) points."""
    points = []
    seen = set()

    def emit(url: str, param: str, method: str, source: str,
             json_body: list | None = None):
        if not url or not param:
            return
        key = (url, param, method)
        if key in seen:
            return
        seen.add(key)
        points.append({"url": url, "param": param, "method": method,
                       "source": source,
                       "json_body": list(json_body or [])})

    # 1. Parameter assets (crawl-mined, seeded, or swagger-derived).
    for asset in state.get_assets_by_type("parameter"):
        attrs = asset.get("attrs", {}) or {}
        url = str(attrs.get("url", "") or "").strip()
        param = str(asset.get("value", "") or "").strip()
        if not url or not param or not in_scope_url(url, base_url, domain):
            continue
        method = str(attrs.get("method", "GET") or "GET").upper()
        emit(url, param, method, "parameter_asset")

    # 2. Swagger-derived api_endpoint assets: query params plus methods.
    for asset in state.get_assets_by_type("api_endpoint"):
        url = str(asset.get("value", "") or "").strip()
        if not url or not in_scope_url(url, base_url, domain):
            continue
        attrs = asset.get("attrs", {}) or {}
        methods = [m for m in (attrs.get("methods") or ["GET"])
                   if m in ("GET", "POST", "PUT", "PATCH", "DELETE")]
        spec_params = attrs.get("params", []) or []
        query_params = [str(p).split(":", 1)[-1] for p in spec_params
                        if str(p).startswith("query:")]
        path_params = [str(p).split(":", 1)[-1] for p in spec_params
                        if str(p).startswith("path:")]
        body_params = [str(p).split(":", 1)[-1] for p in spec_params
                        if str(p).split(":", 1)[0] in ("body", "formData")]
        # {id} templates: inject_param fills path placeholders in place.
        if "{id}" in url or "{Id}" in url:
            for method in methods or ["GET"]:
                emit(url, "id", method, "swagger_template", body_params)
        for param in query_params:
            for method in methods or ["GET"]:
                emit(url, param, method, "swagger_param", body_params)
        # Bare query string already on the URL.
        try:
            query = urlparse(url).query
        except ValueError:
            query = ""
        for name, _ in parse_qsl(query, keep_blank_values=True):
            for method in methods or ["GET"]:
                emit(url, name, method, "swagger_url", body_params)
        # JSON-body endpoints with no query params: body-only points.
        if body_params and not query_params and "{id}" not in url:
            for method in methods:
                if method in ("POST", "PUT", "PATCH"):
                    emit(url, body_params[0], method, "swagger_body",
                         body_params)

    # 3. Crawled URLs carrying their own query strings.
    for asset_type in ("url", "endpoint", "web_path"):
        for asset in state.get_assets_by_type(asset_type):
            url = str(asset.get("value", "") or "").strip()
            if not url or not in_scope_url(url, base_url, domain):
                continue
            try:
                query = urlparse(url).query
            except ValueError:
                continue
            for name, _ in parse_qsl(query, keep_blank_values=True):
                emit(url, name, "GET", asset_type)

    # 4. Raw target URL itself, when parameterized.
    raw = str(base_url or "").strip()
    if raw:
        try:
            query = urlparse(raw).query
        except ValueError:
            query = ""
        for name, _ in parse_qsl(query, keep_blank_values=True):
            emit(raw, name, "GET", "raw_target")

    return points[:max_points]
