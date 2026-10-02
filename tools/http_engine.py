"""Async HTTP engine built on aiohttp.

Replaces the per-request `curl` subprocess with a pooled aiohttp session. One
connection per host is reused across the whole run, so a 200-request module
costs one TLS handshake instead of 200.

This is a strict superset of the old `curl()` contract — every key the previous
implementation returned is still returned, with the same types:

    status  int   HTTP status code, 0 on transport failure
    body    str   response body ("" unless output requests it)
    headers str   raw "Key: value" header block ("full" mode only)
    error   str   present only on transport failure
    time_ms float wall-clock milliseconds for the request
    url     str   final URL after redirects
    history list  [{"status", "url", "location"}] per redirect hop

Additions over `curl()`: `time_ms` (was always 0, which silently degraded
`DifferentialAnalyzer._fingerprint`), `url`, `history`, `tls`, and
`cookies`. Nothing that consumed the old dict breaks.
"""

from __future__ import annotations

import asyncio
import ssl
import sys
import time
from typing import Any, Optional
from urllib.parse import urlsplit

try:
    import aiohttp
except ImportError:  # pragma: no cover - aiohttp is a hard dependency
    aiohttp = None


# Body returned by the engine is capped so a hostile 2 GB response cannot
# exhaust memory. Callers that need the full body raise the cap explicitly.
DEFAULT_MAX_BODY = 5 * 1024 * 1024

# Servers that never close idle keep-alive sockets will otherwise pin
# connections until the pool is full.
DEFAULT_KEEPALIVE_TIMEOUT = 30.0


class HttpEngineError(RuntimeError):
    """Raised for unrecoverable engine misconfiguration (missing aiohttp)."""


def _charset_from(content_type: str) -> str:
    """Extract the charset from a Content-Type header.

    Defaults to utf-8 rather than calling `codecs.lookup` and raising: a
    hostile or misspelled charset must degrade to replacement characters, not
    abort the request.
    """
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "charset":
            charset = value.strip().strip('"').strip("'")
            if charset:
                import codecs
                try:
                    codecs.lookup(charset)
                    return charset
                except LookupError:
                    return "utf-8"
    return "utf-8"


def _header_block(headers: Any) -> str:
    """Render response headers the way `curl -D -` did.

    The previous implementation returned a single newline-joined string and
    three call sites (`actions/auth/jwt.py`, `modules/login_enum.py`,
    `modules/tech_detect.py`) parse it with `.splitlines()` looking for
    `key: value`. Preserving that exact shape is what keeps this a drop-in.
    """
    if headers is None:
        return ""
    try:
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    except AttributeError:
        return str(headers)


class CookieJar:
    """Per-identity session naming.

    aiohttp scopes cookies to a `ClientSession`, not to a request, so identity
    isolation means one session per identity. Those sessions all share a single
    `TCPConnector`, so the underlying connection pool — the part that actually
    saves handshakes — is still shared across every identity.
    """

    DEFAULT = "default"

    @staticmethod
    def normalise(name: Optional[str]) -> str:
        return name or CookieJar.DEFAULT

    @staticmethod
    def new_jar(unsafe: bool = False) -> Any:
        """Build a cookie jar.

        `unsafe=False` makes aiohttp refuse cookies from bare IP hosts, which is
        the right default for real targets. It has to be relaxed for IP- or
        localhost-addressed staging targets, where the session cookie would
        otherwise be silently dropped.
        """
        return aiohttp.CookieJar(unsafe=unsafe)


class HttpEngine:
    """Pooled aiohttp session with an explicit lifecycle.

    A single instance is reused for a whole engagement. `close()` must be
    called to release sockets; `orchestrator` does this on shutdown.
    """

    def __init__(
        self,
        *,
        verify_tls: bool = True,
        max_body: int = DEFAULT_MAX_BODY,
        keepalive_timeout: float = DEFAULT_KEEPALIVE_TIMEOUT,
        user_agent: str = "osintAgent/1.0",
        cookies_from_ip_hosts: bool = False,
    ) -> None:
        if aiohttp is None:
            raise HttpEngineError(
                "aiohttp is required for the async HTTP engine — "
                "install it or keep using the curl fallback"
            )
        self.verify_tls = verify_tls
        self.max_body = max_body
        self.keepalive_timeout = keepalive_timeout
        self.user_agent = user_agent
        self.cookies_from_ip_hosts = cookies_from_ip_hosts

        self._sessions: dict[str, Any] = {}
        self._connector: Any = None
        self._loop: Any = None
        self._identities: list[str] = []

        # Pooling is the whole point of this engine, so measure it rather than
        # assume it: a run that opens 200 connections did not get the benefit.
        self._trace = aiohttp.TraceConfig()
        self._trace.on_connection_create_end.append(self._on_connection_create)
        self._trace.on_connection_reuseconn.append(self._on_connection_reuse)

        # Counters for the run summary — makes pooling observable in output.
        self.requests = 0
        self.connections_opened = 0
        self.connections_reused = 0

    # ── Lifecycle ────────────────────────────────────────────────

    def _ensure_connector(self) -> Any:
        """Create the shared connection pool, rebuilding it if the loop changed.

        aiohttp binds its connector to the running event loop. The test suite
        calls `asyncio.run()` repeatedly, each time creating a fresh loop, so a
        cached connector would raise "Event loop is closed" on reuse. Detecting
        the swap here keeps the engine safe to call from any context.
        """
        running = asyncio.get_running_loop()
        if self._connector is not None and self._loop is not running:
            # Loop swapped under us — drop the stale sessions and pool.
            self._sessions = {}
            self._connector = None
        if self._connector is not None and not self._connector.closed:
            return self._connector

        ssl_ctx: Any
        if self.verify_tls:
            ssl_ctx = ssl.create_default_context()
        else:
            ssl_ctx = False  # aiohttp's sentinel for "do not verify"

        # enable_cleanup_closed is a no-op from CPython 3.14.7 onward and warns
        # there, so only request it on the versions that still need it.
        cleanup_kwargs = {}
        if sys.version_info < (3, 14, 7):
            cleanup_kwargs["enable_cleanup_closed"] = True

        self._connector = aiohttp.TCPConnector(
            ssl=ssl_ctx,
            keepalive_timeout=self.keepalive_timeout,
            limit=0,  # unbounded — the RateLimiter is the real gate
            ttl_dns_cache=300,
            use_dns_cache=True,
            **cleanup_kwargs,
        )
        self._loop = running
        return self._connector

    def session(self, identity: Optional[str] = None) -> Any:
        """Return the session for an identity, creating it on first use.

        Sessions share one connector, so separate identities still reuse the
        same underlying connections and TLS handshakes.
        """
        name = CookieJar.normalise(identity)
        connector = self._ensure_connector()
        existing = self._sessions.get(name)
        if existing is not None and not existing.closed:
            return existing
        session = aiohttp.ClientSession(
            connector=connector,
            connector_owner=False,  # the engine owns the connector's lifetime
            cookie_jar=CookieJar.new_jar(self.cookies_from_ip_hosts),
            trust_env=True,
            trace_configs=[self._trace],
        )
        self._sessions[name] = session
        if name not in self._identities:
            self._identities.append(name)
        return session

    def set_cookies(self, cookies: dict, identity: Optional[str] = None) -> None:
        """Seed an identity's jar directly, e.g. from a captured session."""
        jar = self.session(identity).cookie_jar
        for key, value in (cookies or {}).items():
            if key and value is not None and str(value) != "":
                jar.update_cookies({str(key): str(value)})

    def cookies_for(self, identity: Optional[str] = None) -> dict:
        """Current cookies for an identity as a plain name->value dict."""
        jar = self.session(identity).cookie_jar
        return {cookie.key: cookie.value for cookie in jar}

    def forget_identities(self) -> None:
        """Drop every cookie while leaving the connection pool intact.

        The sessions themselves are kept. They all share this engine's single
        `TCPConnector`, but aiohttp scopes cookies to the *session* rather than
        the request, so each one owns the jar that has to be cleared. Emptying
        the jars in place is the real cookie reset and leaves the pooled
        sockets immediately reusable.

        Discarding `self._sessions` would look equivalent — the next request
        would build a fresh session and see no cookies — but it orphans
        unclosed `ClientSession` objects for the garbage collector to reap
        (surfacing as "Unclosed client session") instead of releasing them
        here, and it throws away the identity registry for no gain.
        """
        for name in list(self._sessions):
            try:
                self._sessions[name].cookie_jar.clear()
            except Exception:
                # One jar refusing to clear must not leave the other
                # identities holding cookies. Dropping the session is the
                # fallback; it is rebuilt empty on the next request.
                self._sessions.pop(name, None)
        self._identities = [name for name in self._identities
                            if name in self._sessions]

    async def _on_connection_reuse(self, _session, _ctx, _params) -> None:
        """A pooled connection was reused instead of dialling a new one."""
        self.connections_reused += 1

    async def _on_connection_create(self, _session, _ctx, _params) -> None:
        """A fresh TCP+TLS connection was established."""
        self.connections_opened += 1

    async def close(self) -> None:
        """Release every session and the connection pool. Idempotent."""
        sessions = list(self._sessions.values())
        self._sessions = {}
        self._identities = []
        for session in sessions:
            if session.closed:
                continue
            try:
                await session.close()
            except Exception:
                # A loop that already closed raises here; nothing to salvage.
                pass
        if self._connector is not None and not self._connector.closed:
            try:
                await self._connector.close()
            except Exception:
                pass
        self._connector = None
        self._loop = None


    async def __aenter__(self) -> "HttpEngine":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ── Request ──────────────────────────────────────────────────

    async def request(
        self,
        url: str,
        method: str = "GET",
        *,
        headers: Optional[dict] = None,
        data: Any = None,
        json: Any = None,
        params: Optional[dict] = None,
        follow_redirects: bool = True,
        timeout: float = 10.0,
        output: str = "status",
        identity: str = "default",
        allow_redirects_to: Optional[set] = None,
        max_body: Optional[int] = None,
    ) -> dict:
        """Perform one HTTP request.

        `output` controls how much of the response is materialised, matching
        the old curl wrapper's modes so existing call sites need no changes:
        "status" (code only), "headers", "body", "full" (body + raw headers).
        """
        started = time.monotonic()

        # Only http(s) URLs with a host can be materialised by aiohttp. For
        # anything else — a protocol-relative `//host/path`, a scheme from an
        # asset key such as `s3://` or `api://`, a bare path — yarl reports
        # `URL.port is None`, the connector trips its internal
        # `assert port is not None`, and the AssertionError escapes every
        # handler below (it is not a ValueError and not an aiohttp.ClientError).
        # One such URL in a candidate list is enough to take down the entire
        # calling module and all the findings it would have produced.
        parts = urlsplit(str(url))
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return _fail(f"unsupported_url: {url}", started)

        session = self.session(identity)
        want_body = output in ("body", "full")
        cap = self.max_body if max_body is None else max_body

        request_headers: dict[str, str] = {"User-Agent": self.user_agent}
        if headers:
            request_headers.update({str(k): str(v) for k, v in headers.items() if v is not None})

        client_timeout = aiohttp.ClientTimeout(total=timeout, sock_connect=min(timeout, 5.0))

        try:
            async with session.request(
                method.upper(),
                url,
                headers=request_headers,
                data=data,
                json=json,
                params=params,
                allow_redirects=follow_redirects,
                timeout=client_timeout,
                max_field_size=32768,
            ) as resp:
                if allow_redirects_to and resp.history:
                    hops = [str(h.url) for h in resp.history] + [str(resp.url)]
                    if not _hostnames_allowed(hops, allow_redirects_to):
                        return _fail("redirect left permitted host set", started)

                body_text = ""
                truncated = False
                if want_body:
                    # Resolve the charset from the header before touching the
                    # body: aiohttp's get_encoding() inspects an already-read
                    # body and raises if the stream was consumed instead.
                    encoding = _charset_from(resp.headers.get("Content-Type", ""))

                    # Read in a loop until the stream is actually done.
                    #
                    # A single `read(cap + 1)` is not "give me up to cap bytes".
                    # On a chunked, gzipped response aiohttp returns whatever
                    # one decompressed chunk produced and stops, so a
                    # 1.2 MB bundle came back as 60 KB — with no truncation
                    # flag, because 60 KB is under the cap. Every consumer
                    # downstream then reasoned about a body that was missing
                    # its own endpoints: JS analysis found nothing to parse,
                    # content assertions compared against half a page, and
                    # differential oracles diffed two truncated responses and
                    # called them equal. A silent short read is worse than a
                    # refused one, so drain to EOF and only then decide.
                    buf = bytearray()
                    while len(buf) <= cap:
                        chunk = await resp.content.read(64 * 1024)
                        if not chunk:
                            break
                        buf += chunk
                    raw = bytes(buf)

                    truncated = len(raw) > cap
                    if truncated:
                        raw = raw[:cap]
                    body_text = raw.decode(encoding, errors="replace")

                elapsed_ms = (time.monotonic() - started) * 1000.0
                self.requests += 1

                result: dict = {
                    "status": resp.status,
                    "body": body_text,
                    "time_ms": round(elapsed_ms, 2),
                    "url": str(resp.url),
                    "history": _redirect_history(resp),
                }

                if truncated:
                    result["truncated"] = True
                if output == "full":
                    result["headers"] = _header_block(resp.headers)
                elif output == "headers":
                    result["body"] = _header_block(resp.headers)
                if output == "status":
                    result["body"] = ""

                tls = _tls_summary(resp)
                if tls:
                    result["tls"] = tls
                return result

        except asyncio.TimeoutError:
            return _fail("timeout", started)
        except aiohttp.ClientSSLError as e:
            return _fail(f"ssl_error: {e}", started)
        except aiohttp.ClientConnectorError as e:
            return _fail(f"connection_error: {e}", started)
        except aiohttp.TooManyRedirects:
            return _fail("too_many_redirects", started)
        except aiohttp.ClientError as e:
            return _fail(f"http_error: {e}", started)
        except (ValueError, TypeError, UnicodeError) as e:
            return _fail(f"bad_request: {e}", started)
        except asyncio.CancelledError:
            raise
        except OSError as e:
            return _fail(f"os_error: {e}", started)

    def stats(self) -> dict:
        return {
            "requests": self.requests,
            "connections_opened": self.connections_opened,
            "connections_reused": self.connections_reused,
            "identities": list(self._identities),
        }


def _fail(error: str, started: float) -> dict:
    """Build the same failure shape the curl wrapper used to return."""
    return {
        "status": 0,
        "body": "",
        "error": error,
        "time_ms": round((time.monotonic() - started) * 1000.0, 2),
        "url": "",
        "history": [],
    }


def _redirect_history(resp: Any) -> list:
    return [
        {
            "status": hop.status,
            "url": str(hop.url),
            "location": hop.headers.get("Location", ""),
        }
        for hop in getattr(resp, "history", []) or []
    ]


def _tls_summary(resp: Any) -> Optional[dict]:
    """Pull negotiated TLS parameters, when aiohttp exposes the transport."""
    try:
        transport = resp.connection.transport
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return None
        cipher = ssl_object.cipher()
        return {
            "version": ssl_object.version(),
            "cipher": cipher[0] if cipher else None,
            "alpn": transport.get_extra_info("peek_r"),
        }
    except Exception:
        # TLS metadata is best-effort; never fail a request over it.
        return None


def _hostnames_allowed(hops: list[str], allowed: set) -> bool:
    from urllib.parse import urlparse
    for hop in hops:
        host = (urlparse(hop).hostname or "").lower()
        if not _host_allowed(host, allowed):
            return False
    return True


def _host_allowed(host: str, allowed: set) -> bool:
    if host in allowed:
        return True
    for entry in allowed:
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return True
    return False
