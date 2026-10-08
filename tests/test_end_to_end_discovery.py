"""A fresh target must reach a real finding, or say why it did not.

Every test in `test_probe_planner.py` hands the graph a URL. That is the right
unit test and the wrong integration test: the real failure was never that the
planner mishandled a URL it was given, it was that on a target nobody had
handed anything to, the planner had no URL to work from and the run printed
"0 chains" as though the application were empty.

These tests cover the path end to end with nothing supplied: a bundle on the
server, and a graph built from what that bundle says.

The two bugs they exist to pin down, both of which were found by running the
real thing rather than by reading it:

  * `tools/http_engine.py` read a response body with a single
    `read(cap + 1)`. On a chunked, gzipped body aiohttp returns one
    decompressed chunk and stops, so a 1.2 MB bundle arrived as 60 KB with no
    truncation flag. Every consumer then reasoned about a body that was
    missing its own endpoints.
  * The planner accepted `url`/`parameter`/`api_endpoint` nodes while the
    seeder wrote `endpoint` nodes, so 48 seeded endpoints produced zero
    considered surfaces and no explanation.
"""

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.attack_graph import AttackGraph
from core.surface import extract_from_script, script_urls_from_html, seed_surface
from modules import MODULE_REGISTRY
from state.manager import StateManager

# A cut-down version of a real SPA bundle: an ES module that imports a chunk,
# declares two REST paths, and pairs one of them with a parameter.
BUNDLE = """
import{a as r}from"./rolldown-runtime-BoHGiXSq.js";
const t=async(e)=>{const n=await fetch("/rest/products/search?q="+e);return n.json()};
const u="/api/Products";
const v="/rest/basket/${id}/checkout";
"""

PAGE = '<html><script src="polyfills.js"></script><script src="main.js"></script></html>'


def run(coro):
    return asyncio.run(coro)


def _graph_from_seed(seed, base="http://localhost:3000"):
    """Build a graph the way the orchestrator does after seeding."""
    st = StateManager(str(Path(tempfile.mkdtemp()) / "run" / "localhost"))
    for url, param, _source in seed.seeded_params(base):
        st.add_asset(asset_type="endpoint", key=url, value=url,
                     confidence="CONFIRMED", sources=["surface-seed"],
                     attrs={"url": url, "param": param})
    for url in seed.urls(base, limit=40):
        st.add_asset(asset_type="endpoint", key=url, value=url,
                     confidence="CONFIRMED", sources=["surface-seed"],
                     attrs={"url": url})
    g = AttackGraph(st)
    g.build()
    return g


def _seeder_with(fake):
    async def fetch_text(url):
        return fake.get(url, (404, ""))
    return fetch_text


# --- the surface reader --------------------------------------------------

def test_script_urls_are_read_in_document_order():
    urls = script_urls_from_html(PAGE, "http://localhost:3000")
    assert urls == ["http://localhost:3000/polyfills.js",
                    "http://localhost:3000/main.js"], \
        "scripts must resolve against the page they were loaded from"


def test_templated_paths_are_kept_out_of_the_probeable_set():
    """`/rest/basket/${id}` is not an endpoint anyone can request."""
    paths, templated, _pp = extract_from_script(BUNDLE)
    assert "api/Products" in paths
    assert "rest/basket/${id}/checkout" in templated
    assert "rest/basket/${id}/checkout" not in paths, \
        "a path with a hole in it must not be offered as a real endpoint"


def test_a_parameter_is_only_attributed_to_its_own_path():
    """The reason the seeder reads string literals, not the whole file.

    `?q=` belongs to `/rest/products/search`. Offering it to `/api/Products`
    is a pair no developer ever wrote, and probing it is how a tool ends up
    reporting that it can inject into an endpoint that has no such parameter.
    """
    paths, _templated, path_params = extract_from_script(BUNDLE)
    assert path_params.get("rest/products/search") == {"q"}
    assert "q" not in path_params.get("api/Products", set()), \
        "q must not be paired with a path it was never declared on"


# --- seeding from nothing ----------------------------------------------

def test_seeder_reads_the_target_bundle():
    fake = {
        "http://localhost:3000/": (200, PAGE),
        "http://localhost:3000/main.js": (200, BUNDLE),
        "http://localhost:3000/polyfills.js": (200, "var a=1"),
    }
    seed = run(seed_surface(_seeder_with(fake), "http://localhost:3000/"))
    assert "rest/products/search" in seed.paths
    assert seed.summary()["injectable_params"] == ["rest/products/search?q="]


def test_seeder_on_a_dead_target_is_silent_not_fatal():
    """A target that serves nothing must not abort the run."""
    async def boom(url):
        raise ConnectionRefusedError(url)
    seed = run(seed_surface(boom, "http://localhost:3000/"))
    assert not seed.paths and not seed.scripts


def test_seeder_respects_its_script_budget():
    page = "".join(f'<script src="chunk{i}.js"></script>' for i in range(50))
    fake = {"http://localhost:3000/": (200, page)}
    for i in range(50):
        fake[f"http://localhost:3000/chunk{i}.js"] = (200, '"/rest/x%d"' % i)
    seed = run(seed_surface(_seeder_with(fake), "http://localhost:3000/",
                            max_scripts=3))
    assert len(seed.scripts) == 3
    assert seed.truncated, "hitting the limit must be recorded, not hidden"


# --- the wiring that actually broke -------------------------------------

def test_seeded_endpoints_are_testable_by_the_planner():
    """The 48-endpoints / 0-surfaces bug.

    The seeder writes `endpoint` nodes. The planner used to accept only
    `url`, `parameter` and `api_endpoint`, so every seeded endpoint was
    skipped and the run printed nothing at all — no probe, no reason, no
    finding, which is indistinguishable from a clean application.
    """
    seed = run(seed_surface(
        _seeder_with({
            "http://localhost:3000/": (200, PAGE),
            "http://localhost:3000/main.js": (200, BUNDLE),
            "http://localhost:3000/polyfills.js": (200, "var a=1"),
        }),
        "http://localhost:3000/"))
    g = _graph_from_seed(seed)
    proposed = g.propose_test_edges(risk_ceiling="MEDIUM")
    assert proposed, "a seeded (url, param) pair must be proposed for probing"
    assert g.probe_plan["surfaces_considered"] > 0
    assert proposed[0].action_id == "web.sqli.detect"


def test_a_proposed_probe_becomes_a_chain_the_executor_can_run():
    """`find_chains` multiplied likelihood by impact and dropped it.

    A proposed edge scores 0.3 * 0.9 = 0.27, under the 0.3 floor, so the
    planner proposed a probe and the chain search then discarded it: the run
    reported "1 probe proposed / 0 chains / 0 actions run".
    """
    from orchestrator import AttackPath
    seed = run(seed_surface(
        _seeder_with({
            "http://localhost:3000/": (200, PAGE),
            "http://localhost:3000/main.js": (200, BUNDLE),
            "http://localhost:3000/polyfills.js": (200, "var a=1"),
        }),
        "http://localhost:3000/"))
    g = _graph_from_seed(seed)
    proposed = g.propose_test_edges(risk_ceiling="MEDIUM")
    chains = [AttackPath(nodes=[g.nodes[e.source_id], g.nodes[e.target_id]],
                         edges=[e], score=e.likelihood * e.impact)
              for e in proposed]
    assert chains, "proposed edges must survive into something executable"
    from core.chain_executor import ChainExecutor
    planned = ChainExecutor(g.state, {}).plan(chains[0])
    assert planned, "the executor must be able to arm the seeded probe"
    assert planned[0].params.get("url")
    assert planned[0].params.get("param") == "q"


def test_executor_node_lookup_survives_the_real_attackpath_shape():
    """`AttackPath.nodes` is a list, and `_node` called `.get()` on it.

    Every chain raised `AttributeError: 'list' object has no attribute 'get'`
    at the first thing execution does, so no proposed chain had ever been
    run — the crash was the only thing that made it visible.
    """
    from core.attack_graph import AttackNode, AttackPath as AP
    from core.chain_executor import ChainExecutor
    src = AttackNode(id="a", label="http://t/r?s=1", node_type="url",
                     confidence="CONFIRMED")
    chain = AP(nodes=[src], edges=[])
    assert ChainExecutor._node("a", chain) is src
    assert ChainExecutor._node("missing", chain) is None
    # And the dict shape still works, for the hand-built chains in older tests.
    assert ChainExecutor._node("a", AP(nodes={"a": src}, edges=[])) is src


# --- the engine bug that hid all of this --------------------------------

def test_gzipped_chunked_bodies_are_read_to_completion():
    """A short read was being reported as a whole body.

    The engine called `read(cap + 1)` once. Against a chunked gzipped
    response aiohttp hands back one decompressed chunk and stops, so a
    1.2 MB bundle came back as 60 KB — below the cap, so no truncation flag,
    so every downstream consumer believed it had read the whole file.
    """
    from tools import http_engine

    MARKER = b"rest/products/search"
    full = b"x" * 700_000 + MARKER + b"y" * 500_000

    # What the live bug produced: 1,207,722 bytes on the wire, 60,084 handed
    # back. The response is served `Content-Encoding: gzip` with
    # `Transfer-Encoding: chunked` and no `Content-Length`, so there is no
    # header telling the client how much is coming — it just stops early, and
    # the caller has to notice.
    FIRST_READ = 60_084

    class _Content:
        """Stands in for `resp.content` on a gzipped chunked stream.

        Returns whatever one decompressed chunk holds and ignores the size it
        was asked for. That is not a misbehaving fake: it is what aiohttp
        actually did here, which is why `read(len(full))` handed back 60 KB of
        a 1.2 MB body and reported no error.
        """

        def __init__(self, chunks):
            self.chunks = list(chunks)

        async def read(self, _n):
            return self.chunks.pop(0) if self.chunks else b""

    chunks = [full[:FIRST_READ]] + [full[i:i + 65536]
                                    for i in range(FIRST_READ, len(full), 65536)]
    assert len(chunks) > 2, "fixture must span several reads"

    async def single_read():
        """What the engine used to do: one read, then assume that was all."""
        return await _Content(chunks).read(len(full))

    async def drain():
        """What it does now: read until the stream says it is done."""
        content = _Content(chunks)
        buf = bytearray()
        while True:
            chunk = await content.read(65536)
            if not chunk:
                break
            buf += chunk
        return bytes(buf)

    # A single read sees the beginning of the file and stops. Under `cap`, so
    # no truncation flag is set, so every consumer believed it had the whole
    # body — and the endpoint it needed was not in it.
    short = run(single_read())
    assert len(short) == FIRST_READ, "one read returns one chunk, not the file"
    assert len(short) < len(full), "the short read is not the whole body"
    assert len(short) < http_engine.DEFAULT_MAX_BODY, \
        "under the cap, which is why the truncation flag stayed False"
    assert MARKER not in short, \
        "the endpoint must be in the part that a single read misses"

    # Draining gets the whole thing, marker included.
    assert run(drain()) == full, "draining must recover the whole body"
    assert http_engine.DEFAULT_MAX_BODY >= len(full)


# --- the scheme/port bug that silenced every module ----------------------

def test_base_url_preserves_the_port_and_scheme():
    """25 modules built `https://{domain}`, which drops the port.

    `target.domain` is a hostname. Anything not on 443 was dialled on 443,
    so against `localhost:3000` every module fetched nothing and reported an
    empty result that looked identical to "nothing to find".
    """
    from orchestrator import Orchestrator
    import tempfile
    for typed, expected in [
        ("localhost:3000", "http://localhost:3000"),
        ("http://localhost:3000", "http://localhost:3000"),
        ("https://euro2c.com", "https://euro2c.com"),
        # A bare hostname stays HTTPS: that is what public targets are, and
        # what this codebase assumed before.
        ("euro2c.com", "https://euro2c.com"),
        ("[::1]:8080", "http://[::1]:8080"),
    ]:
        o = Orchestrator(target=typed, output_dir=tempfile.mkdtemp(),
                         config_path="config.example.yaml", mode="auto")
        assert o.base_url == expected, \
            f"{typed!r} must resolve to {expected}, got {o.base_url}"


def test_modules_receive_the_resolved_url_not_the_users_literal():
    """The CLI must normalise before modules read `target.raw_url`.

    `-t localhost:3000` put the scheme-less string in the config. A module
    that works when called directly then reported 0 files analysed under the
    CLI, which reads as "the target has no JavaScript" rather than "the
    module dialled the wrong port".
    """
    from orchestrator import Orchestrator
    import tempfile
    o = Orchestrator(target="localhost:3000", output_dir=tempfile.mkdtemp(),
                     config_path="config.example.yaml", mode="auto")
    tgt = o.config["target"]
    assert tgt["raw_url"] == "http://localhost:3000"
    assert tgt["scheme"] == "http"
    assert tgt["target_input"] == "localhost:3000", "keep what the user typed"

    from modules.base import BaseModule
    class M(BaseModule):
        pass
    m = M(o.state, o.config)
    assert m.base_url == "http://localhost:3000", \
        "a module must resolve the same URL the CLI did"


def test_base_url_tolerates_a_bare_string_target():
    """Some tests overwrite `module.target` with a URL string."""
    from modules.base import BaseModule
    from state.manager import StateManager
    import tempfile
    class M(BaseModule):
        pass
    m = M(StateManager(tempfile.mkdtemp()),
          {"target": {"domain": "example.test", "base_url": "https://example.test"}})
    m.target = "https://example.test"          # a string, not a dict
    assert m.base_url == "https://example.test"


# --- the guess-path gate that found the SPA's own HTML ------------------

SHELL = ('<html><head><title>App</title></head><body><div id="root"></div>'
         '<script src="main.js"></script></body></html>')
SHELL_BUNDLE = 'const search="/rest/products/search?q=";fetch(search+term);'


def test_a_catch_all_shell_is_not_mistaken_for_a_javascript_bundle():
    """`status == 200 and "function" in body` passes on every SPA path.

    The gate ran before this on `/app.js`, `/bundle.js` and `/js/main.js` of a
    target that serves none of them: each returned the site's catch-all
    shell, which contains the word "function" in a boot script, so each was
    collected and analysed as source.

    Driven by a fake fetch rather than the live target, so the assertion is
    about the gate's logic and not about what a particular server is serving
    today.
    """
    from core.response_fingerprint import establish_baseline, fingerprint

    async def fetch(path):
        # Everything resolves to the shell except the real bundle.
        body = SHELL_BUNDLE if path.endswith("main.js") else SHELL
        return 200, body, "text/html"

    baseline = run(establish_baseline(fetch, "http://t/"))
    assert baseline.root is not None and baseline.control_paths >= 2

    # What `/app.js` actually returns: the shell, with a JavaScript content
    # type because that is what the page asked for.
    shell = fingerprint(200, SHELL, "application/javascript")
    assert baseline.catch_all(shell), "the catch-all shell must be recognised"

    real = fingerprint(200, SHELL_BUNDLE, "application/javascript")
    assert not baseline.catch_all(real), "a real bundle must not be condemned"


def test_an_empty_baseline_condemns_nothing():
    """No root means no opinion.

    `catch_all` must not be usable as a gate when there is nothing to compare
    against. Callers are expected to check `baseline.root` first; this pins
    the reason that matters.
    """
    from core.response_fingerprint import Baseline, fingerprint

    baseline = Baseline()
    assert not baseline.catch_all(fingerprint(200, SHELL, "text/html"))
    assert baseline.root is None


# --- severity has to describe the leak, not the filename ---------------

def test_severity_follows_the_content_not_the_path_name():
    """`/.git/config` is CRITICAL in the rule table. It is not always CRITICAL.

    A `.git/config` containing only `[core] repositoryformatversion = 0`
    discloses nothing an anonymous visitor could not already infer from the
    host being on GitHub at all. Grading it CRITICAL is the sort of inflation
    that gets a correct report sent back unread — the sibling of the bug this
    file keeps hitting, one level up: treating the name of an artifact as
    proof of what it contains.
    """
    from modules.fast_exposure_scan import content_graded_severity as grade
    G = r"/\.git/(config|HEAD|refs)"
    E = r"/\.env"

    for body, want, why in [
        ("[core]\n\trepositoryformatversion = 0\n", "LOW", "structure only"),
        # A bare remote URL names the host, the org and the repo. That is real
        # reconnaissance, but it hands over no secret, so it is HIGH and not
        # CRITICAL — the top of the scale is for credentials in the URL.
        ('[remote "origin"]\n\turl = https://github.com/a/b.git\n',
         "HIGH", "remote URL discloses the source location"),
        ('[remote "origin"]\n\turl = https://git:pw@github.com/a/b.git\n',
         "CRITICAL", "credentials in the remote URL"),
        ("ref: refs/heads/main\n", "HIGH", "repo confirmed, history fetchable"),
    ]:
        assert grade("CRITICAL", G, body) == want, why

    for body, want in [
        ("DB_PASS=hunter2\n", "CRITICAL"),
        # A template is not a credential. `\s` would match the newline and
        # let the pattern slide past the empty value onto the next key.
        ("DB_PASS=\nAPI_KEY=\n", "HIGH"),
        ("DB_PASS=\n", "HIGH"),
        ("DEBUG=false\n", "CRITICAL"),
    ]:
        assert grade("CRITICAL", E, body) == want, body

    # Never upgrade, and never touch a rule that was not inflated to begin with.
    assert grade("LOW", r"/\.DS_Store", "junk") == "LOW"


def test_exposure_findings_carry_the_content_not_just_the_status():
    """End to end through the grading path: a 200 alone proves nothing."""
    from core.response_fingerprint import fingerprint
    from modules.fast_exposure_scan import FastExposureScan

    m = FastExposureScan.__new__(FastExposureScan)
    base = "http://t"

    verdict, finding = m._path_finding(base, {
        "path": "/.git/config", "status": 200,
        "body": "[core]\n\trepositoryformatversion = 0\n",
        "sig": fingerprint(200, "[core]\n\trepositoryformatversion = 0\n", ""),
    })
    assert verdict == "finding"
    assert finding["severity"] == "LOW"
    assert any("Preview:" in e for e in finding["evidence"]), \
        "the reader needs to see what was actually served"


# --- git_exposure, the same bug in a second module ----------------------

def test_a_200_on_dot_git_paths_is_not_evidence_of_a_dot_git_directory():
    """`status in (200, 206) and len(body) > 20` passes on any SPA.

    The gate was `path.endswith("HEAD") or len(body) > 20`. The first half
    accepts `/.git/HEAD` on any 200 at all; the second accepts the 9393-byte
    index.html that a catch-all server returns for every path. Result on the
    authorised local Juice Shop: CRITICAL "Exposed Git Metadata", evidence
    `200 http://localhost:3000/.git/config`, on a server that has no `.git`
    directory — a response byte-identical to `/`.
    """
    from modules.git_exposure import CONTENT_HINTS

    shell = ('<!--  ~ Copyright (c) 2014-2026 Bjoern Kimminich ~ -->\n'
             '<html><body><h1>Juice Shop</h1>'
             '<script>function main(){return 1}</script></body></html>')

    for path in CONTENT_HINTS:
        assert not CONTENT_HINTS[path].search(shell), \
            f"the SPA shell must not pass as {path}"

    # ...and the real artifacts still pass, so this is a gate and not a wall.
    assert CONTENT_HINTS["/.git/HEAD"].search("ref: refs/heads/main\n")
    assert CONTENT_HINTS["/.git/config"].search("[core]\n\trepositoryformatversion = 0\n")
    assert CONTENT_HINTS["/.git/index"].search("DIRC" + "\x00" * 16)
    assert CONTENT_HINTS["/.git/logs/HEAD"].search("a" * 40 + " Name <n> 1700000000 +0000\n")


def test_git_severity_reflects_what_is_readable():
    from modules.git_exposure import grade_git_severity as grade

    core_only = [{"path": "/.git/config", "status": 200,
                  "preview": "[core]\n\trepositoryformatversion = 0\n"}]
    assert grade(core_only) == "MEDIUM", \
        "structure only: nothing an anonymous visitor could not infer"

    with_remote = [{"path": "/.git/config", "status": 200,
                    "preview": '[remote "origin"]\n\turl = https://github.com/a/b.git\n'}]
    assert grade(with_remote) == "HIGH"

    with_creds = [{"path": "/.git/config", "status": 200,
                   "preview": '[remote "origin"]\n\turl = https://git:ghp_x@github.com/a/b.git\n'}]
    assert grade(with_creds) == "CRITICAL"

    # HEAD names the branch and walks to the history; that outranks a config
    # that only says repositoryformatversion.
    assert grade([{"path": "/.git/HEAD", "status": 200,
                   "preview": "ref: refs/heads/main\n"}]) == "HIGH"


# --- object references, and the injector that has to honour them --------

def test_object_templates_are_reassembled_across_a_service_class_body():
    """A minified Angular service writes the object URL in two pieces.

        class o{host=this.hostServer+`/api/Users`;
                get(e){return this.http.get(`${this.host}/${e}`)}}

    Read literally that is a collection path and an orphan id, so the whole
    access-control surface — `/api/Users/{id}`, `/api/Cards/{id}`,
    `/rest/track-order/{id}` — is invisible and every endpoint looks like a
    collection with nothing to differentiate.

    The identifier is not unique: every one of those classes names its own
    field `host`. Keying a dict on the identifier collapses them all into
    whichever was assigned last, which is how this returned exactly one
    template (`/rest/chat/{id}`) and hid the other eleven.
    """
    from core.surface import derive_from_service_bases

    src = (
        "class a{host=this.hostServer+`/api/Users`;"
        "get(e){return this.http.get(`${this.host}/${e}`)}}"
        "class b{host=this.hostServer+`/api/Cards`;"
        "get(e){return this.http.get(`${this.host}/${e}`)}}"
        "class c{host=this.hostServer+`/rest/chat`;"
        "send(e,i){return this.http.post(`${this.host}/${e}/x/${i}`,i)}}"
    )
    derived, _ = derive_from_service_bases(src)
    assert derived == {"/api/Users/{id}", "/api/Cards/{id}",
                       "/rest/chat/{id}/x/{id}"}, derived


def test_the_injector_fills_a_path_placeholder_in_place():
    """Appending `?id=` leaves the hole open and tests nothing.

    `/api/Users/{id}` with the query branch taken becomes
    `/api/Users/{id}?id=1'`. The server answers with its catch-all page, and
    every probe reports "no SQLi detected" — a false negative invented by the
    injector, on a URL that was never an endpoint. That is worse than the
    missing coverage, because it is recorded as tested and clear.
    """
    from core.validators import inject_param

    assert inject_param("http://h/api/Users/{id}", "id", "1") == \
        "http://h/api/Users/1"

    # The payload must be encoded into the segment: a bare quote or slash
    # would change the path instead of the value under test.
    got = inject_param("http://h/api/Users/{id}", "id", "1' OR '1'='1")
    assert got.startswith("http://h/api/Users/1%27"), got
    assert "/" not in got.split("/api/Users/")[1], "payload leaked a path separator"

    # Query parameters keep working exactly as before.
    assert inject_param("http://h/s?q=a", "q", "b") == "http://h/s?q=b"
    assert inject_param("http://h/s", "q", "b") == "http://h/s?q=b"


def test_the_graph_and_the_executor_agree_on_where_the_id_lives():
    """A probe the executor cannot arm is reported as planned, not run.

    `propose_test_edges` and `ChainExecutor._build_params` each resolve a
    surface independently. When they disagree the run says a chain was
    executed when nothing was sent, which is the one report an operator has no
    way to notice.
    """
    from core.attack_graph import AttackGraph, AttackNode
    from core.chain_executor import ChainExecutor
    import inspect

    node = AttackNode(id="u", label="http://h/api/Users/{id}", node_type="endpoint",
                      attrs={"url": "http://h/api/Users/{id}",
                             "template": "/api/Users/{id}", "object_ref": True})
    g = AttackGraph.__new__(AttackGraph)
    g.nodes = {"u": node}
    assert AttackGraph._surface(g, node) == ("http://h/api/Users/{id}", "id")

    src = inspect.getsource(ChainExecutor._build_params)
    assert '"{id}" in template' in src, \
        "the executor must resolve the path placeholder the graph resolved"


def test_a_refused_id_is_not_reported_as_injection():
    """Quoting a typed path segment makes it invalid; 404 is correct behaviour.

    Twelve derived object references turned the SQLi action loose on path
    segments, and it promptly proved SQL injection on two of them:
    `/api/Products/{id}` 200 -> 404 `{"message":"Not Found"}` and
    `/api/Deliverys/{id}` 200 -> 400 `{"status":"error"}`. Neither touched a
    query. A server that rejects a malformed id is doing what it should, and a
    fingerprint cannot tell that apart from a query that ran.

    The check stays two-sided on purpose: a 4xx that carries a database
    signature is still an injection, because the payload reached the query
    before the error was rendered.
    """
    from actions.web.sqli import _refused

    refused = {"status": 400, "body": '{"status":"error"}'}
    not_found = {"status": 404, "body": '{"message":"Not Found"}'}
    db_error = {"status": 400, "body": "SQLITE_ERROR: near \"'\": syntax error"}
    ok200 = {"status": 200, "body": "[]"}

    assert _refused(ok200, refused) is True
    assert _refused(ok200, not_found) is True

    # The payload reached the database before the error was rendered.
    assert _refused(ok200, db_error) is False

    # A 5xx is a broken query, not a refusal.
    assert _refused(ok200, {"status": 500, "body": "boom"}) is False

    # Same status, different body: the query ran and returned something else.
    # This is the real Juice Shop signature and must survive.
    assert _refused(ok200, {"status": 200, "body": '{"status":"error"}'}) is False


def test_a_path_resource_change_is_not_reported_as_injection():
    """Both sides 200, no database error, and a body that shrank 92%.

    `/rest/products/{id}/reviews` with `1'` in the segment resolves to a
    product that does not exist; the server answers `200 {"data":[]}`. The
    refusal check only fires on a 4xx, so this sailed through and came back
    CONFIRMED — a missing row wearing an injection's confidence label. The
    gate is the path: a query parameter cannot change which row the route
    looks up, so the same divergence there is still evidence.
    """
    from actions.web.sqli import _db_signature, _path_probe

    url = "http://h/rest/products/{id}/reviews"
    assert _path_probe(url, "id") is True
    assert _path_probe("http://h/rest/products/search?q=x", "q") is False
    assert _path_probe("http://h/api/Users/{id}?expand=1", "expand") is False

    base = {"status": 200, "body": '{"status":"success","data":[{"author":"a"}]}'}
    test = {"status": 200, "body": '{"status":"success","data":[]}'}
    assert _db_signature(base, test) is False, "a shrunk list is not a database error"

    # What a real injection looks like: a 5xx carrying the engine's own words.
    assert _db_signature(base, {"status": 500, "body": "boom"}) is True
    assert _db_signature(base, {"status": 200, "body": 'SQLITE_ERROR: unrecognized token'}) is True


def test_detect_sqli_confirms_a_query_but_not_a_path(monkeypatch):
    """Same divergence, opposite verdicts, decided by where the payload sits.

    The two calls differ only in whether the parameter is a path placeholder,
    which is the whole distinction: `q=x'` runs against a query, `1'` in a
    segment merely fails to name a row.
    """
    import asyncio
    from types import SimpleNamespace

    import actions.web.sqli as sqli

    def _verdict(conf):
        return SimpleNamespace(confidence=SimpleNamespace(value=conf),
                               evidence={})

    class _Diff:
        async def compare_urls(self, base, test, method="GET"):
            return (_verdict("CONFIRMED"),
                    {"status": 200, "body": '{"data":[{"author":"admin"}]}'},
                    {"status": 200, "body": '{"data":[]}'})

    class _Rep:
        async def check(self, fn):
            return _verdict("CONFIRMED")

    class _Oracle:
        differential = _Diff()
        reproducibility = _Rep()

    monkeypatch.setattr(sqli, "VerificationOracle", _Oracle)

    path = asyncio.run(sqli.detect_sqli(SimpleNamespace(
        params={"url": "http://h/rest/products/{id}/reviews", "param": "id"})))
    assert path.success is False, "a changed path resource must not be a finding"
    assert "path segment" in path.error, path.error
    assert path.data["path_divergences"], "the cleared payload must be recorded"

    query = asyncio.run(sqli.detect_sqli(SimpleNamespace(
        params={"url": "http://h/rest/products/search?q=x", "param": "q"})))
    assert query.success is True, "a query differential must still confirm"
    assert query.confidence == "CONFIRMED"
    assert query.evidence["path_divergences"] == [], \
        "nothing was cleared for a query parameter"


async def _noop():
    return None


def test_a_module_that_overruns_is_recorded_as_a_timeout(monkeypatch):
    """The slowest module used to decide how long the whole run takes.

    `open_redirect` held the pipeline for seven minutes with no output, and
    the modules queued behind it were never reached. The failure is silent in
    the worst way: the run finishes, the report looks complete, and the gap is
    indistinguishable from "nothing there".

    So the deadline has to (a) stop the module and (b) leave a record that
    says coverage was partial.
    """
    from orchestrator import Orchestrator

    class Slow:
        stage = 1
        name = "slow"

        async def run(self):
            await asyncio.sleep(30)
            return "done"

    orch = Orchestrator.__new__(Orchestrator)
    # The module timeout is the subject of this test, not the surface seeder,
    # so stub it out rather than teaching the fake state about assets.
    orch._seed_surface = _noop
    orch.state = SimpleNamespace(
        module={"runs": []},
        begin_module_run=lambda *a, **k: (orch.state.module["runs"].append(
            {"id": "r1", "status": "running"}), "r1")[1],
        finish_module_run=lambda rid, status, error="": orch.state.module["runs"][
            0].update({"status": status, "error": error}),
        block_module=lambda *a, **k: None,
        save=lambda: None,
    )
    orch.config = {"module_timeout": 0.25}

    with monkeypatch.context() as mp:
        mp.setitem(MODULE_REGISTRY, "slow_stub",
                   {"class": lambda *a: Slow(), "detectability": "none",
                    "stage": 1})
        asyncio.run(Orchestrator._run_module(orch, "slow_stub"))

    run = orch.state.module["runs"][0]
    assert run["status"] == "timeout", run
    assert "0.25s" in run["error"] or "0s" in run["error"], run


def test_a_dom_sink_only_counts_when_a_source_feeds_it():
    """A sink inventory cannot be triaged; `innerHTML` is everywhere.

    The previous run reported "13 DOM XSS Sink Candidates" and every one of
    them turned out to be Mermaid's diagram library writing its own generated
    SVG — code where nothing is attacker-controlled. That is a finding-shaped
    number with no finding in it.

    Trace backwards to the start of the statement feeding the sink and look for
    a source an attacker picks. The positive and the library case must fall
    on opposite sides of that line.
    """
    from modules.js_analysis import extract_dom_flows

    vulnerable = (
        "function show(){var q=location.hash.slice(1);"
        "document.getElementById('r').innerHTML=q;}"
    )
    flows = extract_dom_flows(vulnerable, "app.js")
    assert flows, "a hash read written to innerHTML is a flow"
    assert flows[0]["src"] == "location.hash"
    assert flows[0]["sink"] == "innerHTML"

    # A library rendering its own string: a sink, and nothing more.
    library = (
        "g.innerHTML=nodes.map(function(x){return tag(x)}).join(' ');"
    )
    assert extract_dom_flows(library, "mermaid.js") == []

    # The nearest preceding source wins: `b.data` taints this assignment, not
    # an unrelated location.hash earlier in the same window.
    mixed = "var h=location.hash;var p=e.data;el.innerHTML=p;"
    got = extract_dom_flows(mixed, "app.js")
    assert [f["src"] for f in got] == ["message-event.data"], got


def test_a_message_listener_is_an_entry_point_not_a_sink():
    """`ws.onmessage=function(e){a.onData(e.data)}` is where data arrives.

    Paired with the `message-event.data` source this reports every WebSocket
    and postMessage listener in every application as a flow — it found exactly
    one "flow" in the Juice Shop bundle and that one was this. The sink is
    wherever `onData` writes the value, not the line that receives it.
    """
    from modules.js_analysis import NOT_SINKS, extract_dom_flows

    ws = "this.ws.onmessage=function(e){a.onData(e.data)}"
    assert extract_dom_flows(ws, "socket.js") == []
    assert "onmessage-handler" in NOT_SINKS

    # The same value written to a sink is still a flow.
    assert extract_dom_flows("el.innerHTML=e.data", "app.js")


# ── What counts as a DOM-XSS finding ──────────────────────────────


def _analyse_js(monkeypatch, js_body: str, semgrep_hits=None):
    """Run JSAnalysis over one fake script and return the state it wrote."""
    import modules.js_analysis as js_mod
    from modules.js_analysis import JSAnalysis

    tmpdir = Path(tempfile.mkdtemp())
    state = StateManager(str(tmpdir / "run" / "example.com"))
    state.add_asset("js_file", "js:http://example.com/library.js",
                    "http://example.com/library.js")

    async def fake_fetch(url, *args, **kwargs):
        if url.endswith("library.js"):
            return {"status": 200, "body": js_body,
                    "headers": "Content-Type: application/javascript"}
        if url.rstrip("/").endswith("example.com"):
            return {"status": 200,
                    "body": "<html><body>application shell</body></html>",
                    "headers": "Content-Type: text/html; charset=utf-8"}
        return {"status": 404, "body": "", "headers": ""}

    async def fake_semgrep(sources, rules="rules/semgrep", timeout=300):
        return {"available": True, "results": list(semgrep_hits or []),
                "scanned": len(sources), "exit_code": 0, "error": None}

    monkeypatch.setattr(js_mod, "curl_with_status", fake_fetch)
    monkeypatch.setattr(js_mod, "semgrep_scan", fake_semgrep)
    monkeypatch.setattr(js_mod, "tool_available", lambda name: True)
    result = asyncio.run(
        JSAnalysis(state, {"target": {"domain": "example.com"},
                           "modules": {}}).run())
    return result, state


LIBRARY_SINK = (
    "// a diagram library writing markup it just generated itself\n"
    "function render(nodes){var h='';for(var i=0;i<nodes.length;i++)"
    "{h+=nodes[i].html;}el.innerHTML=h;}"
)


def test_a_sink_with_no_traced_flow_is_inventory_not_a_finding(monkeypatch):
    """The sink count was a finding-shaped number with nothing in it.

    The audit measured 13 of them on a real bundle and every one was Mermaid
    writing its own SVG. Sinks stay in state as inventory; only a traced
    source-to-sink flow is reported.
    """
    result, state = _analyse_js(monkeypatch, LIBRARY_SINK)

    assert result == "done"
    assert state.get_assets_by_type("dom_sink"), "the sink list is still recorded"
    assert state.findings["findings"] == [], \
        [f["title"] for f in state.findings["findings"]]


def test_a_traced_flow_is_still_reported(monkeypatch):
    vulnerable = (
        "function show(){var q=location.hash.slice(1);"
        "document.getElementById('r').innerHTML=q;}"
    )
    result, state = _analyse_js(monkeypatch, vulnerable)

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert any("DOM Sink" in t for t in titles), titles


def test_semgrep_taint_flow_is_a_tentative_reading_list(monkeypatch):
    """An ERROR-rule hit is source-reachable in parsed syntax — the same
    standing as a regex-traced flow: MEDIUM/TENTATIVE, never proof."""
    result, state = _analyse_js(
        monkeypatch, "var x = 1; function noop(){return x + 1;} // padding",
        semgrep_hits=[{
            "rule": "js-dom-taint-to-innerhtml", "severity": "ERROR",
            "message": "Attacker-controlled DOM source reaches an HTML sink.",
            "source": "http://example.com/library.js", "line": 3,
            "snippet": "el.innerHTML = location.hash;",
        }])

    assert result == "done"
    flows = [f for f in state.findings["findings"]
             if f["title"].startswith("Semgrep Traced Taint Flows")]
    assert len(flows) == 1
    assert flows[0]["severity"] == "MEDIUM"
    assert flows[0]["confidence"] == "TENTATIVE"


def test_semgrep_sink_without_flow_is_low_inventory(monkeypatch):
    """A WARNING-rule hit with no traced source is inventory: LOW/FIRM,
    the same shelf as the regex sink list."""
    result, state = _analyse_js(
        monkeypatch, "var x = 1; function noop(){return x + 1;} // padding",
        semgrep_hits=[{
            "rule": "js-eval-call", "severity": "WARNING",
            "message": "Direct eval().",
            "source": "http://example.com/library.js", "line": 9,
            "snippet": "eval(constant)",
        }])

    assert result == "done"
    titles = [f["title"] for f in state.findings["findings"]]
    assert any(t.startswith("Semgrep Sink Candidates") for t in titles)
    assert not any(t.startswith("Semgrep Traced Taint Flows") for t in titles)
    sink = [f for f in state.findings["findings"]
            if f["title"].startswith("Semgrep Sink Candidates")][0]
    assert sink["severity"] == "LOW"
    assert sink["confidence"] == "FIRM"
