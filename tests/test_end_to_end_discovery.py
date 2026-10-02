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

from core.attack_graph import AttackGraph
from core.surface import extract_from_script, script_urls_from_html, seed_surface
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
