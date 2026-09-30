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
