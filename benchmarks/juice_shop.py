"""Juice Shop benchmark: regression gate proving real-vuln detection.

Runs a curated module set against a lab instance (default
http://localhost:3000) with the juice_shop_lab knowledge pack injected,
then scores findings against the pack's expectations.

This is the answer to "is it a framework or a Juice Shop script": the
product code stays target-agnostic, and THIS harness — pack plus
expectations — is where lab knowledge lives. If a refactor breaks real
detection, this goes red.

Usage:
    .venv/bin/python benchmarks/juice_shop.py [--base-url URL] [--pack NAME]

Exit codes: 0 all expectations met, 1 expectations missed,
2 lab unreachable (skip, not failure).
"""

import argparse
import asyncio
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from knowledge import apply_pack, load_pack
from state.manager import StateManager

# (module class path, kwargs): ordered so producers run before consumers
# (auth captures the session response_audit spends).
MODULES = [
    "modules.misconfig.MisconfigProbes",
    "modules.error_audit.ErrorAudit",
    "modules.auth_audit.AuthAudit",
    "modules.response_audit.ResponseAudit",
]


def _load_module(dotted: str):
    module_name, class_name = dotted.rsplit(".", 1)
    module = __import__(module_name, fromlist=[class_name])
    return getattr(module, class_name)


def _reachable(base_url: str) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(base_url, timeout=10) as response:
            return response.status < 500
    except Exception:
        return False


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--pack", default="juice_shop_lab")
    args = parser.parse_args()

    if not _reachable(args.base_url):
        print(f"SKIP: lab unreachable at {args.base_url}")
        return 2

    from urllib.parse import urlparse
    host = urlparse(args.base_url).hostname or "localhost"
    pack = load_pack(args.pack)
    config = {"target": {"domain": host, "base_url": args.base_url.rstrip("/")},
              "modules": {}}
    apply_pack(config, pack)

    tmpdir = Path(tempfile.mkdtemp(prefix="juice-bench-"))
    state = StateManager(str(tmpdir / "run" / host.replace(":", "_")))
    print(f"Benchmarking {args.base_url} with pack '{args.pack}'...")

    started = time.monotonic()
    outcomes = {}
    for dotted in MODULES:
        name = dotted.split(".")[-1]
        print(f"  [{name}]...", flush=True)
        outcomes[name] = await _run_one(dotted, state, config)
        print(f"    -> {outcomes[name]}")
    elapsed = time.monotonic() - started

    findings = state.findings.get("findings", [])
    expectations = pack.get("expected_findings", []) or []
    failures = []
    print(f"\n{len(findings)} finding(s) in {elapsed:.0f}s; "
          f"scoring {len(expectations)} expectation(s):")
    for expected in expectations:
        title = str(expected.get("title", ""))
        severity = str(expected.get("severity", ""))
        matched = [f for f in findings
                   if title.lower() in str(f.get("title", "")).lower()
                   and str(f.get("severity", "")).upper() == severity.upper()]
        status = "PASS" if matched else "FAIL"
        print(f"  [{status}] {severity} :: {title} "
              f"({len(matched)} match(es))")
        if not matched:
            failures.append(title)

    print("\nAll findings:")
    for finding in findings:
        print(f"  [{finding.get('severity')}/{finding.get('confidence')}] "
              f"{finding.get('module_id')} :: {finding.get('title')}")
    if failures:
        print(f"\n{len(failures)} expectation(s) missed.")
        return 1
    print("\nAll expectations met.")
    return 0


async def _run_one(dotted: str, state, config):
    cls = _load_module(dotted)
    try:
        return await asyncio.wait_for(cls(state, config).run(), 280)
    except asyncio.TimeoutError:
        return "timeout after 280s"
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


if __name__ == "__main__":
    import asyncio as _asyncio
    sys.exit(_asyncio.run(main()))
