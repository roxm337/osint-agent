#!/usr/bin/env python3
"""OSINT Agent Orchestrator — LLM-powered or autonomous recon pipeline."""

import asyncio
import argparse
import sys
import yaml
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import logging
from state.manager import StateManager
from modules import MODULE_REGISTRY, get_all_module_ids
from tools.wrappers import (
    close_engine, configure_http_limiter, configure_http_session, curl_with_status,
    engine_stats,
)
from tools.external import configure_tool_backend
from core.attack_graph import AttackGraph, AttackPath
from core.surface import seed_surface
from core.budget_manager import BudgetManager, BudgetExceededError
from actions import ActionRegistry, ActionContext, list_actions
from actions.registry import ActionMeta, RiskLevel
from core.verification_oracle import configure_oob

logger = logging.getLogger("osint-agent")

logging.basicConfig(level=logging.INFO, format="%(message)s")


def probe_chains_first(graph, chains, proposed):
    """Put the planner's own probes ahead of every chain the graph offers.

    `find_chains` scores a path by multiplying likelihood by impact, so a
    proposed probe edge — 0.3 likelihood, 0.9 impact — scores 0.27 and falls
    under the 0.3 floor the chain search is called with. Arming these edges
    used to happen only when `chains` came back empty, which is exactly what
    happened while the graph held nothing else: the plan ran because there
    was nothing to crowd it out. Once the seeder started finding an S3 bucket
    and archived JavaScript, the graph returned 38 chains, the arming branch
    was skipped, the 25 proposed probes were printed and then never executed,
    and the run rediscovered no SQL injection that earlier sections had
    already proved on the same target. A plan that is printed and not run is
    the same failure as one that was never made, so the probes are now
    spliced in unconditionally, deduplicated against the chains, and lead the
    queue the executor takes its window from.

    Returns `(chains, probe_chains)` — the new list and the part of it that
    came from the plan, so the caller can report both counts honestly.
    """
    if not proposed:
        return list(chains), []
    already = {(edge.source_id, edge.target_id, edge.action_id)
               for path in chains for edge in path.edges}
    probe_chains = []
    for edge in proposed:
        if edge.source_id not in graph.nodes or edge.target_id not in graph.nodes:
            continue
        if (edge.source_id, edge.target_id, edge.action_id) in already:
            continue
        already.add((edge.source_id, edge.target_id, edge.action_id))
        probe_chains.append(AttackPath(
            nodes=[graph.nodes[edge.source_id], graph.nodes[edge.target_id]],
            edges=[edge],
            score=round(edge.likelihood * edge.impact, 3),
            summary=f"{graph.nodes[edge.source_id].label} "
                    f"--[{edge.edge_type}]--> "
                    f"{graph.nodes[edge.target_id].label}",
        ))
    if not probe_chains:
        return list(chains), []
    return probe_chains + list(chains), probe_chains


def _explicit_port(host: str) -> bool:
    """Does this bare `host[:port]` name a port the user typed?

    Deliberately not `":" in host`: an IPv6 literal contains colons and is not
    a port at all, and treating `[::1]:8080` as portless would send it to
    HTTPS on 443.
    """
    if host.startswith("["):
        return "]" in host and host.split("]", 1)[1].startswith(":")
    return ":" in host


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively layer `override` over `base`.

    Nested mappings merge key by key; anything else — a list of identities, a
    scalar, an explicitly empty value — is taken whole from the override, so a
    config file can still *replace* a list rather than have it unioned.
    """
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class Orchestrator:
    """Main orchestrator. Runs all modules in stage order."""

    @staticmethod
    def _read_config_file(path: str) -> dict:
        """Read one YAML file as a dict, or {} if it is absent or unreadable."""
        p = Path(path)
        if not p.exists():
            return {}
        try:
            loaded = yaml.safe_load(p.read_text())
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            return {}
        return loaded if isinstance(loaded, dict) else {}

    def __init__(self, target: str, output_dir: str,
                 config_path: str = "config.yaml",
                 mode: str = "auto"):
        self.raw_target = target
        self.output_dir = Path(output_dir)
        self.config = self._load_config(config_path)
        self.mode = mode  # auto | llm | module
        self._surface_seeded = False

        # Extract domain from URL if target is a full URL
        parsed = urlparse(target if "://" in target else f"//{target}")
        self.domain = parsed.hostname or target.strip().rstrip("/").split("/")[0]
        self.target = self.domain

        # Set target
        self.config["target"]["domain"] = self.domain
        # Normalise to a fetchable URL before modules see it. `target` is
        # whatever the user typed, so `-t localhost:3000` reached every module
        # as the scheme-less string "localhost:3000"; each then fell back to
        # `https://{domain}` and dialled 443, which is why a module that works
        # when called directly reported 0 files analysed under the CLI. Store
        # the resolved form and keep the literal in `target_input`.
        self.config["target"]["target_input"] = target
        self.config["target"]["raw_url"] = self.base_url
        self.config["target"]["scheme"] = urlparse(self.base_url).scheme
        self.config["target"]["mode"] = mode

        # State
        report_dir = self.output_dir / self.domain
        self.        state = StateManager(str(report_dir))
        configure_oob(self.config)

        # Chain execution. Off unless asked for, and the risk ceiling defaults
        # to LOW so that only SAFE/LOW actions can fire without an explicit
        # opt-in to something more aggressive.
        self.execute_chains = False
        self.max_risk = "LOW"
        self.max_actions = 25
        self.max_chains = 10

    def _load_config(self, path: str) -> dict:
        """Load YAML config, laying the given file over `config.yaml`.

        `-c` used to *replace* the whole configuration. The file an operator
        actually writes for a scoped run carries only what differs — identities
        for two test accounts — and passing it deleted every wordlist,
        threshold and module switch in the product along with everything it
        meant to set. `misconfig_probes` then reported "Checking 0 of 0 paths"
        and `content_discovery` skipped its wordlist, both as green
        completions, because the config no longer contained the lists they
        read. Merge instead: the file wins where it speaks and the rest stays.
        """
        override = self._read_config_file(path)
        # The default config is this file; merging it onto itself is a no-op,
        # so skip it rather than depend on that arithmetic.
        try:
            is_default = Path(path).resolve() == Path("config.yaml").resolve()
        except OSError:
            is_default = False
        base = {} if is_default else self._read_config_file("config.yaml")
        if not base and not is_default:
            # config.yaml is gitignored, so fresh clones do not have one.
            # Without this the merge base is empty and a scoped -c run
            # silently loses every wordlist — the exact defect this
            # layering exists to prevent. The example is the product
            # defaults; it lives next to this file, not in CWD.
            example = Path(__file__).resolve().parent / "config.example.yaml"
            base = self._read_config_file(str(example))
        if not override:
            if base:
                return base
        elif base:
            override = _deep_merge(base, override)
        if override:
            return override
        # Default config
        return {
            "target": {"domain": "", "mode": "active"},
            "paths": {"output_dir": "reports", "state_dir": "reports/{target}/state"},
            "rate_limits": {"default": {"concurrent": 5, "per_minute": 60}},
            "detectability": {"default": "high"},
            "waf": {"block_codes": [503, 429], "honeypot_codes": [500]},
            "modules": {"auto_run": True, "max_consecutive_empty": 5},
            "wordlists": {"subdomains": [], "misconfig_paths": [], "wp_paths": [],
                          "bucket_prefixes": [""], "bucket_suffixes": [""],
                          "cloud_providers": {}},
        }

    async def run_all(self):
        """Run all modules in sequence."""
        # Configure rate limiter from config
        rl = self.config.get("rate_limits", {}).get("http", {})
        configure_http_limiter(
            max_concurrent=rl.get("concurrent", 5),
            max_per_minute=rl.get("per_minute", 60),
        )
        configure_http_session(self.config)
        configure_tool_backend(self.config)

        print(f"\n{'='*60}")
        print(f"  OSINT Agent — {self.target}")
        print(f"  Mode: {self.mode.upper()}")
        print(f"  Output: {self.output_dir / self.target}")
        print(f"{'='*60}\n")

        # The surface seeder read the target's own bundles before the modules
        # ran. It used to be pentest-only, so in a normal pipeline the module
        # that most needs it never saw it: `idor_differ` reported "Testing 0
        # object endpoint(s)" on a target whose entire access-control surface
        # is object references. The derived templates are the input that makes
        # two-session comparison possible at all.
        await self._seed_surface()

        module_ids = get_all_module_ids()

        for module_id in module_ids:
            # Skip if already completed
            if self.state.is_module_complete(module_id):
                print(f"  ⏭ {module_id}: already complete, skipping "
                      f"(delete state to force a re-run)")
                continue

            entry = MODULE_REGISTRY.get(module_id)
            if not entry:
                continue

            # Check dependencies
            deps = entry.get("depends_on", [])
            missing_deps = [d for d in deps if not self.state.is_module_complete(d)]
            if missing_deps:
                # Auto-run dependencies if not done
                for dep_id in missing_deps:
                    if dep_id in module_ids:
                        await self._run_module(dep_id)

            # Run module
            await self._run_module(module_id)

        # Summary
        summary = self.state.summary()
        print(f"\n{'='*60}")
        print(f"  INVESTIGATION COMPLETE")
        print(f"  Target: {self.target}")
        print(f"  Assets: {summary['assets']}")
        print(f"  Findings: {summary['findings']}")
        print(f"  Requests: {summary['total_requests']}")
        print(f"  Completed: {len(summary['modules_completed'])} modules")
        print(f"  Report: {self.output_dir / self.target / f'{self.target}_report.md'}")
        print(f"{'='*60}\n")

        self.state.save()

    async def run_llm(self):
        """Run investigation guided by LLM decisions."""
        from agents.orchestrator_agent import LLMOrchestrator

        rl = self.config.get("rate_limits", {}).get("http", {})
        configure_http_limiter(
            max_concurrent=rl.get("concurrent", 5),
            max_per_minute=rl.get("per_minute", 60),
        )
        configure_http_session(self.config)

        agent = LLMOrchestrator(self.state, self.config)

        print(f"\n{'='*60}")
        print(f"  OSINT Agent — {self.target}")
        print(f"  Mode: LLM ({agent.model})")
        print(f"  Output: {self.output_dir / self.target}")
        print(f"{'='*60}\n")

        max_iterations = 30
        for iteration in range(max_iterations):
            decision = await agent.decide_next()
            logger.info(f"LLM decision: {decision}")

            if decision == "COMPLETE":
                print("\n  LLM: Investigation complete.")
                break

            if decision.startswith("RUN_MODULE:"):
                module_id = decision.split(":", 1)[1].strip()
                if module_id not in MODULE_REGISTRY:
                    logger.info(f"  LLM requested unknown module: {module_id}")
                    continue
                if self.state.is_module_complete(module_id):
                    logger.info(f"  {module_id} already complete, skipping.")
                    continue
                await self._run_module(module_id)

        summary = self.state.summary()
        print(f"\n{'='*60}")
        print(f"  INVESTIGATION COMPLETE (LLM mode)")
        print(f"  Target: {self.target}")
        print(f"  Assets: {summary['assets']}")
        print(f"  Findings: {summary['findings']}")
        print(f"  Requests: {summary['total_requests']}")
        print(f"  Completed: {len(summary['modules_completed'])} modules")
        print(f"  Report: {self.output_dir / self.target / f'{self.target}_report.md'}")
        print(f"{'='*60}\n")

        self.state.save()

    @property
    def base_url(self) -> str:
        """The target as a fetchable URL, port included.

        `self.domain` is `urlparse(...).hostname`, which drops the port. That
        is the right shape for a directory name and the wrong shape for a
        request, so `localhost:3000` would otherwise be dialled as
        `http://localhost/` — port 80, nothing there, a silent empty scan.
        """
        target = self.config.get("target") or {}
        # `target_input` is what the user literally typed, so it has to be
        # checked before `raw_url`: during __init__ this property is read
        # before `raw_url` has been rewritten, and picking up a stale value
        # from the config file is how `localhost:3000` became something else.
        raw = str(target.get("target_input") or target.get("raw_url") or "").strip()
        if not raw:
            return f"https://{self.domain}"
        if "://" not in raw:
            # A bare hostname is assumed HTTPS, which is what every public
            # target is and what the rest of this codebase has always assumed.
            # A bare host:port is assumed HTTP, because a non-default port is
            # almost always a development or staging service, and assuming
            # TLS there is how `-t localhost:3000` dialled 443 and found
            # nothing.
            scheme = "http" if _explicit_port(raw) else "https"
            raw = f"{scheme}://{raw}"
        return raw.rstrip("/")

    async def _seed_surface(self):
        """Add declared API surface to state when recon has not found any.

        Reads the target's own JavaScript rather than guessing at common
        paths. A guess that happens to be right is indistinguishable from a
        guess that was never checked, and a guess that is wrong generates
        findings about an endpoint the target does not have.
        """
        if self.state.assets.get("nodes"):
            return None

        base = self.base_url
        async def fetch_text(url):
            result = await curl_with_status(url, timeout=20)
            return int(result.get("status", 0) or 0), str(result.get("body", "") or "")

        print(f"  No surface in state — reading API surface from {base}")
        try:
            seed = await seed_surface(fetch_text, base)
        except Exception as exc:  # noqa: BLE001 - seeding must never abort a run
            print(f"  Surface seeding failed: {exc}")
            return None

        for url, param, source in seed.seeded_params(base):
            self.state.add_asset(
                asset_type="endpoint", key=url, value=url,
                confidence="CONFIRMED", sources=[source],
                attrs={"url": url, "param": param},
            )
        for url in seed.urls(base, limit=40):
            self.state.add_asset(
                asset_type="endpoint", key=url, value=url,
                confidence="CONFIRMED", sources=["surface-seed: declared in bundle"],
                attrs={"url": url},
            )

        # Object references, kept TENTATIVE because the template is
        # reassembled from two halves of a class body rather than written down
        # whole. A collection endpoint with no way to address an individual
        # record gives an authorisation tester nothing to test, so recording
        # that one exists matters more than being certain of its exact shape.
        for url, template in seed.object_refs(base):
            self.state.add_asset(
                asset_type="endpoint", key=url, value=url,
                confidence="TENTATIVE",
                sources=["surface-seed: derived from service base path"],
                attrs={"url": url, "template": template, "object_ref": True},
            )

        s = seed.summary()
        self.state.save()
        param_pairs = len(seed.seeded_params(base))
        print(f"  Seeded {param_pairs} parameterised endpoint(s) and "
              f"{s['api_paths']} path(s) from {s['scripts_fetched']} script(s)")
        if s["injectable_params"]:
            print(f"  Declared parameter(s): {', '.join(s['injectable_params'])}")
        if s["object_templates"]:
            print(f"  Derived object reference(s) (access-control surface): "
                  f"{', '.join(s['object_templates'][:6])}"
                  f"{' …' if len(s['object_templates']) > 6 else ''}")
        if s["parameterised_names_unknown"]:
            print(f"  Parameterised, names not in bundle: "
                  f"{len(s['parameterised_names_unknown'])} path(s)")
        if s["truncated"]:
            print("  Surface truncated at the seeder's limits.")
        if not seed.paths:
            print("  No API surface declared in the target's scripts — nothing to probe.")
        return seed

    async def run_pentest(self):
        """Post-OSINT pentesting mode: build attack graph, discover chains, execute actions."""
        print(f"\n{'='*60}")
        print(f"  PENTEST MODE — Attack Graph + Action Library")
        print(f"  Target: {self.target}")
        print(f"{'='*60}\n")

        # Init budget
        self.budget = BudgetManager(self.config)

        # A graph built only from prior recon is empty on a fresh target, and
        # an empty graph reports zero findings while looking indistinguishable
        # from a clean one. Read the surface out of the target's own assets
        # before giving up on it.
        await self._seed_surface()

        # Build attack graph from current state
        from urllib.parse import urlparse as _urlparse
        _scope = {self.domain}
        try:
            _base_host = (_urlparse(self.base_url).hostname or "").lower()
            if _base_host:
                _scope.add(_base_host)
        except ValueError:
            pass
        graph = AttackGraph(self.state,
                            scope_hosts={h for h in _scope if h})
        graph.build()
        graph.save(str(self.output_dir / self.target / "attack_graph.json"))
        action_count = ActionRegistry.size()
        print(f"  Attack graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        print(f"  Actions available: {action_count}")
        print(f"  Budget: {self.budget.max_requests} requests, {self.budget.max_wall_clock}s wall clock\n")

        # Print action inventory
        print(f"  Registered actions:")
        for meta in sorted(list_actions(), key=lambda m: m.id):
            print(f"    [{meta.risk.value:12s}] {meta.id:30s} {meta.description[:60]}")
        print()

        # Propose probes before looking for chains. Edges built only from
        # already-confirmed vulns meant a clean scan produced zero chains, so
        # the executor was never aimed at anything and `--execute` had nothing
        # to prove. A (url, param) pair is worth testing before we know
        # anything is wrong with it: the action is the oracle.
        proposed = graph.propose_test_edges(
            max_edges=self.max_actions, risk_ceiling=str(self.max_risk))
        plan = getattr(graph, "probe_plan", {})
        # Re-save: the first write happens before planning, so without this the
        # persisted graph has no `probe_plan` and no answer to the only
        # question anyone asks about a quiet scan — what was tried, and why
        # the rest was not.
        graph.save(str(self.output_dir / self.target / "attack_graph.json"))
        if proposed:
            print(f"  Proposed {len(proposed)} probe(s) on testable surface "
                  f"(risk ceiling {plan.get('risk_ceiling')}, "
                  f"{plan.get('surfaces_considered')} surface(s) considered)")
        elif plan.get("surfaces_considered"):
            # Say why, rather than letting "0 chains" stand in for "nothing
            # was even attempted". A scan that tested nothing and a scan that
            # found nothing must not look alike.
            print(f"  No probes proposed at risk ceiling "
                  f"{plan.get('risk_ceiling')}, over "
                  f"{plan['surfaces_considered']} testable surface(s):")
            for reason, count in sorted(plan.get("not_proposed", {}).items()):
                print(f"    - {reason} ({count})")
            print("  Raise with --max-risk MEDIUM to run detection actions.")
            print()

        # Find exploit chains
        chains = graph.find_chains(max_depth=4, min_score=0.3)
        graph_chains = len(chains)
        chains, probe_chains = probe_chains_first(graph, chains, proposed)
        if probe_chains:
            print(f"  Built {len(probe_chains)} probe chain(s) from the "
                  f"{len(proposed)} proposed edge(s), ahead of "
                  f"{graph_chains} graph chain(s).")

        if not chains:
            print("  No exploit chains found.")
            if not proposed:
                print("  Nothing was proposed and nothing was skipped: the "
                      "graph holds no testable surface.")
                print("  Tip: run recon with --active first, or check the "
                      "seeder output above.")
            chains_found = 0
        else:
            chains_found = len(chains)
            print(f"  Chains to execute: {chains_found} "
                  f"({len(probe_chains)} planned probe(s), "
                  f"{graph_chains} at score >= 0.3):")
            print()
            for i, path in enumerate(chains[:10], 1):
                print(f"  Chain #{i} (score: {path.score:.3f})")
                print(f"    {path.summary}")
                print()

        # Actually prove them. This is the step that used to be missing: the
        # chains above were printed and nothing was ever run against the
        # target, so every finding stayed a claim.
        report = await self._execute_chains(chains, probe_count=len(probe_chains))

        # Summary
        budget_summary = self.budget.summary() if hasattr(self, 'budget') else {}
        print(f"{'='*60}")
        print(f"  PENTEST COMPLETE")
        print(f"  Attack chains found: {chains_found}")
        if report is not None:
            print(f"  Edges proven: {report.proven}  ({report.summary()})")
        print(f"  Budget used: {budget_summary.get('requests', 'N/A')}")
        print(f"  Attack graph: {self.output_dir / self.target / 'attack_graph.json'}")
        print(f"{'='*60}\n")

    async def _execute_chains(self, chains, probe_count: int = 0):
        """Run the proving action for each chain edge, under risk and budget."""
        from core.chain_executor import ChainExecutor

        if not self.execute_chains:
            print("  Chain execution is off. Pass --execute to prove chains.")
            return None

        ceiling = RiskLevel(str(self.max_risk).upper())
        executor = ChainExecutor(
            self.state, self.config, budget=self.budget,
            max_risk=ceiling, max_actions=self.max_actions,
        )
        print(f"  Executing chains (risk ceiling: {ceiling.value}, "
              f"max {self.max_actions} actions)")
        # The window covers the planner's probes in full plus `--max-chains`
        # graph chains. The executor takes the first N chains it is handed, so
        # with `--max-chains 10` a plan of 25 probes would lose 15 of them to
        # whatever the graph happened to score highest — on the benchmark
        # target, archived JavaScript and an S3 bucket. The action budget is
        # what limits cost; this only decides whose request gets spent first.
        report = await executor.execute(
            chains, max_chains=self.max_chains + probe_count)

        # Persist what the executor just proved. `ChainExecutor` writes into
        # `state.findings` in memory, but the only `save()` on this path ran
        # before execution, so a run that proved a SQL injection printed
        # `PROVEN web.sqli.detect -> FINDING-0001` and then left an empty
        # `findings.json` on disk. The console showed a result that no report,
        # no re-run and no scoring pass could ever see.
        self.state.save()

        for outcome in report.ran:
            if outcome.finding_id:
                print(f"    PROVEN  {outcome.action_id} -> {outcome.finding_id} "
                      f"[{outcome.confidence}] {outcome.impact or outcome.detail}")
            else:
                print(f"    ran     {outcome.action_id}: {outcome.detail}")
        for outcome in report.blocked:
            print(f"    BLOCKED {outcome.action_id}: {outcome.detail}")
        for outcome in report.skipped:
            print(f"    skip    {outcome.action_id}: {outcome.detail}")
        for outcome in report.unarmable:
            print(f"    NO ARM  {outcome.action_id}: {outcome.detail}")
        if report.unarmable:
            print(f"    ({len(report.unarmable)} edge(s) had an action but not "
                  "enough data to run it — coverage was incomplete, not clean.)")
        print()
        return report

    async def run_module(self, module_id: str):
        """Run a single module by ID."""
        rl = self.config.get("rate_limits", {}).get("http", {})
        configure_http_limiter(
            max_concurrent=rl.get("concurrent", 5),
            max_per_minute=rl.get("per_minute", 60),
        )
        configure_http_session(self.config)

        entry = MODULE_REGISTRY.get(module_id)
        if not entry:
            print(f"Unknown module: {module_id}")
            print(f"Available: {', '.join(MODULE_REGISTRY.keys())}")
            return
        await self._run_module(module_id)

    async def _run_module(self, module_id: str):
        """Internal: instantiate and run a module."""
        # Seed once per process, whichever entry point got us here. `--module`
        # skips `run_all`, so without this a single-module invocation never
        # sees the object references the seeder derives from the bundle.
        if not getattr(self, "_surface_seeded", False):
            self._surface_seeded = True
            await self._seed_surface()

        entry = MODULE_REGISTRY[module_id]
        module_class = entry["class"]
        module = module_class(self.state, self.config)
        run_id = self.state.begin_module_run(
            module_id,
            detectability=entry.get("detectability", ""),
            stage=entry.get("stage", 0),
        )

        print(f"\n[{module.stage}] {module.name} ({module_id})")
        print(f"  Detectability: {entry['detectability']}")

        # A module with no deadline is a module that decides how long the run
        # takes. `open_redirect` once held the pipeline for seven minutes
        # without producing a line of output, which reads as a hang and, worse,
        # silently ends the run before the modules after it are reached.
        deadline = self.config.get("module_timeout", 300)
        try:
            deadline = float(deadline)
        except (TypeError, ValueError):
            deadline = 300.0
        if deadline <= 0:
            deadline = 300.0

        try:
            result = await asyncio.wait_for(module.run(), timeout=deadline)

            if result == "done":
                print(f"  ✓ Complete")
            elif result == "skipped":
                print(f"  — Skipped")
            elif result == "blocked":
                print(f"  ✗ Blocked")
            self.state.finish_module_run(run_id, result or "unknown")
        except asyncio.TimeoutError:
            # Say the coverage is partial. A timeout recorded as "done" or
            # silently dropped both understate the gap in the same direction.
            print(f"  ⏱ Timed out after {deadline:.0f}s — coverage from this "
                  f"module is incomplete")
            self.state.finish_module_run(
                run_id, "timeout",
                f"exceeded {deadline:.0f}s module deadline")
        except Exception as e:
            print(f"  ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            self.state.block_module(module_id, str(e))
            self.state.finish_module_run(run_id, "error", str(e))

        self.state.save()


async def main():
    parser = argparse.ArgumentParser(
        description="OSINT Agent — Automated Reconnaissance Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full auto recon (passive)
  python orchestrator.py -t euro2c.com

  # Active recon (includes port scan, high-detectability probes)
  python orchestrator.py -t euro2c.com --active

  # Single module
  python orchestrator.py -t euro2c.com --module email_security

  # LLM-guided mode (requires API key in config or env)
  python orchestrator.py -t euro2c.com --mode llm

  # Pentest mode: build attack graph + run action library
  python orchestrator.py -t euro2c.com --pentest

  # Pentest and actually prove the chains (risk ceiling LOW by default)
  python orchestrator.py -t euro2c.com --pentest --execute

  # Raise the ceiling. This is what unlocks sqlmap, cloud metadata and the
  # rest, so it should be a deliberate choice rather than a default.
  python orchestrator.py -t euro2c.com --pentest --execute --max-risk MEDIUM

  # Pentest with active vuln scanning first
  python orchestrator.py -t euro2c.com --active --pentest

  # List available modules
  python orchestrator.py -t euro2c.com --list-modules

  # List available actions
  python orchestrator.py -t euro2c.com --list-actions

  # Custom output dir
  python orchestrator.py -t euro2c.com -o ./reports
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    parser.add_argument("-c", "--config", default="config.yaml", help="Config file")
    parser.add_argument("--active", action="store_true",
                        help="Enable active mode (active probing, port scans, vuln scanners)")
    parser.add_argument("--module", help="Run a single module only")
    parser.add_argument("--mode", default="auto",
                        choices=["auto", "llm"],
                        help="Run mode: auto (deterministic) or llm (LLM-guided)")
    parser.add_argument("--list-modules", action="store_true",
                        help="List all available modules")
    parser.add_argument("--list-actions", action="store_true",
                        help="List all registered pentesting actions")
    parser.add_argument("--pentest", action="store_true",
                        help="Post-OSINT attack graph analysis + action execution")
    parser.add_argument("--execute", action="store_true",
                        help="Actually run the proving action for each chain. "
                             "Without this, pentest mode only prints chains.")
    parser.add_argument("--max-risk", default="LOW",
                        choices=["SAFE", "LOW", "MEDIUM", "HIGH", "DESTRUCTIVE"],
                        help="Risk ceiling for executed actions (default: LOW). "
                             "MEDIUM+ allows sqlmap and cloud metadata probes.")
    parser.add_argument("--max-actions", type=int, default=25,
                        help="Cap on actions executed per engagement (default: 25)")
    parser.add_argument("--max-chains", type=int, default=10,
                        help="Cap on chains executed per engagement (default: 10)")
    parser.add_argument("--agent", action="store_true",
                        help="Autonomous multi-agent pentesting engagement")
    parser.add_argument("--phase", choices=["plan", "recon", "vuln", "exploit", "verify", "report"],
                        help="Run a single agent phase")
    parser.add_argument("--tools", action="store_true",
                        help="List available external tools")
    parser.add_argument("--check-config", action="store_true",
                        help="Show config coverage for known keys and exit")
    parser.add_argument("--install-tools", nargs="*",
                        help="Install missing external tools (optionally by category)")

    args = parser.parse_args()

    if args.tools:
        from tools.tool_manager import ToolManager
        tm = ToolManager()
        summary = tm.summary()
        print(f"\nExternal tools ({summary['available']}/{summary['total']} available):")
        for t in sorted(summary['available_tools']):
            print(f"  ✓ {t}")
        for t in sorted(summary['missing_tools']):
            print(f"  ✗ {t}")
        print(f"\n  Installer: {summary['installer']}")
        print()
        return

    if args.install_tools is not None:
        from tools.tool_manager import ToolManager
        tm = ToolManager()
        tm.scan()
        category = args.install_tools[0] if args.install_tools else None
        if category:
            print(f"Installing missing tools in category: {category}...")
        else:
            print("Installing all missing tools...")
        results = asyncio.run(tm.install_missing(category))
        for r in results:
            print(f"  {'✓' if r['success'] else '✗'} {r.get('message', r.get('error', '?'))}")
        return

    if args.list_actions:
        print(f"\nRegistered pentesting actions ({ActionRegistry.size()}):")
        for meta in sorted(list_actions(), key=lambda m: m.id):
            tools = f" [{','.join(meta.tools)}]" if meta.tools else ""
            print(f"  [{meta.risk.value:12s}] {meta.id:30s} {meta.description[:60]}{tools}")
        print()
        return

    if args.list_modules:
        print("\nAvailable modules:")
        for mid in get_all_module_ids():
            entry = MODULE_REGISTRY[mid]
            kind = " [ACTIVE]" if entry.get("active") else ""
            print(f"  {mid:25s} (stage {entry['stage']}, "
                  f"{entry['detectability']}){kind}")
        print()
        return

    if args.check_config:
        from core.config_doctor import coverage as _coverage
        _probe = Orchestrator(
            target=args.target,
            output_dir=args.output,
            config_path=args.config,
            mode="auto",  # coverage reads config only; nothing runs
        )
        print(f"\nConfig coverage ({args.config} over config.yaml, "
              f"env OSINT_TOOLS_BACKEND/OSINT_TOOLS_IMAGE wins at runtime):")
        missing = 0
        for dotted, present, value, why in _coverage(_probe.config):
            mark = "set" if present else "default"
            if not present:
                missing += 1
            print(f"  [{mark:7s}] {dotted} = {value!r}\n"
                  f"           {why}")
        print(f"\n  {missing} key(s) on defaults — copy them from "
              f"config.example.yaml to tune.\n")
        return

    mode = "active" if args.active else args.mode
    orchestrator = Orchestrator(
        target=args.target,
        output_dir=args.output,
        config_path=args.config,
        mode=mode,
    )
    orchestrator.execute_chains = bool(args.execute)
    orchestrator.max_risk = args.max_risk
    orchestrator.max_actions = args.max_actions
    orchestrator.max_chains = args.max_chains

    # Stale configs run new features on invisible code defaults. Say so
    # once, up front — silent when the file covers everything.
    from core.config_doctor import doctor as _doctor
    for warning in _doctor(orchestrator.config):
        print(f"  config: {warning}")

    if args.pentest and args.execute and args.max_risk not in ("SAFE", "LOW"):
        print(f"\n  Chain execution enabled, risk ceiling {args.max_risk}.")
        print("  Only run this against targets you are authorised to test.\n")

    try:
        if args.agent or args.phase:
            from agents.agent_supervisor import AgentSupervisor
            # Inject the raw target URL so agents can target specific paths
            orchestrator.config["target"]["raw_url"] = args.target

            # Seed the raw URL as an asset + parameters for attack graph
            if "?" in args.target and "=" in args.target:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(args.target)
                url_without_params = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                orchestrator.state.add_asset(
                    "url", f"url:{url_without_params}", url_without_params,
                    confidence="CONFIRMED", sources=["user_target"],
                )
                for param in parse_qs(parsed.query):
                    orchestrator.state.add_asset(
                        "parameter", f"param:{url_without_params}:{param}", param,
                        confidence="CONFIRMED", sources=["user_target"],
                        attrs={"url": url_without_params},
                    )
            else:
                orchestrator.state.add_asset(
                    "url", f"url:{args.target}", args.target,
                    confidence="CONFIRMED", sources=["user_target"],
                )

            supervisor = AgentSupervisor(orchestrator.state, orchestrator.config)

            if args.phase:
                result = await supervisor.run_single_phase(args.phase)
                print(f"\nPhase '{args.phase}' complete.")
            else:
                result = await supervisor.run_full_engagement()
            return

        if args.pentest:
            # Run OSINT first if not already done, then attack graph
            if mode == "active" or args.module:
                if args.module:
                    await orchestrator.run_module(args.module)
                else:
                    await orchestrator.run_all()
            await orchestrator.run_pentest()
        elif args.module:
            await orchestrator.run_module(args.module)
        elif mode == "llm":
            await orchestrator.run_llm()
        else:
            await orchestrator.run_all()
    finally:
        await _close_http()


async def _close_http() -> None:
    """Report connection-pool usage, then release the pool."""
    stats = engine_stats()
    if stats.get("requests"):
        total = stats["requests"]
        opened = stats.get("connections_opened", 0)
        reused = stats.get("connections_reused", 0)
        share = (reused / total * 100) if total else 0.0
        print(f"\n{'='*60}")
        print(f"HTTP: {total} requests over {opened} connections "
              f"({reused} served from the pool, {share:.0f}%)")
    await close_engine()


def cli():
    """Synchronous entry point for console_scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
