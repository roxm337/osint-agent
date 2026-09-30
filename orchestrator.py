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
    close_engine, configure_http_limiter, configure_http_session, engine_stats,
)
from core.attack_graph import AttackGraph
from core.budget_manager import BudgetManager, BudgetExceededError
from actions import ActionRegistry, ActionContext, list_actions
from actions.registry import ActionMeta, RiskLevel
from core.verification_oracle import configure_oob

logger = logging.getLogger("osint-agent")

logging.basicConfig(level=logging.INFO, format="%(message)s")


class Orchestrator:
    """Main orchestrator. Runs all modules in stage order."""

    def __init__(self, target: str, output_dir: str,
                 config_path: str = "config.yaml",
                 mode: str = "auto"):
        self.raw_target = target
        self.output_dir = Path(output_dir)
        self.config = self._load_config(config_path)
        self.mode = mode  # auto | llm | module

        # Extract domain from URL if target is a full URL
        parsed = urlparse(target if "://" in target else f"//{target}")
        self.domain = parsed.hostname or target.strip().rstrip("/").split("/")[0]
        self.target = self.domain

        # Set target
        self.config["target"]["domain"] = self.domain
        self.config["target"]["raw_url"] = target
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
        """Load YAML config."""
        p = Path(path)
        if p.exists():
            try:
                return yaml.safe_load(p.read_text())
            except Exception as e:
                print(f"Warning: Could not load config: {e}")
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

        print(f"\n{'='*60}")
        print(f"  OSINT Agent — {self.target}")
        print(f"  Mode: {self.mode.upper()}")
        print(f"  Output: {self.output_dir / self.target}")
        print(f"{'='*60}\n")

        module_ids = get_all_module_ids()

        for module_id in module_ids:
            # Skip if already completed
            if self.state.is_module_complete(module_id):
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

    async def run_pentest(self):
        """Post-OSINT pentesting mode: build attack graph, discover chains, execute actions."""
        print(f"\n{'='*60}")
        print(f"  PENTEST MODE — Attack Graph + Action Library")
        print(f"  Target: {self.target}")
        print(f"{'='*60}\n")

        # Init budget
        self.budget = BudgetManager(self.config)

        # Build attack graph from current state
        graph = AttackGraph(self.state)
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

        if not chains:
            print("  No exploit chains found. Run more OSINT modules first.")
            print("  Tip: use --active for vuln scanning modules.")
            chains_found = 0
        else:
            chains_found = len(chains)
            print(f"  Found {chains_found} exploit chains (score >= 0.3):")
            print()
            for i, path in enumerate(chains[:10], 1):
                print(f"  Chain #{i} (score: {path.score:.3f})")
                print(f"    {path.summary}")
                print()

        # Actually prove them. This is the step that used to be missing: the
        # chains above were printed and nothing was ever run against the
        # target, so every finding stayed a claim.
        report = await self._execute_chains(chains)

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

    async def _execute_chains(self, chains):
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
        report = await executor.execute(chains, max_chains=self.max_chains)

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

        try:
            result = await module.run()

            if result == "done":
                print(f"  ✓ Complete")
            elif result == "skipped":
                print(f"  — Skipped")
            elif result == "blocked":
                print(f"  ✗ Blocked")
            self.state.finish_module_run(run_id, result or "unknown")
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
