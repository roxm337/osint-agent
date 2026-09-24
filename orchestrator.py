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
from core.scope import ScopeGuard
from state.manager import StateManager
from modules import MODULE_REGISTRY, get_all_module_ids
from tools.wrappers import configure_http_limiter, configure_http_session
from core.attack_graph import AttackGraph
from core.budget_manager import BudgetManager, BudgetExceededError
from actions import ActionRegistry, ActionContext, list_actions
from actions.registry import ActionMeta, RiskLevel, RISK_TO_TIER
from core.risk_gate import RiskGate, RiskTier
from core.verification_oracle import configure_oob

logger = logging.getLogger("osint-agent")

logging.basicConfig(level=logging.INFO, format="%(message)s")


class Orchestrator:
    """Main orchestrator. Runs all modules in stage order."""

    def __init__(self, target: str, output_dir: str,
                 config_path: str = "config.yaml",
                 mode: str = "auto",
                 skip_auth_check: bool = False):
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
        self.scope = ScopeGuard(self.domain, self.config)
        self.scope.require(self.domain)

        # Auth check
        if mode == "active":
            if not skip_auth_check:
                print("\n⚠  Active mode requires authorization.")
                print(f"   Target: {target}")
                resp = input("   Confirm authorization (yes/no): ")
                if resp.lower() not in ("yes", "y"):
                    print("   Aborting.")
                    sys.exit(1)
            self.config["target"]["authorization"] = "confirmed"
            self.config["detectability"]["allow_high"] = True
        elif skip_auth_check:
            # --skip-auth-check without --active: confirm auth but keep detectability passive
            self.config["target"]["authorization"] = "confirmed"

        # State
        report_dir = self.output_dir / self.domain
        self.state = StateManager(str(report_dir))
        configure_oob(self.config)

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
            "target": {"domain": "", "authorization": "pending", "mode": "passive"},
            "paths": {"output_dir": "reports", "state_dir": "reports/{target}/state"},
            "rate_limits": {"default": {"concurrent": 5, "per_minute": 60}},
            "detectability": {"default": "low", "allow_high": False},
            "waf": {"max_bypass_attempts": 10, "backoff_seconds": 60,
                    "block_codes": [503, 429], "honeypot_codes": [500]},
            "modules": {"auto_run": True, "skip_on_waf": True, "max_consecutive_empty": 5},
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

            # Check auth requirement
            if entry.get("requires_auth", False) and not self.config["detectability"]["allow_high"]:
                self.state.skip_module(module_id, "requires auth (run with --active)")
                continue

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
                entry = MODULE_REGISTRY[module_id]
                if entry.get("requires_auth", False) and not self.config["detectability"]["allow_high"]:
                    self.state.skip_module(module_id, "requires auth (run with --active)")
                    logger.info(f"  Skipped {module_id}: requires auth (run with --active)")
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

        # Init budget and risk gate
        self.budget = BudgetManager(self.config)
        self.risk_gate = RiskGate(self.config)

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

        # Summary
        budget_summary = self.budget.summary() if hasattr(self, 'budget') else {}
        print(f"{'='*60}")
        print(f"  PENTEST COMPLETE")
        print(f"  Attack chains found: {chains_found}")
        print(f"  Budget used: {budget_summary.get('requests', 'N/A')}")
        print(f"  Attack graph: {self.output_dir / self.target / 'attack_graph.json'}")
        print(f"{'='*60}\n")

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
        if entry.get("requires_auth", False) and not self.config["detectability"]["allow_high"]:
            self.state.skip_module(module_id, "requires auth (run with --active)")
            self.state.save()
            print(f"Skipped {module_id}: requires auth (run with --active)")
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
            if module.is_blocked():
                result = "blocked"
                self.state.block_module(module_id, "blocked by WAF safety policy")
            else:
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
                        help="Enable active mode (port scans, etc.)")
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
    parser.add_argument("--agent", action="store_true",
                        help="Autonomous multi-agent pentesting engagement")
    parser.add_argument("--phase", choices=["plan", "recon", "vuln", "exploit", "verify", "report"],
                        help="Run a single agent phase")
    parser.add_argument("--roe", metavar="PATH",
                        help="Rules of Engagement YAML file — required for --engage")
    parser.add_argument("--engage", action="store_true",
                        help="Execute the engagement. Without this the agent mode "
                             "runs a dry-run (plan only, no actions executed)")
    parser.add_argument("--tools", action="store_true",
                        help="List available external tools")
    parser.add_argument("--install-tools", nargs="*",
                        help="Install missing external tools (optionally by category)")
    parser.add_argument("--skip-auth-check", action="store_true",
                        help="Skip authorization confirmation")

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
            auth = " [AUTH]" if entry.get("requires_auth") else ""
            print(f"  {mid:25s} (stage {entry['stage']}, "
                  f"{entry['detectability']}){auth}")
        print()
        return

    mode = "active" if args.active else args.mode
    orchestrator = Orchestrator(
        target=args.target,
        output_dir=args.output,
        config_path=args.config,
        mode=mode,
        skip_auth_check=args.skip_auth_check,
    )

    if args.agent or args.phase:
        from agents.agent_supervisor import AgentSupervisor, EngagementGateError
        from core.roe import load_roe, ROEError

        roe = None
        if args.roe:
            try:
                roe = load_roe(args.roe)
            except ROEError as exc:
                print(f"\n✗ Invalid ROE: {exc}\n")
                sys.exit(1)
            # The ROE is the authoritative boundary — the CLI target must be inside it.
            try:
                from core.scope import ScopeGuard
                scope_check = ScopeGuard(orchestrator.domain, roe.enforce(orchestrator.config))
                scope_check.require(orchestrator.domain)
            except ValueError as exc:
                print(f"\n✗ Target {orchestrator.domain} is outside the ROE scope: {exc}\n")
                sys.exit(1)

        if args.engage and roe is None:
            print("\n✗ Engaged mode requires an ROE file. Provide one with --roe <path>.\n")
            sys.exit(1)

        # Inject the raw target URL so agents can target specific paths
        orchestrator.config["target"]["raw_url"] = args.target
        if mode == "active" or args.skip_auth_check:
            orchestrator.config["target"]["authorization"] = "confirmed"
            orchestrator.config["detectability"]["allow_high"] = True

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

        supervisor = AgentSupervisor(orchestrator.state, orchestrator.config,
                                     roe=roe, engage=args.engage)

        if args.phase:
            try:
                result = await supervisor.run_single_phase(args.phase)
            except EngagementGateError as exc:
                print(f"\n✗ {exc}\n")
                sys.exit(1)
            print(f"\nPhase '{args.phase}' complete.")
        else:
            try:
                result = await supervisor.run_full_engagement()
            except EngagementGateError as exc:
                print(f"\n✗ Engagement aborted: {exc}\n")
                sys.exit(1)
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


def cli():
    """Synchronous entry point for console_scripts."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
