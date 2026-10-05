# OSINT Agent

**LLM-orchestrated OSINT & bug-bounty reconnaissance pipeline** — maps a target's
external attack surface, enriches discovered assets, records evidence, prioritizes
findings, and generates reports or attack plans.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-101%20passing-brightgreen)
![Status](https://img.shields.io/badge/status-active%20development-orange)

---

## ⚠️ Authorized use only

This is an **offensive security tool**. Reconnaissance, scanning, and active testing
against systems you do not own or lack **explicit written authorization** to test may
be illegal in your jurisdiction.

The framework ships **no scope enforcement, authorization gate, or risk-tier blocking**.
You are solely responsible for operating within the law and within the rules of
engagement of your target's bug-bounty program or pentest contract.

---

## Features

- **45+ modules** across a 6-stage pipeline: seed → asset expansion → enrichment →
  exposure analysis → active vulnerability testing → prioritization & reporting.
- **Passive by default.** Active/high-detectability modules (port scan, nuclei, XSS/SQLi
  validation, content discovery) run with `--active`.
- **LLM orchestration mode** — an LLM chooses which module to run next and generates a
  structured testing plan (with deterministic fallback when no key is set).
- **Multi-agent autonomous layer** *(in progress)* — supervisor, blackboard coordination,
  and specialized recon/vuln/exploit/verify/report agents over a tiered action registry.
- **Typed asset graph + evidence chain** — assets, edges, findings, and evidence are
  persisted per target with confidence and severity scoring.
- **Report generation** — markdown report, executive summary, findings JSON, and
  bounty-submission drafts.
- **PySide6 desktop GUI** — same engine as the CLI, with results, evidence, graph, and
  settings panels.

---

## Architecture

```text
          User / CLI / GUI
                 │
                 ▼
          orchestrator.py ──────────────┐
                 │                        │  (autonomous layer, in progress)
   ┌─────────────┼─────────────┐         ▼
   ▼             ▼             ▼     agents/*  +  actions/registry.py
 modules/*    core/*        state/    (supervisor · blackboard ·
 recon &      budget ·      manager    specialized agents · action
 exposure     scoring ·     (assets,   registry)
 checks       audit ·       findings,
              reporting     evidence)
   │             │             │
   └──────► tools/* (async HTTP/DNS/WHOIS wrappers, external tool adapters)
                 │
                 ▼
        reports/<target>/  (state, evidence, JSON, markdown)
```

Two generations coexist by design:

1. **Module pipeline** (`orchestrator.py` + `modules/*`) — mature, tested, the working product.
2. **Autonomous agent layer** (`agents/*`, `actions/*`) — a risk-tiered multi-agent system
   under active development (see roadmap).

---

## Installation

Requires **Python 3.10+**.

```bash
# 1. Clone
git clone https://github.com/roxm337/osint-agent.git osint-agent && cd osint-agent

# 2. Virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Core dependencies
pip install -r requirements.txt

# 4. (Optional) browser-rendered crawl
playwright install chromium
```

Or install as a package (exposes the `osint-agent` and `osint-agent-gui` commands):

```bash
pip install -e .            # core
pip install -e ".[full]"    # + aiohttp, dnspython, whois, bs4, lxml, playwright
```

---

## Configuration

The repository ships templates; your real config and secrets stay local (git-ignored).

```bash
cp config.example.yaml config.yaml   # runtime config
cp .env.example .env                 # API keys / LLM credentials
```

- **`config.yaml`** — target, run mode, rate limits, wordlists, scoring weights,
  detectability metadata, and optional inline API keys.
- **`.env`** — API keys resolved as environment fallbacks (VirusTotal, Shodan, Hunter,
  SecurityTrails, HIBP, URLScan, …) and LLM credentials.

API-key lookup is centralized in `core/keyvault.py`: configured values first, then
environment fallbacks. All keys are optional — modules that need a missing key are skipped.

---

## Usage

### CLI

```bash
# Passive reconnaissance (default)
python orchestrator.py -t example.com

# LLM-guided module selection
python orchestrator.py -t example.com --mode llm

# Generate a testing plan
python orchestrator.py -t example.com --module attack_planner

# Active recon (port scan + high-detectability probes)
python orchestrator.py -t example.com --active

# Active vulnerability scanning pass
python orchestrator.py -t example.com --active --pentest

# Autonomous multi-agent run (optionally limited to a phase)
python orchestrator.py -t example.com --agent --phase recon

# Utilities
python orchestrator.py --list-modules
python orchestrator.py --list-actions
python orchestrator.py --tools
```

**Key flags:** `-t/--target` (required), `-o/--output` (default `reports`),
`-c/--config` (default `config.yaml`), `--mode {auto,llm}`, `--module <id>`,
`--active`, `--pentest`, `--agent`, `--phase {plan,recon,vuln,exploit,verify,report}`,
`--list-modules`, `--list-actions`, `--tools`, `--install-tools`.

### GUI

```bash
python -m gui.app        # or: osint-agent-gui
```

The GUI drives the same `orchestrator.py` engine (via `QProcess`), so GUI and CLI share
identical state and config contracts.

- **Engagement group** — `--pentest`, `--execute`, risk ceiling, max actions/chains.
  Execution at MEDIUM and above asks for explicit confirmation first; the effective
  flags and config file are echoed in the ops strip.
- **Findings triage** — filter/search bar, numeric sort on score/severity/priority,
  detail pane, and per-finding verdicts (`true_positive` / `false_positive` /
  `out_of_scope` + notes) persisted to `<output>/<target>/<target>_triage.json`,
  outside the engine's `state/`.
- **Attack graph tab** — renders `attack_graph.json` (nodes, observed vs. proposed
  probe edges) with the probe-plan summary (risk ceiling, surfaces considered,
  reasons probes were not proposed).
- **Settings** — LLM, Runtime (rate limits, module timeout, budget limits), Scanner
  (auth + test identities), Actions (registered action list with risk), Tools
  (status + install), API keys, raw YAML, plus File → "Use Config File…".
- **Dark theme** lives in `gui/theme.qss`.

---

## Pipeline stages

| Stage | Focus | Example modules | Detectability |
|---|---|---|:---:|
| 1 · Seed | Seed target assets | `seed_discovery` | low |
| 2 · Asset expansion | Subdomains, history, contacts | `subdomain_enum`, `wayback_machine`, `asn_expansion` | low |
| 3 · Enrichment | Tech, TLS, mail, threat intel, CVEs | `tech_detection`, `tls_audit`, `exploit_lookup`, `port_scan` | low–high |
| 4 · Exposure analysis | APIs, misconfig, secrets, takeover | `rest_api_audit`, `graphql_audit`, `misconfig_probes`, `dns_takeover` | low–medium |
| 5 · Active testing | Vuln validation | `nuclei_scan`, `xss_scan`, `sqli_scan`, `content_discovery` | **high** |
| 6 · Prioritization & reporting | Score, plan, report, submit | `risk_prioritization`, `attack_planner`, `reporting` | low |

Full stage/detectability matrix and data contracts are documented in the internal
project map.

---

## Run model

Modules carry `detectability` (`low` / `medium` / `high`) and `active` as
**descriptive metadata** for prioritization and reporting. Neither blocks execution —
there is no scope filter, no authorization prompt, and no risk-tier gate anywhere in the
request path. `--active` selects the active-stage modules; it no longer unlocks anything.

`BaseModule.http_get()` records WAF block/allow signals for reporting, and
`modules.max_consecutive_empty` caps unproductive probing per module — an efficiency
knob, not a safety control.

---

## Testing

```bash
pip install pytest pytest-asyncio
python -m pytest                              # full suite (GUI tests need PySide6)
python -m pytest --ignore=tests/test_gui_app.py --ignore=tests/test_gui_graph.py
```

The suite covers core state, scoring, evidence, external-tool parsing, per-stage
modules, the attack planner, the action registry, and the GUI (findings triage,
engagement gating, settings round-trips, attack-graph tab). **603 tests pass**
including the GUI extras.

---

## Project structure

```text
orchestrator.py      CLI entry point and module runner
config.example.yaml  runtime config template (copy to config.yaml)
.env.example         API-key / LLM credential template
agents/              autonomous multi-agent layer (supervisor, blackboard, agents)
actions/             tiered offensive action registry (web/api/auth/cloud/verify)
core/                scoring, prioritization, reporting, keyvault, budget, audit log
modules/             45+ recon / enrichment / exposure / active modules
state/               persistent per-target asset graph, findings, evidence store
tools/               async HTTP/DNS/WHOIS wrappers + external tool adapters
payloads/            payload catalogs for active checks
gui/                 PySide6 desktop application
tests/               pytest suite
```

---

## Design notes

The distinguishing element is not the individual recon checks (those are table stakes),
but the **orchestration layer around them**:

- A **typed action registry** where every capability is a declared, catalogued action
  with required parameters, risk metadata, and a timeout.
- **LLM-guided, then multi-agent, orchestration** that plans, sequences, and executes
  actions, with a supervisor, blackboard, and verification agents confirming findings.
- A **tamper-evident audit log** (SHA-256 hash chain) recording every plan, action, and
  result, plus a typed asset graph with evidence references.

Together these make the tool an **auditable autonomous system** rather than a
fire-and-forget scanner. Execution is unconstrained by design — targeting discipline
is the operator's responsibility.

---

## Roadmap

Phase 1 — module pipeline: **complete & tested.**
Phase 2 — autonomous multi-agent layer (supervisor, blackboard, verification oracle,
budget-managed action execution): **in progress.**

---

## License

No license is set yet. Until a `LICENSE` file is added, all rights are reserved and this
code is **not** licensed for reuse. Choose and add a license before publishing broadly
(e.g. MIT for permissive reuse, or a source-available license if you want to restrict it).

---

## Disclaimer

Provided for authorized security research and education only. The authors accept no
liability for misuse. Test only what you are explicitly permitted to test.
