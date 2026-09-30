# Capability Audit — osintAgent against OWASP Juice Shop

**Target:** `http://localhost:3000/` (OWASP Juice Shop 2026, Docker, 127.0.0.1)
**Date:** 2026-09-29
**Commits under test:** `17a15b2`, `2768006`, `48df0b3` (447 tests green)
**Method:** 26 modules run individually with a hard 100s per-module timeout, then
pentest mode with `--execute`, then hand-arming the chain executor against
known-true endpoints. Every finding below was checked by hand with `curl` before
being believed.

Juice Shop is the right instrument for this: it is deliberately vulnerable, its
bugs are documented, so a miss is unambiguous. It is also a modern Angular SPA
served by Express with SQLite — the exact shape that punishes response-based
heuristics.

---

## 1. Headline result

**The action library is good. The detection layer feeding it is broken. The
graph connecting them never fires.**

| Layer | Verdict |
|---|---|
| Action library (`actions/`, 15 actions) | **Works.** Proved a real SQLi unaided. |
| Chain executor (`core/chain_executor.py`) | **Works.** Correct arming, correct silence, correct promotion. |
| Detection modules (`modules/`) | **Broken on modern SPAs.** 22 false positives, several key false negatives. |
| Attack graph (`core/attack_graph.py`) | **Starved.** 24 nodes → 3 edges → 0 chains, on a target with a known SQLi. |
| `run_pentest --execute` end to end | **Fired nothing.** 0 proven, 0 blocked, 0 skipped, 0 chains. |

The headline number: **21 findings, 22 of them false positives.** The single true
positive the tool produced on its own initiative was an accident of a header
check, not detection.

---

## 2. What genuinely works

### 2.1 The chain executor proved a real, exploitable SQL injection

Hand-armed against `/rest/products/search?q=`, `web.sqli.detect` ran and returned
`CONFIRMED`, with evidence `baseline 200 → test 500` and reproducibility `3/3`.

**Independently verified by hand, not trusted:**

```
')'                  HTTP 500  Error: SQLITE_ERROR: near ")"
' UNION SELECT NULL-- HTTP 500 Error: SQLITE_ERROR: near "UNION"
' AND 1=2--          HTTP 500 Error: SQLITE_ERROR: incomplete input
' OR '1'='1          HTTP 200  full product JSON returned (tautology works)
```

That is a textbook error-based SQLi with a working tautology, and the app leaks
the raw SQLite fragment back. The action's payloads, differential comparison and
reproducibility check are all sound. This is the best thing in the codebase.

### 2.2 The executor's judgement is correct in both directions

Given the same endpoint, `web.sqli.blind_detect` and `web.xss.reflected` both
returned *"no X detected"* and produced **no finding**. It did not manufacture
findings to justify the run. Silence-when-clean is the hardest thing to get
right in this kind of tool and it works.

### 2.3 The risk gate held

At the default `LOW` ceiling, `sqlmap` and `dalfox` were correctly refused; at
`MEDIUM` the real actions ran. An unparseable risk is refused rather than
allowed. 3/3 safety mutations caught.

### 2.4 Param arming is correct

Given a `parameter` node, the executor derives `url` + `param` and arms
`web.sqli.detect` properly. It falls back down a candidate list when the
preferred action cannot be armed, and reports unarmable edges instead of letting
them read as clean.

---

## 3. What is broken

### 3.1 CRITICAL — 22 false positives, graded CRITICAL/HIGH/MEDIUM, all `CONFIRMED`

`fast_exposure_scan` produced 20 of 21 findings. **Every one is false.**

```
/.env              200 len=9393     -> "Exposed Environment File"      CRITICAL
/.git/config       200 len=9393     -> "Exposed Git Metadata"         CRITICAL
/wp-config.php     200 len=9393     -> "Exposed WordPress Config"     CRITICAL
/actuator/env      200 len=9393     -> "Spring Boot Actuator"          CRITICAL
/backup.sql        200 len=9393     -> "Database Backup Exposed"       CRITICAL
/phpmyadmin/       200 len=9393     -> "Database Admin Interface"      HIGH
/phpinfo.php       200 len=9393     -> "phpinfo Page Exposed"          MEDIUM
/graphql           200 len=9393     -> "GraphQL Endpoint Accessible"   MEDIUM
/swagger-ui.html   200 len=9393     -> "API Documentation Exposed"     MEDIUM
/totally/bogus/path 200 len=9393
```

All of these return **byte-identical index.html** — same md5 as `/` itself.
Juice Shop is an Express app serving an Angular SPA; any unmatched path falls
through to the SPA shell, and its client-side router then 404s. The tool read
`200` as "exposed" 20 times.

**The root cause is already known and already fixed — just not here.** Commit
`9dd9c44` added exactly this defence to `content_discovery`: reject a dominant
group of identical `(status, words, length)` responses, and grade by what a
status actually establishes. `fast_exposure_scan` never received the fix. The
same trap is in `misconfig_probes` and `cms_deep_scan`.

**Impact:** 7 CRITICALs and 4 HIGHs, all noise, all `confidence: CONFIRMED`. A
triager who submits even two of these burns their relationship with the program.
For a paid bug-bounty workflow this is worse than finding nothing.

#### Status: FIXED in `fc26eb1`

The specific defect was one line. `_path_finding` had exactly one body check:

```python
if status not in (200, 401, 403) or (status == 200 and len(body.strip()) < 20):
    return None
# ...then, for any matching rule:
confidence = "CONFIRMED" if status == 200 else "FIRM"
```

A 9393-byte shell passes `len < 20`, so a 200 was proof of exposure.

`core/response_fingerprint.py` now provides the shared primitive that `9dd9c44`
lacked — which is precisely why that fix never propagated: the logic was a
private method in one module with nothing to import. A finding now needs two
independent things:

1. The response must be distinguishable from the site's own catch-all,
   established by fingerprinting `/` plus four control paths. Three agreeing
   controls are required before a catch-all is claimed, so one unlucky 404
   cannot condemn a real finding.
2. The body must contain what the artifact would contain. A real `.env` has
   assignments, a real `.git/config` has `[core]`, a real dump has `CREATE
   TABLE`. Serving 200 is not evidence; serving the artifact is.

A `403` no longer claims CRITICAL exposure — access denied discloses nothing, so
it is `INFO`.

Replaying the recorded run through the fixed code:

```
baseline: root=c283ecae8fe2a5a1 dominant={'c283ecae8fe2a5a1': 4} controls=4
verdicts: {'catch_all': 20}
BEFORE fix: 20 findings (7 CRITICAL, 4 HIGH, 9 MEDIUM), all false
AFTER  fix:  0 findings
```

A genuinely exposed `.env` is still reported `CRITICAL`/`CONFIRMED` — pinned by
`test_a_real_exposed_env_file_is_still_reported`, so the fix removes noise
without removing signal. 35 tests, 5/5 mutations caught.

#### Still unfixed — 10 modules with the same trust-a-200 pattern

```
modules/misconfig.py       modules/git_exposure.py     modules/login_enum.py
modules/cloud_enum.py      modules/waf_module.py       modules/rest_api.py
modules/js_analysis.py     modules/social_media.py     modules/graphql_module.py
modules/base.py
```

`git_exposure` and `misconfig` are the highest risk — they probe exactly the
paths that fired here. None produced a finding on Juice Shop, but only because
the target was already down for part of the run and because they happened to
return something under the length threshold. This is the same bug waiting to
happen on the next SPA that returns 200 with a shorter shell.


### 3.2 CRITICAL — the attack graph never produces a chain

On a target with a confirmed SQLi:

```
graph: 24 nodes, 3 edges, 0 chains
edge types: {'affected_by': 1, 'authenticate': 2}
```

`_infer_transitions` creates `exploit` edges only for `parameter`/`url` nodes
whose vuln category contains `"sql"` or `"xss"`. The 8 parameter assets exist,
but every finding is a false positive about `.git`/WordPress, so **no finding
carries a category the graph recognises.** Result: zero exploitable edges.

This is the compounding failure. Garbage categories in → no edges out → the
executor has nothing to do. The layer that works is never reached.

### 3.3 HIGH — `js_analysis` is dead: 0 files on a page with three

```
[js_analysis] Analyzing 0 JS files...
[js_analysis] JS analysis: 0 files | 0 secrets | 0 endpoints | 0 source maps
```

The page loads `main.js`, `scripts.js`, `polyfills.js`. It found none, in 0.0s.
Consequences: no `js_file` nodes → no `extract` edges → the entire JS-secret
path is dead. This is a high-value, high-frequency bug class (exposed API keys
in bundles) going completely undetected.

### 3.4 HIGH — `cors_audit` false negative on a literal `ACAO: *`

The root response carries `Access-Control-Allow-Origin: *`. The module reported
`cors: 0 permissive endpoint(s) of 1`. It depends on `modules.cors_audit.endpoints`
config and on an `AuthHarness` identity that Juice Shop will not yield
unauthenticated, so it degrades to silence rather than reporting a
partially-assessed endpoint. **Silence from a module that could not complete its
check is indistinguishable from silence from a clean target.**

### 3.5 HIGH — `--module <id>` ran the entire pipeline (regression, now fixed)

Found only by running the CLI for real. My own commit `17a15b2` deleted the
`elif args.module:` branch while wiring in `--execute`, so `--module
tech_detection` silently ran all of stages 1–6. The suite stayed green at 440
tests because the old CLI test grepped `main()`'s source for flag strings —
which says nothing about which branch executes.

Fixed in `48df0b3` with `tests/test_cli_dispatch.py`, which drives `main()` with
real argv. Reintroducing the bug fails 5 of 7.

**Meta-finding: 447 tests did not catch a broken CLI. Only running the binary did.**

### 3.6 MEDIUM — `open_redirect` hung past 100s

Never completed. Unbounded. A module that cannot finish blocks the operator with
no partial result and no diagnostic.

### 3.7 MEDIUM — `prototype_pollution` burned 60s for zero findings

60 seconds, 0.0s of useful signal.

### 3.8 MEDIUM — no default budget

`config.example.yaml` has no `budget:` section; `max_requests` defaults to `0`,
which means unbounded. Pentagonest prints `Budget: 0 requests, 0s wall clock` and
`Budget used: 0/∞`. The `BudgetManager` machinery is good but ships inert — a
real engagement needs a default ceiling, not an optional one.

### 3.9 LOW — `subdomain_enum` produced 86 junk assets

Random-prefix permutations like `103.frontline-b96.localhost`, all `TENTATIVE`.
Against a non-domain target this is pure noise that still lands in the asset
graph and inflates it 86×.

### 3.10 LOW — `email_security` hung on DNS

Checking MX/SOA for `localhost` never returns. No guard for non-domain targets.

---

## 4. The other half of the question: can it FIND real critical/high bugs?

Precision was the headline above, but a tool that only removes noise is not a
weapon. The honest position from this run:

**The action library can find real bugs. The autonomous path cannot reach it.**

| Question | Answer | Evidence |
|---|---|---|
| Can the executor prove a real SQLi? | **Yes** | CONFIRMED, independently verified: `SQLITE_ERROR` + working tautology |
| Can it find it *by itself*? | **No** | 0 chains, 0 actions, 0 findings from `--pentest --execute` |
| Can it prove a class it is pointed at? | **Yes, for 2 of 15** | `sqli.detect` proved it; `blind_detect` and `xss.reflected` correctly reported clean |
| Can the detection modules find Juice Shop's known criticals? | **No** | `sqli_scan`, `xss_scan`, `idor_differ`, `mass_assignment`, `prototype_pollution` all returned 0 findings on a target that has all of them |

The gap is **recall**, and it is not a tuning problem. The executor needs a
`(url, param, category)` triple; the detectors were supposed to supply it and
supplied the wrong categories instead. Nothing is wired end to end, so
`--execute` has never found anything by itself.

Ground truth for the recall measurement comes from `/api/Challenges`, which
enumerates the application's own known vulnerabilities. That comparison is
**not yet done** — the Docker daemon died partway through this run and the
target is down. It is the next thing to do, and it needs the target back.

Predicted result, to be measured rather than assumed: low precision (now fixed)
and low recall, with recall limited almost entirely by the missing
authenticated-session support. Juice Shop's highest-value bugs — IDOR on
`/rest/products`, mass assignment on the user profile, access control on
`/rest/admin/users` — are all **behind authentication**, and the tool is
effectively unauthenticated. That is the single largest reason it cannot find
critical and high bugs in real webapps today.

---

## 5. Process defects

| Defect | Consequence |
|---|---|
| `✓ Complete` means "the loop finished", not "anything was tested" | No coverage signal. A module that tests nothing and a module that found nothing look identical. |
| No per-module timeout in the orchestrator | One hung module (`open_redirect`) stalls the run indefinitely. |
| Findings are not de-duplicated | `Exposed Git Metadata` ×2, `Spring Boot Actuator` ×2, `phpinfo` ×2, `GraphQL` ×2, `API Documentation` ×4. |
| No coverage metric anywhere | Nothing tells the operator what fraction of the attack surface was examined. |
| `cors_audit`/`js_analysis` fail silently | No distinction between "clean" and "never ran". |
| Confidently wrong severities | A `200` was graded `CRITICAL`/`CONFIRMED`. Severity must never exceed what the evidence supports. |

---

## 6. What a real red-teaming weapon needs that this does not have

Ordered by how much they block a bounty payout.

1. **Differential baselining as a platform primitive, not a per-module patch.**
   The catch-all-response problem is the single largest source of false
   positives and it is currently fixed module-by-module, which does not scale and
   already failed to propagate to `fast_exposure_scan`. Every HTTP-fetching
   module should get a shared client that (a) fingerprints the dominant
   response, (b) auto-excludes it, (c) refuses to rate above `INFO` without a
   second, distinguishing signal. This one change removes ~all of §3.1.

2. **Real coverage accounting.** Per module: requests sent, endpoints in scope,
   parameters tested, actions run, and what was *not* attempted. "Clean" must be
   a claim the tool can defend, not a default.

3. **Session and auth handling.** The tool is effectively unauthenticated. It
   cannot test a logged-in surface, which is where IDOR, mass assignment,
   privilege escalation and business logic live — the highest-value bug classes
   in any bug bounty. `AuthHarness` exists but nothing depends on it reliably.
   This is the biggest single capability gap.

4. **A working JS pipeline.** `js_analysis` finding 0 of 3 files is disqualifying:
   JS bundles are where API keys, internal hostnames, source maps and hidden
   endpoints live. It should parse the HTML, follow the scripts, download them,
   and extract endpoints/secrets/sourcemaps.

5. **Breadth of exploitation.** 15 actions is narrow. Missing entirely: IDOR
   (object-ID enumeration + cross-identity comparison), broken object-level
   authorisation, business logic and workflow abuse, file upload, deserialisation,
   OAuth/OIDC, GraphQL depth/batching, race conditions, subdomain takeover, and
   privilege escalation primitives. `idor_differ` exists as a module but is not
   wired as an action, so the executor cannot prove IDOR.

6. **Action parameter contracts enforced in one place.** The `requires` field
   exists and is correct, but nothing validated it until commit `2768006`, and
   four JWT actions remain permanently unarmable because no module extracts a
   token into the graph. A capability matrix that reports "action X is never
   armed, because Y" is what makes this maintainable.

7. **Fingerprint-aware adaptation.** Stack detection returned `unknown` on a
   Node/Express app. Routing exploitation by stack (SQLite-specific SQLi, Angular
   template injection, Express-specific middleware flaws) needs this first.

8. **Deduplication and finding hygiene.** Eleven of 21 findings were duplicates
   of five real signals. Presentation noise devalues the real ones.

9. **Default budgets.** Ship `max_requests` and `max_time` with sane ceilings;
   make `--max-risk` and budget explicitly overridable.

10. **Per-module timeouts and cancellation.** A module that hangs must be killed
    and reported as incomplete.

11. **Detachability / rate discipline.** Nothing throttles per-host request rate.
    For real engagements that is how you get blocked or banned.

---

## 7. Recommended order of work

1. **Shared response-baselining HTTP client** (§5.1) — kills the 22 false
   positives, the single biggest trust problem.
2. **Per-module timeout + "incomplete" status** (§3.6, §4) — stops hangs from
   looking like results.
3. **Fix `js_analysis`** (§3.3) — unlocks secret extraction *and* the `extract`
   edges the graph needs.
4. **Propagate the category vocabulary** into the graph so `exploit` edges are
   built from real findings (§3.2).
5. **Authenticated session support** (§5.3) — unlocks the highest-paying bug
   classes.
6. **Wire `idor_differ` as an action** so the executor can prove IDOR.
7. **Coverage accounting + dedup** so "clean" becomes defensible.

Items 1–4 are what separate this from a recon toy: they make the tool's output
*trustworthy*. Nothing else matters until then.

---

## 8. Reproducing this audit

```bash
# per-module timings and deltas
MODULE_TIMEOUT=100 .venv/bin/python -u /tmp/drive_modules.py

# pentest with the executor armed
.venv/bin/python -u /tmp/drive_pentest.py

# executor hand-armed at a known-true endpoint
.venv/bin/python -u /tmp/drive_direct.py

# the false-positive proof: every path is the SPA shell
for p in .env .git/config wp-config.php actuator/env backup.sql phpmyadmin/; do
  curl -s -o /dev/null -w "%{http_code} %{size_download}  $p\n" "http://localhost:3000/$p"
done
curl -s http://localhost:3000/totally/bogus | md5sum   # identical md5 to /
```
