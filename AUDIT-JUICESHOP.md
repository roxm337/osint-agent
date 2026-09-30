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
| Action library (`actions/`, 16 actions) | **Works.** Proved a real SQLi unaided. |
| Chain executor (`core/chain_executor.py`) | **Works.** Correct arming, correct silence, correct promotion. |
| Detection modules (`modules/`) | **Broken on modern SPAs.** 22 false positives, several key false negatives. |
| Attack graph (`core/attack_graph.py`) | **Was starved.** 24 nodes → 3 edges → 0 chains on a target with a known SQLi. Cause found and fixed (`8ec2bc9`): edges were built only from already-confirmed vulns, so a clean detector left the executor nothing to run. |
| `run_pentest --execute` end to end | **Fired nothing.** 0 proven, 0 blocked, 0 skipped, 0 chains — and said nothing about why. Now the planner reports its ceiling and what it skipped, and points at `--max-risk MEDIUM`. |

The headline number: **21 findings, 22 of them false positives.** The single true
positive the tool produced on its own initiative was an accident of a header
check, not detection.

**What has changed since the run**, all verified by mutation testing rather
than by inspection: 20 of the 22 false positives are gone and the detector that
made them can no longer make them again; and the zero-chain result had a single
specific cause that is now fixed, so the executor can originate a hunt instead
of only confirming one. What is still unmeasured is whether the fixed pipeline
finds real bugs on a live target — see §4.

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

#### Two more modules had the same bug, and are fixed (`f9bf594`)

- `misconfig` used `len(body.strip()) > 50` — a 9393-byte SPA shell satisfies
  that too. It now gates on both the catch-all comparison and a per-path
  content assertion, and reports coverage so a run that could distinguish none
  of its probes says so instead of looking like a clean target.
- `rest_api` graded `FIRM` straight off `status == 200`. Those assets feed the
  attack graph, so a phantom endpoint becomes a chain target later: the false
  positive propagated into the exploitation stage, which is worse than a noisy
  report.

#### Six more did not, and are allowlisted with reasons

Most have a better oracle than status, and gating them would make them worse.
`mass_assignment` and `prototype_pollution` compare before/after bodies, so a
SPA shell is a perfectly good baseline for "did this field get written" — a
catch-all check there would suppress true positives. `js_analysis` and
`mobile_assets` use a 200 to decide what to fetch next and file nothing on its
strength. `graphql_module` already requires an `is_graphql` content marker.
`cloud_enum` probes provider-owned hosts, where a 200 from S3 is the bucket
answering. `git_exposure` was on the original suspect list but does not branch
on a status at all. Each exception is recorded in
`tests/test_no_blind_trust.py`, and that test fails if the allowlist grows past
half the modules or names a module that no longer exists.

#### The defence is structural, not a convention

`tests/test_no_blind_trust.py` reads the module sources and fails the build if
a module compares a status to a 200-literal and files findings without routing
through the shared decision point. It checks for a real *call* in the AST, not
an import, because a bare import would otherwise satisfy it.

Availability is not enforcement, though: a module can keep the call, keep the
import, and pass that suite while returning a critical finding on every path.
`tests/test_catch_all_server.py` closes that gap by running the real modules
against a fake server that returns one 200 page for every path and requiring
silence — then against one that genuinely serves `.env` and requiring a
critical, so the gate cannot be a mute button.

Worth recording how that test was wrong twice before it was right. Its first
`rest_api` version passed because `curl_json` was unmocked, so the module made
a real network call and exited before reaching the code under test. And it
asserted the absence of `CONFIRMED` when that code path only ever emits `FIRM`
and `TENTATIVE`, so it could not have failed either way. A test that cannot
fail is worse than no test, because it is counted as coverage.

`fast_exposure_scan` had its own second copy of the ten rules, which is exactly
how the content assertions drifted out of step with them. It now imports the
shared set. Assertion lookup also falls back to matching keys as regexes
against the path, so renaming a rule group can no longer silently disarm its
own check.

`Baseline.catch_all` claimed three signals in its docstring and implemented
two. The docstring now matches the code, and records why status and content
type are excluded: a real 404 and a real 200 often share both, so including
them would suppress true findings.

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

The gap is **recall**, and it was not a tuning problem. The executor needs a
`(url, param, category)` triple; the detectors were supposed to supply it and
supplied the wrong categories instead. Nothing was wired end to end, so
`--execute` had never found anything by itself.

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

#### The zero-chain result had a specific, fixable cause

`--execute` produced 0 chains because `AttackGraph` built exploit edges only
from vulns that were **already confirmed**. A detector that found nothing left
the graph with nothing to execute, so the executor could confirm a human's
hypothesis but could never originate one. The action library was fully capable
the whole time.

`AttackGraph.propose_test_edges` (8ec2bc9) inverts the order: a `(url, param)`
pair is a legitimate target before anything is known to be wrong with it,
because the action is the oracle. `web.sqli.detect` either finds injection or
reports the parameter clean, and a clean result recorded as a clean result is
worth having too. Each proposed edge now carries the `action_id` that will
prove it — a field that was documented on `AttackEdge` and never populated
anywhere in the codebase.

```
LOW ceiling    : 0 probes  — "web.sqli.detect is MEDIUM, above the LOW ceiling" (3)
MEDIUM ceiling : 2 probes  — 2 chains, each naming web.sqli.detect
```

**A finding from doing this: the default configuration cannot hunt.** Every
injection action in the library is MEDIUM or above, so `--max-risk LOW` — the
default — proposes nothing. That classification is defensible, since
`sqli.detect` does send `UNION` payloads, so it has not been changed to make a
feature work. Instead the planner now records *why* it proposed nothing and
the orchestrator prints it. Previously an empty list was returned
indistinguishably from "found nothing", which is exactly how a scan of a real
application reported zero chains and no explanation.

The risk ceiling is enforced by explicit rank rather than by comparing
`RiskLevel` values as text. Those are the strings `LOW`/`MEDIUM`/`HIGH`, and
lexicographically `MEDIUM` sorts *below* `LOW`, so a text comparison would
wave every injection action straight through a LOW ceiling.

**Still unmeasured:** whether MEDIUM detection over real surface actually finds
real bugs. That is a live-target question and the reason the target is needed
back.

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

**Done since the run:**

1. ~~Shared response-baselining~~ (§3.1) — `core/response_fingerprint.py` +
   `core/site_profile.py`, one decision point, 20/20 false positives eliminated,
   enforced by `tests/test_no_blind_trust.py` and `tests/test_catch_all_server.py`.
2. ~~Graph could not originate a hunt~~ (§4) — `propose_test_edges` gives every
   testable `(url, param)` a probe, and the planner explains its own silence.
3. ~~Content assertions could be silently disarmed by a rename~~ — lookup falls
   back to path matching; the duplicated rule set is gone.

**Still to do, in order:**

4. **Measure recall against `/api/Challenges`** — the one number that settles
   whether this finds real critical/high bugs. Needs the target back.
5. **Authenticated session support** (§5.3) — Juice Shop's IDOR, mass
   assignment and access-control bugs are all behind login, so this is the
   biggest single recall constraint on real webapps.
6. **Per-module timeout + "incomplete" status** (§3.6) — `open_redirect` ran
   100s and `email_security` hung on DNS for `localhost`; a hang must not look
   like a result.
7. **Fix `js_analysis`** (§3.3) — 0 files analysed despite 3 script tags; it
   gates secret extraction.
8. **Wire `idor_differ` as an action** so the executor can prove IDOR.
9. **Coverage accounting + dedup** so "clean" becomes defensible.

Items 4 and 5 are what turn this from a trustworthy recon tool into one that
finds high-value bugs. Nothing after them matters as much.

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
