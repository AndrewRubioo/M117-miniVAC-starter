# Client Attack Log (MiniVAC)

**Owner:** Andrew (client attack) · **Team:** Team VAC (Team 21) · **Started:** 2026-11-15
**Status:** 14 attack scenarios and 4 legitimate controls implemented, tested and documented. Backlog in section 7.

Update this file whenever something is tried, tested or implemented. Section 4 is append-only; everything else can be edited. The results table in section 3 comes from the code, so regenerate it rather than editing by hand.

## 1. Scope and ground rules

- Every scenario targets only the MiniVAC toy client (`minivac/client_guard.py`) and toy server (`minivac/server_logic.py`), using temporary files created for the run. Nothing touches real games, VAC, other processes or the OS.
- Results describe the toy model. They are **not** VAC's behavior and not real detection rates.
- Ground truth is a **policy violation** label chosen by us, not proven intent.
- Code lives in `minivac/client_attacks.py` (separate from `experiments.py` so teammates' edits don't collide).

## 2. How client attacks are carried out

In this model the attacker controls the client machine, so the client is untrusted. The defender only sees what the client monitor reports and the actions that reach the server. An attack therefore works if it avoids leaving evidence in either place. The scenarios pull four levers:

1. **Change what the monitor checks:** edit, extend or delete the files the client loads.
2. **Change what runs next to the game:** load extra plugins, or give them an approved name.
3. **Change the monitor itself:** disable it, forge its report, or edit its reference data (the expected hash, the allowlist).
4. **Change timing and inputs:** act between scans, or drive actions that stay inside the server's limits.

This is the "man-at-the-end" setting that Collins et al. (2024) use to study client-side anti-cheat. Levers 1 and 2 are the ones a hash check or allowlist can see. Levers 3 and 4 are the ones it cannot, which is where most of the results below come from.

## 3. Attack catalogue and results

Ground truth and detection per mode. "Client only" runs the toy monitor with permissive server rules, "server only" runs the server rules with no monitor, "combined" runs both.

| ID | Scenario | Ground truth | How it is carried out | Client only | Server only | Combined |
|---|---|---|---|---|---|---|
| CA01 | asset_append_byte | violation | Attacker edits a file the client loads. Any byte change alters the SHA-256, so the hash check sees it. | flagged | not flagged | flagged |
| CA02 | asset_whitespace_change | violation | Same lever, smallest visible edit. Tests whether cosmetic changes slip past the hash. | flagged | not flagged | flagged |
| CA03 | asset_deleted | violation | Attacker removes the file. The guard treats an unreadable file as a mismatch. | flagged | not flagged | flagged |
| CA04 | baseline_digest_rewrite | violation | The reference hash lives in client memory, so the attacker replaces it with the hash of the modified file; the check then passes. | not flagged | not flagged | not flagged |
| CA05 | modify_then_revert | violation | The monitor is point-in-time. The attacker changes things only in the gap between scans, so every scan sees a clean file. | not flagged | not flagged | not flagged |
| CA06 | plugin_case_variant | violation | Tests whether a near-miss of an approved name gets through. Matching is exact, so it is flagged. | flagged | not flagged | flagged |
| CA07 | plugin_trailing_space | violation | Another near-miss of an approved name. Exact matching flags it. | flagged | not flagged | flagged |
| CA08 | plugin_empty_name | violation | Edge case for the allowlist. An empty string is not approved, so it is flagged. | flagged | not flagged | flagged |
| CA09 | plugin_name_spoof | violation | The allowlist trusts the name a plugin gives itself, not its contents. The attacker simply uses an approved name. | not flagged | not flagged | not flagged |
| CA10 | plugin_loaded_after_scan | violation | The monitor scans once. Anything loaded later is never examined. | not flagged | not flagged | not flagged |
| CA11 | monitor_output_forged | violation | The attacker controls the monitor's process, so the report it sends is whatever the attacker chooses. | not flagged | not flagged | not flagged |
| CA12 | allowlist_edited | violation | The allowlist is client-side data the attacker can edit, so the plugin becomes 'approved'. | not flagged | not flagged | not flagged |
| CA13 | macro_fire_on_cooldown_edge | violation | A client-side script fires as fast as the server allows. Every request is individually legal, so rule checks cannot object. | not flagged | not flagged | not flagged |
| CA14 | movement_at_speed_limit | violation | A client-side script rides the server's limit. No single action breaks a rule. | not flagged | not flagged | not flagged |
| CL01 | legit_human_firing | legit | Control: ordinary play, and the contrast case for CA13's perfect regularity. | not flagged | not flagged | not flagged |
| CL02 | legit_approved_plugins | legit | Control: allowed plugins should never be flagged. | not flagged | not flagged | not flagged |
| CL03 | legit_game_update_stale_baseline | legit | Control that exposes a false positive: the hash check cannot tell a patch from tampering. | flagged | not flagged | flagged |
| CL04 | legit_third_party_overlay | legit | Control that exposes a false positive: the allowlist cannot tell a benign tool from a cheat. | flagged | not flagged | flagged |

### Summary by category (combined mode)

| Category | Scenarios | Caught |
|---|---|---|
| Asset tampering (naive edits) | CA01–CA03 | 3 of 3 |
| Plugin name variants | CA06–CA08 | 3 of 3 |
| Plugin name spoof | CA09 | 0 of 1 |
| Monitor tampering | CA04, CA11, CA12 | 0 of 3 |
| Timing evasion | CA05, CA10 | 0 of 2 |
| In-bounds input automation | CA13, CA14 | 0 of 2 |
| **All attacks** | 14 | **6 of 14 (TPR 43%)** |
| Legitimate controls flagged | CL01–CL04 | 2 of 4 (FPR 50%) |

Server only caught 0 of 14: none of these attacks produce an action the server rules reject, which is the point of the design.

## 4. Experiment log (append new entries at the bottom)

### 2026-11-15, entry 1: explored the harness
- Read the README, source and tests. Baseline: 7 unit tests pass. `run_experiments.py` (8 scenarios) gives combined TPR 80%, FPR 0%; the only miss is the disabled monitor.
- Observation: the baseline suite has no legitimate case that the defenses flag, so FPR is 0% in every mode. That makes the false-positive side of the tradeoff invisible.

### 2026-11-15, entry 2: ad-hoc probing in a scratch copy (repo not modified)
Tried candidate attacks directly against `ClientGuard` and `GameServer` to decide which belong in the catalogue.
- Caught: whitespace edit, appended byte, deleted asset, `HUD`, `hud `, empty plugin name.
- Missed: rewriting the expected digest, modify-then-revert between scans, malicious plugin named `hud`, disabled monitor, forged monitor output, edited allowlist.
- Missed by both sides: 1000 shots at cooldown + 1 µs, 1000 moves at exactly max speed.
- False positives found: legitimate game update with a stale baseline; harmless third-party overlay plugin.
- Server-side observation (not a client attack): after 10 s idle the server accepted a 49-unit jump, because idle time counts toward the movement budget. Handed to David (see section 7).

### 2026-11-15, entry 3: implemented the scenario suite
- Added `minivac/client_attacks.py` (14 attacks, 4 controls, each with a "how it is carried out" description), `run_client_attacks.py`, `tests/test_client_attacks.py`, and this log.
- New scenarios needed multi-step behavior (several scans, hundreds of actions), so they use an `AttackEnv` object instead of the single-scan pattern in `experiments.py`.
- Added CA10 (plugin loaded after the only scan) and legitimate control CL01 (irregular human firing) beyond the probe list.
- Result: 15 tests pass (7 original, 8 new). Combined mode: TPR 43% (6 of 14), FPR 50% (2 of 4).
- Tests lock the expected outcome of every scenario in every mode, so a rule change by a teammate that flips a result will fail a test. That is intended; update `expected_detected` in the scenario and add a log entry when it happens.

### 2026-11-15, entry 4: figure exported and HTTP server checked
- Exported a static attack-surface figure: `docs/figures/client_attack_surface.png` (and `.svg`). It shows each client entry point, the attacks that enter there, and whether combined mode caught them.
- Clarified how attacks are sent: `run_client_attacks.py` calls `ClientGuard` and `GameServer` directly in one Python process with a fake clock. No network is involved.
- Started the optional FastAPI server (`minivac/api.py`) and sent requests over HTTP with curl. Valid move accepted; 20-unit teleport rejected (`speed_violation`); second immediate shot rejected (`fire_rate_violation`); an extra `x: 999` field claiming a position was ignored; `/docs` page loads.
- Over HTTP with the real clock, 10 shots sent 0.31 s apart were all accepted: the CA13 macro-fire result holds outside the fake clock too.
- Gap: the API exposes only the server. The client guard has no network endpoint, so asset, plugin and monitor attacks cannot be sent over HTTP, and no client report crosses the network. A client that reports its scan results to the server would be needed to demonstrate CA11-style forging over the wire.

## 5. Key findings (for the report and slides)

1. **The client cannot vouch for itself.** Rewriting the baseline hash (CA04), forging the monitor's output (CA11) and editing the allowlist (CA12) each defeat client checks completely, and the server cannot see them either.
2. **Point-in-time checks leave gaps.** Reverting a change before the next scan (CA05) or loading a plugin after the only scan (CA10) leaves the monitor with nothing to report.
3. **Name-based trust is weak.** An allowlist checks what a plugin calls itself, so a plugin named `hud` passes (CA09). Near-miss names are caught, but only because matching is exact.
4. **Rule checks cannot catch automation that stays in bounds.** Scripted firing and movement at the exact limits (CA13, CA14) pass every server rule, which is the toy-model analog of the "humanized" behavior that motivates statistical detection (e.g. XGuardian). CL01 provides the human contrast case for any future timing-based detector.
5. **Client-side defenses create false positives.** Both controls CL03 and CL04 are flagged, giving a nonzero FPR for the first time and a concrete example of the detection vs. false-positive tradeoff.
6. **Defenses complement each other.** Client checks catch the naive tampering the server cannot see; the server catches illegal actions the client cannot report. Neither covers the blind spots above.

## 6. Limitations and threats to validity

- Toy 1D game, deterministic fake clock, no latency or jitter, no randomness, so repeated runs give identical results.
- The scenario mix drives the headline numbers. The 80% TPR in the original suite and 43% here are **not comparable**; both reflect the scenarios we chose, and the contrast shows how sensitive the metric is to that choice.
- Combined mode ORs client alerts with server rejections. The harness does not model the network channel that would carry client reports, so forging is simulated by changing the monitor's output (CA11).
- Labels are policy violations we assigned. CA13 and CA14 are labeled violations because they represent automation, even though no server rule is broken.
- Sample sizes are tiny; treat the tables as illustrations of mechanisms, not statistics.

## 7. Backlog and handoffs

| Item | Owner | Notes |
|---|---|---|
| Periodic scans (every N ticks) and measure the evasion window for CA05 and CA10 | Andrew / Arian | Tests how much scanning frequency helps vs. CPU cost |
| Hash the plugin contents instead of trusting the name | Arian | Would address CA09; adds a new baseline to protect |
| Server-supplied, authenticated baseline | Arian | README notes a signed manifest still doesn't stop a client lying about its own result |
| Timing-regularity detector for CA13 using CL01 as the contrast | Josh | Server-side behavioral check; measure its FPR on legit variation |
| Idle-time movement budget (idle 10 s, then 49-unit jump accepted) | David | Server rule design question from entry 2 |
| Add latency/jitter and randomized timing, then repeat runs | Team | Needed before quoting any rates |
| HTTP attack client and a client-report endpoint | Andrew | Sends CA13/CA14 over HTTP and lets the server receive (forgeable) guard reports |

## 8. How to reproduce

```bash
python run_client_attacks.py            # prints results, writes client_attack_results.csv
python run_client_attacks.py --markdown # regenerates the table in section 3
python -m unittest discover -s tests -v # 15 tests
```

## 9. Material for the midterm slides

- **Slide idea 1: how client attacks work.** The four levers from section 2, one line each.
- **Slide idea 2: results by category.** The summary table in section 3.
- **Slide idea 3: takeaway.** Client checks catch naive tampering (6 of 6) and miss everything the client controls or that stays in bounds (0 of 8); legit changes cause false positives (2 of 4).
- **Speaker note:** state clearly that this is a toy model and the numbers show mechanisms, not VAC performance.
