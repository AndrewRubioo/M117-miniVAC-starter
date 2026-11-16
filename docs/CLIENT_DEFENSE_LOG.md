# Client Defense Log (MiniVAC)

**Owner:** Arian (client defense) · **Team:** Team VAC (Team 21) · **Started:** 2026-11-15
**Status:** Client defense v2 implemented, tested, and evaluated on Andrew's 21 scenarios plus 11 new ones. Backlog in section 8.
**Branch:** `client-defense`, built on `client-attacks`. It adds files and one README section; no existing code is changed.

This is the companion to `docs/CLIENT_ATTACK_LOG.md`. Scenario IDs starting CA and CL are Andrew's. IDs starting DA (defense-aware attack) and DL (legitimate control) are new here. Section 9 is append-only. The table in section 4.1 comes from the code, so regenerate it with `python run_client_defense.py --markdown` rather than editing it by hand.

## 1. Summary

- **More of Andrew's attacks are caught.** The starter guard caught 6 of his 15 attacks on its own and 7 in combined mode. v2 catches 9 on its own and 10 in combined mode. The three gained are CA04, CA09 and CA12: the attacks that edited the guard's reference data or reused an approved plugin name.
- **The false positives did not move.** Three of his six legitimate controls were flagged before (CL03, CL04, CL06) and the same three are flagged now. v2 names them more precisely and attaches a "repair" or "block" response instead of a ban, but it still cannot tell them from attacks.
- **Four new attacks are caught only when both sides cooperate.** Switching the guard off (DA01), replaying an old report (DA02), replacing the key the guard trusts (DA04) and rolling back to an old signed manifest (DA05) are missed by the client alone and by the server alone, and caught in combined mode.
- **Eight attacks still get past combined mode:** forged reports (CA11, DA03), code hidden from the guard (DA06), changes made only between scans (CA05, CA10), input automation that stays inside the rules (CA13, CA14), and dropping reports then leaving early (DA08). The first seven are missed in every mode. In DA08 the guard raises a local alert that never reaches the server.
- **The new server-side check has a cost.** An honest client whose reports cannot be delivered is flagged (DL03). That is a false positive v2 introduced.

These are results from a toy model with scenarios we chose. They show mechanisms. They are not detection rates for VAC or for any real anti-cheat.

## 2. Scope and ground rules

- Everything here guards only the MiniVAC toy client: one test asset file in a temporary directory, and toy plugins that are a name plus a byte string. No plugin is imported or executed. Nothing touches real games, VAC, other processes or the OS.
- Ground truth is a **policy violation** label chosen by us, not proven intent.
- "Flagged" means some evidence exists. It does not mean the action was blocked, and it does not mean the player was proven to be cheating.
- The starter guard (`minivac/client_guard.py`) is left untouched so that the two guards can be compared on the same attacks, and so Andrew's regression tests keep passing.

## 3. What was built

| File | Side of the trust boundary | Job |
|---|---|---|
| `minivac/manifest.py` | Trusted publisher | The baseline: SHA-256 of each protected asset and each approved plugin, with a MAC tag |
| `minivac/client_defense.py` | Client (untrusted) | `HardenedClientGuard`: measures the client, compares it with the manifest, gates plugin loads, builds reports |
| `minivac/integrity_verifier.py` | Server (trusted) | `IntegrityVerifier`: judges the client's reports against the server's own manifest and notices when reports stop |
| `minivac/client_defense_eval.py` | Test harness | Runs every scenario against v2 in the three modes, plus the scan-interval sweep |
| `run_client_defense.py` | | Prints results, writes `client_defense_results.csv` and `client_defense_scan_sweep.csv` |
| `tests/test_client_defense.py` | | 50 tests |

Each feature below lists the problem, the attack it answers, how it works, what it does not stop, and the test that covers it.

### 3.1 Authenticated manifest

- **Problem:** the starter guard keeps its expected hash and its allowlist as plain attributes. Whoever can write to them decides what "clean" means.
- **Attacks:** CA04 (rewrite the expected digest), CA12 (add a plugin to the allowlist).
- **How it works:** the digests and the allowlist live in one manifest, and the publisher attaches an HMAC-SHA256 tag over a canonical encoding of it. The guard checks the tag before it uses any digest. If the tag does not verify, the guard raises `manifest_auth_failed` and consults none of the manifest. This is the fail-safe default: an unverifiable reference clears nothing.
- **Does not stop:** an attacker who replaces the key the guard trusts (DA04), or who supplies an old manifest with a genuine tag (DA05). The standard library has no public-key signatures, so HMAC stands in for one. A real client would hold only a public key. That changes how the key is replaced, not whether it can be.
- **Tests:** `ManifestTests`, `GuardTests.test_edited_manifest_fails_closed`.

### 3.2 Plugin allowlist by content

- **Problem:** the starter allowlist checks the name a plugin gives itself.
- **Attack:** CA09 (unauthorized code that calls itself `hud`).
- **How it works:** a plugin is approved only if its name is in the manifest and the SHA-256 of its content equals the digest recorded for that name. Names are still matched exactly, so `HUD`, `hud ` and the empty name stay rejected (CA06 to CA08).
- **Does not stop:** code that never appears in the list of loaded plugins the guard is given (DA06). The guard measures what it can enumerate, and the attacker controls the enumeration.
- **Tests:** `GuardTests.test_approved_name_with_other_content_is_caught`, `test_plugin_names_must_match_exactly`.

### 3.3 Load-time plugin gate

- **Problem:** the starter guard looks at plugins only when a scan runs, so anything loaded afterwards is never examined.
- **Attack:** CA10's timing, when the load goes through the game's own loader (DA07).
- **How it works:** the loader asks `authorize_plugin` before loading. An unapproved plugin is refused and a `plugin_blocked` event is raised. This is prevention at the moment of use instead of detection at the next poll, which is the complete-mediation principle. It is inspired by the idea behind Trusted Mode: restrict what may run alongside the game by default.
- **Does not stop:** code injected around the loader. CA10 as Andrew wrote it appends to the plugin list directly, and v2 still misses it.
- **Tests:** `GuardTests.test_load_gate_*`, `EvaluationTests.test_load_gate_blocks_the_cheat_and_admits_the_approved_plugin`.

### 3.4 Typed events with a suggested response

- **Problem:** the starter guard emits one string, `asset_integrity_violation`, for a tampered file, a patched file and a missing file.
- **Addresses:** the false-positive controls CL03, CL04 and CL06.
- **How it works:** events carry a code and a subject (`asset_modified`, `asset_missing`, `plugin_not_approved`, `plugin_content_mismatch`, `plugin_blocked`, `manifest_auth_failed`) and a suggested response: `repair`, `block` or `review`. None is `ban`, because each code has an innocent explanation among the controls.
- **Does not stop:** the false positives themselves. All three controls are still flagged. What changes is what the system can reasonably do about a flag.
- **Tests:** `GuardTests.test_modified_and_missing_assets_are_different_events`, `test_no_event_recommends_a_ban`.

### 3.5 Server-verified integrity reports

- **Problem:** in the starter harness a client alert counts as detection the moment it is raised. Nothing models how the defender learns of it, so nothing models the client lying.
- **Attacks:** DA04 and DA05, and the server-side half of CA04 and CA12.
- **How it works:** after each scan the guard sends its measurements (asset digests, plugin names and digests) with a single-use nonce from the server. The server compares them with its own copy of the manifest. The decision is made on the trusted side, with reference data the attacker cannot reach.
- **Does not stop:** an invented report. The expected digests are public and nothing ties a report to the real state of the client, so sending the expected values with the current nonce passes (CA11, DA03). This is self-reporting. It is not remote attestation, which needs a key the machine's owner cannot extract.
- **Tests:** `VerifierTests`, `EvaluationTests.test_editing_the_client_manifest_does_not_reach_the_server_reference`.

### 3.6 Report freshness and liveness

- **Problem:** if silence costs nothing, the cheapest attack is to switch the guard off.
- **Attacks:** DA01 (guard off), DA02 (replay a report captured before tampering).
- **How it works:** a nonce is accepted once, so a replayed report is refused. A session with no valid report for more than 5 seconds is flagged `integrity_report_overdue` when its next action arrives.
- **Does not stop:** a session shorter than the deadline (DA08), or a forger who keeps answering on time (DA03). It also flags an honest client whose reports are lost (DL03).
- **Tests:** `VerifierTests.test_liveness_boundary`, `test_a_report_cannot_be_used_twice`, `EvaluationTests.test_liveness_check_adds_a_false_positive`.

## 4. Results

**What "flagged" means in each mode.** Client only: the guard raised a local alert, and we assume someone sees it. Server only: the server rejected an action. Combined: the server holds evidence, either a rejected action or a finding from verifying a report. This is stricter than the starter harness, where combined mode counts any local alert. For Andrew's 21 scenarios the two definitions give the same answers. They differ on DA08.

### 4.1 Every scenario

| ID | Scenario | Ground truth | Starter guard (client / server / combined) | v2 guard (client / server / combined) | Server-side evidence in combined mode (v2) |
|---|---|---|---|---|---|
| CA01 | asset_append_byte | violation | flagged / no / flagged | flagged / no / flagged | `asset_modified:test_game_asset.txt` |
| CA02 | asset_whitespace_change | violation | flagged / no / flagged | flagged / no / flagged | `asset_modified:test_game_asset.txt` |
| CA03 | asset_deleted | violation | flagged / no / flagged | flagged / no / flagged | `asset_missing:test_game_asset.txt` |
| CA04 | baseline_digest_rewrite | violation | no / no / no | flagged / no / flagged | `asset_modified:test_game_asset.txt`, `client_declared:manifest_auth_failed:manifest` |
| CA05 | modify_then_revert | violation | no / no / no | no / no / no | none |
| CA06 | plugin_case_variant | violation | flagged / no / flagged | flagged / no / flagged | `plugin_not_approved:'HUD'` |
| CA07 | plugin_trailing_space | violation | flagged / no / flagged | flagged / no / flagged | `plugin_not_approved:'hud '` |
| CA08 | plugin_empty_name | violation | flagged / no / flagged | flagged / no / flagged | `plugin_not_approved:''` |
| CA09 | plugin_name_spoof | violation | no / no / no | flagged / no / flagged | `plugin_content_mismatch:'hud'` |
| CA10 | plugin_loaded_after_scan | violation | no / no / no | no / no / no | none |
| CA11 | monitor_output_forged | violation | no / no / no | no / no / no | none |
| CA12 | allowlist_edited | violation | no / no / no | flagged / no / flagged | `client_declared:manifest_auth_failed:manifest`, `plugin_not_approved:'cheat_plugin'` |
| CA13 | macro_fire_on_cooldown_edge | violation | no / no / no | no / no / no | none |
| CA14 | movement_at_speed_limit | violation | no / no / no | no / no / no | none |
| CA15 | monitor_disabled_plus_teleport | violation | no / flagged / flagged | no / flagged / flagged | `speed_violation` |
| CL01 | legit_human_firing | legit | no / no / no | no / no / no | none |
| CL02 | legit_approved_plugins | legit | no / no / no | no / no / no | none |
| CL03 | legit_game_update_stale_baseline | legit | flagged / no / flagged | flagged / no / flagged | `asset_modified:test_game_asset.txt` |
| CL04 | legit_third_party_overlay | legit | flagged / no / flagged | flagged / no / flagged | `plugin_not_approved:'overlay'` |
| CL05 | legit_human_movement | legit | no / no / no | no / no / no | none |
| CL06 | legit_missing_asset | legit | flagged / no / flagged | flagged / no / flagged | `asset_missing:test_game_asset.txt` |
| DA01 | monitor_disabled_silent_play | violation | not applicable | no / no / flagged | `integrity_report_overdue` |
| DA02 | report_replay | violation | not applicable | no / no / flagged | `integrity_report_overdue`, `report_nonce_invalid` |
| DA03 | report_forged_fresh_nonce | violation | not applicable | no / no / no | none |
| DA04 | trust_anchor_replaced | violation | not applicable | no / no / flagged | `asset_modified:test_game_asset.txt` |
| DA05 | manifest_rollback | violation | not applicable | no / no / flagged | `asset_modified:test_game_asset.txt`, `manifest_version_mismatch` |
| DA06 | hidden_plugin | violation | not applicable | no / no / no | none |
| DA07 | unapproved_plugin_via_loader | violation | not applicable | flagged / no / flagged | `client_declared:plugin_blocked:'cheat_plugin'` |
| DA08 | reports_blocked_short_session | violation | not applicable | flagged / no / no | none |
| DL01 | legit_update_with_new_manifest | legit | not applicable | no / no / no | none |
| DL02 | legit_plugin_via_loader | legit | not applicable | no / no / no | none |
| DL03 | legit_report_channel_outage | legit | not applicable | no / no / flagged | `integrity_report_overdue` |

### 4.2 Counts

Attacks caught, and legitimate controls flagged, out of the number in each set.

| Scenario set | Guard | Client only | Server only | Combined |
|---|---|---|---|---|
| Andrew's 15 attacks | starter | 6 | 1 | 7 |
| Andrew's 15 attacks | v2 | 9 | 1 | 10 |
| Andrew's 6 controls | starter | 3 flagged | 0 | 3 flagged |
| Andrew's 6 controls | v2 | 3 flagged | 0 | 3 flagged |
| 8 new attacks (DA) | v2 | 2 | 0 | 5 |
| 3 new controls (DL) | v2 | 0 | 0 | 1 flagged |
| All 23 attacks | v2 | 11 | 1 | 15 |
| All 9 controls | v2 | 3 flagged | 0 | 4 flagged |

Only the first four rows compare like with like. Do not set "10 of 15" against "15 of 23": the second set contains attacks written to probe v2, and its totals say as much about which scenarios we wrote as about the defense.

### 4.3 By what the attacker is able to do

This is the view to use in the report. Each row is one more thing the attacker can do, and the columns show where that capability stops being caught.

| The attacker can… | Scenarios | Starter, combined | v2, client only | v2, combined |
|---|---|---|---|---|
| Edit a file or add an unapproved plugin | CA01–03, CA06–08 | 6 of 6 | 6 of 6 | 6 of 6 |
| Edit the guard's reference data, or reuse an approved plugin name | CA04, CA09, CA12 | 0 of 3 | 3 of 3 | 3 of 3 |
| Load an unapproved plugin through the game's loader, after the scan | DA07 | not applicable | 1 of 1 | 1 of 1 |
| Replace the key the guard trusts, or give it an old signed manifest | DA04, DA05 | not applicable | 0 of 2 | 2 of 2 |
| Switch the guard off, or replay an old report, in a session longer than the deadline | DA01, DA02 | not applicable | 0 of 2 | 2 of 2 |
| Drop the reports and leave before the deadline | DA08 | not applicable | 1 of 1 (alert raised, nobody receives it) | 0 of 1 |
| Change things only between scans | CA05, CA10 | 0 of 2 | 0 of 2 | 0 of 2 |
| Forge the reports, or hide code from the guard | CA11, DA03, DA06 | 0 of 1 | 0 of 3 | 0 of 3 |
| Automate inputs inside the server's rules | CA13, CA14 | 0 of 2 | 0 of 2 | 0 of 2 |
| Tamper and also send an illegal action | CA15 | 1 of 1 (server rule) | 0 of 1 | 1 of 1 (server rule) |

Detection delay, in simulated seconds from the start of the scenario: 5.5 s for DA01 (first action after the 5 s deadline), 0.5 s for DA02 (first replay attempt), and 0 for everything else that is caught. The fake clock has no network or processing delay, so these are lower bounds.

### 4.4 How much does scanning more often help? (CA05)

The attacker modifies the asset for a while and restores it. The guard scans on a fixed interval with a random phase. 200 seeded trials per cell for the blind attacker, 30-second sessions, real guard on a real temporary file under the fake clock.

Share of trials in which a scan caught the modified file. The prediction is window ÷ interval, capped at 100%.

| Scan every | Scans per minute | Modified for 0.25 s | Modified for 1 s | Modified for 4 s |
|---|---|---|---|---|
| 0.5 s | 120 | 48% (predicted 50%) | 100% (100%) | 100% (100%) |
| 1 s | 60 | 24% (25%) | 100% (100%) | 100% (100%) |
| 2 s | 30 | 13% (12.5%) | 50% (50%) | 100% (100%) |
| 5 s | 12 | 5% (5%) | 14% (20%) | 84% (80%) |
| 10 s | 6 | 2% (2.5%) | 8% (10%) | 42% (40%) |

That table is for an attacker who does not know when scans happen. The guard runs on the attacker's machine, so they can watch it. An attacker who modifies the file right after each scan and restores it 1 ms before the next was caught in 0 of 20 trials at every interval, with the file modified for 99.6% of the session or more.

So scanning more often only raises the cost for an attacker who is not looking. It does not close the gap.

### 4.5 Cost of one scan

Measured with `python run_client_defense.py --overhead` on an Apple M4 Pro, Python 3.13, file already in the OS cache: about 0.02 ms for a 1 KiB asset, 0.36 ms for 1 MiB, 5.6 ms for 16 MiB. That is roughly 3 GB per second of hashing. Extrapolating, which we have not measured: a full rescan of a 30 GB install would take about 10 seconds of CPU even with every file in memory, so a real client could not rescan everything every few seconds. These numbers depend on the machine and are not written to the CSV files.

## 5. The four scenarios that needed a v2 translation

Seventeen of Andrew's scenario functions run against v2 unchanged. Four reach into attributes that only the starter guard has, so the same move is re-expressed against v2. A test asserts that these four are the only ones, and the harness raises an error if an untranslated scenario touches starter-guard internals, so a future scenario cannot be misreported silently.

| ID | Starter guard | v2 |
|---|---|---|
| CA04 | Assign `guard.expected_asset_digest` | Overwrite the digest inside the local manifest. The attacker cannot produce a matching tag. |
| CA09 | Append a second `hud` to a list of names, which cannot express different code | Inject a plugin named `hud` whose content is not the approved content |
| CA11 | Replace `guard.inspect` with a function that returns no alerts | Replace `guard.scan` with one that returns the expected measurements, so the report to the server is forged too |
| CA12 | Add a name to `guard.allowed_plugins` | Add the plugin's name and digest to the local manifest. The tag no longer matches. |

Andrew, please check that these are fair to what you intended. CA04 and CA12 are caught in v2 because the attacker in them does not also replace the trust anchor. DA04 is the version where they do.

## 6. Key findings (for the report and slides)

1. **Protecting the reference data closes the cheapest attacks and nothing more.** Authenticating the manifest and hashing plugin content catch CA04, CA09 and CA12. The attacker's next step is to replace the key the guard trusts (DA04), and the client-only result goes back to a miss.
2. **The reference belongs on the trusted side.** DA04 and DA05 pass every local check and are caught only because the server compares the reported measurements with its own manifest.
3. **Defense in depth is more than "either side catches it."** DA01, DA02, DA04 and DA05 are caught by neither side alone. They are caught by a mechanism that needs both: the client measures, the server judges.
4. **Silence can be made visible. Lying cannot.** A disabled guard is flagged after the report deadline (DA01) and a replayed report at once (DA02). A forged report with a fresh nonce passes in every mode (CA11, DA03). Without a key or hardware that the machine's owner cannot reach, a client report is a claim.
5. **Client-only numbers are an upper bound.** They assume every local alert reaches someone. In DA08 the guard raises the alert and the attacker drops it on the way out.
6. **Polling leaves a window and an informed attacker lives in it.** A blind attacker is caught in proportion to window ÷ interval. A schedule-aware attacker is never caught, at any interval tested.
7. **The false positives are structural.** CL03, CL04 and CL06 are still flagged, each by the same check that catches an attack. Naming events precisely lets the response be "repair" or "block" rather than "ban", which lowers the cost of a false positive without lowering their number.
8. **New checks bring new false positives.** The liveness rule flags an honest client during a report outage (DL03). Raising the deadline reduces that and lengthens the window in DA08.

## 7. Limitations and threats to validity

- Toy 1D game, one asset, plugins that are byte strings, deterministic fake clock, no network. Reports are passed in-process, so "dropping" or "forging" one is a function call.
- The scenario mix drives every count. We wrote the DA scenarios knowing how v2 works, which is the point of them, and also why their totals are not a detection rate.
- HMAC stands in for a public-key signature. In the toy the guard is handed the publisher's `verify` method, which carries the secret key. A real client would not hold it.
- The guard's timer is simulated: a scan is run when the client is about to act and the interval has elapsed. A real monitor runs on its own thread.
- The guard scans once at launch before each scenario starts. The starter harness does not, so scan counts are not comparable between the two.
- `IntegrityVerifier` does not authenticate who is submitting. Anyone can submit a report under another player's ID, which would spend that player's nonce and get them flagged. The existing API has no accounts either. This is a server-side attack worth writing up (see section 8).
- Not modeled at all: reading or writing game memory, which Collins et al. (2024) treat as the basic cheat primitive, and kernel-level anti-cheat.
- Sample sizes are tiny outside the sweep. The sweep is a Monte Carlo estimate of a simple probability and matches it; it is evidence that the harness works, not a discovery.

## 8. Backlog and handoffs

Items from section 7 of `CLIENT_ATTACK_LOG.md` that this work covers: periodic scans and the evasion window for CA05 (section 4.4), hashing plugin content (3.2), and a server-supplied authenticated baseline (3.1, 3.5).

| Item | Owner | Notes |
|---|---|---|
| Review the four translations in section 5 | Andrew | Are CA04, CA09, CA11 and CA12 still the attacks you meant? |
| Attack v2 | Andrew, Suhaib | New CA scenarios are picked up automatically. A test fails until their v2 outcome is recorded in `EXPECTED_V2`. |
| HTTP endpoints for the verifier | Josh, Andrew | `POST /integrity/challenge` and `POST /integrity/report` in `api.py`, and a call to `check_liveness` when an action arrives. `IntegrityVerifier` is plain Python and the report is already JSON-shaped. |
| Frame another player through the report endpoint | David, Ay | See section 7. Needs session authentication to fix. |
| Malformed and oversized reports | David, Ay | Shape checks exist and are tested. Size limits and rate limits do not. |
| Behavioral detection for CA13 and CA14 | Josh | Nothing on the client side can see these. |
| Policy for CL04 | Suhaib, Arian | Let a player opt in to third-party software and mark the session untrusted, instead of flagging it. |
| Deadline and retry policy for DL03 | Arian | Measure the trade against DA08 by sweeping the report deadline. |
| Figure for the slides | Arian | Section 4.3 as a diagram, in the style of `docs/figures/client_attack_surface.png`. |
| Interactive client that shows guard events | Arian, team | Priority 2 in the project plan. Not started. |

## 9. Experiment log (append new entries at the bottom)

### 2026-11-15, entry 1: baseline reproduced
- Cloned the repo and checked out `client-attacks`. 17 tests pass. `run_client_attacks.py` reproduces the numbers in Andrew's log: client only 6 of 15, server only 1 of 15, combined 7 of 15, with 3 of 6 controls flagged.

### 2026-11-15, entry 2: design decisions
- New modules instead of edits to `client_guard.py`. Andrew's tests lock the starter guard's outcomes, and a before-and-after comparison needs both guards to exist.
- Standard library only, to keep "no dependencies" true for the experiments. That rules out public-key signatures, hence HMAC and the caveat in 3.1.
- Split by trust boundary: the manifest, the client guard and the server verifier are three files, so the code layout shows which side each decision is made on.

### 2026-11-15, entry 3: v2 implemented and evaluated
- Added the six features in section 3 and the harness. Predicted the outcome of all 31 scenarios before the first run and all 31 matched.
- Tests pass on Python 3.10, 3.11 and 3.13.

### 2026-11-15, entry 4: mutation check found a gap in the scenarios
- Broke 14 things on purpose in a throwaway copy, one at a time (guard ignores the tag, nonce reusable, liveness off by one, client and server sharing one manifest object, and so on), and ran the tests against each.
- 13 were caught. The survivor: counting local alerts as detection in combined mode changed no outcome, because no scenario had an alert that failed to reach the server.
- Added DA08 (drop the reports, leave before the deadline) to separate the two. All 14 are now caught. Totals: 32 scenarios, 67 tests (17 existing, 50 new).

## 10. How to reproduce

```bash
python run_client_defense.py             # prints results, writes the two CSV files
python run_client_defense.py --markdown  # regenerates the table in section 4.1
python run_client_defense.py --overhead  # scan cost on your machine
python -m unittest discover -s tests -v  # 67 tests
```

## 11. Sources and what is ours

- The mechanisms in section 3 are our own toy designs. None is a description of how VAC or Trusted Mode is implemented, and we do not know those internals.
- "Inspired by Trusted Mode" in 3.3 refers only to the publicly described idea of restricting which third-party software may interact with the game. **To verify before the report:** read the Steam Support article "CS2 - Trusted Mode" (https://help.steampowered.com/en/faqs/view/09A0-4879-4353-EF95) and quote it directly. Its text could not be loaded while this log was written.
- **To verify before citing:** Source-engine "pure servers" (`sv_pure`) are, from memory, a Valve mechanism in which the server decides which client files must match its own. If the Valve Developer Community page confirms that, it is a documented real-world relative of 3.5.
- Collins et al. (2024) for the man-at-the-end framing, as in Andrew's log.
