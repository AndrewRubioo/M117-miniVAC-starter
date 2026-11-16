# MiniVAC — M117 cybersecurity proof of concept

A **small, deliberately simplified anti-cheat testbed** for an academic course project.
It is **not** Valve Anti-Cheat (VAC), a VAC implementation, a cheat, a CS2 plugin,
or a reliable anti-cheat product. It does not inspect third-party processes or
modify other software. Everything runs against your own test game state/files.

## What's implemented

- A server-authoritative, 1D toy game with movement and shooting (`minivac/server_logic.py`).
- Client-side local SHA-256 asset checks and a plugin name allowlist (`minivac/client_guard.py`).
- Deterministic normal and policy-violating cases (`minivac/experiments.py`).
- A three-way comparison: client only, server only, combined (`run_experiments.py`).
- An optional FastAPI HTTP server exposing POST `/action` and GET `/state/{player_id}` (`minivac/api.py`).
- Automated tests (`tests/test_minivac.py`).

## Run the experiments (no dependencies)

Python 3.10+ recommended. From this repository directory:

```bash
python run_experiments.py
python -m unittest discover -s tests -v
```

The first command writes `experiment_results.csv`. Its numbers only represent
the synthetic cases supplied in the demo, **not actual detection efficacy**.

## Client defense v2 (Arian, `client-defense` branch)

A hardened client guard evaluated against the client-attack scenarios, alongside
the starter guard rather than replacing it:

- `minivac/manifest.py`: authenticated baseline manifest (asset and plugin digests with an HMAC tag).
- `minivac/client_defense.py`: guard that verifies the manifest, allowlists plugins by content, gates plugin loads, and reports its measurements.
- `minivac/integrity_verifier.py`: server-side check of those reports against the server's own manifest, with replay and silence detection.

```bash
python run_client_defense.py
```

This writes `client_defense_results.csv` and `client_defense_scan_sweep.csv`.
Design, results and limitations are in `docs/CLIENT_DEFENSE_LOG.md`. A client
report is a claim made by an untrusted machine; it is not remote attestation.

## Run a real client/server process boundary (optional)

```bash
python -m pip install -r requirements.txt
uvicorn minivac.api:app --host 127.0.0.1 --port 8000
```

Visit http://127.0.0.1:8000/docs to send actions through FastAPI's interactive
docs. Try `POST /action` with:

Valid movement:
```json
{"player_id":"student", "kind":"move", "dx":0.2}
```

Impossible movement (rejected by server):
```json
{"player_id":"student", "kind":"move", "dx":20.0}
```

Two immediate `shoot` requests will cause the second to be rejected as a
fire-rate violation. **Use only localhost**; this is an educational server without
accounts, authentication, authorization, TLS, or deployment hardening.

## Included scenarios and intended classification

| Scenario | Ground truth: policy violation? | Client monitor | Server checks |
| --- | --- | --- | --- |
| normal_movement | no | no flag | accept |
| normal_firing | no | no flag | accept |
| approved_plugin | no | no flag | accept |
| tampered_asset | yes | flag | unrelated action accepted |
| unapproved_plugin | yes | flag | unrelated action accepted |
| impossible_movement | yes | no flag | reject |
| rapid_fire | yes | no flag | reject |
| disabled_client_monitor | yes | monitor disabled, no flag | unrelated action accepted |

This last scenario is a deliberately unmitigated vulnerability: client-only
monitoring can be suppressed by an adversary with control of the endpoint.
The combined detector cannot guarantee detection of client-local changes that
do not produce observable illegal game actions. A reported client hash is not
cryptographic remote attestation. A signed manifest does not stop a malicious
client from lying about the outcome of its integrity check.

## Architecture and research boundaries

- **Client:** Untrusted. Local integrity alerts are useful signals only; don't
  assume clients truthfully report the results.
- **Server:** Authoritative for player position, shooting cooldown, clock, and
  acceptance of actions. It never trusts client-claimed game state.
- **Threat model:** Attackers can alter the toy client file, load a named test
  plugin, submit invalid in-game actions, and disable the toy client monitor.
  Attackers cannot modify the server implementation.
- **Scope limitation:** A 1D simulator cannot model CS2's physics, latency,
  reconciliation, wallhacks, native process injection, or VAC internals.
- **Evaluation:** Detection labels are ground-truth *policy violations*, not
  proven malicious intent. For credible results, add varied legitimate use,
  latency/jitter simulation, diverse attack variations, repeated measurements,
  and paired tests across modes.

## Suggested six-person collaboration

- **David (server attack):** Design invalid movement and action input cases.
- **Ay (server attack/defense):** Expand rule validation, test edge cases.
- **Suhaib (client attack/defense):** Add test-only tampering scenarios.
- **Josh (server defense):** Own server rules, event logs, and defensive metrics.
- **Andrew (client attack):** Write unauthorized-plugin and modified-asset cases.
- **Arian (client defense):** Own file integrity checks, allowlist, robustness analysis.

## Next steps before claiming a full prototype

1. Implement a minimal interactive client sending JSON requests to the REST server.
2. Add a graphical representation only if you want a visual demo; it's not needed
   for the security evaluation.
3. Use an **authenticated** trusted baseline for file manifests in realistic designs.
4. Keep a distinction between *blocking an action* and *detecting a user cheat*.
5. Design true positive/false positive data and a fair, reproducible test protocol.
6. Evaluate CPU time per check, server latency and conservative thresholds.
7. Re-read public documentation: do not claim these rules are VAC's exact code.

## Relevant reading

- Collins et al., *Anti-Cheat: Attacks and the Effectiveness of Client-Side Defences* (ACM CheckMATE 2024).
- Bethea et al., *Server-Side Verification of Client Behavior in Online Games* (NDSS 2010).
- OWASP, Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- FastAPI First Steps: https://fastapi.tiangolo.com/tutorial/first-steps/
