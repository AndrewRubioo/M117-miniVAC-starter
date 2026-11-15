"""Client-side attack scenarios for the MiniVAC testbed (owner: Andrew, client attack).

Scope: every scenario here targets ONLY the toy ClientGuard and toy GameServer in
this repository, using files created in a temporary directory. Nothing touches
real games, VAC, other processes, or the OS. Results describe the toy model, not
real anti-cheat performance.

How a "client attack" works in this model
-----------------------------------------
The attacker controls the client machine. The defender only sees (a) what the
client monitor reports and (b) the actions that reach the server. So each
scenario changes one of four things and we record whether any evidence survives:
  1. what the monitor checks      -> the asset file
  2. what runs next to the game   -> loaded plugins
  3. the monitor itself           -> disable it, forge its output, edit its data
  4. timing and inputs            -> act between scans, or stay inside server limits

Each scenario carries ground truth (`violation`) and the detection result the
current rules are expected to produce (`expected_detected`, ordered as
client_only, server_only, combined). Tests lock these in, so a change to anyone's
rules that flips an outcome shows up as a failing test.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
from .client_guard import ClientGuard, sha256_file
from .experiments import CONFIGURATIONS, FakeClock
from .server_logic import FIRE_COOLDOWN, MAX_SPEED, GameServer

BASELINE_TEXT = "Official test asset v1\n"
PLAYER = "student"


@dataclass
class AttackEnv:
    """Everything an attacker (or a legitimate user) can touch in one scenario."""
    asset: Path
    guard: ClientGuard
    server: GameServer
    clock: FakeClock
    plugins: list[str] = field(default_factory=lambda: ["hud"])
    client_alerts: list[str] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    scans: int = 0

    def scan(self) -> list[str]:
        """One run of the client monitor over the current asset and plugin list."""
        self.scans += 1
        alerts = self.guard.inspect(self.asset, list(self.plugins))
        self.client_alerts.extend(alerts)
        return alerts

    def act(self, kind: str, dx: float = 0.0) -> dict:
        result = self.server.action(PLAYER, kind, dx)
        self.actions.append(result)
        return result


@dataclass(frozen=True)
class ClientScenario:
    id: str
    name: str
    category: str
    violation: bool          # ground-truth policy violation (not proven intent)
    summary: str             # what is tried
    how: str                 # how it is carried out in the toy model
    run: Callable[[AttackEnv], None]
    expected_detected: tuple[bool, bool, bool]  # client_only, server_only, combined


def _play(env: AttackEnv) -> None:
    """Ordinary harmless server action so the server sees a session, as in experiments.py."""
    env.act("move", 0.2)


# ---- asset tampering ---------------------------------------------------------
def _append_byte(env):
    env.asset.write_bytes(env.asset.read_bytes() + b"\x00")
    env.scan(); _play(env)

def _whitespace_change(env):
    env.asset.write_text("Official test asset v1 \n", encoding="utf8")
    env.scan(); _play(env)

def _delete_asset(env):
    env.asset.unlink()
    env.scan(); _play(env)

def _baseline_rewrite(env):
    env.asset.write_text("Modified test asset\n", encoding="utf8")
    env.guard.expected_asset_digest = sha256_file(env.asset)  # attacker picks the reference hash
    env.scan(); _play(env)

def _modify_then_revert(env):
    original = env.asset.read_bytes()
    env.scan()                                   # scan 1: clean
    env.asset.write_text("Modified test asset\n", encoding="utf8")
    _play(env)                                   # play happens while modified
    env.asset.write_bytes(original)              # restore before the next scan
    env.scan()                                   # scan 2: clean again

# ---- plugin allowlist --------------------------------------------------------
def _plugin_variant(name: str):
    def run(env):
        env.plugins.append(name)
        env.scan(); _play(env)
    return run

def _plugin_after_scan(env):
    env.scan()                                   # scan sees only "hud"
    env.plugins.append("cheat_plugin")           # loaded after the only scan
    _play(env)

# ---- monitor tampering -------------------------------------------------------
def _forged_output(env):
    env.asset.write_text("Modified test asset\n", encoding="utf8")
    env.plugins.append("cheat_plugin")
    env.guard.inspect = lambda asset, plugins: []   # monitor now always reports "clean"
    env.scan(); _play(env)

def _allowlist_edit(env):
    env.plugins.append("cheat_plugin")
    env.guard.allowed_plugins = env.guard.allowed_plugins | {"cheat_plugin"}
    env.scan(); _play(env)

# ---- in-bounds automation ----------------------------------------------------
def _macro_fire(env):
    for _ in range(100):
        env.act("shoot")
        env.clock.advance(FIRE_COOLDOWN + 1e-6)  # exactly on the cooldown edge, perfectly periodic
    env.scan()

def _max_speed_moves(env):
    for _ in range(100):
        env.clock.advance(0.1)
        env.act("move", MAX_SPEED * 0.1)         # always exactly the speed limit
    env.scan()

# ---- legitimate controls (ground truth: no violation) -------------------------
def _human_firing(env):
    for gap in (0.41, 0.37, 0.52, 0.33, 0.61, 0.45, 0.38, 0.57):
        env.act("shoot")
        env.clock.advance(gap)                   # irregular, always above cooldown
    env.scan()

def _approved_plugins(env):
    env.plugins.append("accessibility")
    env.scan(); _play(env)

def _legit_update(env):
    env.asset.write_text("Official test asset v2\n", encoding="utf8")  # game patched, baseline stale
    env.scan(); _play(env)

def _third_party_overlay(env):
    env.plugins.append("overlay")                # benign tool, not on the allowlist
    env.scan(); _play(env)


# ---- client tamper that also produces an illegal action ------------------------
def _disabled_monitor_teleport(env):
    env.asset.write_text("Modified test asset\n", encoding="utf8")
    env.guard.active = False                     # silence the client monitor
    env.scan()
    env.act("move", 20.0)                        # effect of the cheat reaches the server

# ---- more legitimate controls --------------------------------------------------
def _human_movement(env):
    for gap, dx in ((0.2, 0.3), (0.15, 0.6), (0.3, 1.1), (0.25, 0.9),
                    (0.1, 0.35), (0.35, 1.4), (0.2, 0.5), (0.18, 0.7)):
        env.clock.advance(gap)
        env.act("move", dx)                      # varying speed, always under the limit
    env.scan()

def _missing_asset_legit(env):
    env.asset.unlink()                           # incomplete install or antivirus quarantine
    env.scan(); _play(env)


T, F = True, False
SCENARIOS: list[ClientScenario] = [
    ClientScenario("CA01", "asset_append_byte", "asset_tampering", T,
        "Append one byte to the asset file.",
        "Attacker edits a file the client loads. Any byte change alters the SHA-256, so the hash check sees it.",
        _append_byte, (T, F, T)),
    ClientScenario("CA02", "asset_whitespace_change", "asset_tampering", T,
        "Change only whitespace in the asset.",
        "Same lever, smallest visible edit. Tests whether cosmetic changes slip past the hash.",
        _whitespace_change, (T, F, T)),
    ClientScenario("CA03", "asset_deleted", "asset_tampering", T,
        "Delete the asset file.",
        "Attacker removes the file. The guard treats an unreadable file as a mismatch.",
        _delete_asset, (T, F, T)),
    ClientScenario("CA04", "baseline_digest_rewrite", "monitor_tampering", T,
        "Modify the asset AND overwrite the expected digest.",
        "The reference hash lives in client memory, so the attacker replaces it with the hash of the modified file; the check then passes.",
        _baseline_rewrite, (F, F, F)),
    ClientScenario("CA05", "modify_then_revert", "timing_evasion", T,
        "Modify the asset during play, restore it before the next scan.",
        "The monitor is point-in-time. The attacker changes things only in the gap between scans, so every scan sees a clean file.",
        _modify_then_revert, (F, F, F)),
    ClientScenario("CA06", "plugin_case_variant", "plugin_allowlist", T,
        "Load a plugin named 'HUD' (capitalised).",
        "Tests whether a near-miss of an approved name gets through. Matching is exact, so it is flagged.",
        _plugin_variant("HUD"), (T, F, T)),
    ClientScenario("CA07", "plugin_trailing_space", "plugin_allowlist", T,
        "Load a plugin named 'hud ' (trailing space).",
        "Another near-miss of an approved name. Exact matching flags it.",
        _plugin_variant("hud "), (T, F, T)),
    ClientScenario("CA08", "plugin_empty_name", "plugin_allowlist", T,
        "Load a plugin with an empty name.",
        "Edge case for the allowlist. An empty string is not approved, so it is flagged.",
        _plugin_variant(""), (T, F, T)),
    ClientScenario("CA09", "plugin_name_spoof", "plugin_allowlist", T,
        "Unauthorized code that reports itself as 'hud'.",
        "The allowlist trusts the name a plugin gives itself, not its contents. The attacker simply uses an approved name.",
        _plugin_variant("hud"), (F, F, F)),
    ClientScenario("CA10", "plugin_loaded_after_scan", "timing_evasion", T,
        "Load an unapproved plugin after the only scan.",
        "The monitor scans once. Anything loaded later is never examined.",
        _plugin_after_scan, (F, F, F)),
    ClientScenario("CA11", "monitor_output_forged", "monitor_tampering", T,
        "Modify the asset and load a plugin, then force the monitor to report no alerts.",
        "The attacker controls the monitor's process, so the report it sends is whatever the attacker chooses.",
        _forged_output, (F, F, F)),
    ClientScenario("CA12", "allowlist_edited", "monitor_tampering", T,
        "Add the attacker's plugin to the monitor's allowlist.",
        "The allowlist is client-side data the attacker can edit, so the plugin becomes 'approved'.",
        _allowlist_edit, (F, F, F)),
    ClientScenario("CA13", "macro_fire_on_cooldown_edge", "input_automation", T,
        "100 shots, each exactly one cooldown apart, perfectly regular.",
        "A client-side script fires as fast as the server allows. Every request is individually legal, so rule checks cannot object.",
        _macro_fire, (F, F, F)),
    ClientScenario("CA14", "movement_at_speed_limit", "input_automation", T,
        "100 moves, each exactly at the speed limit.",
        "A client-side script rides the server's limit. No single action breaks a rule.",
        _max_speed_moves, (F, F, F)),
    ClientScenario("CA15", "monitor_disabled_plus_teleport", "illegal_action_effect", T,
        "Disable the monitor and tamper, then make a 20-unit move.",
        "The client side is silenced, but the cheat's effect is an action no legitimate client could send, so the server rejects it regardless of the client.",
        _disabled_monitor_teleport, (F, T, T)),
    ClientScenario("CL01", "legit_human_firing", "legit_control", F,
        "8 shots with irregular gaps above the cooldown.",
        "Control: ordinary play, and the contrast case for CA13's perfect regularity.",
        _human_firing, (F, F, F)),
    ClientScenario("CL02", "legit_approved_plugins", "legit_control", F,
        "Use the approved 'hud' and 'accessibility' plugins.",
        "Control: allowed plugins should never be flagged.",
        _approved_plugins, (F, F, F)),
    ClientScenario("CL03", "legit_game_update_stale_baseline", "legit_control", F,
        "Asset legitimately updated to v2 but the client's baseline is still v1.",
        "Control that exposes a false positive: the hash check cannot tell a patch from tampering.",
        _legit_update, (T, F, T)),
    ClientScenario("CL04", "legit_third_party_overlay", "legit_control", F,
        "A harmless overlay plugin that is not on the allowlist.",
        "Control that exposes a false positive: the allowlist cannot tell a benign tool from a cheat.",
        _third_party_overlay, (T, F, T)),
    ClientScenario("CL05", "legit_human_movement", "legit_control", F,
        "8 moves at varying speeds, always under the limit.",
        "Control: ordinary movement, and the contrast case for CA14's exact speed-limit riding.",
        _human_movement, (F, F, F)),
    ClientScenario("CL06", "legit_missing_asset", "legit_control", F,
        "Asset file missing because of an incomplete install or antivirus quarantine.",
        "Control that exposes a false positive: the guard cannot tell a missing file from CA03's deliberate deletion.",
        _missing_asset_legit, (T, F, T)),
]
BY_ID = {s.id: s for s in SCENARIOS}


def run_scenario(scenario: ClientScenario, client_checks: bool, server_checks: bool) -> dict:
    clock = FakeClock()
    server = GameServer(enforce_rules=server_checks, clock=clock)
    with TemporaryDirectory(prefix="minivac_ca_") as tempdir:
        asset = Path(tempdir) / "test_game_asset.txt"
        asset.write_text(BASELINE_TEXT, encoding="utf8")
        guard = ClientGuard(expected_asset_digest=sha256_file(asset), active=client_checks)
        env = AttackEnv(asset=asset, guard=guard, server=server, clock=clock)
        scenario.run(env)
    rejected = [a["reason"] for a in env.actions if not a["accepted"]]
    return {
        "id": scenario.id,
        "scenario": scenario.name,
        "category": scenario.category,
        "policy_violation": scenario.violation,
        "detected": bool(env.client_alerts or rejected),
        "client_alerts": sorted(set(env.client_alerts)),
        "server_rejections": sorted(set(rejected)),
        "scans": env.scans,
        "actions": len(env.actions),
    }


def evaluate_client_attacks() -> dict[str, list[dict]]:
    return {
        name: [run_scenario(s, client, server) for s in SCENARIOS]
        for name, (client, server) in CONFIGURATIONS.items()
    }


def markdown_catalogue() -> str:
    """Catalogue table (id, what is tried, how, ground truth, result per config)."""
    results = evaluate_client_attacks()
    mark = lambda r: "flagged" if r["detected"] else "not flagged"
    lines = ["| ID | Scenario | Ground truth | How it is carried out | Client only | Server only | Combined |",
             "|---|---|---|---|---|---|---|"]
    for i, s in enumerate(SCENARIOS):
        gt = "violation" if s.violation else "legit"
        cells = [mark(results[c][i]) for c in ("client_only", "server_only", "combined")]
        lines.append(f"| {s.id} | {s.name} | {gt} | {s.how} | {cells[0]} | {cells[1]} | {cells[2]} |")
    return "\n".join(lines)
