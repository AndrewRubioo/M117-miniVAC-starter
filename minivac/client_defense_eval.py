"""Evaluate client defense v2 on the client-attack catalogue (owner: Arian, client defense).

Three experiments, all confined to the toy client and server in this repository:

1. Andrew's 21 scenarios (client_attacks.py), re-run against the v2 guard. His
   scenario functions are used unchanged wherever they can be. Four of them
   reach into internals of the starter guard that v2 does not have, so they get
   a v2 translation of the same move; see V2_TRANSLATIONS.
2. Eleven new scenarios written against v2 itself: eight defense-aware attacks
   (DA) and three legitimate controls (DL). A defense should be judged by an
   attacker who knows it exists, not only by attacks written before it did.
3. A scan-interval sweep: how often a point-in-time scan catches a tamper window
   of a given length (the open question behind CA05 and CA10).

Modes follow experiments.CONFIGURATIONS. What "detected" means in each:
  client_only  the guard raised a local alert (the defender takes its word)
  server_only  the server rejected an action
  combined     the SERVER holds evidence: a rejected action, or a finding from
               its own verification of the client's reports. A local alert
               counts only if it reaches the server in a report.
So client_only is an upper bound: it assumes every local alert is seen by
someone. Combined mode drops that assumption, which is why one scenario (DA08)
is "caught" client-only and missed combined.
"""
from __future__ import annotations
import random
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from .client_attacks import BASELINE_TEXT, PLAYER, ClientScenario
from .client_attacks import SCENARIOS as LEGACY_SCENARIOS
from .client_attacks import run_scenario as run_starter
from .client_defense import (HardenedClientGuard, LoadedPlugin, ScanResult,
                             SecurityEvent, build_report, measure_file)
from .experiments import CONFIGURATIONS, FakeClock
from .integrity_verifier import IntegrityVerifier
from .manifest import Manifest, ManifestAuthority, SignedManifest, sha256_bytes
from .server_logic import GameServer

ASSET_NAME = "test_game_asset.txt"
ARCHIVED_TEXT = "Official test asset v0\n"   # an older release the publisher really shipped
TAMPERED_TEXT = "Modified test asset\n"
OFFICIAL_PLUGINS = {"hud": b"toy hud plugin v1\n",
                    "accessibility": b"toy accessibility plugin v1\n"}
CHEAT_BYTES = b"toy unauthorized plugin\n"
SCAN_INTERVAL = 2.0     # seconds between scans by an honest monitor
PLAY_SECONDS = 10.0     # length of the scripted sessions in the DA/DL scenarios
MODES = list(CONFIGURATIONS)  # client_only, server_only, combined


def official_manifest(version: int, asset_text: str) -> Manifest:
    return Manifest(version,
                    assets={ASSET_NAME: sha256_bytes(asset_text.encode("utf8"))},
                    plugins={name: sha256_bytes(code) for name, code in OFFICIAL_PLUGINS.items()})


class _LegacyPluginNames(list):
    """Lets Andrew's `env.plugins.append(name)` run unchanged against v2.

    The starter env keeps plugins as a list of names. v2 keeps (name, content)
    records in `env.loaded`, so this is a snapshot of the names whose edits are
    written through to `env.loaded`. An edit it cannot carry over raises: editing
    only the snapshot would run the scenario without the change it asked for,
    and its result would be reported as if nothing were wrong.
    """

    def __init__(self, env: "DefenseEnv") -> None:
        super().__init__(plugin.name for plugin in env.loaded)
        self._env = env

    def append(self, name: str) -> None:
        self._env.inject_plugin(name)
        super().append(name)

    def extend(self, names) -> None:
        for name in names:
            self.append(name)

    def remove(self, name: str) -> None:
        super().remove(name)  # ValueError if it is not loaded, as a plain list would
        loaded = self._env.loaded
        del loaded[next(i for i, plugin in enumerate(loaded) if plugin.name == name)]

    def clear(self) -> None:
        self._env.loaded.clear()
        super().clear()

    def _unsupported(self, *args, **kwargs):
        raise NotImplementedError(
            "env.plugins supports append, extend, remove and clear against v2. For anything "
            "else use env.inject_plugin(name, content) or edit env.loaded directly.")

    insert = pop = sort = reverse = _unsupported
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _unsupported


@dataclass
class DefenseEnv:
    """One scenario's world. Same surface as client_attacks.AttackEnv (asset,
    guard, server, clock, plugins, scan, act) plus what v2 adds."""
    asset: Path
    guard: HardenedClientGuard
    server: GameServer
    clock: FakeClock
    authority: ManifestAuthority            # the trusted publisher; attacks never sign with it
    verifier: IntegrityVerifier | None      # present only in combined mode
    loaded: list[LoadedPlugin] = field(default_factory=list)
    hidden: list[LoadedPlugin] = field(default_factory=list)  # running, but not enumerable
    client_alerts: list[str] = field(default_factory=list)
    server_findings: list[str] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    scans: int = 0                          # scans that ran; a disabled guard runs none
    reports: int = 0
    last_report: dict | None = None
    report_channel_up: bool = True
    first_client_alert_at: float | None = None
    first_server_evidence_at: float | None = None
    _last_scan_at: float = 0.0
    _pending: list[SecurityEvent] = field(default_factory=list)

    # ---- the client ----------------------------------------------------------
    @property
    def plugins(self) -> _LegacyPluginNames:
        return _LegacyPluginNames(self)

    def inject_plugin(self, name: str, content: bytes | None = None) -> None:
        """Put a plugin next to the game WITHOUT asking the loader. A plugin in
        the starter model is only a name, so a name with no content given gets
        the official bytes if it is an official plugin and other bytes if not."""
        if content is None:
            content = OFFICIAL_PLUGINS.get(name, b"third-party code: " + name.encode("utf8"))
        self.loaded.append(LoadedPlugin(name, content))

    def load_plugin(self, name: str, content: bytes) -> bool:
        """Load through the game's plugin loader, which asks the guard first."""
        plugin = LoadedPlugin(name, content)
        blocked = self.guard.authorize_plugin(plugin)
        if blocked is None:
            self.loaded.append(plugin)
            return True
        self._note_client_alerts([str(blocked)])
        self._pending.append(blocked)
        self.scan()  # alerts are reported at once, not at the next timer tick
        return False

    def scan(self) -> list[str]:
        """One pass of the monitor. In combined mode the result goes to the server."""
        self._last_scan_at = self.clock()
        result = self.guard.scan({ASSET_NAME: self.asset}, list(self.loaded))
        if result is None:  # monitor disabled: no alert, no report, and no scan to count
            return []
        self.scans += 1
        alerts = [str(event) for event in result.events]
        self._note_client_alerts(alerts)
        if self.verifier is not None and self.report_channel_up:
            # Blocked loads wait here until a report gets through; an outage delays
            # them, it does not lose them.
            pending, self._pending = self._pending, []
            self.last_report = build_report(PLAYER, self.verifier.challenge(PLAYER),
                                            result, pending)
            self.reports += 1
            self._note_server_evidence(self.verifier.submit_report(PLAYER, self.last_report))
        return alerts

    def act(self, kind: str, dx: float = 0.0) -> dict:
        # An honest monitor runs on its own timer. The simulation has no threads,
        # so the timer is serviced whenever the client is about to act.
        if self.guard.active and self.clock() - self._last_scan_at >= SCAN_INTERVAL:
            self.scan()
        if self.verifier is not None:
            self._note_server_evidence(self.verifier.check_liveness(PLAYER))
        result = self.server.action(PLAYER, kind, dx)
        self.actions.append(result)
        if not result["accepted"]:
            self._note_server_evidence([result["reason"]], keep=False)
        return result

    # ---- moves only an attacker makes ------------------------------------------
    def send_raw_report(self, report: dict | None) -> None:
        """Speak the report protocol directly; the attacker owns the network stack."""
        if self.verifier is not None and report is not None:
            self._note_server_evidence(self.verifier.submit_report(PLAYER, report))

    def archived_release(self) -> tuple[str, SignedManifest]:
        """An old release with its genuine signed manifest. Anyone who installed
        it once still has both, so having them needs no access to the key."""
        return ARCHIVED_TEXT, self.authority.issue(official_manifest(0, ARCHIVED_TEXT))

    # ---- moves only the trusted publisher makes ----------------------------------
    def publish_update(self, new_asset_text: str) -> None:
        """Ship a game update properly: new asset, new signed manifest for the
        client, and the server's reference updated in the same release."""
        version = self.guard.signed_manifest.manifest.version + 1
        self.asset.write_text(new_asset_text, encoding="utf8")
        self.guard.signed_manifest = self.authority.issue(
            official_manifest(version, new_asset_text))
        if self.verifier is not None:
            self.verifier.manifest = official_manifest(version, new_asset_text)

    # ---- bookkeeping -------------------------------------------------------------
    def _note_client_alerts(self, alerts: list[str]) -> None:
        if alerts and self.first_client_alert_at is None:
            self.first_client_alert_at = self.clock()
        self.client_alerts.extend(alerts)

    def _note_server_evidence(self, findings: list[str], keep: bool = True) -> None:
        if findings and self.first_server_evidence_at is None:
            self.first_server_evidence_at = self.clock()
        if keep:
            self.server_findings.extend(findings)


# ---- helpers shared by scenarios ------------------------------------------------
def _play(env: DefenseEnv) -> None:
    """One ordinary action, so the server sees a session."""
    env.act("move", 0.2)


def _play_session(env: DefenseEnv, before_each=None, seconds: float = PLAY_SECONDS) -> None:
    """Rule-abiding play for `seconds`: a small move every half second."""
    for _ in range(int(seconds / 0.5)):
        env.clock.advance(0.5)
        if before_each is not None:
            before_each()
        env.act("move", 0.4)


def _forge_monitor(env: DefenseEnv) -> None:
    """Make the monitor say what the server wants to hear, whatever is on disk.

    Needs no secret: every expected digest is in the manifest on the attacker's
    own disk. From here on the honest timer keeps firing, each "scan" returns
    the expected values, and each report carries a fresh nonce."""
    clean = env.guard.signed_manifest.manifest.copy()

    def forged_scan(assets, loaded_plugins):
        if not env.guard.active:  # server_only mode: there is no monitor to impersonate
            return None
        return ScanResult(events=[], assets=dict(clean.assets),
                          plugins=[("hud", clean.plugins["hud"])],
                          manifest_version=clean.version)

    env.guard.scan = forged_scan


# ---- v2 translations of the four scenarios tied to starter-guard internals -------
def _v2_baseline_rewrite(env):
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    # Same move as CA04: overwrite the stored expected digest. The attacker has
    # no key, so the manifest's tag is left as it was.
    env.guard.signed_manifest.manifest.assets[ASSET_NAME] = measure_file(env.asset)
    env.scan(); _play(env)

def _v2_name_spoof(env):
    env.inject_plugin("hud", CHEAT_BYTES)        # approved name, unapproved code
    env.scan(); _play(env)

def _v2_forged_output(env):
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    env.inject_plugin("cheat_plugin", CHEAT_BYTES)
    _forge_monitor(env)
    env.scan(); _play(env)

def _v2_allowlist_edit(env):
    cheat = LoadedPlugin("cheat_plugin", CHEAT_BYTES)
    env.guard.signed_manifest.manifest.plugins[cheat.name] = cheat.digest  # tag not updated
    env.inject_plugin(cheat.name, cheat.content)
    env.scan(); _play(env)

V2_TRANSLATIONS = {
    "CA04": (_v2_baseline_rewrite,
             "Starter: assign guard.expected_asset_digest. v2: overwrite the digest inside the local manifest; the attacker cannot produce a matching tag."),
    "CA09": (_v2_name_spoof,
             "Starter: a second 'hud' in a list of names, which cannot express different code. v2: a plugin named 'hud' whose content is not the approved content."),
    "CA11": (_v2_forged_output,
             "Starter: replace guard.inspect with a function returning no alerts. v2: replace guard.scan with one returning the expected measurements, so the report sent to the server is forged too."),
    "CA12": (_v2_allowlist_edit,
             "Starter: add a name to guard.allowed_plugins. v2: add the plugin's name and digest to the local manifest; the tag no longer matches."),
}

# ---- new scenarios written against v2 --------------------------------------------
def _monitor_disabled_silent(env):
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    env.guard.active = False                     # monitor off; every action stays legal
    _play_session(env)

def _report_replay(env):
    captured = env.last_report                   # the clean launch report, recorded off the wire
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    env.guard.active = False
    _play_session(env, before_each=lambda: env.send_raw_report(captured))

def _report_forged_live(env):
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    env.inject_plugin("cheat_plugin", CHEAT_BYTES)
    _forge_monitor(env)
    _play_session(env)

def _trust_anchor_replaced(env):
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    rogue = ManifestAuthority()                  # the attacker's own key
    forged = env.guard.signed_manifest.manifest.copy()
    forged.assets[ASSET_NAME] = measure_file(env.asset)
    env.guard.signed_manifest = rogue.issue(forged)
    env.guard.trust_anchor = rogue.verify        # swap the key the guard trusts
    env.scan(); _play(env)                       # the guard still measures honestly

def _manifest_rollback(env):
    old_text, old_signed = env.archived_release()
    env.asset.write_text(old_text, encoding="utf8")
    env.guard.signed_manifest = old_signed       # genuine tag, outdated contents
    env.scan(); _play(env)

def _hidden_plugin(env):
    env.hidden.append(LoadedPlugin("cheat_plugin", CHEAT_BYTES))  # never enters the enumerated list
    env.scan(); _play(env)

def _unapproved_via_loader(env):
    env.scan()
    env.load_plugin("cheat_plugin", CHEAT_BYTES)  # CA10's timing, but through the loader
    _play(env)

def _reports_blocked_short_session(env):
    env.report_channel_up = False                # the attacker drops outgoing reports
    env.asset.write_text(TAMPERED_TEXT, encoding="utf8")
    env.scan()                                   # the monitor still runs and alerts locally
    _play_session(env, seconds=3.0)              # gone before the report deadline

def _legit_update_with_manifest(env):
    env.publish_update("Official test asset v2\n")
    env.scan(); _play(env)

def _legit_plugin_via_loader(env):
    env.scan()
    env.load_plugin("accessibility", OFFICIAL_PLUGINS["accessibility"])
    _play(env)

def _legit_report_outage(env):
    env.report_channel_up = False                # reports cannot be delivered; game traffic can
    _play_session(env)


T, F = True, False
# Expected v2 outcome of each of Andrew's scenarios (client_only, server_only, combined).
EXPECTED_V2 = {
    "CA01": (T, F, T), "CA02": (T, F, T), "CA03": (T, F, T), "CA04": (T, F, T),
    "CA05": (F, F, F), "CA06": (T, F, T), "CA07": (T, F, T), "CA08": (T, F, T),
    "CA09": (T, F, T), "CA10": (F, F, F), "CA11": (F, F, F), "CA12": (T, F, T),
    "CA13": (F, F, F), "CA14": (F, F, F), "CA15": (F, T, T),
    "CL01": (F, F, F), "CL02": (F, F, F), "CL03": (T, F, T), "CL04": (T, F, T),
    "CL05": (F, F, F), "CL06": (T, F, T),
}

NEW_SCENARIOS: list[ClientScenario] = [
    ClientScenario("DA01", "monitor_disabled_silent_play", "report_suppression", T,
        "Tamper, switch the monitor off, then play 10 s inside every server rule.",
        "With the monitor off there is no local alert. In combined mode there is also no report, and the server flags a session that has stopped reporting.",
        _monitor_disabled_silent, (F, F, T)),
    ClientScenario("DA02", "report_replay", "report_suppression", T,
        "Record the clean launch report, tamper, then replay that report while playing.",
        "The attacker answers the server with a report captured before tampering. Each report must carry a fresh server nonce, so the old one is refused.",
        _report_replay, (F, F, T)),
    ClientScenario("DA03", "report_forged_fresh_nonce", "report_forgery", T,
        "Tamper and load a cheat plugin, then report the expected digests with each fresh nonce for 10 s.",
        "The expected values are public and nothing ties a report to the real client state, so an invented report is indistinguishable from a true one.",
        _report_forged_live, (F, F, F)),
    ClientScenario("DA04", "trust_anchor_replaced", "monitor_tampering", T,
        "Tamper, re-sign a matching manifest with the attacker's own key, and make the guard trust that key.",
        "Authentication only moves the target from the data to the key that checks it. The local check passes; the server's own manifest is out of the attacker's reach.",
        _trust_anchor_replaced, (F, F, T)),
    ClientScenario("DA05", "manifest_rollback", "monitor_tampering", T,
        "Install an old asset version together with its genuine, validly signed old manifest.",
        "A valid tag proves who issued a manifest, not that it is current. The client cannot know the current version without asking the server.",
        _manifest_rollback, (F, F, T)),
    ClientScenario("DA06", "hidden_plugin", "enumeration_evasion", T,
        "Run unauthorized code that never appears in the list of loaded plugins.",
        "The guard can only measure what it can enumerate, and the attacker controls the enumeration.",
        _hidden_plugin, (F, F, F)),
    ClientScenario("DA07", "unapproved_plugin_via_loader", "plugin_allowlist", T,
        "After the scan, load an unapproved plugin through the game's plugin loader.",
        "Same timing as CA10, but the loader asks the guard before loading, so the plugin is refused and never runs.",
        _unapproved_via_loader, (T, F, T)),
    ClientScenario("DA08", "reports_blocked_short_session", "report_suppression", T,
        "Tamper, drop the client's outgoing reports, play 3 s and leave before the 5 s report deadline.",
        "The monitor keeps running and raises a local alert, but the attacker controls the machine's network, so the alert never arrives and the session ends before silence is suspicious.",
        _reports_blocked_short_session, (T, F, F)),
    ClientScenario("DL01", "legit_update_with_new_manifest", "legit_control", F,
        "Game update shipped properly: new asset, new signed manifest, server reference updated.",
        "Control and twin of CL03: with a versioned manifest delivered alongside the patch, an update is not mistaken for tampering.",
        _legit_update_with_manifest, (F, F, F)),
    ClientScenario("DL02", "legit_plugin_via_loader", "legit_control", F,
        "Load the approved 'accessibility' plugin through the loader mid-session.",
        "Control and twin of DA07: the load-time gate must let approved plugins through.",
        _legit_plugin_via_loader, (F, F, F)),
    ClientScenario("DL03", "legit_report_channel_outage", "legit_control", F,
        "An honest client whose reports cannot be delivered for 10 s while game traffic still flows.",
        "Control that exposes a false positive v2 introduces: to the server an outage looks the same as DA01's disabled monitor.",
        _legit_report_outage, (F, F, T)),
]


def _translated(legacy: ClientScenario) -> ClientScenario:
    """Andrew's scenario with v2's expected outcome, and a v2 run function only
    where his cannot apply. A scenario added later has no expectation yet (None)."""
    changes: dict = {"expected_detected": EXPECTED_V2.get(legacy.id)}
    if legacy.id in V2_TRANSLATIONS:
        changes["run"] = V2_TRANSLATIONS[legacy.id][0]
    return replace(legacy, **changes)


LEGACY_IDS = [s.id for s in LEGACY_SCENARIOS]
SCENARIOS: list[ClientScenario] = [_translated(s) for s in LEGACY_SCENARIOS] + NEW_SCENARIOS
BY_ID = {s.id: s for s in SCENARIOS}
_GUARD_FIELDS = {"signed_manifest", "trust_anchor", "active"}


def run_defended(scenario: ClientScenario, client_checks: bool, server_checks: bool) -> dict:
    """Run one scenario against the v2 guard in one mode."""
    clock = FakeClock()
    server = GameServer(enforce_rules=server_checks, clock=clock)
    authority = ManifestAuthority()
    manifest = official_manifest(1, BASELINE_TEXT)
    combined = client_checks and server_checks
    with TemporaryDirectory(prefix="minivac_cd_") as tempdir:
        asset = Path(tempdir) / ASSET_NAME
        asset.write_text(BASELINE_TEXT, encoding="utf8")
        guard = HardenedClientGuard(authority.issue(manifest.copy()),
                                    trust_anchor=authority.verify, active=client_checks)
        verifier = IntegrityVerifier(manifest.copy(), clock=clock) if combined else None
        env = DefenseEnv(asset=asset, guard=guard, server=server, clock=clock,
                         authority=authority, verifier=verifier,
                         loaded=[LoadedPlugin("hud", OFFICIAL_PLUGINS["hud"])])
        started_at = clock()
        if verifier is not None:
            verifier.open_session(PLAYER)
        if guard.active:
            env.scan()  # launch-time check and first report
        scenario.run(env)

    if scenario.id in LEGACY_IDS and scenario.id not in V2_TRANSLATIONS:
        stray = set(vars(env.guard)) - _GUARD_FIELDS
        if stray:  # an untranslated scenario poked at starter-guard internals
            raise RuntimeError(f"{scenario.id} sets guard attributes v2 does not have "
                               f"({sorted(stray)}); it needs an entry in V2_TRANSLATIONS")

    rejected = [a["reason"] for a in env.actions if not a["accepted"]]
    if combined:
        detected, first = bool(rejected or env.server_findings), env.first_server_evidence_at
    else:
        detected = bool(env.client_alerts or rejected)
        times = [t for t in (env.first_client_alert_at, env.first_server_evidence_at)
                 if t is not None]
        first = min(times) if times else None
    return {
        "id": scenario.id,
        "scenario": scenario.name,
        "category": scenario.category,
        "policy_violation": scenario.violation,
        "detected": detected,
        "client_alerts": sorted(set(env.client_alerts)),
        "server_rejections": sorted(set(rejected)),
        "server_findings": sorted(set(env.server_findings)),
        "scans": env.scans,
        "reports": env.reports,
        "actions": len(env.actions),
        # Simulated seconds from scenario start to the first evidence. The fake
        # clock has no network or processing delay, so this is a lower bound.
        "latency_s": round(first - started_at, 3) if detected and first is not None else None,
    }


def evaluate_defense(scenarios: list[ClientScenario] | None = None) -> dict[str, list[dict]]:
    chosen = SCENARIOS if scenarios is None else scenarios
    return {mode: [run_defended(s, client, server) for s in chosen]
            for mode, (client, server) in CONFIGURATIONS.items()}


def evaluate_starter() -> dict[str, list[dict]]:
    """Andrew's 21 scenarios against the starter guard: the 'before' column."""
    return {mode: [run_starter(s, client, server) for s in LEGACY_SCENARIOS]
            for mode, (client, server) in CONFIGURATIONS.items()}


# ---- experiment 3: how much does scanning more often help? -------------------------
def scan_window_experiment(scan_interval: float, tamper_window: float,
                           schedule_aware: bool = False, trials: int = 200,
                           session: float = 30.0, seed: int = 117) -> dict:
    """Tamper with the asset for a while, then restore it (CA05), against a
    monitor that scans every `scan_interval` seconds.

    blind attacker           picks a random moment and keeps the asset modified
                             for `tamper_window` seconds
    schedule-aware attacker  watches the monitor (it runs on their machine),
                             modifies right after each scan and restores right
                             before the next one; `tamper_window` is ignored

    Runs the real v2 guard on a real temporary file under a fake clock, with a
    random scan phase per trial and a seeded generator, so it is reproducible.
    """
    rng = random.Random(f"{seed}:{scan_interval}:{tamper_window}:{schedule_aware}")
    authority = ManifestAuthority()
    signed = authority.issue(official_manifest(1, BASELINE_TEXT))
    guard = HardenedClientGuard(signed, trust_anchor=authority.verify)
    gap = 1e-3  # how closely the schedule-aware attacker cuts it, in seconds
    caught = scans = 0
    tampered_time = 0.0
    with TemporaryDirectory(prefix="minivac_sweep_") as tempdir:
        asset = Path(tempdir) / ASSET_NAME
        for _ in range(trials):
            asset.write_text(BASELINE_TEXT, encoding="utf8")
            phase = rng.uniform(0.0, scan_interval)
            scan_times = []
            while phase + len(scan_times) * scan_interval < session:
                scan_times.append(phase + len(scan_times) * scan_interval)
            if schedule_aware:
                # Modified from session start to just before the first scan, then
                # between every pair of scans, then from the last scan to the end.
                starts = [0.0] + [t + gap for t in scan_times]
                ends = [t - gap for t in scan_times] + [session]
                windows = [(a, b) for a, b in zip(starts, ends) if b > a]
            else:
                start = rng.uniform(0.0, session - tamper_window)
                windows = [(start, start + tamper_window)]
            # Order at equal times: tamper, restore, scan. The window is [start, end).
            timeline = sorted([(t, 2, "scan") for t in scan_times]
                              + [(a, 0, "tamper") for a, _ in windows]
                              + [(b, 1, "restore") for _, b in windows])
            flagged = False
            for _, _, step in timeline:
                if step == "tamper":
                    asset.write_text(TAMPERED_TEXT, encoding="utf8")
                elif step == "restore":
                    asset.write_text(BASELINE_TEXT, encoding="utf8")
                else:
                    scans += 1
                    flagged = flagged or bool(guard.scan({ASSET_NAME: asset}, []).events)
            caught += flagged
            tampered_time += sum(b - a for a, b in windows)
    return {
        "strategy": "schedule_aware" if schedule_aware else "blind",
        "scan_interval_s": scan_interval,
        "tamper_window_s": None if schedule_aware else tamper_window,
        "trials": trials,
        "caught": caught,
        "detection_rate": round(caught / trials, 3),
        # A scan lands in a randomly placed window of length W with probability min(1, W/T).
        "predicted_rate": None if schedule_aware else round(min(1.0, tamper_window / scan_interval), 3),
        "scans_per_minute": round(60.0 / scan_interval, 1),
        "share_of_session_tampered": round(tampered_time / (trials * session), 3),
    }


SWEEP_INTERVALS = (0.5, 1.0, 2.0, 5.0, 10.0)
SWEEP_WINDOWS = (0.25, 1.0, 4.0)


def scan_window_sweep(trials: int = 200) -> list[dict]:
    rows = [scan_window_experiment(interval, window, trials=trials)
            for window in SWEEP_WINDOWS for interval in SWEEP_INTERVALS]
    rows += [scan_window_experiment(interval, 0.0, schedule_aware=True, trials=20)
             for interval in SWEEP_INTERVALS]
    return rows


def markdown_catalogue() -> str:
    """Results table for docs/CLIENT_DEFENSE_LOG.md, generated so it cannot drift from the code."""
    starter, defended = evaluate_starter(), evaluate_defense()
    cells = lambda rows, i: " / ".join("flagged" if rows[m][i]["detected"] else "no" for m in MODES)
    lines = ["| ID | Scenario | Ground truth | Starter guard (client / server / combined) "
             "| v2 guard (client / server / combined) | Server-side evidence in combined mode (v2) |",
             "|---|---|---|---|---|---|"]
    for i, s in enumerate(SCENARIOS):
        truth = "violation" if s.violation else "legit"
        before = cells(starter, i) if i < len(LEGACY_SCENARIOS) else "not applicable"
        row = defended["combined"][i]
        evidence = ", ".join(f"`{e}`" for e in row["server_rejections"] + row["server_findings"])
        lines.append(f"| {s.id} | {s.name} | {truth} | {before} | {cells(defended, i)} "
                     f"| {evidence or 'none'} |")
    return "\n".join(lines)


def measure_scan_cost(sizes=(1024, 1024 * 1024, 16 * 1024 * 1024), repeats: int = 20) -> list[dict]:
    """Wall-clock cost of one scan for a few asset sizes. Machine-dependent, so
    it is printed by the runner and never written to the committed results."""
    authority = ManifestAuthority()
    rows = []
    with TemporaryDirectory(prefix="minivac_cost_") as tempdir:
        asset = Path(tempdir) / ASSET_NAME
        for size in sizes:
            asset.write_bytes(b"\x00" * size)
            manifest = Manifest(1, {ASSET_NAME: measure_file(asset)}, {})
            guard = HardenedClientGuard(authority.issue(manifest), trust_anchor=authority.verify)
            start = time.perf_counter()
            for _ in range(repeats):
                guard.scan({ASSET_NAME: asset}, [])
            rows.append({"asset_bytes": size,
                         "ms_per_scan": (time.perf_counter() - start) / repeats * 1000})
    return rows
