"""Run reproducible synthetic scenarios in each security configuration."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from .client_guard import ClientGuard, sha256_file
from .server_logic import GameServer


@dataclass
class FakeClock:
    now: float = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


SCENARIOS: dict[str, bool] = {
    "normal_movement": False,
    "normal_firing": False,
    "approved_plugin": False,
    "tampered_asset": True,
    "unapproved_plugin": True,
    "impossible_movement": True,
    "rapid_fire": True,
    "disabled_client_monitor": True,
}

CONFIGURATIONS = {
    "client_only": (True, False),
    "server_only": (False, True),
    "combined": (True, True),
}


def evaluate_case(scenario: str, client_checks: bool, server_checks: bool) -> dict:
    if scenario not in SCENARIOS:
        raise KeyError(f"Unknown scenario: {scenario}")
    clock = FakeClock()
    server = GameServer(enforce_rules=server_checks, clock=clock)

    with TemporaryDirectory(prefix="minivac_") as tempdir:
        asset = Path(tempdir) / "test_game_asset.txt"
        asset.write_text("Official test asset v1\n", encoding="utf8")
        baseline = sha256_file(asset)
        guard = ClientGuard(expected_asset_digest=baseline, active=client_checks)
        plugins = ["hud"]

        if scenario in {"tampered_asset", "disabled_client_monitor"}:
            asset.write_text("Modified test asset\n", encoding="utf8")
        if scenario == "unapproved_plugin":
            plugins.append("unapproved_test_plugin")
        if scenario == "disabled_client_monitor":
            guard.active = False  # test adversarial control of the monitoring process

        client_alerts = guard.inspect(asset, plugins)
        actions: list[dict] = []
        if scenario == "impossible_movement":
            actions.append(server.action("student", "move", dx=20.0))
        elif scenario == "rapid_fire":
            actions.append(server.action("student", "shoot"))
            actions.append(server.action("student", "shoot"))
        elif scenario == "normal_firing":
            actions.append(server.action("student", "shoot"))
            clock.advance(0.5)
            actions.append(server.action("student", "shoot"))
        else:
            actions.append(server.action("student", "move", dx=0.2))

        rejected = [a["reason"] for a in actions if not a["accepted"]]
        detected = bool(client_alerts or rejected)
        return {
            "scenario": scenario,
            "policy_violation": SCENARIOS[scenario],
            "detected": detected,
            "client_alerts": client_alerts,
            "server_rejections": rejected,
        }


def evaluate_all() -> dict[str, list[dict]]:
    return {
        name: [evaluate_case(s, client, server) for s in SCENARIOS]
        for name, (client, server) in CONFIGURATIONS.items()
    }


def metrics(rows: list[dict]) -> dict[str, float | int]:
    tp = sum(r["policy_violation"] and r["detected"] for r in rows)
    fp = sum(not r["policy_violation"] and r["detected"] for r in rows)
    fn = sum(r["policy_violation"] and not r["detected"] for r in rows)
    tn = sum(not r["policy_violation"] and not r["detected"] for r in rows)
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "TPR": tp / (tp + fn) if tp + fn else 0,
            "FPR": fp / (fp + tn) if fp + tn else 0}
