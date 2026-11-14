"""Server-authoritative toy game rules. No dependence on VAC or CS2."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable
import math
import time

MAX_SPEED = 5.0  # toy world units / second
FIRST_MOVE_ALLOWANCE = 0.1  # seconds for a first request
FIRE_COOLDOWN = 0.3  # seconds
EPSILON = 1e-8


@dataclass
class PlayerState:
    x: float = 0.0
    shots_fired: int = 0
    last_move_at: float | None = None
    last_shot_at: float | None = None


@dataclass
class GameServer:
    """Server uses its OWN clock, not a client-reported timestamp or position."""

    enforce_rules: bool = True
    clock: Callable[[], float] = time.monotonic
    players: dict[str, PlayerState] = field(default_factory=dict)
    audit_log: list[dict] = field(default_factory=list)

    def action(self, player_id: str, kind: str, dx: float = 0.0) -> dict:
        if not player_id or len(player_id) > 50:
            return self._record(player_id, kind, False, "invalid_player")
        if kind not in {"move", "shoot"}:
            return self._record(player_id, kind, False, "unknown_action")

        state = self.players.setdefault(player_id, PlayerState())
        now = self.clock()
        if kind == "move":
            try:
                delta = float(dx)
            except (ValueError, TypeError, OverflowError):
                return self._record(player_id, kind, False, "invalid_delta")
            if not math.isfinite(delta):
                return self._record(player_id, kind, False, "invalid_delta")
            elapsed = (FIRST_MOVE_ALLOWANCE if state.last_move_at is None
                       else max(0.0, now - state.last_move_at))
            max_delta = MAX_SPEED * elapsed + EPSILON
            if self.enforce_rules and abs(delta) > max_delta:
                return self._record(player_id, kind, False, "speed_violation")
            state.x += delta
            state.last_move_at = now
        else:
            if (self.enforce_rules and state.last_shot_at is not None
                    and now - state.last_shot_at < FIRE_COOLDOWN):
                return self._record(player_id, kind, False, "fire_rate_violation")
            state.shots_fired += 1
            state.last_shot_at = now
        return self._record(player_id, kind, True, "accepted")

    def _record(self, player_id: str, kind: str, accepted: bool, reason: str) -> dict:
        event = {"player_id": player_id, "action": kind,
                 "accepted": accepted, "reason": reason}
        self.audit_log.append(event)
        return event

    def state(self, player_id: str) -> dict:
        player = self.players.get(player_id, PlayerState())
        return {"x": player.x, "shots_fired": player.shots_fired}
