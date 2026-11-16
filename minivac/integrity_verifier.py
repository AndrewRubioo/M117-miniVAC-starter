"""Server-side judge of client integrity reports (owner: Arian, client defense).

This is the trusted half of client defense v2. The client guard measures and
reports; this module decides. Two things follow from putting the decision here:

1. The reference manifest is the SERVER'S copy. Editing the client's manifest,
   or replacing the key the client trusts, changes nothing here (CA04, CA12, DA04).
2. Silence is visible. A session that stops sending valid reports is flagged, so
   switching the monitor off is no longer free (DA01), and an old report cannot
   be replayed because each one must carry a fresh server nonce (DA02).

What it cannot do: tell a true report from an invented one. The expected
digests are public and nothing binds a report to the real state of the client,
so a client that sends the expected values with the current nonce passes (CA11,
DA03). This is self-reporting, not remote attestation.

Pure Python with an injectable clock, like server_logic.GameServer, so it can be
tested without a network and mounted behind an HTTP endpoint later.
"""
from __future__ import annotations
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable
from .manifest import (ASSET_MISSING, ASSET_MODIFIED, PLUGIN_CONTENT_MISMATCH,
                       PLUGIN_NOT_APPROVED, Manifest)

REPORT_DEADLINE = 5.0  # seconds, on the server clock, a session may go without a valid report

REPORT_MALFORMED = "report_malformed"
REPORT_NONCE_INVALID = "report_nonce_invalid"
REPORT_OVERDUE = "integrity_report_overdue"
ASSET_UNREPORTED = "asset_unreported"
MANIFEST_VERSION_MISMATCH = "manifest_version_mismatch"
CLIENT_DECLARED = "client_declared"


@dataclass
class _Session:
    started_at: float
    nonce: str | None = None
    last_report_at: float | None = None
    overdue_flagged: bool = False


@dataclass
class IntegrityVerifier:
    manifest: Manifest
    clock: Callable[[], float] = time.monotonic
    report_deadline: float = REPORT_DEADLINE
    audit_log: list[dict] = field(default_factory=list)
    _sessions: dict[str, _Session] = field(default_factory=dict)

    def open_session(self, player_id: str) -> None:
        """Start the report deadline for a player. Called when they join."""
        self._session(player_id)

    def challenge(self, player_id: str) -> str:
        """Issue the single-use nonce the next report must carry."""
        nonce = secrets.token_hex(16)
        self._session(player_id).nonce = nonce
        return nonce

    def submit_report(self, player_id: str, report: object) -> list[str]:
        """Judge one client report. Returns the findings; an empty list means clean."""
        session = self._session(player_id)
        if not _well_formed(report):
            return self._record(player_id, "report", [REPORT_MALFORMED])

        # Freshness. The nonce is spent whether or not it matches.
        expected, session.nonce = session.nonce, None
        if expected is None or report["nonce"] != expected:
            return self._record(player_id, "report", [REPORT_NONCE_INVALID])

        # Compare the claimed measurements with the server's own manifest.
        findings: list[str] = []
        if report["manifest_version"] != self.manifest.version:
            findings.append(MANIFEST_VERSION_MISMATCH)
        for name, digest in self.manifest.assets.items():
            if name not in report["assets"]:
                findings.append(f"{ASSET_UNREPORTED}:{name}")
            elif report["assets"][name] is None:
                findings.append(f"{ASSET_MISSING}:{name}")
            elif report["assets"][name] != digest:
                findings.append(f"{ASSET_MODIFIED}:{name}")
        for plugin in report["plugins"]:
            name = plugin["name"]
            if name not in self.manifest.plugins:
                findings.append(f"{PLUGIN_NOT_APPROVED}:{name!r}")
            elif plugin["sha256"] != self.manifest.plugins[name]:
                findings.append(f"{PLUGIN_CONTENT_MISMATCH}:{name!r}")

        # Events only the client can know about, such as a load it blocked. Taken
        # as a signal: a cheater would not volunteer them, an honest client does.
        for event in report["events"]:
            if event not in findings:
                findings.append(f"{CLIENT_DECLARED}:{event}")

        # A valid nonce shows only that something on the client answered just now.
        session.last_report_at = self.clock()
        session.overdue_flagged = False
        return self._record(player_id, "report", findings)

    def check_liveness(self, player_id: str) -> list[str]:
        """Call when a game action arrives: is this session still reporting?

        Flags once per silent stretch, when more than `report_deadline` seconds
        have passed since the last valid report (or since the session opened).
        """
        session = self._session(player_id)
        last = session.started_at if session.last_report_at is None else session.last_report_at
        if session.overdue_flagged or self.clock() - last <= self.report_deadline:
            return []
        session.overdue_flagged = True
        return self._record(player_id, "liveness", [REPORT_OVERDUE])

    def _session(self, player_id: str) -> _Session:
        if player_id not in self._sessions:
            self._sessions[player_id] = _Session(started_at=self.clock())
        return self._sessions[player_id]

    def _record(self, player_id: str, check: str, findings: list[str]) -> list[str]:
        self.audit_log.append({"player_id": player_id, "at": self.clock(),
                               "check": check, "findings": list(findings)})
        return findings


def _well_formed(report: object) -> bool:
    """Shape check. The report is attacker-controlled input and must never crash the server."""
    if not isinstance(report, dict):
        return False
    assets, plugins, events = report.get("assets"), report.get("plugins"), report.get("events")
    return (isinstance(report.get("nonce"), str)
            and isinstance(report.get("manifest_version"), int)
            and isinstance(assets, dict)
            and all(isinstance(k, str) and (v is None or isinstance(v, str))
                    for k, v in assets.items())
            and isinstance(plugins, list)
            and all(isinstance(p, dict) and isinstance(p.get("name"), str)
                    and isinstance(p.get("sha256"), str) for p in plugins)
            and isinstance(events, list)
            and all(isinstance(e, str) for e in events))
