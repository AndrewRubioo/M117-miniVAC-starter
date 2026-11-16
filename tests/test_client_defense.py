import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from minivac import client_attacks
from minivac.client_attacks import ClientScenario
from minivac.client_defense import (SUGGESTED_RESPONSE, HardenedClientGuard, LoadedPlugin,
                                    build_report)
from minivac.client_defense_eval import (BY_ID, EXPECTED_V2, LEGACY_IDS, MODES,
                                         NEW_SCENARIOS, OFFICIAL_PLUGINS, SCENARIOS,
                                         V2_TRANSLATIONS, evaluate_defense,
                                         evaluate_starter, official_manifest, run_defended,
                                         scan_window_experiment)
from minivac.experiments import CONFIGURATIONS, FakeClock, metrics
from minivac.integrity_verifier import (REPORT_DEADLINE, REPORT_MALFORMED,
                                        REPORT_NONCE_INVALID, REPORT_OVERDUE,
                                        IntegrityVerifier)
from minivac.manifest import (ASSET_MISSING, ASSET_MODIFIED, MANIFEST_AUTH_FAILED,
                              PLUGIN_BLOCKED, PLUGIN_CONTENT_MISMATCH, PLUGIN_NOT_APPROVED,
                              ManifestAuthority)

ASSET = "test_game_asset.txt"
OFFICIAL_TEXT = "Official test asset v1\n"
HUD = LoadedPlugin("hud", OFFICIAL_PLUGINS["hud"])


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.authority = ManifestAuthority()
        self.signed = self.authority.issue(official_manifest(1, OFFICIAL_TEXT))

    def test_issued_manifest_verifies(self):
        self.assertTrue(self.authority.verify(self.signed))

    def test_any_edit_breaks_the_tag(self):
        edits = {
            "asset digest": lambda m: m.assets.update({ASSET: "0" * 64}),
            "new approved plugin": lambda m: m.plugins.update({"cheat_plugin": "0" * 64}),
            "removed plugin": lambda m: m.plugins.pop("hud"),
            "version": lambda m: setattr(m, "version", 2),
        }
        for label, edit in edits.items():
            with self.subTest(edit=label):
                signed = self.authority.issue(official_manifest(1, OFFICIAL_TEXT))
                edit(signed.manifest)
                self.assertFalse(self.authority.verify(signed))

    def test_tag_from_another_key_does_not_verify(self):
        forged = ManifestAuthority().issue(official_manifest(1, OFFICIAL_TEXT))
        self.assertFalse(self.authority.verify(forged))

    def test_malformed_input_fails_closed_instead_of_raising(self):
        for label, tag in {"not hex": "zz", "empty": "", "wrong type": None}.items():
            with self.subTest(tag=label):
                self.signed.tag = tag
                self.assertFalse(self.authority.verify(self.signed))
        unserialisable = self.authority.issue(official_manifest(1, OFFICIAL_TEXT))
        unserialisable.manifest.assets[ASSET] = object()
        self.assertFalse(self.authority.verify(unserialisable))

    def test_encoding_does_not_depend_on_insertion_order(self):
        a, b = official_manifest(1, OFFICIAL_TEXT), official_manifest(1, OFFICIAL_TEXT)
        b.plugins = dict(reversed(list(b.plugins.items())))
        self.assertEqual(a.canonical_bytes(), b.canonical_bytes())

    def test_copy_shares_nothing_with_the_original(self):
        original = official_manifest(1, OFFICIAL_TEXT)
        clone = original.copy()
        clone.assets[ASSET] = "0" * 64
        clone.plugins["cheat_plugin"] = "0" * 64
        self.assertEqual(original.canonical_bytes(),
                         official_manifest(1, OFFICIAL_TEXT).canonical_bytes())


class GuardTests(unittest.TestCase):
    def setUp(self):
        self._tempdir = TemporaryDirectory(prefix="minivac_test_")
        self.addCleanup(self._tempdir.cleanup)
        self.asset = Path(self._tempdir.name) / ASSET
        self.asset.write_text(OFFICIAL_TEXT, encoding="utf8")
        self.authority = ManifestAuthority()
        self.guard = HardenedClientGuard(
            self.authority.issue(official_manifest(1, OFFICIAL_TEXT)),
            trust_anchor=self.authority.verify)

    def events(self, plugins=(HUD,)):
        return [str(e) for e in self.guard.scan({ASSET: self.asset}, list(plugins)).events]

    def test_clean_install_raises_nothing(self):
        accessibility = LoadedPlugin("accessibility", OFFICIAL_PLUGINS["accessibility"])
        self.assertEqual(self.events([HUD, accessibility]), [])

    def test_modified_and_missing_assets_are_different_events(self):
        self.asset.write_bytes(self.asset.read_bytes() + b"\x00")
        self.assertEqual(self.events(), [f"{ASSET_MODIFIED}:{ASSET}"])
        self.asset.unlink()
        self.assertEqual(self.events(), [f"{ASSET_MISSING}:{ASSET}"])

    def test_plugin_names_must_match_exactly(self):
        for name in ("cheat_plugin", "HUD", "hud ", ""):
            with self.subTest(name=name):
                self.assertEqual(self.events([HUD, LoadedPlugin(name, b"x")]),
                                 [f"{PLUGIN_NOT_APPROVED}:{name!r}"])

    def test_approved_name_with_other_content_is_caught(self):
        spoof = LoadedPlugin("hud", b"not the approved hud code")
        self.assertEqual(self.events([HUD, spoof]), [f"{PLUGIN_CONTENT_MISMATCH}:'hud'"])

    def test_disabled_guard_returns_nothing_at_all(self):
        self.asset.write_text("Modified test asset\n", encoding="utf8")
        self.guard.active = False
        self.assertIsNone(self.guard.scan({ASSET: self.asset}, [HUD]))

    def test_edited_manifest_fails_closed(self):
        # The attacker makes the manifest agree with the tampered file. If the guard
        # used the edited digests it would report a clean client.
        self.asset.write_text("Modified test asset\n", encoding="utf8")
        manifest = self.guard.signed_manifest.manifest
        manifest.assets[ASSET] = self.guard.scan({ASSET: self.asset}, []).assets[ASSET]
        self.assertEqual(self.events(), [f"{MANIFEST_AUTH_FAILED}:manifest"])

    def test_measurements_are_reported_whatever_the_verdict(self):
        self.asset.write_text("Modified test asset\n", encoding="utf8")
        result = self.guard.scan({ASSET: self.asset}, [HUD])
        self.assertNotEqual(result.assets[ASSET],
                            self.guard.signed_manifest.manifest.assets[ASSET])
        self.assertEqual(result.plugins, [("hud", HUD.digest)])

    def test_load_gate_allows_approved_and_blocks_the_rest(self):
        self.assertIsNone(self.guard.authorize_plugin(HUD))
        for plugin, reason in ((LoadedPlugin("cheat_plugin", b"x"), PLUGIN_NOT_APPROVED),
                               (LoadedPlugin("hud", b"x"), PLUGIN_CONTENT_MISMATCH)):
            with self.subTest(plugin=plugin.name):
                blocked = self.guard.authorize_plugin(plugin)
                self.assertEqual(blocked.code, PLUGIN_BLOCKED)
                self.assertEqual(blocked.detail, reason)

    def test_load_gate_blocks_everything_when_manifest_is_not_authentic(self):
        self.guard.signed_manifest.manifest.plugins["cheat_plugin"] = "0" * 64
        self.assertEqual(self.guard.authorize_plugin(HUD).detail, MANIFEST_AUTH_FAILED)

    def test_disabled_load_gate_mediates_nothing(self):
        self.guard.active = False
        self.assertIsNone(self.guard.authorize_plugin(LoadedPlugin("cheat_plugin", b"x")))

    def test_no_event_recommends_a_ban(self):
        codes = {ASSET_MISSING, ASSET_MODIFIED, MANIFEST_AUTH_FAILED, PLUGIN_BLOCKED,
                 PLUGIN_CONTENT_MISMATCH, PLUGIN_NOT_APPROVED}
        self.assertEqual(set(SUGGESTED_RESPONSE), codes)
        self.assertLessEqual(set(SUGGESTED_RESPONSE.values()), {"repair", "block", "review"})


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self._tempdir = TemporaryDirectory(prefix="minivac_test_")
        self.addCleanup(self._tempdir.cleanup)
        self.asset = Path(self._tempdir.name) / ASSET
        self.asset.write_text(OFFICIAL_TEXT, encoding="utf8")
        self.authority = ManifestAuthority()
        self.guard = HardenedClientGuard(
            self.authority.issue(official_manifest(1, OFFICIAL_TEXT)),
            trust_anchor=self.authority.verify)
        self.clock = FakeClock()
        self.verifier = IntegrityVerifier(official_manifest(1, OFFICIAL_TEXT), clock=self.clock)

    def report(self, plugins=(HUD,), extra=()):
        result = self.guard.scan({ASSET: self.asset}, list(plugins))
        return build_report("p1", self.verifier.challenge("p1"), result, extra)

    def test_clean_report_has_no_findings(self):
        self.assertEqual(self.verifier.submit_report("p1", self.report()), [])

    def test_server_judges_against_its_own_manifest(self):
        # Client side fully subverted: tampered file, attacker-signed manifest,
        # attacker's key as trust anchor. The guard itself reports no event.
        self.asset.write_text("Modified test asset\n", encoding="utf8")
        rogue = ManifestAuthority()
        self.guard.signed_manifest = rogue.issue(official_manifest(1, "Modified test asset\n"))
        self.guard.trust_anchor = rogue.verify
        report = self.report()
        self.assertEqual(report["events"], [])
        self.assertEqual(self.verifier.submit_report("p1", report), [f"{ASSET_MODIFIED}:{ASSET}"])

    def test_a_report_cannot_be_used_twice(self):
        report = self.report()
        self.assertEqual(self.verifier.submit_report("p1", report), [])
        self.assertEqual(self.verifier.submit_report("p1", report), [REPORT_NONCE_INVALID])

    def test_report_needs_the_nonce_this_server_issued(self):
        report = self.report()
        report["nonce"] = "0" * 32
        self.assertEqual(self.verifier.submit_report("p1", report), [REPORT_NONCE_INVALID])
        other_player = self.report()
        self.assertEqual(self.verifier.submit_report("p2", other_player), [REPORT_NONCE_INVALID])

    def test_liveness_boundary(self):
        self.verifier.submit_report("p1", self.report())
        self.clock.advance(REPORT_DEADLINE)
        self.assertEqual(self.verifier.check_liveness("p1"), [])           # exactly on time
        self.clock.advance(0.001)
        self.assertEqual(self.verifier.check_liveness("p1"), [REPORT_OVERDUE])
        self.assertEqual(self.verifier.check_liveness("p1"), [])           # flagged once
        self.verifier.submit_report("p1", self.report())
        self.assertEqual(self.verifier.check_liveness("p1"), [])           # reporting again

    def test_session_that_never_reports_becomes_overdue(self):
        self.verifier.open_session("p1")
        self.clock.advance(REPORT_DEADLINE + 0.001)
        self.assertEqual(self.verifier.check_liveness("p1"), [REPORT_OVERDUE])

    def test_rejected_reports_do_not_keep_a_session_alive(self):
        report = self.report()
        self.verifier.submit_report("p1", report)
        self.clock.advance(REPORT_DEADLINE + 0.001)
        self.verifier.submit_report("p1", report)                          # replay
        self.assertEqual(self.verifier.check_liveness("p1"), [REPORT_OVERDUE])

    def test_malformed_reports_are_findings_not_crashes(self):
        good = self.report()
        bad_reports = [None, [], {}, "report",
                       {**good, "nonce": 7},
                       {**good, "manifest_version": "1"},
                       {**good, "assets": [ASSET]},
                       {**good, "assets": {ASSET: 7}},
                       {**good, "plugins": [{"name": ["hud"], "sha256": "x"}]},
                       {**good, "plugins": ["hud"]},
                       {**good, "events": [None]}]
        for bad in bad_reports:
            with self.subTest(report=repr(bad)[:40]):
                self.assertEqual(self.verifier.submit_report("p1", bad), [REPORT_MALFORMED])

    def test_omitting_a_protected_asset_is_a_finding(self):
        report = self.report()
        report["assets"] = {}
        self.assertEqual(self.verifier.submit_report("p1", report), [f"asset_unreported:{ASSET}"])

    def test_events_only_the_client_knows_are_passed_through(self):
        blocked = self.guard.authorize_plugin(LoadedPlugin("cheat_plugin", b"x"))
        findings = self.verifier.submit_report("p1", self.report(extra=[blocked]))
        self.assertEqual(findings, [f"client_declared:{PLUGIN_BLOCKED}:'cheat_plugin'"])

    def test_every_check_is_logged(self):
        self.verifier.submit_report("p1", self.report())
        self.clock.advance(REPORT_DEADLINE + 1)
        self.verifier.check_liveness("p1")
        self.assertEqual([(e["check"], e["findings"]) for e in self.verifier.audit_log],
                         [("report", []), ("liveness", [REPORT_OVERDUE])])


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.starter = evaluate_starter()
        cls.defended = evaluate_defense()

    def flagged(self, results, mode, ids=None):
        return {r["id"] for r in results[mode] if r["detected"] and (ids is None or r["id"] in ids)}

    def test_results_match_expected_detection(self):
        """Regression lock, same idea as Andrew's: a flip here means a rule changed."""
        for i, s in enumerate(SCENARIOS):
            self.assertIsNotNone(
                s.expected_detected,
                f"{s.id} is new in client_attacks.py: run it and record its v2 outcome in EXPECTED_V2")
            for m, mode in enumerate(MODES):
                with self.subTest(scenario=s.id, mode=mode):
                    self.assertEqual(self.defended[mode][i]["detected"], s.expected_detected[m])

    def test_andrews_scenarios_run_unchanged_except_four_documented_translations(self):
        self.assertEqual(set(V2_TRANSLATIONS), {"CA04", "CA09", "CA11", "CA12"})
        self.assertEqual(set(EXPECTED_V2), set(LEGACY_IDS))
        for legacy in client_attacks.SCENARIOS:
            if legacy.id not in V2_TRANSLATIONS:
                self.assertIs(BY_ID[legacy.id].run, legacy.run, legacy.id)

    def test_scenario_poking_starter_internals_is_refused_not_misreported(self):
        def pokes_starter_guard(env):
            env.guard.expected_asset_digest = "0" * 64
        fake = ClientScenario("CA01", "x", "x", True, "x", "x", pokes_starter_guard, (True,) * 3)
        with self.assertRaises(RuntimeError):
            run_defended(fake, True, True)

    def test_server_only_is_identical_to_the_starter(self):
        self.assertEqual(self.flagged(self.defended, "server_only", LEGACY_IDS),
                         self.flagged(self.starter, "server_only"))

    def test_v2_newly_catches_exactly_three_of_andrews_attacks(self):
        for mode in ("client_only", "combined"):
            before = self.flagged(self.starter, mode)
            after = self.flagged(self.defended, mode, LEGACY_IDS)
            self.assertEqual(after - before, {"CA04", "CA09", "CA12"}, mode)
            self.assertEqual(before - after, set(), mode)

    def test_false_positives_on_andrews_controls_are_unchanged(self):
        legit = {s.id for s in client_attacks.SCENARIOS if not s.violation}
        for mode in ("client_only", "combined"):
            self.assertEqual(self.flagged(self.defended, mode, legit), {"CL03", "CL04", "CL06"})
            self.assertEqual(self.flagged(self.starter, mode) & legit, {"CL03", "CL04", "CL06"})

    def test_editing_the_client_manifest_does_not_reach_the_server_reference(self):
        # If the simulation let client and server share one manifest object, the
        # server would "agree" with the attacker's edits and these findings would vanish.
        self.assertIn(f"{ASSET_MODIFIED}:{ASSET}",
                      run_defended(BY_ID["CA04"], True, True)["server_findings"])
        self.assertIn(f"{PLUGIN_NOT_APPROVED}:'cheat_plugin'",
                      run_defended(BY_ID["CA12"], True, True)["server_findings"])

    def test_four_attacks_are_caught_only_when_both_sides_cooperate(self):
        ids = {"DA01", "DA02", "DA04", "DA05"}
        self.assertEqual(self.flagged(self.defended, "client_only", ids), set())
        self.assertEqual(self.flagged(self.defended, "server_only", ids), set())
        self.assertEqual(self.flagged(self.defended, "combined", ids), ids)

    def test_forged_reports_and_hidden_code_evade_every_mode(self):
        for mode in MODES:
            self.assertEqual(self.flagged(self.defended, mode, {"CA11", "DA03", "DA06"}), set())

    def test_forged_reports_satisfy_the_liveness_check(self):
        row = run_defended(BY_ID["DA03"], True, True)
        self.assertGreaterEqual(row["reports"], 5)       # the forger keeps answering on time
        self.assertEqual(row["server_findings"], [])

    def test_disabled_monitor_is_noticed_only_after_the_report_deadline(self):
        row = run_defended(BY_ID["DA01"], True, True)
        self.assertEqual(row["server_findings"], [REPORT_OVERDUE])
        self.assertEqual(row["latency_s"], REPORT_DEADLINE + 0.5)   # first action past the deadline
        self.assertEqual(row["server_rejections"], [])              # every action was legal

    def test_replay_is_refused_on_the_first_attempt(self):
        row = run_defended(BY_ID["DA02"], True, True)
        self.assertIn(REPORT_NONCE_INVALID, row["server_findings"])
        self.assertEqual(row["latency_s"], 0.5)

    def test_liveness_check_adds_a_false_positive(self):
        self.assertEqual(self.flagged(self.defended, "client_only", {"DL03"}), set())
        self.assertEqual(self.flagged(self.defended, "combined", {"DL03"}), {"DL03"})
        self.assertEqual(metrics(self.defended["combined"])["FP"], 4)

    def test_load_gate_blocks_the_cheat_and_admits_the_approved_plugin(self):
        blocked = run_defended(BY_ID["DA07"], True, False)
        self.assertEqual(blocked["client_alerts"], [f"{PLUGIN_BLOCKED}:'cheat_plugin'"])
        self.assertEqual(run_defended(BY_ID["DL02"], True, False)["client_alerts"], [])

    def test_proper_update_is_not_mistaken_for_tampering(self):
        for mode in MODES:
            self.assertEqual(self.flagged(self.defended, mode, {"DL01"}), set())
        self.assertEqual(self.flagged(self.defended, "combined", {"CL03"}), {"CL03"})  # stale baseline still is

    def test_combined_sees_what_the_client_reports_unless_the_report_is_dropped(self):
        self.assertEqual(self.flagged(self.defended, "client_only")
                         - self.flagged(self.defended, "combined"), {"DA08"})

    def test_local_alert_that_never_reaches_the_server_does_not_count_in_combined(self):
        row = run_defended(BY_ID["DA08"], True, True)
        self.assertEqual(row["client_alerts"], [f"{ASSET_MODIFIED}:{ASSET}"])  # raised locally
        self.assertEqual(row["server_findings"], [])                          # never arrived
        self.assertFalse(row["detected"])
        self.assertEqual(row["actions"], 6)   # 3 s of play, under the report deadline

    def test_new_scenarios_are_documented_and_do_not_reuse_andrews_ids(self):
        ids = [s.id for s in SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))
        for s in NEW_SCENARIOS:
            self.assertTrue(s.summary and s.how, s.id)


class ScanSweepTests(unittest.TestCase):
    def test_seeded_run_is_reproducible(self):
        self.assertEqual(scan_window_experiment(2.0, 1.0, trials=40),
                         scan_window_experiment(2.0, 1.0, trials=40))

    def test_blind_attacker_is_caught_in_proportion_to_window_over_interval(self):
        row = scan_window_experiment(2.0, 1.0, trials=200)
        self.assertEqual(row["predicted_rate"], 0.5)
        self.assertAlmostEqual(row["detection_rate"], 0.5, delta=0.1)

    def test_window_longer_than_the_interval_is_always_caught(self):
        self.assertEqual(scan_window_experiment(1.0, 4.0, trials=40)["detection_rate"], 1.0)

    def test_schedule_aware_attacker_is_never_caught(self):
        for interval in (0.5, 5.0):
            row = scan_window_experiment(interval, 0.0, schedule_aware=True, trials=10)
            self.assertEqual(row["caught"], 0)
            self.assertGreater(row["share_of_session_tampered"], 0.99)


if __name__ == "__main__":
    unittest.main()
