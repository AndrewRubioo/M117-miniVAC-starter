import unittest
from minivac.client_attacks import (BY_ID, SCENARIOS, evaluate_client_attacks,
                                    run_scenario)
from minivac.experiments import CONFIGURATIONS, metrics

MODES = list(CONFIGURATIONS)  # client_only, server_only, combined

# Attacks the client controls end to end: no mode should see them.
CLIENT_CONTROLLED_BLIND_SPOTS = {"CA04", "CA05", "CA09", "CA10", "CA11", "CA12"}
# Attacks that stay inside every server rule.
IN_BOUNDS_AUTOMATION = {"CA13", "CA14"}


class CatalogueTests(unittest.TestCase):
    def test_ids_unique_and_documented(self):
        ids = [s.id for s in SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))
        for s in SCENARIOS:
            self.assertTrue(s.summary and s.how, f"{s.id} needs summary and how")

    def test_results_match_expected_detection(self):
        """Regression lock: flips here mean someone's rules changed an outcome."""
        for s in SCENARIOS:
            for mode, (client, server) in CONFIGURATIONS.items():
                with self.subTest(scenario=s.id, mode=mode):
                    got = run_scenario(s, client, server)["detected"]
                    self.assertEqual(got, s.expected_detected[MODES.index(mode)])


class FindingTests(unittest.TestCase):
    def test_client_controlled_attacks_evade_every_mode(self):
        for sid in CLIENT_CONTROLLED_BLIND_SPOTS:
            for mode, (client, server) in CONFIGURATIONS.items():
                with self.subTest(scenario=sid, mode=mode):
                    self.assertFalse(run_scenario(BY_ID[sid], client, server)["detected"])

    def test_in_bounds_automation_is_never_rejected_by_server(self):
        for sid in IN_BOUNDS_AUTOMATION:
            row = run_scenario(BY_ID[sid], True, True)
            self.assertEqual(row["server_rejections"], [])
            self.assertEqual(row["actions"], 100)

    def test_naive_tampering_is_caught_only_with_client_checks(self):
        for sid in ("CA01", "CA02", "CA03", "CA06", "CA07", "CA08"):
            self.assertTrue(run_scenario(BY_ID[sid], True, False)["detected"])
            self.assertFalse(run_scenario(BY_ID[sid], False, True)["detected"])

    def test_scan_counts_show_why_timing_attacks_work(self):
        self.assertEqual(run_scenario(BY_ID["CA05"], True, True)["scans"], 2)   # both clean
        self.assertEqual(run_scenario(BY_ID["CA10"], True, True)["scans"], 1)   # only before the load

    def test_legit_controls_expose_false_positives(self):
        rows = evaluate_client_attacks()
        self.assertEqual(metrics(rows["client_only"])["FP"], 3)
        self.assertEqual(metrics(rows["server_only"])["FP"], 0)
        flagged_legit = {r["id"] for r in rows["combined"]
                         if not r["policy_violation"] and r["detected"]}
        self.assertEqual(flagged_legit, {"CL03", "CL04", "CL06"})

    def test_server_catches_client_attack_once_it_breaks_a_rule(self):
        sc = BY_ID["CA15"]
        self.assertFalse(run_scenario(sc, True, False)["detected"])    # monitor disabled
        row = run_scenario(sc, False, True)
        self.assertTrue(row["detected"])
        self.assertEqual(row["server_rejections"], ["speed_violation"])

    def test_human_movement_is_accepted(self):
        row = run_scenario(BY_ID["CL05"], True, True)
        self.assertFalse(row["detected"])
        self.assertEqual(row["actions"], 8)

    def test_human_firing_is_irregular_but_accepted(self):
        row = run_scenario(BY_ID["CL01"], True, True)
        self.assertFalse(row["detected"])
        self.assertEqual(row["actions"], 8)


if __name__ == "__main__":
    unittest.main()
