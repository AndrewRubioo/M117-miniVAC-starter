import unittest
from minivac.experiments import FakeClock, evaluate_case, evaluate_all, metrics
from minivac.server_logic import GameServer


class ServerTests(unittest.TestCase):
    def test_regular_move_is_allowed(self):
        server = GameServer(clock=FakeClock())
        self.assertTrue(server.action("p1", "move", dx=0.2)["accepted"])
        self.assertAlmostEqual(server.state("p1")["x"], 0.2)

    def test_teleport_is_rejected_without_state_change(self):
        server = GameServer(clock=FakeClock())
        result = server.action("p1", "move", dx=10.0)
        self.assertEqual(result["reason"], "speed_violation")
        self.assertEqual(server.state("p1")["x"], 0.0)

    def test_fire_rate_is_rejected(self):
        server = GameServer(clock=FakeClock())
        self.assertTrue(server.action("p1", "shoot")["accepted"])
        self.assertEqual(server.action("p1", "shoot")["reason"], "fire_rate_violation")

    def test_no_client_timestamp_can_override_clock(self):
        # API accepts only player_id, kind, and delta; the game rules use server.clock.
        server = GameServer(clock=FakeClock())
        server.action("p1", "shoot")
        self.assertFalse(server.action("p1", "shoot")["accepted"])


class ExperimentTests(unittest.TestCase):
    def test_expected_detection(self):
        self.assertTrue(evaluate_case("tampered_asset", True, False)["detected"])
        self.assertFalse(evaluate_case("tampered_asset", False, True)["detected"])
        self.assertTrue(evaluate_case("impossible_movement", False, True)["detected"])
        self.assertFalse(evaluate_case("impossible_movement", True, False)["detected"])

    def test_compromised_client_monitor_blindspot(self):
        case = evaluate_case("disabled_client_monitor", True, True)
        self.assertFalse(case["detected"])

    def test_legit_scenarios_not_flagged(self):
        for config_rows in evaluate_all().values():
            self.assertEqual(metrics(config_rows)["FP"], 0)


if __name__ == "__main__":
    unittest.main()
