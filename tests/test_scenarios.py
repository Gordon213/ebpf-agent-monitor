import unittest

from ui.scenarios import catalog, run_scenario


EXPECTED = {
    "unexpected_shell": "unexpected_shell",
    "sensitive_file": "sensitive_file_access",
    "workspace_boundary": "workspace_boundary_violation",
    "infinite_loop": "infinite_loop",
    "resource_abuse": "resource_abuse",
    "excessive_deletion": "excessive_file_deletion",
    "malicious_ip": "malicious_destination",
    "high_risk_port": "high_risk_network_port",
    "resource_contention": "resource_contention",
    "unauthorized_handoff": "unauthorized_agent_handoff",
    "collective_storm": "collective_api_storm",
}


class ScenarioTest(unittest.TestCase):
# 场景目录要列全 11 个触发器，且每个都有标题和摘要。
    def test_catalog_lists_every_trigger(self):
        self.assertEqual([item["id"] for item in catalog()], list(EXPECTED))

# 每个触发器都要能跑出对应告警和非空 Prompt。
    def test_each_trigger_produces_its_alert_and_prompt(self):
        for name, anomaly in EXPECTED.items():
            with self.subTest(name=name):
                result = run_scenario(name)
                types = [alert["anomaly_type"] for alert in result["alerts"]]
                self.assertIn(anomaly, types)
                matched = next(alert for alert in result["alerts"] if alert["anomaly_type"] == anomaly)
                self.assertTrue(matched.get("causal_prompt"))
                self.assertTrue(matched.get("rule"))
                self.assertTrue(result["steps"])
                self.assertEqual(result["steps"][0]["offset_ms"], 0)
                self.assertTrue(any(anomaly in step["triggered"] for step in result["steps"]))
