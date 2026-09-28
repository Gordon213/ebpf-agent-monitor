from __future__ import annotations

import unittest

from tools.run_review_demo import add_check, alert_matches, describe_alert, event_summary


class ReviewDemoTest(unittest.TestCase):
    def test_alert_match_requires_exact_agent_prompt_and_response(self) -> None:
        alert = {
            "anomaly_type": "unexpected_shell",
            "agent_id": 1,
            "causal_prompt": "PROMPT_A",
            "causal_response": "ACK:PROMPT_A",
        }
        self.assertTrue(
            alert_matches(
                alert,
                {
                    "anomaly_type": "unexpected_shell",
                    "agent_id": 1,
                    "causal_prompt": "PROMPT_A",
                    "require_response": True,
                },
            )
        )
        self.assertFalse(
            alert_matches(alert, {"agent_id": 2, "causal_prompt": "PROMPT_B"})
        )

    def test_event_summary_never_persists_tls_plaintext(self) -> None:
        summary = event_summary(
            {
                "type": "tls_write",
                "agent_id": 1,
                "payload": "Authorization: Bearer secret-value",
                "data_len": 42,
            }
        )
        self.assertNotIn("payload", summary)
        self.assertEqual(summary["data_len"], 42)
        self.assertIn("HTTPS 请求", summary["description"])

    def test_human_readable_descriptions_are_added_to_results(self) -> None:
        checks: list[dict[str, object]] = []
        add_check(checks, "Ring Buffer 无丢失且 ABI 有效", True, {"dropped": 0})
        self.assertIn("内核到用户态", str(checks[0]["description"]))

        alert = describe_alert({"anomaly_type": "resource_contention"})
        self.assertIn("两个 Agent", alert["description"])


if __name__ == "__main__":
    unittest.main()
