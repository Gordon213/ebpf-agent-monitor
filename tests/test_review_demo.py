from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from tools import performance_eval, run_review_demo
from tools.run_review_demo import add_check, alert_matches, describe_alert, event_summary
from user.analyzer import Analyzer


class ReviewDemoTest(unittest.TestCase):
# 告警配对要求 Agent、Prompt、Response 完全一致，避免因果串线。
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

# 事件摘要里不能出现 TLS 明文，防止报告泄露内容。
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

# 报告里的检查项都要带人类可读的描述，便于评审阅读。
    def test_human_readable_descriptions_are_added_to_results(self) -> None:
        checks: list[dict[str, object]] = []
        add_check(checks, "Ring Buffer 无丢失且 ABI 有效", True, {"dropped": 0})
        self.assertIn("内核到用户态", str(checks[0]["description"]))

        alert = describe_alert({"anomaly_type": "resource_contention"})
        self.assertIn("两个 Agent", alert["description"])


class ReviewLifecycleTest(unittest.TestCase):
    def config(self):
        return run_review_demo.load_config(
            run_review_demo.DEFAULT_CONFIG_DIR / "review-2-observability.yaml"
        )

    def test_private_paths_keep_rules_and_expected_evidence_in_sync(self):
        config = self.config()
        original = copy.deepcopy(config)
        with tempfile.TemporaryDirectory() as directory:
            runtime, rules_file, paths = run_review_demo.prepare_review_workspace(config, Path(directory))
            rules = yaml.safe_load(rules_file.read_text())
            baseline = yaml.safe_load(run_review_demo.root_path(config["analyzer_config"]).read_text())
            self.assertEqual(config, original)
            for key in ("loop_detection", "resource_limits", "semantic_capture"):
                self.assertEqual(rules[key], baseline[key])
            self.assertTrue(all(path.startswith(directory + "/") for path in runtime["expected"]["paths"]))
            self.assertEqual(rules["agents"][1]["workspace"], paths["/tmp/ebpf-agent-workspace"] + "/agent-1")
            self.assertEqual(rules["multi_agent"]["shared_paths"], [paths["/tmp/ebpf-agent-workspace"] + "/shared"])
            analyzer = Analyzer(rules)
            event = {"agent_id": 2, "type": "openat", "object": paths["protected_file"],
                     "retval": 3, "timestamp_ns": 1_000_000_000}
            self.assertIn("sensitive_file_access", [item["anomaly_type"] for item in analyzer.process(event)])
            shared = paths["/tmp/ebpf-agent-workspace"] + "/shared/review-contended.txt"
            analyzer.process(dict(event, agent_id=1, object=shared, flags=1))
            self.assertIn("resource_contention", [item["anomaly_type"] for item in analyzer.process(dict(event, object=shared, flags=1))])
            handoff = paths["/tmp/ebpf-agent-handoff"] + "/review-unapproved.txt"
            analyzer.process(dict(event, agent_id=1, object=handoff, flags=1))
            self.assertIn("unauthorized_agent_handoff", [item["anomaly_type"] for item in analyzer.process(dict(event, object=handoff, flags=0))])

    def test_a_new_run_does_not_reuse_existing_read_only_fixtures(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            _, _, old = run_review_demo.prepare_review_workspace(self.config(), Path(first))
            old_file = Path(old["protected_file"])
            old_file.chmod(0o444)
            _, _, new = run_review_demo.prepare_review_workspace(self.config(), Path(second))
            self.assertNotEqual(old["protected_file"], new["protected_file"])
            self.assertEqual(Path(new["protected_file"]).read_text(), "harmless review decoy\n")
            self.assertEqual(old_file.stat().st_mode & 0o777, 0o444)

    def test_interrupt_during_startup_reaps_all_started_children(self):
        real_popen = subprocess.Popen
        for stage in ("tls", "second-agent"):
            spawned = []

            def start(command, **kwargs):
                if stage == "second-agent" and len(spawned) == 2:
                    raise KeyboardInterrupt
                marker = "TLS SERVER READY 1234" if not spawned else "REVIEW AGENT 1 PID 1234"
                code = "import time; print(" + repr(marker) + ", flush=True); time.sleep(60)"
                process = real_popen([sys.executable, "-c", code], **kwargs)
                spawned.append(process)
                return process

            read = (patch.object(run_review_demo, "read_startup", side_effect=KeyboardInterrupt)
                    if stage == "tls" else patch.object(run_review_demo, "read_startup", wraps=run_review_demo.read_startup))
            with self.subTest(stage=stage), read, \
                    patch.object(run_review_demo, "generate_certificate", return_value=(Path("cert"), Path("key"))), \
                    patch.object(run_review_demo.subprocess, "Popen", side_effect=start):
                try:
                    with self.assertRaises(KeyboardInterrupt):
                        run_review_demo.run_live(self.config())
                    self.assertTrue(spawned)
                    self.assertTrue(all(process.poll() is not None for process in spawned))
                    self.assertTrue(all(process.stdout.closed and process.stderr.closed for process in spawned))
                finally:
                    for process in spawned:
                        run_review_demo.stop_review_process(process)

    def test_performance_startup_interrupt_reaps_its_workload(self):
        real_popen = subprocess.Popen
        spawned = []

        def start(command, **kwargs):
            process = real_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
            spawned.append(process)
            return process

        with patch.object(performance_eval.subprocess, "Popen", side_effect=start), \
                patch.object(performance_eval, "read_ready", side_effect=KeyboardInterrupt):
            try:
                with self.assertRaises(KeyboardInterrupt):
                    performance_eval.run_trial("file", 1, 0, False, None, None)
                self.assertTrue(all(process.poll() is not None for process in spawned))
            finally:
                for process in spawned:
                    performance_eval.stop_trial_process(process)


if __name__ == "__main__":
    unittest.main()
