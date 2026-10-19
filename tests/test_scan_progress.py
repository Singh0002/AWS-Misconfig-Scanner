"""Tests for the progress bar and the one-scan-at-a-time rule (S-2-4)."""

import os
import tempfile
import unittest

import results
import scan_progress as sp


class TestProgressState(unittest.TestCase):
    def test_idle_scan_can_start(self):
        self.assertTrue(sp.can_start(sp.idle()))
        self.assertEqual(sp.text(sp.idle()), "No scan running.")
        self.assertEqual(sp.fraction(sp.idle()), 0.0)

    def test_second_scan_blocked_while_running(self):
        self.assertFalse(sp.can_start(sp.start()))

    def test_can_start_again_after_done_or_failed(self):
        running = sp.update(sp.start(), 1, 4, "x")
        self.assertTrue(sp.can_start(sp.finish(running, True)))
        self.assertTrue(sp.can_start(sp.finish(running, False)))

    def test_fraction_follows_updates(self):
        p = sp.update(sp.start(), 3, 10, "Checking S3 versioning")
        self.assertAlmostEqual(sp.fraction(p), 0.3)
        self.assertEqual(sp.text(p), "Checking S3 versioning")

    def test_done_never_goes_past_total(self):
        p = sp.update(sp.start(), 12, 10, "x")
        self.assertEqual(p["done"], 10)
        self.assertEqual(sp.fraction(p), 1.0)

    def test_negative_numbers_are_clamped(self):
        p = sp.update(sp.start(), -5, -1, "x")
        self.assertEqual((p["done"], p["total"]), (0, 0))
        self.assertEqual(sp.fraction(p), 0.0)

    def test_finish_ok_fills_the_bar(self):
        p = sp.finish(sp.update(sp.start(), 2, 5, "x"), True)
        self.assertEqual(sp.fraction(p), 1.0)
        self.assertEqual(p["state"], sp.DONE)

    def test_failed_scan_keeps_its_place_and_says_so(self):
        p = sp.finish(sp.update(sp.start(), 2, 5, "x"), False)
        self.assertAlmostEqual(sp.fraction(p), 0.4)
        self.assertEqual(p["state"], sp.FAILED)
        self.assertIn("stopped", p["message"])

    def test_late_update_cannot_restart_a_finished_scan(self):
        finished = sp.finish(sp.update(sp.start(), 2, 5, "x"), True)
        self.assertEqual(sp.update(finished, 1, 5, "late")["state"], sp.DONE)


class TestScanTab(unittest.TestCase):
    """Runs the real app.py with Streamlit's test runner and a fake coordinator."""

    def setUp(self):
        from streamlit.testing.v1 import AppTest

        self.tmp = tempfile.TemporaryDirectory()
        os.environ["CLOUDGUARDIAN_DB"] = os.path.join(self.tmp.name, "test.db")
        import coordinator

        self.coordinator = coordinator
        self.had_runner = hasattr(coordinator, "run_scan")
        self.at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py"), default_timeout=20)

    def tearDown(self):
        if not self.had_runner and hasattr(self.coordinator, "run_scan"):
            del self.coordinator.run_scan
        os.environ.pop("CLOUDGUARDIAN_DB", None)
        self.tmp.cleanup()

    def start_button(self):
        return [b for b in self.at.button if b.label == "Start scan"][0]

    def test_page_starts_idle_with_start_button_enabled(self):
        self.at.run()
        self.assertFalse(self.at.exception)
        self.assertFalse(self.start_button().disabled)
        self.assertEqual(self.at.session_state.progress["state"], sp.IDLE)

    def test_without_a_coordinator_nothing_runs_and_button_stays_usable(self):
        if hasattr(self.coordinator, "run_scan"):
            self.skipTest("coordinator.run_scan exists now; this case no longer applies")
        self.at.run()
        self.start_button().click().run()
        self.assertEqual(self.at.session_state.progress["state"], sp.IDLE)
        self.assertIn("isn't hooked up", self.at.info[0].value)
        self.assertFalse(self.start_button().disabled)

    def test_no_rules_selected_gives_a_warning_and_no_scan(self):
        self.at.run()
        for box in self.at.checkbox:
            if box.key and box.key.startswith("service_"):
                box.uncheck()
        self.at.run()
        self.start_button().click().run()
        self.assertIn("Pick at least one", self.at.warning[0].value)
        self.assertEqual(self.at.session_state.progress["state"], sp.IDLE)

    def test_scan_reports_progress_then_finishes(self):
        calls = []

        def fake_run_scan(services, rules, on_progress):
            calls.append((list(services), list(rules)))
            on_progress(1, 2, "Checking S3")
            on_progress(2, 2, "Checking IAM")
            return results.new_scan(["S3", "IAM"])

        self.coordinator.run_scan = fake_run_scan
        self.at.run()
        self.start_button().click().run()
        self.assertEqual(len(calls), 1)  # exactly one scan was started
        self.assertEqual(calls[0][0], ["S3", "IAM"])
        self.assertEqual(self.at.session_state.progress["state"], sp.DONE)
        self.assertEqual(sp.fraction(self.at.session_state.progress), 1.0)
        self.assertFalse(self.at.exception)
        self.assertEqual(self.at.session_state.scan["metadata"]["selected_services"], '["S3", "IAM"]')
        self.assertFalse(self.start_button().disabled)  # can scan again afterwards

    def test_failed_scan_shows_error_type_only_and_unlocks(self):
        def broken_run_scan(services, rules, on_progress):
            on_progress(1, 4, "Checking S3")
            raise RuntimeError("secret-account-detail")

        self.coordinator.run_scan = broken_run_scan
        self.at.run()
        self.start_button().click().run()
        self.assertEqual(self.at.session_state.progress["state"], sp.FAILED)
        self.assertIn("RuntimeError", self.at.error[0].value)
        self.assertNotIn("secret-account-detail", self.at.error[0].value)
        self.assertFalse(self.start_button().disabled)


if __name__ == "__main__":
    unittest.main()
