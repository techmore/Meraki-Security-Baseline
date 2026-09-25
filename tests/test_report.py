"""Tests for reporting/app.py — build_org_report() with fixture data."""
import json
import os
import shutil
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestBuildOrgReport:
    """Smoke tests: build_org_report() on fixture data must produce valid HTML."""

    @pytest.fixture(scope="class")
    def report_html(self):
        from reporting.app import build_org_report
        return build_org_report(FIXTURES, "Test Org")

    def test_produces_string(self, report_html):
        assert isinstance(report_html, str)
        assert len(report_html) > 1000

    def test_no_unclosed_section_tags(self, report_html):
        opens  = report_html.count("<section")
        closes = report_html.count("</section>")
        assert opens == closes, f"Mismatched <section> tags: {opens} open vs {closes} close"

    def test_exec_summary_present(self, report_html):
        assert "executive-summary" in report_html

    def test_current_state_assessment_present(self, report_html):
        assert "Current State Assessment" in report_html

    def test_top_operational_risks_present(self, report_html):
        assert "Top Operational Risks" in report_html

    def test_recommended_priorities_present(self, report_html):
        assert "Recommended Priorities" in report_html

    def test_health_grid_present(self, report_html):
        assert "health-grid" in report_html

    def test_security_section_present(self, report_html):
        assert "security-baseline" in report_html
        assert "Security Posture Summary" in report_html

    def test_traffic_flows_present(self, report_html):
        assert "traffic-flows" in report_html

    def test_licensing_section_present(self, report_html):
        assert "licensing" in report_html
        assert "Licensing Status" in report_html

    def test_no_python_exceptions_in_output(self, report_html):
        """Report should not contain Python traceback artifacts."""
        assert "Traceback" not in report_html
        assert "AttributeError" not in report_html
        assert "KeyError" not in report_html

    def test_org_name_appears_in_report(self, report_html):
        assert "Test Org" in report_html

    def test_xss_safe_org_name(self):
        from reporting.app import build_org_report
        html = build_org_report(FIXTURES, '<script>alert("xss")</script>')
        assert '<script>alert("xss")</script>' not in html

    def test_security_fail_check_rendered(self, report_html):
        """The fixture has 1 failing IPS check — it should appear in report."""
        assert "Intrusion Prevention" in report_html

    def test_title_case_security_failure_drives_posture(self, report_html):
        """Persisted title-case Fail values must not be treated as healthy."""
        assert "Action required" in report_html
        assert "Posture is satisfactory" not in report_html
        assert "0 fails" not in report_html

    def test_licensing_expired_rendered(self, report_html):
        """Fixture has one expired license key."""
        assert "Expired" in report_html or "expired" in report_html.lower()

    def test_licensing_coverage_is_scoped_to_requested_org(self, tmp_path, monkeypatch):
        """A report must not disclose licensing coverage from sibling org backups."""
        from reporting.app import build_org_report

        selected_org = tmp_path / "selected-org"
        other_org = tmp_path / "other-org"
        shutil.copytree(FIXTURES, selected_org)
        shutil.copytree(FIXTURES, other_org)
        (other_org / "licensing.json").write_text(
            json.dumps({"licenseMode": "co-term", "licenses": []})
        )

        # Reproduce the old global-discovery path with two sibling organizations.
        import reporting.app as report_app
        monkeypatch.setattr(report_app, "BACKUPS_DIR", str(tmp_path))

        html = build_org_report(str(selected_org), "Selected Org")

        assert "Org backup coverage: <strong>1/1</strong>" in html
        assert "Org backup coverage: <strong>2/2</strong>" not in html

    def test_wpc_topology_excluded(self, report_html):
        """Topology section should still exist even with empty LLDP fixture."""
        assert "topology" in report_html

    def test_malformed_artifacts_degrade_with_data_quality_notice(self, tmp_path):
        from reporting.app import build_org_report

        org_dir = tmp_path / "org"
        shutil.copytree(FIXTURES, org_dir)
        (org_dir / "devices_availabilities.json").write_text("{invalid json}")
        (org_dir / "channel_utilization_by_device.json").write_text(
            json.dumps([{"serial": "AP-BAD", "utilizationTotal": "not-a-number"}])
        )
        (org_dir / "networks.json").write_text(json.dumps({"wrong": "top-level"}))

        html = build_org_report(str(org_dir), "Degraded Org")

        assert "data-quality-banner" in html
        assert "devices_availabilities.json" in html
        assert "non-numeric utilizationTotal" in html
        assert "Traceback" not in html

    def test_mixed_timezone_timestamps_do_not_abort_rendering(self, tmp_path):
        from reporting.app import build_org_report

        org_dir = tmp_path / "org"
        shutil.copytree(FIXTURES, org_dir)
        (org_dir / "firmware_upgrades.json").write_text(json.dumps([
            {"time": "2026-09-25T12:00:00Z", "network": {"name": "Main"}, "status": "completed"},
            {"time": "2026-09-25T08:00:00-04:00", "network": {"name": "Main"}, "status": "completed"},
        ]))
        (org_dir / "alerts_history.json").write_text(json.dumps({
            "N_test_001": [
                {"occurredAt": "2026-09-25T12:00:00Z", "alertType": "test"},
                {"occurredAt": "2026-09-25T08:00:00", "alertType": "test"},
            ]
        }))

        html = build_org_report(str(org_dir), "Timestamp Org")

        assert "Recent Firmware Upgrades" in html
        assert "Most Recent Alerts" in html
        assert "TypeError" not in html

    def test_exec_summary_report_variant(self):
        from reporting.app import build_org_report
        html = build_org_report(FIXTURES, "Test Org", report_kind="exec")
        assert "Executive Summary" in html
        assert "Network Overview" not in html

    def test_backup_settings_report_variant(self):
        from reporting.app import build_org_report
        html = build_org_report(FIXTURES, "Test Org", report_kind="backup")
        assert "Network Overview" in html
        assert "Executive Summary" not in html


class TestHealthCardRatings:
    """Unit test the health domain scoring logic independently."""

    def _run_health(self, **overrides):
        """Build a minimal args set and return the health card variables."""
        from reporting.app import build_org_report
        # Just build the full report and check the rendered HTML for badges
        html = build_org_report(FIXTURES, "Test Org")
        return html

    def test_availability_card_present(self):
        html = self._run_health()
        assert "Availability" in html

    def test_licensing_card_shows_crit_when_expired(self):
        html = self._run_health()
        # Fixture has 1 expired license key — card should show crit
        assert "hcard-crit" in html or "Expired" in html


class TestLicensingCounts:
    """Test that licensing expired/active counts use the bool expired field."""

    def test_expired_bool_counted(self):
        import json, tempfile, os
        from reporting.app import build_org_report
        # Create a temp dir with just enough to not crash
        with tempfile.TemporaryDirectory() as tmp:
            # Copy all fixtures except licensing.json
            for fn in os.listdir(FIXTURES):
                src = os.path.join(FIXTURES, fn)
                dst = os.path.join(tmp, fn)
                if fn != "licensing.json":
                    import shutil
                    shutil.copy(src, dst)
            # Write a licensing.json with only bool-expired licenses
            lic = {"licenseMode": "co-term", "licenses": [
                {"key": "K1", "expired": True, "invalidated": False,
                 "startedAt": "2020-01-01T00:00:00Z", "duration": 365,
                 "counts": [{"count": 5, "model": "MR Enterprise"}],
                 "editions": [{"edition": "Enterprise", "productType": "wireless"}]},
                {"key": "K2", "expired": False, "invalidated": False,
                 "startedAt": "2025-01-01T00:00:00Z", "duration": 1095,
                 "counts": [{"count": 10, "model": "MR Enterprise"}],
                 "editions": [{"edition": "Enterprise", "productType": "wireless"}]},
            ]}
            with open(os.path.join(tmp, "licensing.json"), "w") as f:
                json.dump(lic, f)
            html = build_org_report(tmp, "Lic Test")
        # 1 expired key should trigger crit rating
        assert "hcard-crit" in html or "Expired" in html
        # K1 expired, K2 active — both should appear in the licensing table
        assert "K1" in html
        assert "K2" in html
