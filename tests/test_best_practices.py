"""Unit tests for the report-native best-practice adapter."""

from reporting.best_practices import build_best_practice_checks, render_best_practice_section


def _check(checks, check_id):
    return next(check for check in checks if check["check_id"] == check_id)


def _base_checks(**overrides):
    values = {
        "networks": [{"id": "N1", "name": "Main", "productTypes": ["wireless"]}],
        "devices_avail": [{"serial": "AP1", "productType": "wireless"}],
        "channel_util": [],
        "rf_profiles": {},
        "firmware_upgrades": [],
        "switch_port_statuses": [],
        "security_checks": [],
        "alerts_history": {},
        "wireless_ssids": {},
        "ap_to_switch": {},
        "artifact_available": {},
    }
    values.update(overrides)
    return build_best_practice_checks(**values)


def test_high_channel_utilization_is_a_failure():
    checks = _base_checks(
        channel_util=[{"serial": "AP1", "utilizationTotal": 82}],
        artifact_available={"channel_utilization_by_device.json": True},
    )

    check = _check(checks, "wireless.channel_utilization")

    assert check["status"] == "fail"
    assert check["coverage"] == "complete"
    assert "82.0%" in check["observation"]


def test_missing_telemetry_is_explicitly_not_evaluated():
    checks = _base_checks()

    rf_check = _check(checks, "wireless.rf_profile_baseline")
    governance_check = _check(checks, "governance.admin_mfa_api")

    assert rf_check["status"] == "info"
    assert rf_check["coverage"] == "not_collected"
    assert governance_check["status"] == "info"
    assert governance_check["coverage"] == "not_collected"


def test_security_statuses_are_normalized_and_failures_preserved():
    checks = _base_checks(
        security_checks=[{"check": "IPS", "status": "Fail"}],
    )

    check = _check(checks, "security.baseline")

    assert check["status"] == "fail"
    assert "1 failed" in check["observation"]


def test_alert_collection_errors_are_not_reported_as_clean_history():
    checks = _base_checks(
        alerts_history={"N1": {"error": "HTTP 403"}},
        artifact_available={"alerts_history.json": True},
    )

    check = _check(checks, "network.health_alert_history")

    assert check["status"] == "info"
    assert check["coverage"] == "partial"
    assert "cannot be inferred" in check["observation"]


def test_ap_uplink_check_uses_confirmed_mapping_and_flags_negotiation():
    checks = _base_checks(
        switch_port_statuses=[
            {
                "switchSerial": "SW1",
                "portId": "7",
                "speed": "100 Mbps",
                "duplex": "full",
                "errors": [],
            }
        ],
        ap_to_switch={"AP1": {"switch": "SW1", "port": "7"}},
    )

    check = _check(checks, "wireless.ap_uplink_negotiation")

    assert check["status"] == "warning"
    assert check["coverage"] == "complete"


def test_renderer_escapes_check_content_and_lists_collection_gaps():
    html = render_best_practice_section([
        {
            "check_id": "test.check",
            "scope_name": "<script>alert(1)</script>",
            "status": "info",
            "coverage": "not_collected",
            "observation": "</td><script>alert(2)</script>",
            "recommendation": "Review & validate",
            "source_artifact": "artifact.json",
        }
    ])

    assert "<script>" not in html
    assert "&lt;/td&gt;&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "Best-Practice Coverage" in html
    assert "Collection Gaps" in html
    assert "Not evaluated" in html
