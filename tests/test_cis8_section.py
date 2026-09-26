"""Tests for the CIS Controls v8 assessment report section."""

from reporting.report_sections.cis8 import build_cis8_section


def test_cis8_section_contains_inventory_and_control_rows():
    html = build_cis8_section(12, 0, 0)

    assert '<section id="cis8"' in html
    assert "12 devices tracked via Meraki Dashboard" in html
    assert html.count("<tr>") == 11
    assert 'class="check-pass">Pass</span>' in html
    assert "0 port issue(s) and 0 config anomaly(ies)" in html


def test_cis8_issues_degrade_secure_configuration_and_network_management():
    html = build_cis8_section(12, 3, 2)

    assert "3 port issue(s) and 2 config anomaly(ies)" in html
    assert html.count('class="check-warning">Partial</span>') == 4
    assert 'class="check-pass">Pass</span>' not in html


def test_cis8_configuration_only_issue_does_not_degrade_network_management():
    html = build_cis8_section(12, 0, 2)

    assert "0 port issue(s) and 2 config anomaly(ies)" in html
    assert html.count('class="check-warning">Partial</span>') == 3
    assert html.count('class="check-pass">Pass</span>') == 1
