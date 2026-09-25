"""Tests for shared report section ordering and TOC assembly."""

from reporting.section_registry import render_report_sections, render_toc


def test_full_and_backup_toc_membership_comes_from_shared_definitions():
    full = render_toc("full")
    backup = render_toc("backup")

    assert '<span class="toc-num">1</span><span class="toc-entry">Executive Summary</span>' in full
    assert "UniFi Comparison &amp; Refresh Planning" in full
    assert "Executive Summary" not in backup
    assert '<span class="toc-num">16</span><span class="toc-entry">UniFi Comparison &amp; Refresh Planning</span>' in backup


def test_registry_preserves_body_order_and_rejects_missing_sections():
    bodies = {
        "executive_summary": "exec",
        "network_overview": "overview",
        "network_topology": "topology",
        "traffic_flows": "traffic",
        "device_issues": "issues",
        "poe_analysis": "poe",
        "security_baseline": "security",
        "recommendations": "recommendations",
        "cis8": "cis8",
        "licensing": "licensing",
        "config_coverage": "config",
        "budget_forecast": "budget",
        "wan_capacity": "wan",
        "ap_interference": "ap",
        "client_analysis": "clients",
        "switch_deep_dive": "switch",
        "unifi_comparison": "unifi",
    }

    assert render_report_sections(bodies, "full") == "".join(bodies.values())
    assert render_report_sections(bodies, "backup") == "".join(
        value for key, value in bodies.items() if key != "executive_summary"
    )

    del bodies["unifi_comparison"]
    try:
        render_report_sections(bodies, "full")
    except KeyError as exc:
        assert "unifi_comparison" in str(exc)
    else:
        raise AssertionError("missing section body was not rejected")
