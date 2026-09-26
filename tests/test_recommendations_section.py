"""Tests for the recommendations report section."""

from reporting.report_sections.recommendations import build_recommendations_section


def test_recommendations_render_markdown_and_timeline():
    html = build_recommendations_section("## Priority\n- Fix uplinks", [], {}, {})

    assert '<section id="recommendations"' in html
    assert "<h2>Priority</h2>" in html
    assert "<li>Fix uplinks</li>" in html
    assert "Prioritized Action Timeline" in html
    assert "Hardware Mix &amp; AP Profile Optimization" not in html


def test_recommendations_escape_network_names_and_show_profile_findings():
    html = build_recommendations_section(
        "<script>alert(1)</script>",
        ["<img src=x onerror=alert(1)>", "Branch"],
        {
            "N_1": [
                {
                    "apBandSettings": {"bandSteeringEnabled": False},
                    "twoFourGhzSettings": {"minBitrate": 11},
                    "fiveGhzSettings": {"minBitrate": 12, "channelWidth": "20MHz"},
                }
            ]
        },
        {"N_1": "West<script>"},
    )

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;, Branch" in html
    assert "West&lt;script&gt;: band steering disabled" in html
    assert "2.4 GHz min bitrate ≤ 11 Mbps" in html
    assert "5 GHz min bitrate ≤ 12 Mbps" in html
    assert "5 GHz channel width fixed at 20 MHz" in html
    assert "<script>" not in html
    assert "<img src=x" not in html
