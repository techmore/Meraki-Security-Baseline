"""Tests for extracted report section builders."""

from reporting.sections import (
    _build_client_analysis_section,
    _build_unifi_comparison_section,
)


def test_client_analysis_escapes_dimension_labels():
    html = _build_client_analysis_section([
        {
            "ssid": '<script>alert("xss")</script>',
            "os": "Laptop",
            "vlan": 20,
            "rssi": -55,
        }
    ])

    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html
    assert "<script>alert(\"xss\")</script>" not in html
    assert "Excellent (&gt;-60)" in html


def test_unifi_comparison_prefers_specific_model_and_escapes_eol_names():
    html = _build_unifi_comparison_section(
        [("MR46E", 2)],
        ["MR46E", "<script>alert(1)</script>"],
    )

    assert "U7 Pro Max" in html
    assert "<td>$699</td>" in html
    assert "<td>$449</td>" in html
    assert "⚠ EOL" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
