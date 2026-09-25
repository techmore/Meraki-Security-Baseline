"""Tests for extracted report section builders."""

from reporting.sections import _build_client_analysis_section


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
