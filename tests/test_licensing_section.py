"""Tests for the organization licensing report section."""

from reporting.report_sections.licensing import build_licensing_section


def test_missing_licensing_artifact_is_not_described_as_an_empty_response():
    html = build_licensing_section({}, artifact_available=False)

    assert "No <code>licensing.json</code> was found" in html
    assert "Org backup coverage: <strong>0/1</strong>" in html
    assert "No license keys were returned" not in html


def test_licensing_section_escapes_api_values_and_calculates_expiration():
    html = build_licensing_section(
        {
            "licenseMode": "co-term<script>",
            "licenses": [
                {
                    "key": "<script>alert(1)</script>",
                    "counts": [{"count": 2, "model": "MR Enterprise<img>"}],
                    "status": '<img src=x onerror="alert(2)">',
                    "startedAt": "2026-01-01T00:00:00Z",
                    "duration": 30,
                }
            ],
        },
        artifact_available=True,
    )

    assert "co-term&lt;script&gt;" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "MR Enterprise&lt;img&gt;" in html
    assert "&lt;img src=x onerror=&quot;alert(2)&quot;&gt;" in html
    assert "2026-01-31" in html
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
