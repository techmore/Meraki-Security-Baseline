"""Tests for the generated HTML safety boundary."""

from reporting.html_shell import build_html, sanitize_html_fragment


def test_fragment_sanitizer_drops_executable_markup_and_unsafe_links():
    fragment = (
        '<p>safe</p><script>alert(1)</script>'
        '<img src="x" onerror="alert(2)">'
        '<div onclick="alert(3)"><a href="javascript:alert(4)">bad</a>'
        '<a href="#safe">good</a></div>'
    )

    sanitized = sanitize_html_fragment(fragment)

    assert sanitized == '<p>safe</p><div><a>bad</a><a href="#safe">good</a></div>'
    assert '<script' not in sanitized
    assert 'onerror' not in sanitized
    assert 'onclick' not in sanitized
    assert 'javascript:' not in sanitized


def test_build_html_escapes_document_title_and_preserves_report_svg():
    title = '</title><script>alert(5)</script>'
    body = '<svg viewBox="0 0 10 10"><text>Network</text></svg>'

    html = build_html(title, body)

    assert '<title>&lt;/title&gt;&lt;script&gt;alert(5)&lt;/script&gt;</title>' in html
    assert '<script>' not in html
    assert '<svg viewBox="0 0 10 10"><text>Network</text></svg>' in html
