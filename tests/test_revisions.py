"""Tests for immutable report revision storage."""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from reporting.revisions import ReportRevision, fingerprint_inputs


def _make_revision(org_dir: Path, timestamp: datetime) -> ReportRevision:
    return ReportRevision(
        org_dir=str(org_dir),
        org_name="Test Org",
        generated_at=timestamp,
        report_version="1.0",
        backup_schema_version=1,
        input_fingerprint=fingerprint_inputs(str(org_dir)),
    )


def test_fingerprint_ignores_generated_reports_and_revisions(tmp_path):
    (tmp_path / "networks.json").write_text('{"id": "N1"}', encoding="utf-8")
    first = fingerprint_inputs(str(tmp_path))

    (tmp_path / "report.html").write_text("old report", encoding="utf-8")
    (tmp_path / "Example_2026-09-25_120000_report.html").write_text(
        "archived report", encoding="utf-8"
    )
    revision_dir = tmp_path / "reports" / "20260925T120000000000Z"
    revision_dir.mkdir(parents=True)
    (revision_dir / "manifest.json").write_text("{}", encoding="utf-8")
    assert fingerprint_inputs(str(tmp_path)) == first

    (tmp_path / "networks.json").write_text('{"id": "N2"}', encoding="utf-8")
    assert fingerprint_inputs(str(tmp_path)) != first


def test_revision_manifest_and_index_preserve_same_timestamp_runs(tmp_path):
    timestamp = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)
    first = _make_revision(tmp_path, timestamp)
    first_html = first.write_html("full", "first")
    assert first_html.read_text(encoding="utf-8") == "first"
    first.record_pdf("full", available=False)
    first.record_paths(
        "full",
        html_archive=tmp_path / "first_report.html",
        html_alias=tmp_path / "report.html",
    )
    first_manifest = first.finalize()

    second = _make_revision(tmp_path, timestamp)
    second.write_html("full", "second")
    second.record_pdf("full", available=True)
    second.record_paths(
        "full",
        html_archive=tmp_path / "second_report.html",
        html_alias=tmp_path / "report.html",
        pdf_archive=tmp_path / "second_report.pdf",
        pdf_alias=tmp_path / "report.pdf",
    )
    second_manifest = second.finalize()

    assert first.revision_id != second.revision_id
    assert first.revision_dir.is_dir()
    assert second.revision_dir.is_dir()
    assert first_manifest["status"] == "complete"
    assert second_manifest["variants"]["full"]["pdf"] == "report.pdf"

    first_saved = json.loads((first.revision_dir / "manifest.json").read_text(encoding="utf-8"))
    second_saved = json.loads((second.revision_dir / "manifest.json").read_text(encoding="utf-8"))
    index = json.loads((tmp_path / "reports" / "index.json").read_text(encoding="utf-8"))
    assert first_saved["revision_id"] == first.revision_id
    assert second_saved["revision_id"] == second.revision_id
    assert index["latest_revision"] == second.revision_id
    assert [entry["revision_id"] for entry in index["revisions"]] == [
        second.revision_id,
        first.revision_id,
    ]


def test_report_generator_preserves_each_run_and_keeps_latest_aliases(tmp_path, monkeypatch):
    import reporting.app as app

    backup_root = tmp_path / "backups"
    org_dir = backup_root / "Test Org"
    shutil.copytree(Path(__file__).parent / "fixtures", org_dir)
    monkeypatch.setattr(app, "BACKUPS_DIR", str(backup_root))
    monkeypatch.setattr(app, "write_pdf", lambda _html, _pdf: False)

    assert app.main() == 0
    assert app.main() == 0

    index = json.loads((org_dir / "reports" / "index.json").read_text(encoding="utf-8"))
    assert len(index["revisions"]) == 2
    latest = index["latest_revision"]
    latest_dir = org_dir / "reports" / latest
    assert (latest_dir / "manifest.json").exists()
    assert (latest_dir / "report.html").exists()
    assert (latest_dir / "report_exec_summary.html").exists()
    assert (latest_dir / "report_backup_settings.html").exists()
    assert (org_dir / "report.html").read_bytes() == (latest_dir / "report.html").read_bytes()
    assert not (org_dir / "report.pdf").exists()
