"""Immutable report revision storage and metadata.

Report aliases are useful for existing automation, but they are not an audit
history. This module keeps each generated report set in a unique directory and
records the inputs and variants that produced it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

_STABLE_REPORT_NAMES = {
    "report.html",
    "report.pdf",
    "report_exec_summary.html",
    "report_exec_summary.pdf",
    "report_backup_settings.html",
    "report_backup_settings.pdf",
}
_ARCHIVED_REPORT_RE = re.compile(
    r"(?:_report|_exec_summary_report|_backup_settings_report)\.(?:html|pdf)$"
)

VARIANT_FILENAMES = {
    "full": {"html": "report.html", "pdf": "report.pdf"},
    "exec": {"html": "report_exec_summary.html", "pdf": "report_exec_summary.pdf"},
    "backup": {"html": "report_backup_settings.html", "pdf": "report_backup_settings.pdf"},
}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_generated_report(name: str) -> bool:
    return name in _STABLE_REPORT_NAMES or bool(_ARCHIVED_REPORT_RE.search(name))


def fingerprint_inputs(org_dir: str) -> str:
    """Return a stable hash of report inputs, excluding generated reports."""
    root = Path(org_dir)
    digest = hashlib.sha256()
    if not root.is_dir():
        return f"sha256:{digest.hexdigest()}"

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == "reports":
            continue
        if path.name == ".DS_Store" or _is_generated_report(path.name):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write_text(path: Path, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2) + "\n")


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_index(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as source:
            value = json.load(source)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Cannot read report revision index %s: %s", path, exc)
        return {}


class ReportRevision:
    """Collect one immutable set of report outputs and its manifest."""

    def __init__(
        self,
        org_dir: str,
        org_name: str,
        generated_at: datetime,
        report_version: str,
        backup_schema_version: Optional[int],
        input_fingerprint: str,
    ) -> None:
        self.org_dir = Path(org_dir)
        self.reports_dir = self.org_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.generated_at = _as_utc(generated_at)
        base_id = self.generated_at.strftime("%Y%m%dT%H%M%S%fZ")
        self.revision_id = base_id
        suffix = 1
        while (self.reports_dir / self.revision_id).exists():
            self.revision_id = f"{base_id}-{suffix:02d}"
            suffix += 1
        self.revision_dir = self.reports_dir / self.revision_id
        self.revision_dir.mkdir()
        self.manifest: Dict[str, Any] = {
            "revision_id": self.revision_id,
            "generated_at": self.generated_at.isoformat(timespec="microseconds"),
            "org_name": org_name,
            "report_version": report_version,
            "backup_schema_version": backup_schema_version,
            "input_fingerprint": input_fingerprint,
            "status": "in_progress",
            "variants": {},
        }

    def write_html(self, variant: str, html: str) -> Path:
        filenames = VARIANT_FILENAMES[variant]
        path = self.revision_dir / filenames["html"]
        atomic_write_text(path, html)
        self.manifest["variants"].setdefault(variant, {})["html"] = filenames["html"]
        return path

    def pdf_path(self, variant: str) -> Path:
        return self.revision_dir / VARIANT_FILENAMES[variant]["pdf"]

    def record_pdf(self, variant: str, available: bool) -> Optional[Path]:
        filenames = VARIANT_FILENAMES[variant]
        entry = self.manifest["variants"].setdefault(variant, {})
        if available:
            entry["pdf"] = filenames["pdf"]
            return self.revision_dir / filenames["pdf"]
        entry["pdf"] = None
        entry["pdf_status"] = "unavailable"
        return None

    def record_paths(
        self,
        variant: str,
        html_archive: Path,
        html_alias: Path,
        pdf_archive: Optional[Path] = None,
        pdf_alias: Optional[Path] = None,
    ) -> None:
        entry = self.manifest["variants"].setdefault(variant, {})
        entry["html_archive"] = str(html_archive.relative_to(self.org_dir))
        entry["html_alias"] = str(html_alias.relative_to(self.org_dir))
        if pdf_archive is not None:
            entry["pdf_archive"] = str(pdf_archive.relative_to(self.org_dir))
        if pdf_alias is not None:
            entry["pdf_alias"] = str(pdf_alias.relative_to(self.org_dir))

    def finalize(
        self,
        status: str = "complete",
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        self.manifest["status"] = status
        if error:
            self.manifest["error"] = error
        manifest_path = self.revision_dir / "manifest.json"
        atomic_write_json(manifest_path, self.manifest)

        index_path = self.reports_dir / "index.json"
        index = _load_index(index_path)
        revisions = index.get("revisions") if isinstance(index.get("revisions"), list) else []
        summary = {
            "revision_id": self.manifest["revision_id"],
            "generated_at": self.manifest["generated_at"],
            "report_version": self.manifest["report_version"],
            "backup_schema_version": self.manifest["backup_schema_version"],
            "input_fingerprint": self.manifest["input_fingerprint"],
            "status": self.manifest["status"],
            "path": f"reports/{self.revision_id}",
            "variants": self.manifest["variants"],
        }
        if error:
            summary["error"] = error
        revisions = [
            existing
            for existing in revisions
            if isinstance(existing, dict) and existing.get("revision_id") != self.revision_id
        ]
        revisions.insert(0, summary)
        atomic_write_json(
            index_path,
            {
                "latest_revision": self.revision_id,
                "updated_at": self.generated_at.isoformat(timespec="microseconds"),
                "revisions": revisions,
            },
        )
        return self.manifest
