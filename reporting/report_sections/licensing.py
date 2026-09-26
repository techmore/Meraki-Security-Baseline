"""Licensing summary report section."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ..common import _he, parse_datetime, safe_int


def build_licensing_section(licensing_data: Any, *, artifact_available: bool) -> str:
    """Render organization-scoped licensing status and collection coverage."""
    licensing_mode = (
        licensing_data.get("licenseMode")
        if isinstance(licensing_data, dict)
        else None
    )
    coverage_ok = int(
        artifact_available
        and isinstance(licensing_data, dict)
        and bool(licensing_data)
        and not licensing_data.get("error")
    )
    raw_licenses = (
        licensing_data.get("licenses", [])
        if isinstance(licensing_data, dict)
        else []
    )
    if not isinstance(raw_licenses, list):
        raw_licenses = []

    rows = []
    for license_record in raw_licenses:
        if not isinstance(license_record, dict):
            continue
        counts = license_record.get("counts") or []
        if isinstance(counts, list) and counts:
            license_type = ", ".join(
                f"{count.get('count', '?')}× {count.get('model', '?')}"
                for count in counts
                if isinstance(count, dict)
            )
            if not license_type:
                license_type = "—"
        else:
            license_type = (
                license_record.get("licenseType")
                or license_record.get("productType")
                or "—"
            )

        is_expired = (
            license_record.get("expired") is True
            or str(license_record.get("status", "")).lower()
            in ("expired", "inactive")
        )
        if license_record.get("invalidated"):
            status = "Invalidated"
            status_class = "warning"
        elif is_expired:
            status = "Expired"
            status_class = "fail"
        else:
            status = license_record.get("status") or "Active"
            status_class = "pass"

        expiration = (
            license_record.get("expirationDate")
            or license_record.get("expiration")
            or "—"
        )
        if (
            expiration == "—"
            and license_record.get("startedAt")
            and license_record.get("duration")
        ):
            try:
                started = parse_datetime(license_record["startedAt"])
                duration = safe_int(license_record.get("duration"), None)
                if started is None or duration is None:
                    raise ValueError("invalid license timestamp or duration")
                expiration = (started + timedelta(days=duration)).strftime("%Y-%m-%d")
            except (OverflowError, TypeError, ValueError):
                pass

        key = _he(str(license_record.get("key") or "—"))
        rows.append(
            "<tr>"
            f"<td><code style='font-size:9px'>{key}</code></td>"
            f"<td>{_he(str(license_type))}</td>"
            f'<td><span class="check-{status_class}">{_he(str(status))}</span></td>'
            f"<td>{_he(str(expiration))}</td>"
            "</tr>"
        )

    active_count = sum(
        1
        for license_record in raw_licenses
        if isinstance(license_record, dict)
        and not license_record.get("invalidated")
        and (
            license_record.get("expired") is False
            or str(license_record.get("status", "")).lower()
            in ("ok", "active", "in compliance")
        )
    )
    expired_count = sum(
        1
        for license_record in raw_licenses
        if isinstance(license_record, dict)
        and (
            license_record.get("expired") is True
            or str(license_record.get("status", "")).lower()
            in ("expired", "inactive")
        )
    )

    if isinstance(licensing_data, dict) and licensing_data.get("error"):
        summary_note = (
            "<strong>Licensing data unavailable</strong> — the API returned an error for this "
            "organization. Verify that the API key has <em>read</em> access to the licensing "
            "endpoints and re-run the backup pipeline."
        )
    elif licensing_mode:
        critical_class = "text-crit" if expired_count else ""
        summary_note = (
            f"This organization uses the <strong>{_he(str(licensing_mode))}</strong> licensing model. "
            f"Licensing is tracked at the organization level — {len(raw_licenses)} license key(s) on "
            f"record: <strong>{active_count} active</strong>, "
            f"<strong class='{critical_class}'>{expired_count} expired</strong>. "
            "Meraki co-term licenses do not map 1:1 to individual devices or networks; Dashboard "
            "determines overall compliance from the combined pool of active seat counts."
        )
    else:
        summary_note = (
            "Licensing scope could not be determined from the collected payload. "
            "This section should be treated as partial until the pipeline is validated against "
            "the <code>/organizations/{id}/licenses/overview</code> endpoint."
        )

    if rows:
        licensing_table = f"""
        <table class="data dense">
          <thead>
            <tr>
              <th>License Key</th>
              <th>Coverage (Model / Count)</th>
              <th>Status</th>
              <th>Expiration</th>
            </tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
        </table>"""
    elif artifact_available:
        licensing_table = """
        <div class="summary-card">
          <div class="summary-body">
            No license keys were returned by the Meraki API for this organization.
            If this organization uses <strong>per-device licensing</strong>, verify that
            <code>GET /organizations/{id}/licenses</code> is returning data and that the
            backup pipeline is storing it correctly. If the org is managed under an
            Enterprise Agreement or co-term umbrella, licensing may be tracked at the
            parent organization level.
          </div>
        </div>"""
    else:
        licensing_table = """
        <div class="summary-card">
          <div class="summary-body">
            No <code>licensing.json</code> was found in this backup. Ensure the backup
            pipeline calls <code>GET /organizations/{id}/licenses</code> and stores the
            result before generating reports.
          </div>
        </div>"""

    return f"""
    <section id="licensing" class="report-section">
      <h2>10. Licensing Summary</h2>
      <p>Cisco Meraki devices require active cloud-managed licenses to maintain Dashboard
         visibility and security feature enforcement. Expired licenses can cause devices to
         enter limited mode. Review expirations and plan renewals at least 90 days in advance.</p>
      <div class="summary-card">
        <div class="summary-title">Licensing Status &amp; Scope</div>
        <div class="summary-body">
          {summary_note}
          <br><br>
          Org backup coverage: <strong>{coverage_ok}/1</strong> org(s) with
          licensing data collected.
        </div>
      </div>
      {licensing_table}
      <div class="summary-card">
        <div class="summary-title">Licensing Best Practices</div>
        <div class="summary-body">
          <ul>
            <li>Set Dashboard expiry alerts at 90, 60, and 30 days before license end</li>
            <li>Confirm device count in Dashboard matches physical inventory to avoid
                under-licensing surprises at renewal</li>
            <li>Ensure Advanced Security (AMP, IDS/IPS) tier licenses are applied to all
                MX appliances — base licenses do not include threat prevention features</li>
            <li>Consider co-termination or EA consolidation to reduce renewal complexity
                across multiple license key expiry dates</li>
          </ul>
        </div>
      </div>
    </section>
    """
