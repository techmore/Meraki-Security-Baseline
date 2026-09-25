"""Report-native best-practice checks.

This module intentionally does not import or vendor the upstream
``obrigg/meraki-health-check`` project. It translates artifacts already
collected by this repository into a stable, auditable check schema and makes
collection gaps explicit instead of treating missing data as a pass.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .common import _he, normalize_security_status, safe_float


Check = Dict[str, Any]


def _make_check(
    check_id: str,
    status: str,
    observation: str,
    recommendation: str,
    source_artifact: str,
    coverage: str,
    *,
    scope: str = "organization",
    scope_name: str = "Organization",
) -> Check:
    return {
        "check_id": check_id,
        "scope": scope,
        "scope_name": scope_name,
        "status": status,
        "observation": observation,
        "recommendation": recommendation,
        "source_artifact": source_artifact,
        "coverage": coverage,
    }


def _artifact_available(
    artifact_available: Dict[str, bool], filename: str, fallback: bool
) -> bool:
    value = artifact_available.get(filename)
    return fallback if value is None else bool(value)


def _channel_utilization_check(
    channel_util: Any,
    wireless_device_count: int,
    artifact_available: Dict[str, bool],
) -> Check:
    values: List[float] = []
    for row in channel_util if isinstance(channel_util, list) else []:
        if not isinstance(row, dict):
            continue
        direct_value = safe_float(row.get("utilizationTotal"), None)
        if direct_value is not None:
            values.append(direct_value)
            continue
        bands = row.get("byBand") if isinstance(row.get("byBand"), list) else []
        for band in bands:
            if not isinstance(band, dict):
                continue
            total = band.get("total")
            total_value = (
                safe_float(total.get("percentage"), None)
                if isinstance(total, dict)
                else None
            )
            if total_value is not None:
                values.append(total_value)

    if not values:
        has_artifact = _artifact_available(
            artifact_available, "channel_utilization_by_device.json", False
        )
        observation = (
            "The channel-utilization artifact was collected, but it contained no usable AP samples."
            if has_artifact
            else "Channel-utilization telemetry was not collected for this report."
        )
        coverage = "partial" if has_artifact else "not_collected"
        return _make_check(
            "wireless.channel_utilization",
            "info",
            observation,
            "Collect AP channel-utilization samples before making RF capacity or interference decisions.",
            "channel_utilization_by_device.json",
            coverage,
        )

    high_count = sum(value > 70 for value in values)
    elevated_count = sum(value > 45 for value in values)
    peak = max(values)
    if high_count:
        status = "fail"
        observation = (
            f"{high_count} of {len(values)} measured AP sample(s) exceeded 70% total channel "
            f"utilization; the observed peak was {peak:.1f}%."
        )
        recommendation = (
            "Review airtime consumers, channel width, transmit power, and AP placement on the affected sites."
        )
    elif elevated_count:
        status = "warning"
        observation = (
            f"{elevated_count} of {len(values)} measured AP sample(s) exceeded the 45% review "
            f"threshold; the observed peak was {peak:.1f}%."
        )
        recommendation = "Trend utilization by band and AP before changing RF settings or adding capacity."
    else:
        status = "pass"
        observation = f"{len(values)} measured AP sample(s) were at or below the 45% review threshold."
        recommendation = "Continue periodic utilization sampling so the result reflects busy operating periods."
    return _make_check(
        "wireless.channel_utilization",
        status,
        observation,
        recommendation,
        "channel_utilization_by_device.json",
        "complete",
    )


def _rf_profile_check(
    rf_profiles: Any,
    wireless_device_count: int,
    artifact_available: Dict[str, bool],
) -> Check:
    profiles: List[Dict[str, Any]] = []
    if isinstance(rf_profiles, dict):
        for value in rf_profiles.values():
            if isinstance(value, list):
                profiles.extend(item for item in value if isinstance(item, dict))

    if not profiles:
        has_artifact = _artifact_available(
            artifact_available, "wireless_rf_profiles.json", False
        )
        return _make_check(
            "wireless.rf_profile_baseline",
            "info",
            "RF profile data was not collected or no profiles were available to inspect.",
            "Collect RF profiles and review band steering, minimum bitrates, channel width, and power ranges.",
            "wireless_rf_profiles.json",
            "partial" if has_artifact else "not_collected",
        )

    findings: List[str] = []
    for profile in profiles:
        profile_name = str(profile.get("name") or profile.get("id") or "unnamed profile")
        band_settings = profile.get("apBandSettings")
        if isinstance(band_settings, dict) and band_settings.get("bandSteeringEnabled") is False:
            findings.append(f"{profile_name}: band steering disabled")
        two_four = profile.get("twoFourGhzSettings")
        if isinstance(two_four, dict):
            min_bitrate = safe_float(two_four.get("minBitrate"), None)
            if min_bitrate is not None and min_bitrate <= 11:
                findings.append(f"{profile_name}: 2.4 GHz minimum bitrate is low")
        five = profile.get("fiveGhzSettings")
        if isinstance(five, dict):
            min_bitrate = safe_float(five.get("minBitrate"), None)
            if min_bitrate is not None and min_bitrate <= 12:
                findings.append(f"{profile_name}: 5 GHz minimum bitrate is low")
            width = str(five.get("channelWidth") or "").lower()
            if width in {"20", "20 mhz", "20mhz"}:
                findings.append(f"{profile_name}: 5 GHz channel width is fixed at 20 MHz")

    if findings:
        return _make_check(
            "wireless.rf_profile_baseline",
            "warning",
            f"{len(profiles)} RF profile(s) were collected; {len(findings)} internal review finding(s) were identified.",
            "; ".join(findings[:4])
            + ("; review the remaining findings in the RF profile detail." if len(findings) > 4 else "."),
            "wireless_rf_profiles.json",
            "complete",
        )
    return _make_check(
        "wireless.rf_profile_baseline",
        "pass",
        f"{len(profiles)} RF profile(s) were collected without triggering the internal baseline checks.",
        "Revalidate RF settings against the intended client population and building design.",
        "wireless_rf_profiles.json",
        "complete",
    )


def _firmware_check(
    firmware_upgrades: Any,
    artifact_available: Dict[str, bool],
) -> Check:
    has_artifact = _artifact_available(
        artifact_available, "firmware_upgrades.json", isinstance(firmware_upgrades, list)
    )
    if not has_artifact:
        return _make_check(
            "firmware.upgrade_telemetry",
            "info",
            "Firmware upgrade history was not collected for this report.",
            "Collect current device firmware and stable-release metadata before making lifecycle or upgrade-cycle decisions.",
            "firmware_upgrades.json",
            "not_collected",
        )
    count = (
        len([item for item in firmware_upgrades if isinstance(item, dict)])
        if isinstance(firmware_upgrades, list)
        else 0
    )
    if count:
        return _make_check(
            "firmware.upgrade_telemetry",
            "info",
            f"{count} historical firmware upgrade record(s) were collected, but current-version comparison is not part of this check.",
            "Add current device versions and stable-channel comparison to distinguish upgrade history from upgrade readiness.",
            "firmware_upgrades.json",
            "partial",
        )
    return _make_check(
        "firmware.upgrade_telemetry",
        "info",
        "Firmware upgrade history was collected but contained no records.",
        "Confirm whether the empty history is expected, then collect current device versions and stable-release metadata.",
        "firmware_upgrades.json",
        "partial",
    )


def _switch_port_health_check(
    switch_port_statuses: Any,
    artifact_available: Dict[str, bool],
) -> Check:
    ports = (
        [port for port in switch_port_statuses if isinstance(port, dict)]
        if isinstance(switch_port_statuses, list)
        else []
    )
    if not ports:
        return _make_check(
            "switch.port_health",
            "info",
            "Switch port status telemetry was not collected or contained no port rows.",
            "Collect switch port status and configuration data before assessing port errors, duplex, or negotiation health.",
            "switch_port_statuses.json",
            "not_collected"
            if not _artifact_available(artifact_available, "switch_port_statuses.json", False)
            else "partial",
        )

    hard_errors = 0
    warnings = 0
    half_duplex = 0
    for port in ports:
        errors = port.get("errors") or []
        errors = (
            [errors]
            if isinstance(errors, str)
            else errors
            if isinstance(errors, list)
            else [str(errors)]
        )
        hard_errors += sum("disconnect" not in str(error).lower() for error in errors)
        port_warnings = port.get("warnings") or []
        warnings += len(
            port_warnings if isinstance(port_warnings, list) else [port_warnings]
        )
        if "half" in str(port.get("duplex") or "").lower():
            half_duplex += 1
    if hard_errors:
        status = "fail"
        observation = f"{hard_errors} non-disconnect port error(s) were reported across {len(ports)} port row(s)."
        recommendation = "Review the affected ports and correlate errors with device, cable, and uplink context."
    elif warnings or half_duplex:
        status = "warning"
        observation = (
            f"{warnings} port warning(s) and {half_duplex} half-duplex port(s) were reported; "
            "disconnected ports are not counted as hard errors."
        )
        recommendation = (
            "Investigate negotiation and cabling findings while treating unused/disconnected ports as an operational state unless policy says otherwise."
        )
    else:
        status = "pass"
        observation = f"{len(ports)} switch port row(s) were collected without non-disconnect errors or half-duplex findings."
        recommendation = "Continue sampling port health and retain intentional disconnected-port context in the audit evidence."
    return _make_check(
        "switch.port_health",
        status,
        observation,
        recommendation,
        "switch_port_statuses.json",
        "complete",
    )


def _ap_uplink_check(
    devices_avail: Any,
    switch_port_statuses: Any,
    ap_to_switch: Any,
) -> Check:
    aps = (
        [
            device
            for device in devices_avail
            if isinstance(device, dict)
            and str(device.get("productType") or "").lower() == "wireless"
        ]
        if isinstance(devices_avail, list)
        else []
    )
    if not aps:
        return _make_check(
            "wireless.ap_uplink_negotiation",
            "info",
            "No wireless devices were present in the inventory slice.",
            "Collect AP inventory before assessing AP uplink negotiation.",
            "devices_availabilities.json + lldp_cdp.json + switch_port_statuses.json",
            "complete",
        )

    ports = (
        [port for port in switch_port_statuses if isinstance(port, dict)]
        if isinstance(switch_port_statuses, list)
        else []
    )
    port_index = {
        (str(port.get("switchSerial") or ""), str(port.get("portId") or "")): port
        for port in ports
    }
    mapped = 0
    missing_status = 0
    findings: List[str] = []
    for ap in aps:
        serial = str(ap.get("serial") or "")
        relationship = ap_to_switch.get(serial) if isinstance(ap_to_switch, dict) else None
        if not isinstance(relationship, dict):
            continue
        mapped += 1
        key = (str(relationship.get("switch") or ""), str(relationship.get("port") or ""))
        port = port_index.get(key)
        if not port:
            missing_status += 1
            continue
        speed = str(port.get("speed") or "").lower()
        duplex = str(port.get("duplex") or "").lower()
        if speed.startswith(("10 ", "100 ", "10mb", "100mb")):
            findings.append(f"{serial}: negotiated at {port.get('speed')}")
        if "half" in duplex:
            findings.append(f"{serial}: half duplex")
        errors = port.get("errors") or []
        errors = (
            [errors]
            if isinstance(errors, str)
            else errors
            if isinstance(errors, list)
            else [str(errors)]
        )
        if any("disconnect" not in str(error).lower() for error in errors):
            findings.append(f"{serial}: non-disconnect port error")

    if not mapped or missing_status:
        detail = f"{mapped} of {len(aps)} AP(s) had confirmed LLDP/CDP switch mappings"
        if missing_status:
            detail += f"; {missing_status} mapped AP port(s) lacked matching status telemetry"
        return _make_check(
            "wireless.ap_uplink_negotiation",
            "info",
            detail + ".",
            "Collect complete LLDP/CDP and switch port status artifacts before drawing AP uplink conclusions.",
            "devices_availabilities.json + lldp_cdp.json + switch_port_statuses.json",
            "partial",
        )
    if findings:
        return _make_check(
            "wireless.ap_uplink_negotiation",
            "warning",
            f"{len(findings)} AP uplink negotiation finding(s) were identified across {mapped} mapped AP(s).",
            "; ".join(findings[:4])
            + ("; review the remaining AP uplinks in the switch detail." if len(findings) > 4 else "."),
            "devices_availabilities.json + lldp_cdp.json + switch_port_statuses.json",
            "complete",
        )
    return _make_check(
        "wireless.ap_uplink_negotiation",
        "pass",
        f"{mapped} AP(s) had confirmed switch/port mappings with no low-speed, half-duplex, or non-disconnect error findings.",
        "Keep LLDP/CDP and port-status collection enabled so AP-to-switch attribution stays evidence based.",
        "devices_availabilities.json + lldp_cdp.json + switch_port_statuses.json",
        "complete",
    )


def _alert_history_check(alerts_history: Any, artifact_available: Dict[str, bool]) -> Check:
    has_artifact = _artifact_available(
        artifact_available, "alerts_history.json", isinstance(alerts_history, dict)
    )
    if not has_artifact:
        return _make_check(
            "network.health_alert_history",
            "info",
            "Historical network alert data was not collected.",
            "Collect alert history and distinguish active incidents from historical events in the audit workflow.",
            "alerts_history.json",
            "not_collected",
        )
    alerts = []
    collection_errors = []
    if isinstance(alerts_history, dict):
        for network_id, value in alerts_history.items():
            if isinstance(value, list):
                alerts.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict) and value.get("error"):
                collection_errors.append(str(network_id))
    if collection_errors:
        return _make_check(
            "network.health_alert_history",
            "info",
            f"Alert history collection failed for {len(collection_errors)} network(s); a clean alert result cannot be inferred.",
            "Resolve the alert-history collection failures and regenerate the report before using this check for assurance.",
            "alerts_history.json",
            "partial",
        )
    if alerts:
        return _make_check(
            "network.health_alert_history",
            "warning",
            f"{len(alerts)} historical alert event(s) were collected; history alone does not prove that an incident is active.",
            "Review event timing and recurrence, then correlate with current device and client health before escalating.",
            "alerts_history.json",
            "complete",
        )
    return _make_check(
        "network.health_alert_history",
        "pass",
        "No historical alert events were present in the collected window.",
        "Keep alert-history collection enabled and record the collection window with each report revision.",
        "alerts_history.json",
        "complete",
    )


def _ssid_check(wireless_ssids: Any, artifact_available: Dict[str, bool]) -> Check:
    has_artifact = _artifact_available(
        artifact_available, "wireless_ssids.json", isinstance(wireless_ssids, dict)
    )
    if not has_artifact:
        return _make_check(
            "wireless.ssid_inventory",
            "info",
            "SSID configuration was not collected.",
            "Collect SSID configuration so authentication, isolation, bitrate, and SSID sprawl can be reviewed.",
            "wireless_ssids.json",
            "not_collected",
        )
    values = wireless_ssids.values() if isinstance(wireless_ssids, dict) else []
    rows = [item for values_for_network in values if isinstance(values_for_network, list) for item in values_for_network if isinstance(item, dict)]
    if not rows:
        return _make_check(
            "wireless.ssid_inventory",
            "info",
            "SSID configuration was collected but contained no SSID rows.",
            "Confirm whether the empty result is expected for the organization, then collect SSID configuration again.",
            "wireless_ssids.json",
            "partial",
        )
    enabled = sum(item.get("enabled") is True for item in rows)
    if enabled > 8:
        return _make_check(
            "wireless.ssid_inventory",
            "warning",
            f"{len(rows)} SSID row(s) were collected and {enabled} are enabled; more than eight enabled SSIDs is an internal review threshold.",
            "Review whether each enabled SSID has a current owner, client population, security policy, and business purpose.",
            "wireless_ssids.json",
            "complete",
        )
    return _make_check(
        "wireless.ssid_inventory",
        "pass",
        f"{len(rows)} SSID row(s) were collected and {enabled} are enabled.",
        "Review authentication, isolation, and bitrate settings for each enabled SSID during the wireless deep dive.",
        "wireless_ssids.json",
        "complete",
    )


def _security_check(security_checks: Any) -> Check:
    checks = (
        [check for check in security_checks if isinstance(check, dict)]
        if isinstance(security_checks, list)
        else []
    )
    statuses = [normalize_security_status(check.get("status")) for check in checks]
    failures = statuses.count("fail")
    warnings = statuses.count("warning")
    if not checks:
        return _make_check(
            "security.baseline",
            "info",
            "Security baseline checks were not available for this report.",
            "Collect the security baseline before treating network security posture as assessed.",
            "security_baseline.json",
            "not_collected",
        )
    status = "fail" if failures else "warning" if warnings else "pass"
    return _make_check(
        "security.baseline",
        status,
        f"{len(checks)} security baseline check(s) were evaluated; {failures} failed and {warnings} produced warnings.",
        "Resolve failed or warning baseline checks and retain the detailed security section as the remediation record.",
        "security_baseline.json",
        "complete",
    )


def _not_collected_checks() -> List[Check]:
    return [
        _make_check(
            "governance.admin_mfa_api",
            "info",
            "Administrator inventory, 2FA enforcement, and API-v0 usage were not collected by this pipeline.",
            "Add a redacted administrator/authentication inventory and API-version posture check before declaring governance coverage complete.",
            "Not collected by current pipeline",
            "not_collected",
        ),
        _make_check(
            "switch.control_plane_hardening",
            "info",
            "RSTP/STP, MTU/jumbo-frame, and storm-control settings are not collected by this pipeline.",
            "Add read-only collection for control-plane and Layer-2 hardening settings, with explicit platform applicability.",
            "Not collected by current pipeline",
            "not_collected",
        ),
        _make_check(
            "switch.packet_counter_thresholds",
            "info",
            "Packet-counter thresholds and time-series error trends are not collected as a best-practice check.",
            "Add time-windowed packet/error counters so transient events can be separated from persistent port problems.",
            "Not collected by current pipeline",
            "not_collected",
        ),
    ]


def build_best_practice_checks(
    *,
    networks: Any,
    devices_avail: Any,
    channel_util: Any,
    rf_profiles: Any,
    firmware_upgrades: Any,
    switch_port_statuses: Any,
    security_checks: Any,
    alerts_history: Any,
    wireless_ssids: Any,
    ap_to_switch: Any,
    artifact_available: Optional[Dict[str, bool]] = None,
) -> List[Check]:
    """Build stable report-native best-practice checks from backup artifacts."""
    del networks  # Reserved for future per-network check scopes.
    availability = artifact_available or {}
    wireless_device_count = (
        sum(
            1
            for device in devices_avail
            if isinstance(device, dict)
            and str(device.get("productType") or "").lower() == "wireless"
        )
        if isinstance(devices_avail, list)
        else 0
    )
    checks = [
        _channel_utilization_check(channel_util, wireless_device_count, availability),
        _rf_profile_check(rf_profiles, wireless_device_count, availability),
        _firmware_check(firmware_upgrades, availability),
        _switch_port_health_check(switch_port_statuses, availability),
        _ap_uplink_check(devices_avail, switch_port_statuses, ap_to_switch),
        _alert_history_check(alerts_history, availability),
        _ssid_check(wireless_ssids, availability),
        _security_check(security_checks),
    ]
    checks.extend(_not_collected_checks())
    return checks


def _status_label(status: str) -> str:
    return {
        "pass": "Pass",
        "fail": "Fail",
        "warning": "Warning",
        "info": "Not evaluated",
    }.get(status, "Not evaluated")


def _coverage_label(coverage: str) -> str:
    return {
        "complete": "Collected",
        "partial": "Partial",
        "not_collected": "Not collected",
    }.get(coverage, "Not collected")


def render_best_practice_section(checks: List[Check]) -> str:
    """Render the best-practice adapter as a subsection of Network Overview."""
    if not checks:
        return ""
    counts = {
        status: sum(check.get("status") == status for check in checks)
        for status in ("pass", "warning", "fail", "info")
    }
    summary = (
        '<div class="kpi-row best-practice-summary">'
        f'<div class="kpi"><div class="kpi-label">Checks Passed</div><div class="kpi-value">{counts["pass"]}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Review Findings</div><div class="kpi-value">{counts["warning"] + counts["fail"]}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Not Evaluated</div><div class="kpi-value">{counts["info"]}</div></div>'
        f'<div class="kpi"><div class="kpi-label">Total Checks</div><div class="kpi-value">{len(checks)}</div></div>'
        "</div>"
    )
    rows = []
    for check in checks:
        status = str(check.get("status") or "info")
        status_class = {
            "pass": "check-pass",
            "fail": "check-fail",
            "warning": "check-warning",
            "info": "check-unknown",
        }.get(status, "check-unknown")
        rows.append(
            "<tr>"
            f'<td>{_he(check.get("check_id", ""))}</td>'
            f'<td>{_he(check.get("scope_name", "Organization"))}</td>'
            f'<td class="{status_class}">{_he(_status_label(status))}</td>'
            f'<td>{_he(_coverage_label(str(check.get("coverage") or "not_collected")))}</td>'
            f'<td>{_he(check.get("observation", ""))}</td>'
            f'<td>{_he(check.get("recommendation", ""))}</td>'
            f'<td>{_he(check.get("source_artifact", ""))}</td>'
            "</tr>"
        )
    gaps = [
        check
        for check in checks
        if check.get("coverage") != "complete" or check.get("status") == "info"
    ]
    gap_rows = "".join(
        f'<li><strong>{_he(check.get("check_id", ""))}</strong>: {_he(check.get("observation", ""))}</li>'
        for check in gaps
    )
    return f'''
      <div id="best-practice-coverage" class="best-practice-block">
        <h3>Best-Practice Coverage</h3>
        <p class="section-note">This report-native adapter is informed by
          <a href="https://github.com/obrigg/meraki-health-check">obrigg/meraki-health-check</a>,
          but does not execute or vendor upstream code. Thresholds below are internal triage signals,
          not authoritative Meraki or Cisco guidance. Missing telemetry is shown as
          <strong>Not evaluated</strong> rather than a passing result.</p>
        {summary}
        <table class="data">
          <thead><tr><th>Check</th><th>Scope</th><th>Status</th><th>Coverage</th>
            <th>Observation</th><th>Recommendation</th><th>Source Artifact</th></tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
        <h4>Collection Gaps</h4>
        <ul class="best-practice-gaps">{gap_rows}</ul>
      </div>
    '''
