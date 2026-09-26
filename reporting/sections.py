import math
import os

from typing import Any, Dict, List, Optional, Tuple

from .common import (
    _describe_port_neighbor,
    _describe_vlan_mode,
    _format_usage_kb,
    _he,
    _inline_md,
    _is_sfp_like_port,
    _port_group_label,
    _port_heat_label,
    _port_heat_score,
    _port_role_label,
    _port_role_short,
    _port_sort_key,
    _speed_label,
    _switch_anchor,
    _build_switch_link_narrative,
    render_section,
    safe_float,
    safe_int,
)
from .topology import _build_topology_facts

def _render_switch_port_grid(
    ports: List[Dict[str, Any]],
    port_configs: Optional[Dict[str, Dict[str, Any]]] = None,
    serial_to_dev: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    if not ports:
        return '<div class="switch-detail-grid-empty">No port telemetry available.</div>'
    grouped: Dict[str, List[str]] = {}
    counts = {"uplink": 0, "downlink": 0, "endpoint": 0, "unused": 0}
    port_configs = port_configs or {}
    serial_to_dev = serial_to_dev or {}
    for port in sorted(ports, key=lambda item: _port_sort_key(item.get("portId"))):
        port_id = str(port.get("portId") or "?")
        status = str(port.get("status") or "").lower()
        speed = str(port.get("speed") or "")
        errors = port.get("errors") or []
        if isinstance(errors, str):
            errors = [errors]
        role = _port_role_label(port, port_configs.get(port_id), serial_to_dev)
        if errors:
            cls = "issue"
        elif port.get("isUplink"):
            cls = "uplink"
        elif "disconnected" in status or "not connected" in status or not status:
            cls = "down"
        elif speed.startswith("100 ") or speed.startswith("10 "):
            cls = "warn"
        elif (port.get("poe") or {}).get("isAllocated"):
            cls = "poe"
        else:
            cls = "ok"
        if cls == "uplink":
            counts["uplink"] += 1
        elif role == "Downlink":
            counts["downlink"] += 1
        elif cls == "down":
            counts["unused"] += 1
        else:
            counts["endpoint"] += 1
        speed_label = _speed_label(speed)
        speed_cls = ""
        if speed_label in ("2.5G", "5G"):
            speed_cls = "speed-mgig"
        elif speed_label in ("10G", "25G"):
            speed_cls = "speed-uplink"
        sfp_cls = " sfp-port" if _is_sfp_like_port(port_id) else ""
        grouped.setdefault(_port_group_label(port_id), []).append(
            f'<div class="switch-port-cell {cls}{sfp_cls} {speed_cls}" title="{_he(port_id)} - {_he(role)} - {_he(speed or "Unknown")}">'
            f'<span class="switch-port-num">{_he(port_id)}</span>'
            f'<span class="switch-port-meta">{_he(_port_role_short(role))} {_he(speed_label) if status and cls != "down" else ""}</span>'
            f"</div>"
        )
    summary = (
        '<div class="switch-port-summary">'
        f'<span><strong>{counts["uplink"]}</strong> uplink</span>'
        f'<span><strong>{counts["downlink"]}</strong> downlink</span>'
        f'<span><strong>{counts["endpoint"]}</strong> edge</span>'
        f'<span><strong>{counts["unused"]}</strong> down</span>'
        '</div>'
    )
    groups_html = []
    for label, cells in grouped.items():
        midpoint = max(1, math.ceil(len(cells) / 2))
        group_kind = "SFP / Module" if label != "Front Panel" else "Front Panel"
        row_one = "".join(cells[:midpoint])
        row_two = "".join(cells[midpoint:])
        row_two_html = f'<div class="switch-port-row">{row_two}</div>' if row_two else ""
        groups_html.append(
            f'<div class="switch-port-group">'
            f'<div class="switch-port-group-title">{_he(label)} <span class="switch-port-group-kind">{_he(group_kind)}</span></div>'
            f'<div class="switch-port-face">'
            f'<div class="switch-port-row">{row_one}</div>'
            f'{row_two_html}'
            f"</div></div>"
        )
    return summary + "".join(groups_html)


def _build_client_analysis_section(wireless_clients: List[Dict[str, Any]]) -> str:
    """Render wireless-client distributions from normalized client records."""
    ssid_counts: Dict[str, int] = {}
    os_counts: Dict[str, int] = {}
    vlan_counts: Dict[str, int] = {}
    rssi_buckets = {
        "Excellent (>-60)": 0,
        "Good (-60 to -70)": 0,
        "Fair (-70 to -80)": 0,
        "Poor (<-80)": 0,
    }

    for client in wireless_clients:
        ssid = str(client.get("ssid") or "Unknown")
        ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1

        client_os = str(
            client.get("os") or client.get("deviceTypePrediction") or "Unknown"
        )
        os_counts[client_os] = os_counts.get(client_os, 0) + 1

        vlan = str(client.get("vlan") or client.get("vlanId") or "—")
        vlan_counts[vlan] = vlan_counts.get(vlan, 0) + 1

        rssi = client.get("rssi")
        if rssi is not None:
            try:
                rssi_value = int(rssi)
                if rssi_value > -60:
                    rssi_buckets["Excellent (>-60)"] += 1
                elif rssi_value >= -70:
                    rssi_buckets["Good (-60 to -70)"] += 1
                elif rssi_value >= -80:
                    rssi_buckets["Fair (-70 to -80)"] += 1
                else:
                    rssi_buckets["Poor (<-80)"] += 1
            except (ValueError, TypeError):
                pass

    def top_rows(values: Dict[str, int], limit: int = 10) -> str:
        rows = sorted(values.items(), key=lambda item: item[1], reverse=True)[:limit]
        return "".join(
            f"<tr><td>{_he(label)}</td><td>{count}</td></tr>"
            for label, count in rows
        )

    rssi_rows = "".join(
        f"<tr><td>{_he(bucket)}</td><td>{count}</td></tr>"
        for bucket, count in rssi_buckets.items()
    )
    if wireless_clients:
        client_tables = f"""
        <h3>Clients by SSID</h3>
        <table class="data">
          <thead><tr><th>SSID</th><th>Client Count</th></tr></thead>
          <tbody>{top_rows(ssid_counts)}</tbody>
        </table>

        <h3>Clients by OS / Device Type</h3>
        <table class="data">
          <thead><tr><th>OS / Device Type</th><th>Client Count</th></tr></thead>
          <tbody>{top_rows(os_counts)}</tbody>
        </table>

        <h3>Clients by VLAN</h3>
        <table class="data">
          <thead><tr><th>VLAN</th><th>Client Count</th></tr></thead>
          <tbody>{top_rows(vlan_counts)}</tbody>
        </table>

        <h3>Signal Strength Distribution</h3>
        <table class="data">
          <thead><tr><th>RSSI Range</th><th>Client Count</th></tr></thead>
          <tbody>{rssi_rows}</tbody>
        </table>
        """
    else:
        client_tables = """
        <div class="summary-card">
          <div class="summary-body">No wireless client data available in this backup.</div>
        </div>"""

    return f"""
    <section id="client-analysis" class="report-section">
      <h2>15. Client Analysis</h2>
      <p>Analysis of <strong>{len(wireless_clients)}</strong> wireless client record(s) captured
         in this backup. Wired client detail requires switch port client data which is not
         collected in the current pipeline.</p>
      {client_tables}
    </section>
    """


_UNIFI_MODEL_MAP = {
    # MX appliances -> UniFi Dream Machine / Cloud Gateway
    "MX68": ("UDM SE", 1_299, 649),
    "MX75": ("UCG-Ultra", 599, 299),
    "MX85": ("UDM Pro Max", 1_999, 899),
    "MX95": ("UDM Pro Max", 1_999, 899),
    "MX105": ("UDM Pro SE", 1_499, 699),
    "MX250": ("UCG-Enterprise", 3_999, 1_799),
    "MX450": ("UCG-Enterprise", 3_999, 1_799),
    # MS switches -> UniFi USW Pro / Aggregation
    "MS120": ("USW Lite 16 PoE", 349, 179),
    "MS125": ("USW Pro 24 PoE", 849, 549),
    "MS210": ("USW Pro 24", 649, 399),
    "MS220": ("USW Pro 24", 649, 399),
    "MS225": ("USW Pro 24 PoE", 849, 549),
    "MS250": ("USW Pro 48 PoE", 1_299, 799),
    "MS320": ("USW Pro Aggregation", 999, 699),
    "MS350": ("USW Enterprise 24 PoE", 1_299, 899),
    "MS390": ("USW Enterprise 48 PoE", 1_799, 1_199),
    "MS410": ("USW Aggregation", 799, 499),
    "MS420": ("USW Aggregation", 799, 499),
    "MS425": ("USW Pro Aggregation", 999, 699),
    "MS450": ("USW Pro Aggregation", 999, 699),
    # MR access points -> UniFi U6 / U7 series
    "MR18": ("U6 Lite", 199, 109),
    "MR20": ("U6 Lite", 199, 109),
    "MR28": ("U6 Mesh", 199, 129),
    "MR30": ("U6 LR", 299, 169),
    "MR33": ("U6 LR", 299, 169),
    "MR36": ("U6 Pro", 349, 189),
    "MR42": ("U6 Pro", 349, 189),
    "MR44": ("U7 Pro", 499, 299),
    "MR46": ("U7 Pro", 499, 299),
    "MR46E": ("U7 Pro Max", 699, 449),
    "MR52": ("U7 Pro Max", 699, 449),
    "MR55": ("U7 Pro Max", 699, 449),
    "MR56": ("U7 Pro Max", 699, 449),
    "MR57": ("U7 Pro Max", 699, 449),
    "MR70": ("U6 Mesh", 199, 129),
    "MR74": ("U6 Mesh Pro", 299, 179),
    "MR76": ("U7 Outdoor", 499, 299),
    "MR84": ("U7 Pro Max", 699, 449),
    "MR86": ("U7 Outdoor", 499, 299),
}


def _build_unifi_comparison_section(
    top_models: List[Tuple[str, int]],
    eol_models: List[str],
) -> str:
    """Render the planning-only UniFi hardware comparison."""
    rows: List[str] = []
    meraki_total = 0
    unifi_total = 0
    eol_swap_meraki = 0
    eol_swap_unifi = 0
    mapped_models = 0
    eol_model_names = {str(model).upper() for model in eol_models}

    for model, count in top_models:
        model_name = str(model)
        model_upper = model_name.upper()
        matching_keys = [
            key for key in _UNIFI_MODEL_MAP if model_upper.startswith(key)
        ]
        if not matching_keys:
            continue
        # Specific variants such as MR46E must win over their shorter family prefix.
        map_key = max(matching_keys, key=len)
        unifi_name, meraki_price, unifi_price = _UNIFI_MODEL_MAP[map_key]
        is_eol = model_upper in eol_model_names
        meraki_row_total = meraki_price * count
        unifi_row_total = unifi_price * count
        meraki_total += meraki_row_total
        unifi_total += unifi_row_total
        mapped_models += 1
        if is_eol:
            eol_swap_meraki += meraki_row_total
            eol_swap_unifi += unifi_row_total
        rows.append(
            "<tr>"
            f"<td>{_he(model_name)}</td>"
            f"<td>{count}</td>"
            f"<td>{_he(unifi_name)}</td>"
            f"<td>${meraki_price:,}</td>"
            f"<td>${unifi_price:,}</td>"
            f"<td>${meraki_row_total:,}</td>"
            f"<td>${unifi_row_total:,}</td>"
            f'<td>{"⚠ EOL" if is_eol else "—"}</td>'
            "</tr>"
        )

    savings = meraki_total - unifi_total
    savings_pct = round(100 * savings / meraki_total) if meraki_total else 0
    if rows:
        hardware_table = f"""
        <table class="data dense">
          <thead>
            <tr>
              <th>Meraki Model</th><th>Qty</th><th>UniFi Equivalent</th>
              <th>Meraki Unit (est.)</th><th>UniFi Unit (est.)</th>
              <th>Meraki Total</th><th>UniFi Total</th><th>Flag</th>
            </tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
          <tfoot>
            <tr>
              <td colspan="5"><strong>Hardware totals (mapped devices only)</strong></td>
              <td><strong>${meraki_total:,}</strong></td>
              <td><strong>${unifi_total:,}</strong></td>
              <td><strong>−{savings_pct}%</strong></td>
            </tr>
          </tfoot>
        </table>"""
    else:
        hardware_table = (
            '<div class="summary-card"><div class="summary-body">'
            "No device models in this inventory matched the UniFi comparison table. "
            "Verify model names in inventory_summary.json."
            "</div></div>"
        )

    if eol_models:
        eol_summary = _he(", ".join(eol_models[:4]))
        recommendation = (
            "<strong>EOL hardware refresh is the most pressing decision.</strong> The "
            f"{len(eol_models)} EOL model(s) identified ({eol_summary}) represent the "
            "highest-risk devices. Whether they are refreshed with new Meraki hardware "
            "or replaced with an alternative platform, they should exit production "
            "within the next 12–18 months."
        )
    else:
        recommendation = (
            "<strong>No EOL hardware was flagged.</strong> The refresh decision is less "
            "time-pressured."
        )
    eol_cost_summary = (
        "· EOL devices (hardware only): Meraki "
        f"<strong>${eol_swap_meraki:,}</strong> vs UniFi "
        f"<strong>${eol_swap_unifi:,}</strong>"
        if eol_swap_meraki
        else ""
    )

    return f"""
    <section id="unifi-comparison" class="report-section">
      <h2>17. UniFi Comparison &amp; Refresh Planning</h2>
      <p>This section provides a heuristic cost comparison between the current Meraki
         environment and a notional UniFi replacement. It is a planning estimate only — not
         a procurement quote or a recommendation to replace. Prices are approximate 2025–2026
         street/MSRP estimates and will vary by reseller, volume, and configuration.
         <strong>Always validate with current partner pricing before presenting externally.</strong></p>

      <div class="summary-card">
        <div class="summary-title">Planning Summary</div>
        <div class="summary-body">
          Mapped devices: {mapped_models} model type(s)
          · Meraki hardware estimate: <strong>${meraki_total:,}</strong>
          · UniFi hardware estimate: <strong>${unifi_total:,}</strong>
          · Estimated hardware delta: <strong>${savings:,} ({savings_pct}% lower)</strong>
          {eol_cost_summary}
          <br><br>
          <em>Note: Meraki hardware prices above do not include annual licensing (typically
          $X–$Y per device per year for Enterprise tier). UniFi has no recurring per-device
          subscription fees beyond optional UniFi OS Cloud (optional, ~$29/mo for remote management).</em>
        </div>
      </div>

      {hardware_table}

      <h3>Licensing &amp; Support Model Comparison</h3>
      <table class="data">
        <thead>
          <tr><th>Factor</th><th>Cisco Meraki</th><th>Ubiquiti UniFi</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Licensing model</strong></td>
            <td>Mandatory annual per-device license (co-term or Enterprise Agreement).
                Devices enter limited mode without active license.</td>
            <td>No per-device license fees. Hardware purchased once. Optional cloud
                management subscription (~$29/mo).</td>
          </tr>
          <tr>
            <td><strong>Management platform</strong></td>
            <td>Meraki Dashboard (cloud-only SaaS). Full-featured, zero on-prem required.
                Dashboard unavailable without internet or during Meraki outages.</td>
            <td>UniFi Network Application (self-hosted on UDM or Linux server, or UniFi Cloud).
                Can operate fully on-prem without internet dependency.</td>
          </tr>
          <tr>
            <td><strong>Security features</strong></td>
            <td>AMP, IDS/IPS, content filtering, SD-WAN, AutoVPN — Enterprise tier required
                for full threat protection.</td>
            <td>IDS/IPS (Teleport, basic), content filtering (limited), no SD-WAN.
                Security depth is lower on MX-equivalent features.</td>
          </tr>
          <tr>
            <td><strong>Wireless</strong></td>
            <td>Strong enterprise RF management, auto-channel, airtime fairness, band steering.
                Mature roaming (802.11r/k/v) across all current MR models.</td>
            <td>Strong Wi-Fi 6/6E hardware. RF management improving but less mature than Meraki
                in dense multi-AP environments. Roaming support improving in newer firmware.</td>
          </tr>
          <tr>
            <td><strong>Switching</strong></td>
            <td>Full cloud-managed stack with per-port telemetry, STP, ACLs, QoS, LACP.
                Excellent visibility. PoE budget management strong.</td>
            <td>Comparable L2/L3 feature set at lower cost. STP, ACLs, LACP, VLAN, QoS.
                Less real-time telemetry granularity in cloud view.</td>
          </tr>
          <tr>
            <td><strong>Lifecycle / support</strong></td>
            <td>Firmware delivered via Dashboard; end-of-support dates published.
                TAC support included with license. Hardware warranty separate.</td>
            <td>Firmware self-managed (auto-update configurable). Community forums primary
                support channel; hardware warranty typically 1 year.</td>
          </tr>
          <tr>
            <td><strong>Migration complexity</strong></td>
            <td colspan="2">Full replacement requires re-cabling where physical form factor differs,
                VLAN/SSID reconfiguration, staff retraining, and thorough parallel-run testing.
                Budget 20–30% of hardware cost for professional services on a full migration.</td>
          </tr>
        </tbody>
      </table>

      <h3>Recommendation</h3>
      <div class="summary-card">
        <div class="summary-body">
          {recommendation}
          <br><br>
          If the primary driver is licensing cost reduction, a phased migration starting with
          access switching and APs (lowest migration complexity) can deliver savings without
          replacing edge appliances. If operational simplicity and feature parity are priorities,
          retaining Meraki at the edge and evaluating UniFi for access-layer devices is a
          common hybrid approach.
          <br><br>
          Any migration decision should be preceded by a formal RFP or vendor evaluation
          incorporating current pricing, professional services scope, and a pilot deployment.
        </div>
      </div>
    </section>
    """


def _build_switch_detail_section(
    devices_by_network: Dict[str, Dict[str, Any]],
    lldp_cdp: Dict[str, Any],
    switch_port_statuses_by_switch: Dict[str, Any],
    switch_port_configs_by_switch: Dict[str, Any],
    poe_by_serial: Dict[str, Dict[str, Any]],
    port_issues_by_switch: Dict[str, List[Dict[str, Any]]],
) -> Tuple[str, List[Tuple[str, str]]]:
    switch_entries: List[Tuple[str, str, str, str]] = []
    for net_data in sorted(devices_by_network.values(), key=lambda item: item["name"]):
        for dev in sorted(
            [d for d in net_data["devices"] if d.get("productType") == "switch"],
            key=lambda item: item.get("name") or item.get("serial") or "",
        ):
            switch_entries.append(
                (
                    net_data["name"],
                    dev.get("serial") or "",
                    dev.get("name") or dev.get("model") or dev.get("serial") or "Switch",
                    dev.get("model") or "",
                )
            )

    toc_items = [(_switch_anchor(serial, name), f"{site} - {name}") for site, serial, name, _ in switch_entries]
    if not switch_entries:
        return (
            """
    <section id="switch-deep-dive" class="report-section">
      <h2>16. Switch Deep Dive</h2>
      <div class="summary-card"><div class="summary-body">No switch inventory was available for detailed port-level analysis.</div></div>
    </section>
    """,
            toc_items,
        )

    all_devices = [
        device
        for net_data in devices_by_network.values()
        for device in net_data.get("devices", [])
        if isinstance(device, dict)
    ]
    serial_to_dev, status_by_switch, parent_of, children_of, edge_counts = _build_topology_facts(
        all_devices, lldp_cdp, switch_port_statuses_by_switch
    )

    section_parts = [
        """
    <section id="switch-deep-dive" class="report-section">
      <h2>16. Switch Deep Dive</h2>
      <p>Port-level views for each MS switch, including link status, negotiated speed, traffic, PoE draw, inferred connected device, and upstream/downstream placement in the switching tree.</p>
    </section>
    """
    ]

    for site_name, serial, switch_name, model in switch_entries:
        ports = sorted(
            status_by_switch.get(serial, {}).values(),
            key=lambda item: (
                0,
                int(str(item.get("portId", "0"))) if str(item.get("portId", "")).isdigit() else 0,
                str(item.get("portId") or ""),
            ),
        )
        port_configs = {
            str(p.get("portId")): p
            for p in (switch_port_configs_by_switch.get(serial) or [])
            if isinstance(p, dict)
        }
        parent = parent_of.get(serial)
        parent_name = (
            serial_to_dev.get(parent[0], {}).get("name") or parent[0]
            if parent else "Internet edge"
        )
        child_names = [
            serial_to_dev.get(child, {}).get("name") or child
            for child in children_of.get(serial, [])
        ]
        issue_count = len(port_issues_by_switch.get(serial, []))
        poe_data = poe_by_serial.get(serial, {})
        poe_watts = safe_float(poe_data.get("avgWatts")) if isinstance(poe_data, dict) else 0.0
        active_ports = sum(1 for port in ports if str(port.get("status") or "").lower() == "connected")
        uplink_ports = [port for port in ports if port.get("isUplink")]
        ranked_ports = sorted(
            ports,
            key=lambda port: (-_port_heat_score(port), _port_sort_key(port.get("portId"))),
        )
        hottest_ports = [
            f"{port.get('portId')} ({_port_heat_label(_port_heat_score(port)).lower()} {_port_heat_score(port):.0f})"
            for port in ranked_ports[:5]
            if _port_heat_score(port) >= 15
        ]
        link_narrative = _build_switch_link_narrative(
            serial,
            parent,
            child_names,
            uplink_ports,
            edge_counts.get(serial, 0),
            serial_to_dev,
        )
        table_rows = []
        for port in ranked_ports:
            port_id = str(port.get("portId") or "")
            port_config = port_configs.get(port_id)
            usage = port.get("usageInKb") or {}
            traffic = port.get("trafficInKbps") or {}
            if not isinstance(usage, dict):
                usage = {}
            if not isinstance(traffic, dict):
                traffic = {}
            errors = port.get("errors") or []
            if isinstance(errors, str):
                errors = [errors]
            warnings = port.get("warnings") or []
            if isinstance(warnings, str):
                warnings = [warnings]
            poe = port.get("poe") or {}
            if not isinstance(poe, dict):
                poe = {}
            power_wh = port.get("powerUsageInWh")
            indicators = []
            if port.get("isUplink"):
                indicators.append('<span class="badge badge-info">Uplink</span>')
            if poe.get("isAllocated") or (isinstance(power_wh, (int, float)) and power_wh > 0):
                indicators.append('<span class="badge badge-ok">PoE</span>')
            if errors:
                indicators.append(f'<span class="badge badge-fail">{len(errors)} error(s)</span>')
            elif warnings:
                indicators.append(f'<span class="badge badge-warn">{len(warnings)} warning(s)</span>')
            speed = str(port.get("speed") or "—")
            if speed.startswith("100 ") or speed.startswith("10 "):
                indicators.append(f'<span class="badge badge-warn">{_he(speed)}</span>')
            role = _port_role_label(port, port_config, serial_to_dev)
            vlan_text = _describe_vlan_mode(port_config)
            port_name = "—"
            if isinstance(port_config, dict):
                port_name = str(port_config.get("name") or "—")
            heat_score = _port_heat_score(port)
            heat_label = _port_heat_label(heat_score)
            heat_badge_cls = {
                "Hot": "badge-fail",
                "Warm": "badge-warn",
                "Cool": "badge-info",
                "Idle": "badge-ok",
            }[heat_label]
            table_rows.append(
                "<tr>"
                f"<td>{_he(port_id or '—')}</td>"
                f"<td>{_he(port_name)}</td>"
                f"<td><span class=\"badge {heat_badge_cls}\">{_he(heat_label)} {heat_score:.0f}</span></td>"
                f"<td>{_he(role)}</td>"
                f"<td>{_he(str(port.get('status') or 'Unknown'))}</td>"
                f"<td>{_he(speed)}</td>"
                f"<td>{_he(str(port.get('duplex') or '—'))}</td>"
                f"<td>{_he(vlan_text)}</td>"
                f"<td>{_format_usage_kb((usage or {}).get('total'))}</td>"
                f"<td>{_he(str((traffic or {}).get('total') or '—'))} Kbps</td>"
                f"<td>{_he(f'{float(power_wh):.1f} Wh' if isinstance(power_wh, (int, float)) else ('Allocated' if poe.get('isAllocated') else '—'))}</td>"
                f"<td>{''.join(indicators) or '—'}</td>"
                f"<td>{_inline_md(_describe_port_neighbor(port, serial_to_dev))}</td>"
                "</tr>"
            )

        section_parts.append(
            f"""
    <section id="{_switch_anchor(serial, switch_name)}" class="report-section switch-detail-page">
      <h3>{_he(switch_name)}</h3>
      <p class="switch-detail-kicker">{_he(site_name)} &mdash; {_he(model or 'MS switch')} &mdash; <code>{_he(serial)}</code></p>
      <div class="switch-detail-stats">
        <div class="switch-detail-stat"><span class="label">Above</span><span class="value">{_he(parent_name if not parent else f'{parent_name} ({parent[1]} -> {parent[2] or "?"})')}</span></div>
        <div class="switch-detail-stat"><span class="label">Below</span><span class="value">{_he(', '.join(child_names) if child_names else 'No downstream switches discovered')}</span></div>
        <div class="switch-detail-stat"><span class="label">Edge Devices</span><span class="value">{edge_counts.get(serial, 0)}</span></div>
        <div class="switch-detail-stat"><span class="label">Ports Up</span><span class="value">{active_ports} / {len(ports) or 0}</span></div>
        <div class="switch-detail-stat"><span class="label">Uplinks</span><span class="value">{_he(', '.join(str(port.get('portId')) for port in uplink_ports) if uplink_ports else 'None flagged')}</span></div>
        <div class="switch-detail-stat"><span class="label">PoE Avg</span><span class="value">{poe_watts:.1f} W</span></div>
        <div class="switch-detail-stat"><span class="label">Port Issues</span><span class="value">{issue_count}</span></div>
      </div>
        <div class="switch-detail-card">
        <div class="summary-body switch-detail-narrative">{_he(link_narrative)}</div>
        <div class="summary-body switch-detail-narrative"><strong>Heat ranking:</strong> {_he(', '.join(hottest_ports) if hottest_ports else 'No materially busy ports detected in current telemetry.')}</div>
        <div class="summary-title">Port Map</div>
        {_render_switch_port_grid(ports, port_configs, serial_to_dev)}
        <div class="switch-detail-legend">
          <span><i class="swatch ok"></i>healthy</span>
          <span><i class="swatch uplink"></i>uplink</span>
          <span><i class="swatch poe"></i>PoE</span>
          <span><i class="swatch warn"></i>low speed / warning</span>
          <span><i class="swatch issue"></i>error</span>
          <span><i class="swatch down"></i>down</span>
          <span><i class="swatch speed-mgig"></i>2.5G / multi-gig</span>
          <span><i class="swatch speed-uplink"></i>10G+ / high-speed uplink</span>
          <span><i class="swatch sfp"></i>SFP / module port</span>
        </div>
      </div>
      <table class="data switch-detail-table">
        <thead>
          <tr>
            <th>Port</th><th>Port Label</th><th>Heat</th><th>Role</th><th>Status</th><th>Speed</th><th>Duplex</th><th>VLAN / Mode</th>
            <th>Total Data</th><th>Current Throughput</th><th>Power</th><th>Indicators</th><th>Connected Device</th>
          </tr>
        </thead>
        <tbody>{''.join(table_rows) if table_rows else '<tr><td colspan="13">No switch port status data available.</td></tr>'}</tbody>
      </table>
    </section>
    """
        )

    return "".join(section_parts), toc_items


def _build_ap_interference_section(
    devices_by_network: Dict[str, Dict[str, Any]],
    channel_util: Any,
    wireless_stats: Dict[str, Any],
    ap_to_switch: Dict[str, Dict[str, Any]],
) -> str:
    if not isinstance(channel_util, list):
        return """
    <section id="ap-interference" class="report-section">
      <h2>14. AP Interference Audit</h2>
      <div class="summary-card"><div class="summary-body">No AP channel utilization data was available for interference analysis.</div></div>
    </section>
    """

    networks_by_serial: Dict[str, str] = {}
    ap_by_serial: Dict[str, Dict[str, Any]] = {}
    for net_id, net_data in devices_by_network.items():
        for dev in net_data.get("devices", []):
            if dev.get("productType") == "wireless" and dev.get("serial"):
                networks_by_serial[dev["serial"]] = net_id
                ap_by_serial[dev["serial"]] = dev

    per_ap_rows: List[Dict[str, Any]] = []
    site_summary: Dict[str, Dict[str, Any]] = {}
    for row in channel_util:
        if not isinstance(row, dict):
            continue
        serial = row.get("serial")
        net_id = (row.get("network") or {}).get("id") or networks_by_serial.get(serial) or "unassigned"
        net_data = devices_by_network.get(net_id, {"name": "Unassigned"})
        ap = ap_by_serial.get(serial, {})
        stats = []
        for band in row.get("byBand") or []:
            if not isinstance(band, dict):
                continue
            wifi_data = band.get("wifi") or {}
            non_wifi_data = band.get("nonWifi") or {}
            total_data = band.get("total") or {}
            wifi = safe_float(wifi_data.get("percentage") if isinstance(wifi_data, dict) else None)
            non_wifi = safe_float(non_wifi_data.get("percentage") if isinstance(non_wifi_data, dict) else None)
            total = safe_float(total_data.get("percentage") if isinstance(total_data, dict) else None)
            stats.append(
                {
                    "band": str(band.get("band") or "?"),
                    "wifi": wifi,
                    "non_wifi": non_wifi,
                    "total": total,
                }
            )
        if not stats:
            continue
        worst = max(stats, key=lambda item: (item["non_wifi"], item["total"], item["wifi"]))
        avg_total = sum(item["total"] for item in stats) / len(stats)
        avg_non_wifi = sum(item["non_wifi"] for item in stats) / len(stats)
        conn = None
        for item in wireless_stats.get(net_id, []) if isinstance(wireless_stats, dict) else []:
            if isinstance(item, dict) and item.get("serial") == serial:
                conn = item.get("connectionStats") or {}
                break
        assoc = safe_int((conn or {}).get("assoc"))
        auth = safe_int((conn or {}).get("auth"))
        success = safe_int((conn or {}).get("success"))
        if worst["non_wifi"] >= 25 or worst["total"] >= 75:
            severity = "High"
            severity_cls = "check-fail"
        elif worst["non_wifi"] >= 10 or worst["total"] >= 45:
            severity = "Medium"
            severity_cls = "check-warning"
        else:
            severity = "Low"
            severity_cls = "check-pass"
        findings = []
        if worst["non_wifi"] >= 25:
            findings.append("high non-802.11 interference")
        elif worst["non_wifi"] >= 10:
            findings.append("moderate non-802.11 interference")
        if worst["wifi"] >= 40:
            findings.append("heavy co-channel contention")
        if worst["band"] == "2.4" and worst["total"] >= 40:
            findings.append("crowded 2.4 GHz airtime")
        if success and assoc and (success / max(auth, 1)) < 2:
            findings.append("possible client retry / onboarding friction")
        if not findings:
            findings.append("no major RF symptoms in sampled telemetry")

        recs = []
        if worst["non_wifi"] >= 25:
            recs.append("inspect non-Wi-Fi noise sources near the AP")
        if worst["wifi"] >= 40:
            recs.append("review channel plan and AP density for overlap")
        if worst["band"] == "2.4" and worst["total"] >= 40:
            recs.append("reduce 2.4 GHz reliance and prefer 5 GHz/6 GHz capable clients")
        if assoc > 80:
            recs.append("review load distribution and client balancing")
        if not recs:
            recs.append("continue monitoring; no immediate RF action indicated")

        ap_row = {
            "site": net_data["name"],
            "name": ap.get("name") or serial,
            "serial": serial,
            "model": ap.get("model") or "",
            "status": ap.get("status") or "unknown",
            "band": worst["band"],
            "worst_total": worst["total"],
            "worst_non_wifi": worst["non_wifi"],
            "worst_wifi": worst["wifi"],
            "avg_total": avg_total,
            "avg_non_wifi": avg_non_wifi,
            "assoc": assoc,
            "auth": auth,
            "success": success,
            "severity": severity,
            "severity_cls": severity_cls,
            "findings": findings,
            "recommendations": recs,
        }
        per_ap_rows.append(ap_row)

        site = site_summary.setdefault(
            net_id,
            {"name": net_data["name"], "aps": 0, "high": 0, "avg_non_wifi": 0.0, "avg_total": 0.0, "bands": {}},
        )
        site["aps"] += 1
        site["avg_non_wifi"] += avg_non_wifi
        site["avg_total"] += avg_total
        if severity == "High":
            site["high"] += 1
        band_key = f'{worst["band"]} GHz'
        site["bands"][band_key] = site["bands"].get(band_key, 0) + 1

    if not per_ap_rows:
        return """
    <section id="ap-interference" class="report-section">
      <h2>14. AP Interference Audit</h2>
      <div class="summary-card"><div class="summary-body">APs were present, but no usable per-band channel utilization telemetry was available.</div></div>
    </section>
    """

    site_cards = []
    for site in sorted(site_summary.values(), key=lambda item: item["name"]):
        aps = max(site["aps"], 1)
        site_cards.append(
            f"""
      <div class="summary-card">
        <div class="summary-title">{_he(site['name'])}</div>
        <div class="summary-body">
          <strong>{site['aps']}</strong> APs with RF telemetry,
          <strong>{site['high']}</strong> high-interference APs,
          avg non-Wi-Fi interference <strong>{site['avg_non_wifi']/aps:.1f}%</strong>,
          avg total channel utilization <strong>{site['avg_total']/aps:.1f}%</strong>,
          dominant affected band <strong>{_he(max(site['bands'].items(), key=lambda item: item[1])[0])}</strong>.
        </div>
      </div>
        """
    )

    hot_aps = sorted(
        per_ap_rows,
        key=lambda item: (-item["worst_non_wifi"], -item["worst_total"], item["site"], item["name"]),
    )
    switch_ap_links: Dict[str, List[Dict[str, Any]]] = {}
    for ap in hot_aps:
        link = ap_to_switch.get(ap["serial"]) if isinstance(ap_to_switch, dict) else None
        if not isinstance(link, dict) or not link.get("switch"):
            continue
        switch_serial = str(link["switch"])
        switch_ap_links.setdefault(switch_serial, []).append(
            {
                "switch_port": str(link.get("port") or "?"),
                "ap": ap,
            }
        )
    ap_deep_dive_parts = []
    for switch_serial, linked in sorted(switch_ap_links.items(), key=lambda item: len(item[1]), reverse=True):
        linked_sorted = sorted(
            linked,
            key=lambda item: (
                {"High": 0, "Medium": 1, "Low": 2}.get(item["ap"]["severity"], 3),
                -item["ap"]["worst_non_wifi"],
                item["switch_port"],
            ),
        )
        rows = "".join(
            "<tr>"
            f"<td>{_he(item['switch_port'])}</td>"
            f"<td>{_he(item['ap']['name'])}</td>"
            f"<td><span class=\"{item['ap']['severity_cls']}\">{_he(item['ap']['severity'])}</span></td>"
            f"<td>{_he(item['ap']['band'])} GHz</td>"
            f"<td>{item['ap']['worst_non_wifi']:.1f}%</td>"
            f"<td>{item['ap']['worst_total']:.1f}%</td>"
            f"<td>{item['ap']['assoc']}</td>"
            f"<td>{_he('; '.join(item['ap']['findings']))}</td>"
            "</tr>"
            for item in linked_sorted[:20]
        )
        ap_deep_dive_parts.append(
            f"""
      <div class="building-section">
        <h4>{_he(switch_serial)}</h4>
        <table class="data dense">
          <thead>
            <tr><th>Port</th><th>AP</th><th>Severity</th><th>Band</th><th>Non-WiFi</th><th>Total</th><th>Assoc</th><th>AP Findings</th></tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
            """
        )
    ap_findings_rows = "".join(
        "<tr>"
        f"<td>{_he(item['site'])}</td>"
        f"<td>{_he(item['name'])}<br><code>{_he(item['serial'])}</code></td>"
        f"<td><span class=\"{item['severity_cls']}\">{_he(item['severity'])}</span></td>"
        f"<td>{_he(item['band'])} GHz</td>"
        f"<td>{item['worst_non_wifi']:.1f}%</td>"
        f"<td>{item['worst_wifi']:.1f}%</td>"
        f"<td>{item['worst_total']:.1f}%</td>"
        f"<td>{item['assoc']}</td>"
        f"<td>{_he('; '.join(item['findings']))}</td>"
        f"<td>{_he('; '.join(item['recommendations']))}</td>"
        "</tr>"
        for item in hot_aps[:25]
    )
    diagnostic_rows = "".join(
        "<tr>"
        f"<td>{_he(item['site'])}</td>"
        f"<td>{_he(item['name'])}</td>"
        f"<td>{_he(item['serial'])}</td>"
        f"<td>{item['avg_non_wifi']:.1f}%</td>"
        f"<td>{item['avg_total']:.1f}%</td>"
        f"<td>{item['assoc']}</td>"
        f"<td>{item['auth']}</td>"
        f"<td>{item['success']}</td>"
        "</tr>"
        for item in hot_aps[:50]
    )

    recommendations = []
    if any(item["worst_non_wifi"] >= 25 for item in hot_aps):
        recommendations.append("Physically inspect high-noise AP locations for microwaves, Bluetooth density, wireless presentation gear, and other non-802.11 emitters.")
    if any(item["worst_wifi"] >= 40 for item in hot_aps):
        recommendations.append("Review channel reuse and AP placement in high-contention areas to reduce co-channel overlap.")
    if any(item["band"] == "2.4" and item["worst_total"] >= 40 for item in hot_aps):
        recommendations.append("Reduce 2.4 GHz dependency where possible by tuning SSIDs, minimum bitrates, and client steering.")
    if not recommendations:
        recommendations.append("No widespread interference hotspot was detected in the sampled dataset; continue trend monitoring.")

    return f"""
    <section id="ap-interference" class="report-section">
      <h2>14. AP Interference Audit</h2>
      <p>This section converts Meraki channel-utilization telemetry into an RF interference view by site and by AP. `non-Wi-Fi` represents likely external RF noise, while `Wi-Fi` represents airtime consumed by neighboring WLAN activity and co-channel contention. Where exact AP neighbor telemetry is unavailable, neighbor pressure is inferred from high Wi-Fi airtime on the affected band.</p>
      {''.join(site_cards)}
      <h3>Priority AP Findings</h3>
      <table class="data dense">
        <thead>
          <tr>
            <th>Site</th><th>AP</th><th>Severity</th><th>Band</th><th>Non-WiFi</th>
            <th>WiFi</th><th>Total</th><th>Assoc</th><th>Findings</th><th>Recommendations</th>
          </tr>
        </thead>
        <tbody>{ap_findings_rows}</tbody>
      </table>
      <div class="summary-card">
        <div class="summary-title">RF Recommendations</div>
        <div class="summary-body"><ul>{''.join(f'<li>{_he(item)}</li>' for item in recommendations)}</ul></div>
      </div>
      <h3>AP Deep Dive By Switch</h3>
      {''.join(ap_deep_dive_parts) if ap_deep_dive_parts else '<div class="summary-card"><div class="summary-body">AP-to-switch mapping was not available in the current telemetry, so AP deep dives could not yet be grouped by switch.</div></div>'}
      <h3>Diagnostic Dump</h3>
      <table class="data dense">
        <thead>
          <tr><th>Site</th><th>AP</th><th>Serial</th><th>Avg Non-WiFi</th><th>Avg Total</th><th>Assoc</th><th>Auth</th><th>Success</th></tr>
        </thead>
        <tbody>{diagnostic_rows}</tbody>
      </table>
    </section>
    """


def _build_inbound_firewall_rules_section(
    networks: List[Dict[str, Any]],
    rules_by_network: Dict[str, Dict[str, Any]],
) -> str:
    """Render observed MX inbound firewall policy without overstating risk.

    The Meraki endpoint has returned both a top-level ``rules`` object and a
    bare list in different backup sets. The report accepts either shape and
    keeps collection gaps visible instead of turning missing data into a
    healthy result.
    """

    def _is_appliance_network(network: Dict[str, Any]) -> bool:
        product_types = network.get("productTypes")
        if not isinstance(product_types, list) or not product_types:
            return True
        return "appliance" in product_types

    def _raw_value(rule: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = rule.get(key)
            if value is not None and value != "":
                return value
        return None

    def _display_value(value: Any, default: str = "—") -> str:
        if value is None or value == "":
            return default
        if isinstance(value, (list, tuple)):
            values = [str(item) for item in value if item is not None and str(item) != ""]
            return ", ".join(values) if values else default
        return str(value)

    def _is_any_source(value: Any) -> bool:
        if isinstance(value, (list, tuple)):
            return any(_is_any_source(item) for item in value)
        normalized = str(value or "").strip().lower()
        return normalized in {"any", "all", "anywhere", "0.0.0.0/0", "::/0", "0/0"}

    def _policy(value: Any) -> str:
        normalized = str(value or "unknown").strip().lower()
        if normalized in {"allow", "permit", "accept"}:
            return "allow"
        if normalized in {"deny", "drop", "reject"}:
            return "deny"
        return "unknown"

    def _table(headers: List[str], rows: str, empty_message: str = "") -> str:
        body = rows or f'<tr><td colspan="{len(headers)}">{_he(empty_message)}</td></tr>'
        header_html = "".join(f"<th>{_he(header)}</th>" for header in headers)
        return (
            '<table class="data dense"><thead><tr>'
            + header_html
            + f"</tr></thead><tbody>{body}</tbody></table>"
        )

    appliance_networks = [
        network
        for network in networks
        if isinstance(network, dict) and network.get("id") and _is_appliance_network(network)
    ]
    if not appliance_networks:
        return (
            '<div class="summary-card"><div class="summary-title">Firewall Rules &amp; Internet Exposure</div>'
            '<div class="summary-body">Not evaluated: no appliance networks were present in the backup set.</div></div>'
        )

    coverage_rows = []
    normalized_rules: List[Dict[str, Any]] = []
    covered_networks = 0
    missing_networks = 0
    for network in sorted(appliance_networks, key=lambda item: str(item.get("name") or item.get("id"))):
        network_id = str(network["id"])
        network_name = str(network.get("name") or network_id)
        detail = rules_by_network.get(network_id) or {}
        if not isinstance(detail, dict):
            detail = {}
        state = str(detail.get("status") or "missing")
        raw_rules = detail.get("rules")
        rules = [rule for rule in raw_rules if isinstance(rule, dict)] if isinstance(raw_rules, list) else []
        if state == "complete":
            covered_networks += 1
            state_label = "Collected"
            rule_count = str(len(rules))
        else:
            missing_networks += 1
            state_label = "Not evaluated"
            rule_count = "—"
        coverage_rows.append(
            "<tr>"
            f"<td>{_he(network_name)}</td>"
            f"<td>{_he(state_label)}</td>"
            f"<td>{_he(rule_count)}</td>"
            "</tr>"
        )
        if state != "complete":
            continue
        for rule in rules:
            policy = _policy(_raw_value(rule, "policy", "action"))
            source = _raw_value(rule, "srcCidr", "sourceCidr", "srcCidr6")
            record = {
                "network": network_name,
                "policy": policy,
                "protocol": _display_value(_raw_value(rule, "protocol")),
                "source": _display_value(source),
                "destination": _display_value(_raw_value(rule, "destCidr", "destinationCidr", "destCidr6")),
                "destination_port": _display_value(_raw_value(rule, "destPort", "destinationPort")),
                "comment": _display_value(_raw_value(rule, "comment", "description", "name")),
                "allow_any_source": policy == "allow" and _is_any_source(source),
            }
            normalized_rules.append(record)

    allow_any_rules = [rule for rule in normalized_rules if rule["allow_any_source"]]
    deny_rules = [rule for rule in normalized_rules if rule["policy"] == "deny"]
    summary = (
        f"{covered_networks}/{len(appliance_networks)} appliance network(s) have a collected "
        f"inbound rule artifact, with {len(normalized_rules)} explicit rule(s) observed. "
        f"{len(allow_any_rules)} allow rule(s) explicitly permit any source and "
        f"{len(deny_rules)} deny rule(s) are configured."
    )
    if missing_networks:
        summary += (
            f" {missing_networks} network(s) are Not evaluated because the artifact was "
            "missing, unavailable, or unsupported."
        )

    def _rule_row(rule: Dict[str, Any]) -> str:
        policy_class = "check-fail" if rule["allow_any_source"] else (
            "check-unknown" if rule["policy"] == "unknown" else ""
        )
        policy_html = (
            f'<span class="{policy_class}">{_he(rule["policy"].title())}</span>'
            if policy_class
            else _he(rule["policy"].title())
        )
        return (
            "<tr>"
            f"<td>{_he(rule['network'])}</td>"
            f"<td>{policy_html}</td>"
            f"<td>{_he(rule['protocol'])}</td>"
            f"<td>{_he(rule['source'])}</td>"
            f"<td>{_he(rule['destination'])}</td>"
            f"<td>{_he(rule['destination_port'])}</td>"
            f"<td>{_he(rule['comment'])}</td>"
            "</tr>"
        )

    notable_rows = "".join(_rule_row(rule) for rule in allow_any_rules[:50])
    all_rows = "".join(_rule_row(rule) for rule in normalized_rules[:200])
    omitted_count = max(0, len(normalized_rules) - 200)
    omitted_note = (
        f'<p class="table-note">Showing the first 200 of {len(normalized_rules)} collected rules; '
        f"{omitted_count} additional rule(s) omitted.</p>"
        if omitted_count
        else ""
    )
    notable_block = _table(
        ["Network", "Policy", "Protocol", "Source", "Destination", "Destination Port", "Comment"],
        notable_rows,
        "No explicit allow rule with an any-source value was observed in collected artifacts.",
    )
    rules_block = _table(
        ["Network", "Policy", "Protocol", "Source", "Destination", "Destination Port", "Comment"],
        all_rows,
        "No explicit inbound rules were returned for the collected networks.",
    )
    return f"""
      <div class="firewall-rules-block">
        <h3>Firewall Rules &amp; Internet Exposure</h3>
        <p>{_he(summary)}</p>
        <div class="summary-card">
          <div class="summary-title">Observed Policy vs. Interpreted Risk</div>
          <div class="summary-body">These tables show the rule configuration returned by Meraki. An allow rule with any source is a review flag, not proof that a service is reachable or exploitable. Confirm destination services, NAT behavior, and business justification before remediation.</div>
        </div>
        <h4>Collection Coverage</h4>
        {_table(["Network", "Collection Status", "Rules"], "".join(coverage_rows))}
        <h4>Notable Permissive Rules</h4>
        {notable_block}
        <h4>Configured Inbound Rules</h4>
        {rules_block}
        {omitted_note}
      </div>
    """


def _build_wan_capacity_section(
    uplink_statuses: Any,
    appliance_uplinks_usage: Any,
    devices_avail: List[Dict[str, Any]],
    networks_by_id: Dict[str, Dict[str, Any]],
) -> str:
    if not isinstance(uplink_statuses, list) or not uplink_statuses:
        return """
    <section id="wan-capacity" class="report-section">
      <h2>13. Internet Capacity &amp; Utilization</h2>
      <div class="summary-card"><div class="summary-body">No WAN uplink telemetry was available in this backup.</div></div>
    </section>
    """

    device_by_serial = {
        d.get("serial"): d for d in devices_avail if isinstance(d, dict) and d.get("serial")
    }
    rows = []
    summary = {"active": 0, "ready": 0, "failed": 0, "unknown_speed": 0}
    recommendation_flags = {"missing_speed": False, "degraded": False}
    usage_by_network = appliance_uplinks_usage if isinstance(appliance_uplinks_usage, dict) else {}
    for device in uplink_statuses:
        if not isinstance(device, dict):
            continue
        serial = device.get("serial")
        dev = device_by_serial.get(serial, {})
        net_id = device.get("networkId") or ((dev.get("network") or {}).get("id"))
        site_name = (networks_by_id.get(net_id) or {}).get("name") or "Unassigned"
        for uplink in device.get("uplinks", []) or []:
            if not isinstance(uplink, dict):
                continue
            status = str(uplink.get("status") or "unknown").lower()
            speed = uplink.get("speed")
            interface = uplink.get("interface") or "wan"
            if status == "active":
                summary["active"] += 1
            elif status == "ready":
                summary["ready"] += 1
            else:
                summary["failed"] += 1
                recommendation_flags["degraded"] = True
            if not speed:
                summary["unknown_speed"] += 1
                recommendation_flags["missing_speed"] = True
            max_capacity = str(speed or "Unknown")
            net_usage = usage_by_network.get(net_id)
            series = []
            if isinstance(net_usage, list):
                for point in net_usage:
                    if not isinstance(point, dict):
                        continue
                    if str(point.get("interface") or "").lower() != str(interface).lower():
                        continue
                    recv = safe_float(point.get("receivedKbps"))
                    sent = safe_float(point.get("sentKbps"))
                    series.append(recv + sent)
            sustain = "Current snapshot only"
            peak = "Historical peak not collected"
            freq = "Usage frequency unavailable"
            avg_usage = 0.0
            peak_usage = 0.0
            busy_samples = 0
            if series:
                avg_usage = sum(series) / len(series)
                peak_usage = max(series)
                busy_samples = sum(1 for value in series if value >= max(peak_usage * 0.7, 1))
                sustain = f"{avg_usage:.0f} Kbps avg over 7d"
                peak = f"{peak_usage:.0f} Kbps peak"
                freq = f"{busy_samples}/{len(series)} samples near peak"
            score = 100 if status == "active" else 72 if status == "ready" else 28
            rows.append(
                {
                    "site": site_name,
                    "device": dev.get("name") or serial or "MX",
                    "model": device.get("model") or dev.get("model") or "",
                    "interface": interface,
                    "status": status.title(),
                    "public_ip": uplink.get("publicIp") or uplink.get("ip") or "—",
                    "max_capacity": max_capacity,
                    "sustain": sustain,
                    "peak": peak,
                    "frequency": freq,
                    "score": score,
                    "avg_usage": avg_usage,
                    "peak_usage": peak_usage,
                }
            )

    rows.sort(key=lambda item: (item["site"], item["device"], item["interface"]))
    graph_rows = "".join(
        "<div class=\"wan-capacity-row\">"
        f"<div class=\"wan-capacity-label\">{_he(item['site'])} / {_he(item['device'])} / {_he(item['interface'])}</div>"
        f"<div class=\"wan-capacity-bar\"><span style=\"width:{item['score']}%\"></span></div>"
        f"<div class=\"wan-capacity-meta\">{_he(item['status'])} &middot; Max speed: {_he(item['max_capacity'])}</div>"
        "</div>"
        for item in rows
    )
    table_rows = "".join(
        "<tr>"
        f"<td>{_he(item['site'])}</td>"
        f"<td>{_he(item['device'])}<br><code>{_he(item['model'])}</code></td>"
        f"<td>{_he(item['interface'])}</td>"
        f"<td>{_he(item['status'])}</td>"
        f"<td>{_he(item['max_capacity'])}</td>"
        f"<td>{_he(item['sustain'])}</td>"
        f"<td>{_he(item['peak'])}</td>"
        f"<td>{_he(item['frequency'])}</td>"
        f"<td>{_he(item['public_ip'])}</td>"
        "</tr>"
        for item in rows
    )
    recommendations = []
    if recommendation_flags["missing_speed"]:
        recommendations.append("The current backup contains uplink state but not negotiated or subscribed WAN bandwidth for one or more circuits. Add Meraki appliance uplink usage/history endpoints so the report can show sustained throughput and true peak demand.")
    if not any(item["peak_usage"] > 0 for item in rows):
        recommendations.append("WAN usage history is still absent or empty for these circuits. Validate the new appliance uplink usage history collection path and confirm the Meraki org/network supports that endpoint.")
    if recommendation_flags["degraded"]:
        recommendations.append("At least one WAN uplink is not active. Review failover policy, ISP health, and MX uplink preferences before release.")
    if not recommendations:
        recommendations.append("WAN links appear healthy in the current snapshot. To validate circuit sizing, add historical usage collection so peak and sustained demand can be compared against contracted bandwidth.")

    return f"""
    <section id="wan-capacity" class="report-section">
      <h2>13. Internet Capacity &amp; Utilization</h2>
      <p>This section summarizes current MX WAN uplink state and the maximum internet capacity exposed by the current backup. When Meraki uplink usage history is available, the report also estimates sustained load, observed peak load, and how frequently the circuit approaches its own observed peak during the sampled period.</p>
      <div class="summary-card">
        <div class="summary-title">WAN Snapshot</div>
        <div class="summary-body">
          Active uplinks: <strong>{summary['active']}</strong> &nbsp;|&nbsp;
          Warm standby / ready: <strong>{summary['ready']}</strong> &nbsp;|&nbsp;
          Degraded / other: <strong>{summary['failed']}</strong> &nbsp;|&nbsp;
          Unknown speed circuits: <strong>{summary['unknown_speed']}</strong>
        </div>
      </div>
      <div class="wan-capacity-chart">{graph_rows}</div>
      <table class="data">
        <thead>
          <tr>
            <th>Site</th><th>MX / Uplink</th><th>Interface</th><th>Status</th><th>Max Capacity</th>
            <th>Sustained Load</th><th>Peak Load</th><th>Usage Frequency</th><th>Public IP</th>
          </tr>
        </thead>
        <tbody>{table_rows}</tbody>
      </table>
      <div class="summary-card">
        <div class="summary-title">What Is Missing For True Capacity Planning</div>
        <div class="summary-body"><ul>{''.join(f'<li>{_he(item)}</li>' for item in recommendations)}</ul></div>
      </div>
    </section>
    """


def _build_config_coverage_section(
    org_dir: str,
    networks: List[Dict[str, Any]],
) -> str:
    org_checks = [
        ("Switch Port Configs", "switch_port_configs.json"),
        ("Switch Port Statuses", "switch_port_statuses.json"),
        ("LLDP/CDP Neighbors", "lldp_cdp.json"),
        ("Wireless Settings", "wireless_settings.json"),
        ("Wireless SSIDs", "wireless_ssids.json"),
        ("Wireless RF Profiles", "wireless_rf_profiles.json"),
        ("Appliance Uplink Usage", "appliance_uplinks_usage.json"),
        ("Security Baseline Summary", "security_baseline.json"),
        ("Licensing", "licensing.json"),
        ("Firmware Upgrades", "firmware_upgrades.json"),
    ]
    org_rows = []
    for label, filename in org_checks:
        status = "Present" if os.path.exists(os.path.join(org_dir, filename)) else "Missing"
        org_rows.append([label, status])

    network_rows = []
    for net in sorted(networks, key=lambda item: item.get("name") or ""):
        net_id = net.get("id")
        if not net_id:
            continue
        net_name = net.get("name") or net_id
        base = os.path.join(org_dir, "networks", net_id)
        def _has(name: str) -> str:
            return "Present" if os.path.exists(os.path.join(base, name)) else "Missing"
        network_rows.append(
            [
                net_name,
                _has("appliance_firewall_settings.json"),
                _has("appliance_port_forwarding_rules.json"),
                _has("appliance_inbound_firewall_rules.json"),
                _has("appliance_intrusion.json"),
                _has("appliance_malware.json"),
            ]
        )

    return f"""
    <section id="config-coverage" class="report-section">
      <h2>11. Configuration Backup Coverage</h2>
      <p>This section documents which configuration artifacts are present in the current backup set. Missing items indicate API collection gaps or inaccessible product scopes that should be added before final audit sign-off.</p>
      {render_section("Org-Wide Configuration Artifacts", [["Artifact", "Status"]] + org_rows if org_rows else [])}
      {render_section("Per-Network Appliance Configuration", [["Network", "Firewall Settings", "Port Forwarding", "Inbound Firewall Rules", "IDS/IPS", "AMP/Malware"]] + network_rows if network_rows else [])}
    </section>
    """


def _build_budget_forecast_section(
    inventory_summary: Dict[str, Any],
    pricing_payload: Dict[str, Any],
) -> str:
    by_model = inventory_summary.get("by_model") or {}
    if not by_model:
        return """
    <section id="budget-forecast" class="report-section">
      <h2>12. Hardware Cost &amp; Refresh Plan</h2>
      <div class="summary-card"><div class="summary-body">No model inventory data was available to build a refresh budget.</div></div>
    </section>
    """

    price_map = pricing_payload.get("models") if isinstance(pricing_payload, dict) else None
    if not isinstance(price_map, dict):
        price_map = {}

    rows = []
    missing = []
    total_cost = 0.0
    annual_reserve = 0.0
    normalized_models = {
        str(model): max(0, safe_int(count))
        for model, count in by_model.items()
    }
    for model, count in sorted(normalized_models.items(), key=lambda item: (-item[1], item[0])):
        price_entry = price_map.get(model, {})
        if not isinstance(price_entry, dict):
            price_entry = {}
        price = price_entry.get("unit_cost")
        cycle = price_entry.get("replacement_cycle_years")
        if price is None:
            missing.append(model)
            rows.append([model, str(count), "Missing", "—", "—", "—"])
            continue
        try:
            price = float(price)
        except (ValueError, TypeError):
            missing.append(model)
            rows.append([model, str(count), "Invalid", "—", "—", "—"])
            continue
        ext = price * count
        cycle_years = int(cycle) if isinstance(cycle, (int, float, str)) and str(cycle).isdigit() else 8
        annual = ext / cycle_years if cycle_years else ext / 8
        total_cost += ext
        annual_reserve += annual
        rows.append([model, str(count), f"${price:,.0f}", f"${ext:,.0f}", str(cycle_years), f"${annual:,.0f}"])

    missing_note = ""
    if missing:
        missing_note = (
            "<div class=\"summary-card\"><div class=\"summary-title\">Missing Pricing</div>"
            "<div class=\"summary-body\">Provide pricing.json with unit_cost per model to complete the refresh budget. Missing models: "
            + _he(", ".join(sorted(missing)[:12]))
            + ".</div></div>"
        )

    summary_card = (
        "<div class=\"summary-card\"><div class=\"summary-title\">8-Year Refresh Reserve</div>"
        "<div class=\"summary-body\">"
        f"Estimated total replacement cost: <strong>${total_cost:,.0f}</strong><br>"
        f"Suggested annual reserve (based on replacement cycles): <strong>${annual_reserve:,.0f}</strong>"
        "</div></div>"
    )

    return f"""
    <section id="budget-forecast" class="report-section">
      <h2>12. Hardware Cost &amp; Refresh Plan</h2>
      <p>This section estimates an 8-year hardware refresh reserve using inventory counts and optional pricing inputs. Provide a pricing map to replace placeholders with actual budget numbers.</p>
      {summary_card}
      {render_section("Model Cost Rollup", [["Model", "Count", "Unit Cost", "Extended", "Cycle (yrs)", "Annual Reserve"]] + rows)}
      {missing_note}
    </section>
    """
