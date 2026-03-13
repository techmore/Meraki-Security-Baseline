#!/usr/bin/env python3
import logging
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List

from .common import (
    BACKUPS_DIR,
    REPORT_VERSION,
    _he,
    _hardware_consistency_note,
    _model_capability_summary,
    build_fallback_security_checks,
    find_org_dirs,
    load_json,
    md_to_html,
    render_kpi_row,
    render_section,
    render_security_baseline,
)
from .topology import _topo_pages, _topo_summary_rows, _topo_svg
from .sections import (
    _build_ap_interference_section,
    _build_switch_detail_section,
    _build_wan_capacity_section,
)
from .html_shell import build_html, write_pdf

log = logging.getLogger(__name__)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def build_org_report(org_dir: str, org_name: str, exec_purpose: str = "") -> str:
    rec_path = os.path.join(org_dir, "recommendations.md")
    rec_md = ""
    if os.path.exists(rec_path):
        with open(rec_path, "r", encoding="utf-8") as f:
            rec_md = f.read()

    # Load all relevant data files
    inventory_summary = load_json(os.path.join(org_dir, "inventory_summary.json")) or {}
    poe_summary = load_json(os.path.join(org_dir, "poe_power_summary.json")) or {}
    channel_util = (
        load_json(os.path.join(org_dir, "channel_utilization_by_device.json")) or {}
    )
    devices_avail = (
        load_json(os.path.join(org_dir, "devices_availabilities.json")) or []
    )
    lldp_cdp = load_json(os.path.join(org_dir, "lldp_cdp.json")) or {}
    wireless_stats = (
        load_json(os.path.join(org_dir, "wireless_connection_stats.json")) or {}
    )
    # wireless_clients.json is {net_id: [client, …]} — flatten to a single list
    _wc_raw = load_json(os.path.join(org_dir, "wireless_clients.json")) or {}
    if isinstance(_wc_raw, dict):
        wireless_clients = [
            cl for clients in _wc_raw.values()
            if isinstance(clients, list)
            for cl in clients
            if isinstance(cl, dict)
        ]
    elif isinstance(_wc_raw, list):
        wireless_clients = [cl for cl in _wc_raw if isinstance(cl, dict)]
    else:
        wireless_clients = []
    switch_port_statuses_by_switch = (
        load_json(os.path.join(org_dir, "switch_port_statuses.json")) or {}
    )
    switch_port_configs_by_switch = (
        load_json(os.path.join(org_dir, "switch_port_configs.json")) or {}
    )
    uplink_statuses = load_json(os.path.join(org_dir, "uplink_statuses.json")) or []
    appliance_uplinks_usage = load_json(os.path.join(org_dir, "appliance_uplinks_usage.json")) or {}
    devices_statuses_raw = load_json(os.path.join(org_dir, "devices_statuses.json")) or []
    clients_overview_raw = load_json(os.path.join(org_dir, "clients_overview.json")) or {}
    licensing_data = load_json(os.path.join(org_dir, "licensing.json")) or {}

    # switch_port_configs / statuses are {serial: [port, …]} dicts — flatten,
    # injecting switchSerial so downstream code can reference the parent switch.
    def _flatten_ports(path: str) -> List[Dict]:
        raw = load_json(path) or {}
        if isinstance(raw, list):
            return raw
        result = []
        for serial, ports in raw.items():
            if isinstance(ports, list):
                for p in ports:
                    if isinstance(p, dict):
                        p.setdefault("switchSerial", serial)
                        result.append(p)
        return result

    switch_port_configs = _flatten_ports(
        os.path.join(org_dir, "switch_port_configs.json")
    )
    switch_port_statuses = _flatten_ports(
        os.path.join(org_dir, "switch_port_statuses.json")
    )
    networks = load_json(os.path.join(org_dir, "networks.json")) or []
    security_baseline = load_json(os.path.join(org_dir, "security_baseline.json")) or {}
    org_dirs = find_org_dirs(BACKUPS_DIR)

    # Device availability analysis
    device_status_counts: Dict[str, int] = {}
    device_type_counts: Dict[str, int] = {}
    for device in devices_avail:
        status = device.get("status", "unknown")
        product_type = device.get("productType", "unknown")
        device_status_counts[status] = device_status_counts.get(status, 0) + 1
        device_type_counts[product_type] = device_type_counts.get(product_type, 0) + 1

    # PoE analysis
    poe_ports = (
        poe_summary.get("port_poe_totals", []) if isinstance(poe_summary, dict) else []
    )
    poe_switches = (
        poe_summary.get("switch_poe_totals", [])
        if isinstance(poe_summary, dict)
        else []
    )
    poe_by_serial = {s.get("serial", ""): s for s in poe_switches}

    # Channel utilization analysis
    if isinstance(channel_util, list):
        high_util_devices = [
            d for d in channel_util if float(d.get("utilizationTotal", 0)) > 70
        ]
        moderate_util_devices = [
            d for d in channel_util if 30 <= float(d.get("utilizationTotal", 0)) <= 70
        ]
        ap_util_by_serial = {d.get("serial", ""): d for d in channel_util}
    else:
        high_util_devices = []
        moderate_util_devices = []
        ap_util_by_serial = {}

    # Switch port issue analysis
    # Note: the Meraki API returns "errors" and "warnings" as lists of strings, not integers.
    switch_port_issues = []
    if isinstance(switch_port_statuses, list):
        for port in switch_port_statuses[:100]:
            port_errors = port.get("errors") or []  # always a list
            if isinstance(port_errors, str):
                port_errors = [port_errors]
            port_warnings = port.get("warnings") or []
            if isinstance(port_warnings, str):
                port_warnings = [port_warnings]
            speed_raw = port.get("speed") or ""
            # speed may be "10 Mbps", "100 Mbps", 10, 100, etc.
            speed_num = None
            try:
                speed_num = int(str(speed_raw).split()[0])
            except (ValueError, IndexError):
                pass
            is_uplink = bool(port.get("isUplink"))
            if any(
                [
                    bool(port_errors),
                    is_uplink and speed_num in [10, 100],
                ]
            ):
                switch_port_issues.append(
                    {
                        "switch": port.get("switchSerial", "Unknown"),
                        "port": port.get("portId", "Unknown"),
                        "errors": port_errors,          # list of strings
                        "error_count": len(port_errors),
                        "warning_count": len(port_warnings),
                        "speed": speed_raw,
                        "duplex": port.get("duplex", "Unknown"),
                        "poeMode": port.get("poeMode", "Unknown"),
                        "status": port.get("status", "Unknown"),
                        "isUplink": is_uplink,
                    }
                )

    # Configuration issues
    config_issues = []
    if isinstance(switch_port_configs, list):
        for port in switch_port_configs[:100]:
            if port.get("enabled") == False and port.get("poeEnabled") == True:
                config_issues.append(
                    {
                        "switch": port.get("switchSerial", "Unknown"),
                        "port": port.get("portId", "Unknown"),
                        "issue": "PoE enabled but port disabled",
                        "type": "Configuration",
                    }
                )

    # Port issues indexed by switch serial
    port_issues_by_switch: Dict[str, list] = {}
    for issue in switch_port_issues:
        port_issues_by_switch.setdefault(issue["switch"], []).append(issue)

    networks_by_id = {
        n.get("id"): n for n in networks if isinstance(n, dict) and n.get("id")
    }

    # Group devices by network (building / site)
    devices_by_network: Dict[str, dict] = {}
    serial_to_network: Dict[str, dict] = {}
    for device in devices_avail:
        net = device.get("network") or {}
        net_id = net.get("id", "unassigned")
        net_name = (
            net.get("name")
            or (networks_by_id.get(net_id) or {}).get("name")
            or "Unassigned"
        )
        serial = device.get("serial", "")
        if net_id not in devices_by_network:
            devices_by_network[net_id] = {"name": net_name, "id": net_id, "devices": []}
        devices_by_network[net_id]["devices"].append(device)
        if serial:
            serial_to_network[serial] = {"id": net_id, "name": net_name}

    # Inventory summary
    inv_by_type = inventory_summary.get("by_type") or {}
    top_models = inventory_summary.get("top_models") or []
    total_devices = sum(inv_by_type.values()) if inv_by_type else len(devices_avail)

    # KPI items (compact row — kept for TOC/overview tables)
    online_count_v = device_status_counts.get("online", 0)
    offline_count_v = sum(v for k, v in device_status_counts.items() if k != "online")
    kpi_items = [
        ("Total Sites", str(len(networks) or len(devices_by_network))),
        ("Total Devices", str(total_devices)),
        ("Online", str(online_count_v)),
        ("Offline / Alert", str(offline_count_v)),
        ("MX Appliances", str(inv_by_type.get("appliance", 0))),
        ("MS Switches", str(inv_by_type.get("switch", 0))),
        ("MR Access Points", str(inv_by_type.get("wireless", 0))),
        ("High Util APs", str(len(high_util_devices))),
        ("Port Issues", str(len(switch_port_issues))),
        ("Config Issues", str(len(config_issues))),
    ]

    security_checks = (
        security_baseline.get("checks")
        if isinstance(security_baseline, dict) and security_baseline.get("checks")
        else build_fallback_security_checks(devices_avail, inv_by_type, switch_port_issues)
    )

    # ── Health at a Glance domain scoring ──────────────────────────────────
    def _hcard(domain: str, rating: str, stat: str, detail: str) -> str:
        """rating: 'good' | 'warn' | 'crit' | 'info'"""
        icons = {"good": "✓", "warn": "⚠", "crit": "✕", "info": "–"}
        return (
            f'<div class="health-card health-card--{rating}">'
            f'<div class="health-card-header">'
            f'<span class="health-card-icon">{icons.get(rating, "–")}</span>'
            f'<span class="health-card-domain">{_he(domain)}</span>'
            f'</div>'
            f'<div class="health-card-stat">{stat}</div>'
            f'<div class="health-card-detail">{detail}</div>'
            f'</div>'
        )

    # Availability
    avail_pct = round(100 * online_count_v / max(total_devices, 1))
    if avail_pct >= 98:
        _avail_rating = "good"
    elif avail_pct >= 90:
        _avail_rating = "warn"
    else:
        _avail_rating = "crit"
    _avail_card = _hcard(
        "Availability", _avail_rating,
        f"{avail_pct}% online",
        f"{online_count_v} of {total_devices} devices",
    )

    # Wireless / RF
    _ap_total = inv_by_type.get("wireless", 0)
    _high_ap = len(high_util_devices)
    _mod_ap  = len(moderate_util_devices)
    if _high_ap > max(1, _ap_total * 0.15):
        _rf_rating = "crit"
    elif _high_ap > 0:
        _rf_rating = "warn"
    else:
        _rf_rating = "good" if _ap_total > 0 else "info"
    _rf_card = _hcard(
        "Wireless / RF", _rf_rating,
        f"{_high_ap} high-util AP{'s' if _high_ap != 1 else ''}",
        f"{_mod_ap} moderate · {_ap_total} total APs",
    )

    # Switching
    _sw_issues = len(switch_port_issues)
    _cfg_issues = len(config_issues)
    if _sw_issues > 5 or _cfg_issues > 5:
        _sw_rating = "crit"
    elif _sw_issues > 0 or _cfg_issues > 0:
        _sw_rating = "warn"
    else:
        _sw_rating = "good" if inv_by_type.get("switch", 0) > 0 else "info"
    _sw_card = _hcard(
        "Switching", _sw_rating,
        f"{_sw_issues} port issue{'s' if _sw_issues != 1 else ''}",
        f"{_cfg_issues} config anomal{'ies' if _cfg_issues != 1 else 'y'} · {inv_by_type.get('switch', 0)} switches",
    )

    # WAN
    _wan_active = sum(
        1 for u in (uplink_statuses if isinstance(uplink_statuses, list) else [])
        if isinstance(u, dict) and str(u.get("status", "")).lower() == "active"
    )
    _wan_total = sum(
        1 for u in (uplink_statuses if isinstance(uplink_statuses, list) else [])
        if isinstance(u, dict) and u.get("interface")
    )
    _wan_down = _wan_total - _wan_active
    if _wan_total == 0:
        _wan_rating, _wan_stat, _wan_detail = "info", "No WAN data", "uplink status unavailable"
    elif _wan_down > 0:
        _wan_rating = "crit" if _wan_active == 0 else "warn"
        _wan_stat = f"{_wan_down} link{'s' if _wan_down != 1 else ''} down"
        _wan_detail = f"{_wan_active} active of {_wan_total} uplinks"
    else:
        _wan_rating = "good"
        _wan_stat = f"{_wan_active} active"
        _wan_detail = f"{_wan_total} uplink{'s' if _wan_total != 1 else ''} healthy"
    _wan_card = _hcard("WAN / Internet", _wan_rating, _wan_stat, _wan_detail)

    # Security
    _sec_fail  = sum(1 for c in (security_checks or []) if isinstance(c, dict) and c.get("status") == "fail")
    _sec_warn  = sum(1 for c in (security_checks or []) if isinstance(c, dict) and c.get("status") == "warning")
    _sec_pass  = sum(1 for c in (security_checks or []) if isinstance(c, dict) and c.get("status") == "pass")
    if _sec_fail > 0:
        _sec_rating = "crit"
    elif _sec_warn > 0:
        _sec_rating = "warn"
    else:
        _sec_rating = "good" if _sec_pass > 0 else "info"
    _sec_card = _hcard(
        "Security Baseline", _sec_rating,
        f"{_sec_fail} fail{'s' if _sec_fail != 1 else ''} · {_sec_warn} warn{'s' if _sec_warn != 1 else ''}",
        f"{_sec_pass} checks passed",
    )

    # Lifecycle (EOL heuristic — flag known legacy model prefixes)
    _EOL_PREFIXES = (
        "MR18", "MR24", "MR26", "MR32", "MR34",
        "MS220", "MS320", "MS420",
        "MX64", "MX65", "MX80", "MX84", "MX90", "MX400", "MX600",
    )
    _eol_models = [
        m for m, _ in top_models
        if any(str(m).upper().startswith(p) for p in _EOL_PREFIXES)
    ]
    _model_count = len(top_models)
    if _eol_models:
        _lc_rating = "crit"
        _lc_stat   = f"{len(_eol_models)} EOL model{'s' if len(_eol_models) != 1 else ''}"
        _lc_detail = ", ".join(_eol_models[:4]) + (" …" if len(_eol_models) > 4 else "")
    elif _model_count > 8:
        _lc_rating = "warn"
        _lc_stat   = f"{_model_count} distinct models"
        _lc_detail = "high hardware fragmentation"
    else:
        _lc_rating = "good" if _model_count > 0 else "info"
        _lc_stat   = f"{_model_count} model{'s' if _model_count != 1 else ''}"
        _lc_detail = "no known EOL hardware flagged"
    _lc_card = _hcard("Lifecycle / Hardware", _lc_rating, _lc_stat, _lc_detail)

    # Licensing
    _lic_mode = licensing_data.get("licenseMode") if isinstance(licensing_data, dict) else None
    _lic_list = licensing_data.get("licenses", []) if isinstance(licensing_data, dict) else []
    # co-term licenses use an `expired` bool; per-device licenses use a `status` string
    _lic_expired = sum(
        1 for lic in _lic_list
        if isinstance(lic, dict) and (
            lic.get("expired") is True
            or str(lic.get("status", "")).lower() in ("expired", "inactive")
        )
    )
    _lic_active = sum(
        1 for lic in _lic_list
        if isinstance(lic, dict) and not lic.get("invalidated") and (
            lic.get("expired") is False
            or str(lic.get("status", "")).lower() in ("ok", "active", "in compliance")
        )
    )
    if isinstance(licensing_data, dict) and licensing_data.get("error"):
        _lic_rating, _lic_stat, _lic_detail = "info", "Data unavailable", "license API not accessible"
    elif _lic_expired > 0:
        _lic_rating = "crit"
        _lic_stat   = f"{_lic_expired} expired"
        _lic_detail = f"{_lic_active} active · {_lic_mode or 'unknown'} model"
    elif _lic_active > 0:
        _lic_rating = "good"
        _lic_stat   = f"{_lic_active} active"
        _lic_detail = f"{_lic_mode or 'co-term'} licensing"
    else:
        _lic_rating, _lic_stat, _lic_detail = "info", "No detail", f"{_lic_mode or 'unknown'} model"
    _lic_card = _hcard("Licensing", _lic_rating, _lic_stat, _lic_detail)

    health_grid_html = (
        '<div class="health-grid">'
        + _avail_card + _rf_card + _sw_card + _wan_card
        + _sec_card + _lc_card + _lic_card
        + '</div>'
    )

    # =========================================================
    # COVER PAGE
    # =========================================================
    _now = datetime.now()
    _report_date = _now.strftime("%B %d, %Y")
    _report_ts = _now.strftime("%B %d, %Y at %I:%M %p").replace(" 0", " ")
    cover_html = f"""
    <section class="cover">
      <div class="cover-inner">
        <div class="cover-top">
          <div class="cover-brand">Techmore</div>
          <div class="cover-rule"></div>
          <div class="cover-title">Network Health &amp;<br>Optimization Report</div>
          <div class="cover-subtitle">{_he(org_name)}</div>
          <div class="cover-run-ts">Generated {_report_ts}</div>
        </div>
        <div class="cover-bottom">
          <div class="cover-bottom-rule"></div>
          <div class="cover-bottom-info">
            <span class="cover-conf">Confidential &mdash; Prepared by Techmore</span>
            <span class="cover-ver-date">v{REPORT_VERSION} &nbsp;&bull;&nbsp; {_report_date}</span>
          </div>
        </div>
      </div>
    </section>
    """

    # =========================================================
    # TABLE OF CONTENTS PAGE
    # =========================================================
    toc_site_items = "".join(
        f'<li class="toc-sub-item">{net_data["name"]}</li>'
        for net_data in sorted(devices_by_network.values(), key=lambda x: x["name"])
    )
    switch_deep_dive_html, toc_switch_items = _build_switch_detail_section(
        devices_by_network,
        lldp_cdp,
        switch_port_statuses_by_switch,
        switch_port_configs_by_switch,
        poe_by_serial,
        port_issues_by_switch,
    )
    ap_interference_html = _build_ap_interference_section(
        devices_by_network,
        channel_util,
        wireless_stats,
        switch_port_statuses_by_switch,
    )
    wan_capacity_html = _build_wan_capacity_section(
        uplink_statuses,
        appliance_uplinks_usage,
        devices_avail,
        networks_by_id,
    )
    toc_switch_subitems = "".join(
        f'<li class="toc-sub-item"><a href="#{_he(anchor)}">{_he(label)}</a></li>'
        for anchor, label in toc_switch_items
    )
    toc_html = f"""
    <section class="toc-page">
      <div class="toc-header">Table of Contents</div>
      <ol class="toc-list">
        <li>
          <span class="toc-num">1</span>
          <span class="toc-entry">Executive Summary</span>
        </li>
        <li>
          <span class="toc-num">2</span>
          <span class="toc-entry">Network Overview</span>
        </li>
        <li>
          <span class="toc-num">3</span>
          <span class="toc-entry">Network Topology</span>
          <ol class="toc-sub">
            {toc_site_items}
          </ol>
        </li>
        <li>
          <span class="toc-num">4</span>
          <span class="toc-entry">Traffic Flows &amp; Bottleneck Analysis</span>
        </li>
        <li>
          <span class="toc-num">5</span>
          <span class="toc-entry">Device Health &amp; Issues</span>
        </li>
        <li>
          <span class="toc-num">6</span>
          <span class="toc-entry">PoE Power Analysis</span>
        </li>
        <li>
          <span class="toc-num">7</span>
          <span class="toc-entry">Security Baseline</span>
        </li>
        <li>
          <span class="toc-num">8</span>
          <span class="toc-entry">Recommendations &amp; Implementation Plan</span>
        </li>
        <li>
          <span class="toc-num">9</span>
          <span class="toc-entry">CIS 8 Controls Assessment</span>
        </li>
        <li>
          <span class="toc-num">10</span>
          <span class="toc-entry">Licensing Summary</span>
        </li>
        <li>
          <span class="toc-num">11</span>
          <span class="toc-entry">Internet Capacity &amp; Utilization</span>
        </li>
        <li>
          <span class="toc-num">12</span>
          <span class="toc-entry">AP Interference Audit</span>
        </li>
        <li>
          <span class="toc-num">13</span>
          <span class="toc-entry">Client Analysis</span>
        </li>
        <li>
          <span class="toc-num">14</span>
          <span class="toc-entry">Switch Deep Dive</span>
          <ol class="toc-sub">
            {toc_switch_subitems}
          </ol>
        </li>
      </ol>
    </section>
    """

    # =========================================================
    # SECTION 1: EXECUTIVE SUMMARY  (fills its own page)
    # =========================================================
    online_count = device_status_counts.get("online", 0)
    availability_pct = round(100 * online_count / total_devices) if total_devices else 0
    _offline_count = total_devices - online_count

    # Build a prioritized risk list from health card ratings
    _risk_bullets: list[str] = []
    _prio_bullets: list[str] = []

    if _avail_rating == "crit":
        _risk_bullets.append(
            f"<strong>Device availability is critical</strong> — {_offline_count} of "
            f"{total_devices} devices offline or alerting ({availability_pct}% online). "
            "Investigate offline units immediately; cloud management and SD-WAN path "
            "selection depend on appliance reachability."
        )
        _prio_bullets.append(
            "<strong>Immediate (0–2 weeks):</strong> Triage offline devices, confirm "
            "connectivity to Meraki Dashboard, and restore any degraded links."
        )
    elif _avail_rating == "warn":
        _risk_bullets.append(
            f"<strong>Availability is below target</strong> — {_offline_count} device(s) "
            f"offline, bringing availability to {availability_pct}%. Monitor closely and "
            "escalate if the count increases."
        )

    if _rf_rating == "crit":
        _risk_bullets.append(
            f"<strong>Wireless RF congestion detected</strong> — {len(high_util_devices)} "
            "access point(s) exceeding 70% channel utilization. Dense AP deployments or "
            "insufficient 5 GHz client steering are the most common causes. Congestion at "
            "this level degrades throughput and roaming quality for all associated clients."
        )
        _prio_bullets.append(
            "<strong>Short-term (2–6 weeks):</strong> Audit high-utilization APs — reduce "
            "SSID count, enable band steering, rebalance channel plan, or add APs to relieve "
            "congested cells."
        )
    elif _rf_rating == "warn":
        _risk_bullets.append(
            f"<strong>Wireless RF utilization is elevated</strong> — {len(high_util_devices)} "
            "AP(s) above 70% utilization. Proactive channel and SSID tuning is advised "
            "before utilization climbs further."
        )

    if _sw_rating in ("crit", "warn"):
        _risk_bullets.append(
            f"<strong>Switch port issues require attention</strong> — {len(switch_port_issues)} "
            "port(s) with errors or sub-gigabit uplinks detected. Frame errors and duplex "
            "mismatches can introduce latency and packet loss that affects every device "
            "downstream of the affected port."
        )
        _prio_bullets.append(
            "<strong>Short-term (2–6 weeks):</strong> Resolve switch port errors and duplex "
            "mismatches; replace cabling or SFPs where hardware faults are confirmed."
        )

    if _lc_rating in ("crit", "warn") and _eol_models:
        _eol_str = ", ".join(_eol_models[:4]) + (" …" if len(_eol_models) > 4 else "")
        _risk_bullets.append(
            f"<strong>End-of-life hardware in production</strong> — model(s) {_eol_str} are "
            "past or approaching Cisco Meraki end-of-support. EOL devices no longer receive "
            "firmware security patches and may lose Dashboard management access when licenses "
            "lapse. Continued operation increases security exposure and reduces operational "
            "predictability."
        )
        _prio_bullets.append(
            "<strong>Medium-term (6–12 weeks):</strong> Initiate hardware refresh planning "
            f"for EOL device(s) — {_eol_str}. Prioritize units in critical path roles "
            "(core switching, edge appliances)."
        )
    elif _lc_rating == "warn" and _model_count > 8:
        _risk_bullets.append(
            f"<strong>High hardware fragmentation</strong> — {_model_count} distinct device "
            "models detected. Fragmented hardware inventories complicate firmware management, "
            "spare-parts stocking, and consistent feature availability across the environment."
        )

    if _lic_rating == "crit" and _lic_expired > 0:
        _risk_bullets.append(
            f"<strong>Expired license keys present</strong> — {_lic_expired} license key(s) "
            "have lapsed. Expired co-term licenses can cause devices to enter limited mode, "
            "losing Dashboard visibility and security feature enforcement. Renew or re-assign "
            "before the next renewal window."
        )
        _prio_bullets.append(
            "<strong>Immediate (0–2 weeks):</strong> Review expired license keys in the "
            "Meraki Dashboard and engage your Cisco account team to assess renewal impact."
        )

    if _sec_rating in ("crit", "warn"):
        _risk_bullets.append(
            f"<strong>Security baseline gaps</strong> — {_sec_fail} check(s) failing and "
            f"{_sec_warn} warning(s). Baseline failures such as disabled AMP, IDS/IPS in "
            "detection-only mode, or exposed port forwarding represent direct threat exposure "
            "for the environment."
        )
        _prio_bullets.append(
            "<strong>Short-term (2–6 weeks):</strong> Address failing security baseline "
            "checks — enable AMP and IDS/IPS in prevention mode; review internet-exposed "
            "services."
        )

    # Long-term catch-all
    _prio_bullets.append(
        "<strong>Long-term (3–6 months):</strong> Develop a hardware refresh roadmap "
        "addressing lifecycle gaps, standardize access switching tiers, and validate "
        "licensing coverage aligns with the physical device inventory."
    )

    # Overall health rating label
    _crit_domains = [r for r in [_avail_rating, _rf_rating, _sw_rating, _wan_rating,
                                  _sec_rating, _lc_rating, _lic_rating] if r == "crit"]
    _warn_domains = [r for r in [_avail_rating, _rf_rating, _sw_rating, _wan_rating,
                                  _sec_rating, _lc_rating, _lic_rating] if r == "warn"]
    if _crit_domains:
        _overall_label = (
            f'<span class="hcard-rating hcard-crit">'
            f'Needs Attention — {len(_crit_domains)} Critical Domain(s)</span>'
        )
    elif _warn_domains:
        _overall_label = (
            f'<span class="hcard-rating hcard-warn">'
            f'Monitor — {len(_warn_domains)} Warning(s)</span>'
        )
    else:
        _overall_label = '<span class="hcard-rating hcard-good">Healthy</span>'

    _risk_html = (
        "<ul>" + "".join(f"<li>{b}</li>" for b in _risk_bullets) + "</ul>"
        if _risk_bullets
        else "<p>No critical or warning-level findings were identified in this scan.</p>"
    )
    _prio_html = "<ol>" + "".join(f"<li>{b}</li>" for b in _prio_bullets) + "</ol>"

    # LLM purpose override
    _purpose_body = (
        exec_purpose
        if exec_purpose
        else (
            f"This network audit report covers the <strong>{_he(org_name)}</strong> Cisco Meraki "
            f"environment as of {_report_date}. It is prepared for IT leadership, operations "
            "teams, and decision makers who need a clear view of current network health, risk "
            "posture, lifecycle status, and near-term action priorities. Each section provides "
            "observed findings, interpreted risk, and prioritized recommendations. Where data "
            "was unavailable at collection time, findings are noted as partial or pending."
        )
    )

    exec_html = f"""
    <section id="executive-summary" class="report-section exec-full-page">
      <h1>1. Executive Summary</h1>

      <div class="summary-card exec-purpose-card">
        <div class="summary-body">{_purpose_body}</div>
      </div>

      <h2>Current State Assessment</h2>
      <div class="summary-card">
        <div class="summary-body">
          The <strong>{_he(org_name)}</strong> network spans
          <strong>{len(devices_by_network)}</strong> site(s) with a total of
          <strong>{total_devices}</strong> cloud-managed Meraki devices:
          {inv_by_type.get("appliance", 0)} MX security appliance(s),
          {inv_by_type.get("switch", 0)} MS switch(es), and
          {inv_by_type.get("wireless", 0)} MR access point(s).
          At the time of this report, <strong>{online_count}</strong> of {total_devices} devices
          ({availability_pct}%) were online and reporting to Dashboard.
          Overall environment health: {_overall_label}
          <br><br>
          {_hardware_consistency_note(top_models)}
        </div>
      </div>

      <h2>Top Operational Risks</h2>
      <div class="summary-card">
        <div class="summary-body">
          {_risk_html}
        </div>
      </div>

      <h2>Recommended Priorities</h2>
      <div class="summary-card">
        <div class="summary-body">
          {_prio_html}
        </div>
      </div>

      <h2>Infrastructure Inventory</h2>
      <table class="data">
        <thead>
          <tr>
            <th>Layer</th>
            <th>Device Type</th>
            <th>Count</th>
            <th>Role in Network</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>WAN / Edge</strong></td>
            <td>MX Security Appliance</td>
            <td>{inv_by_type.get("appliance", 0)}</td>
            <td>Internet gateway, stateful firewall, site-to-site and client VPN,
                DHCP/DNS, content filtering, and SD-WAN path selection.
                All ingress/egress traffic passes through the MX.</td>
          </tr>
          <tr>
            <td><strong>Distribution / Access</strong></td>
            <td>MS Ethernet Switch</td>
            <td>{inv_by_type.get("switch", 0)}</td>
            <td>Wired LAN switching, VLAN segmentation, 802.1Q trunking,
                PoE power delivery for APs and IP devices, and port-level
                access control via ACLs or 802.1X.</td>
          </tr>
          <tr>
            <td><strong>Wireless</strong></td>
            <td>MR Access Point</td>
            <td>{inv_by_type.get("wireless", 0)}</td>
            <td>802.11 wireless on 2.4 GHz and 5 GHz, automatic RF management,
                seamless client roaming, and SSID-to-VLAN mapping for
                traffic segmentation.</td>
          </tr>
        </tbody>
      </table>

      <h2>Health at a Glance</h2>
      {health_grid_html}
      {render_kpi_row(kpi_items)}
    </section>
    """

    # =========================================================
    # SECTION 2: NETWORK OVERVIEW (functional ordering)
    # =========================================================
    network_overview_rows = []
    for net_id, net_data in sorted(
        devices_by_network.items(), key=lambda x: x[1]["name"]
    ):
        nd = net_data["devices"]
        appliances = [d for d in nd if d.get("productType") == "appliance"]
        switches = [d for d in nd if d.get("productType") == "switch"]
        aps = [d for d in nd if d.get("productType") == "wireless"]
        online = len([d for d in nd if d.get("status") == "online"])
        total = len(nd)
        net_ap_serials = {d.get("serial") for d in aps}
        net_high_util = len(
            [d for d in high_util_devices if d.get("serial") in net_ap_serials]
        )
        offline = total - online

        badges = []
        if offline > 0:
            badges.append(f'<span class="badge badge-fail">{offline} offline</span>')
        if net_high_util > 0:
            badges.append(
                f'<span class="badge badge-warn">{net_high_util} AP high util</span>'
            )
        if not badges:
            badges.append('<span class="badge badge-ok">Healthy</span>')

        network_overview_rows.append(
            f"<tr>"
            f"<td><strong>{net_data['name']}</strong></td>"
            f"<td>{len(appliances)}</td>"
            f"<td>{len(switches)}</td>"
            f"<td>{len(aps)}</td>"
            f"<td>{online}/{total}</td>"
            f"<td>{'&nbsp;'.join(badges)}</td>"
            f"</tr>"
        )

    network_overview_html = f"""
    <section id="network-overview" class="report-section">
      <h1>2. Network Overview</h1>
      <p>Each row represents one managed network (site / building), listed in the functional
         order of the traffic path: WAN edge (MX) &rarr; switching layer (MS) &rarr;
         wireless layer (MR) &rarr; end clients.</p>
      <table class="data">
        <thead>
          <tr>
            <th>Site / Building</th>
            <th>MX Appliances</th>
            <th>MS Switches</th>
            <th>MR Access Points</th>
            <th>Devices Online</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {"".join(network_overview_rows)}
        </tbody>
      </table>
      <h2>Model Inventory &amp; Capabilities</h2>
      <table class="data">
        <thead>
          <tr>
            <th>Model</th><th>Count</th><th>Capability Summary</th>
          </tr>
        </thead>
        <tbody>
          {"".join(f"<tr><td>{_he(model)}</td><td>{count}</td><td>{_he(_model_capability_summary(model))}</td></tr>" for model, count in top_models[:12])}
        </tbody>
      </table>
      <div class="summary-card">
        <div class="summary-title">PoE Budget Note</div>
        <div class="summary-body">
          Current backups include measured PoE consumption and per-port allocation signals, but
          they do not yet include authoritative switch maximum PoE budget values. The report can
          therefore show actual draw and PoE-heavy switches today, but budget headroom remains an
          API collection gap that should be added to the backup pipeline before final capacity
          planning or switch replacement decisions are made.
        </div>
      </div>
    </section>
    """

    # =========================================================
    # SECTION 3: NETWORK TOPOLOGY
    # =========================================================
    topo_enrichment = {
        "device_ip": {
            d["serial"]: d.get("lanIp", "")
            for d in (devices_statuses_raw if isinstance(devices_statuses_raw, list) else [])
            if d.get("serial")
        },
        "uplink_statuses": uplink_statuses,
        "uplinks_usage": appliance_uplinks_usage,
        "clients_overview": clients_overview_raw,
        "port_configs": switch_port_configs_by_switch,
        "port_statuses": switch_port_statuses_by_switch,
    }

    topo_site_parts: List[str] = []
    for net_id, net_data in sorted(devices_by_network.items(), key=lambda x: x[1]["name"]):
        site_devs = net_data["devices"]
        if not site_devs:
            continue
        infra_devs = [
            d for d in site_devs if d.get("productType") in ("appliance", "switch")
        ]
        site_serials = {d["serial"] for d in site_devs if d.get("serial")}
        has_lldp = isinstance(lldp_cdp, dict) and any(
            s in lldp_cdp for s in site_serials
        )
        lldp_banner = (
            ""
            if has_lldp
            else (
                '<div class="topo-no-lldp">'
                "&#9432; No LLDP/CDP neighbour data found for this site. "
                "All connections are inferred from device type. "
                "Enable LLDP on switches and verify API scope to see confirmed adjacencies."
                "</div>"
            )
        )
        if not infra_devs:
            topo_body = (
                '<div class="summary-card"><div class="summary-body">'
                "No switch or MX infrastructure was present in this site slice. "
                "Wireless edge devices exist, but there is not enough switching hierarchy "
                "here to render an upstream/downstream topology tree."
                "</div></div>"
            )
        else:
            summary_rows = _topo_summary_rows(
                site_devs,
                lldp_cdp,
                switch_port_statuses_by_switch,
            )
            pages = _topo_pages(
                site_devs, lldp_cdp, ap_util_by_serial,
                port_issues_by_switch, switch_port_statuses_by_switch,
                enrichment=topo_enrichment,
            )
            topo_diagrams = ""
            for i, page in enumerate(pages):
                pb = ' style="page-break-before:always"' if i > 0 else ""
                title_html = (
                    f'<h3 class="topo-branch-title">{_he(page["title"])}</h3>'
                    if page.get("title") else ""
                )
                topo_diagrams += f'<div class="topo-diagram"{pb}>{title_html}{page["svg"]}</div>'
            topo_body = topo_diagrams + render_section(
                "Topology Summary",
                [["Device", "Model", "Upstream", "Child Switches", "Edge Devices"]]
                + summary_rows if summary_rows else [],
            )
        topo_site_parts.append(
            f'<div class="topo-site">'
            f'<h2>{_he(net_data["name"])}</h2>'
            f'{lldp_banner}'
            f'{topo_body}'
            f'</div>'
        )

    topo_legend = """
    <div class="topo-legend">
      <span class="topo-legend-item">
        <svg width="10" height="10" style="vertical-align:middle;margin-right:4px">
          <circle cx="5" cy="5" r="4" fill="#4ade80"/></svg>Online</span>
      <span class="topo-legend-item">
        <svg width="10" height="10" style="vertical-align:middle;margin-right:4px">
          <circle cx="5" cy="5" r="4" fill="#f87171"/></svg>Offline / Alert</span>
      <span class="topo-legend-item">
        <svg width="10" height="10" style="vertical-align:middle;margin-right:4px">
          <circle cx="5" cy="5" r="4" fill="#94a3b8"/></svg>Dormant</span>
      <span class="topo-legend-item">
        <svg width="22" height="10" style="vertical-align:middle;margin-right:4px">
          <line x1="0" y1="5" x2="22" y2="5" stroke="#8a9269" stroke-width="1.5"/></svg>LLDP confirmed</span>
      <span class="topo-legend-item">
        <svg width="22" height="10" style="vertical-align:middle;margin-right:4px">
          <line x1="0" y1="5" x2="22" y2="5" stroke="#8a9269" stroke-width="1.5" stroke-dasharray="4 3"/></svg>Inferred</span>
      <span class="topo-legend-item">
        <span style="color:#fbbf24;font-size:12px;margin-right:4px">&#9888;</span>Has issues</span>
    </div>"""

    topology_html = f"""
    <section id="network-topology" class="report-section">
      <h1>3. Network Topology</h1>
      <p>Hierarchical diagrams for each managed site showing upstream and downstream packet
         flow from the internet edge through MX security appliances into the switching
         fabric. The diagram renders appliances and switches as the primary tree, while
         wireless and other edge devices are summarized inside their parent switch counts.
         Switch cards display approximate front-panel port layouts, uplink ports, upstream
         neighbors, and child device counts. Solid edges indicate LLDP/CDP-confirmed
         adjacencies; dashed edges indicate the internet handoff above root devices.</p>
      {topo_legend}
      {"".join(topo_site_parts) if topo_site_parts else
       '<div class="summary-card"><div class="summary-body">No site topology data available.</div></div>'}
    </section>
    """

    # =========================================================
    # SECTION 4: TRAFFIC FLOWS & BOTTLENECK ANALYSIS
    # =========================================================
    traffic_sections_html = []

    for net_id, net_data in sorted(
        devices_by_network.items(), key=lambda x: x[1]["name"]
    ):
        net_name = net_data["name"]
        nd = net_data["devices"]
        appliances = [d for d in nd if d.get("productType") == "appliance"]
        switches = [d for d in nd if d.get("productType") == "switch"]
        aps = [d for d in nd if d.get("productType") == "wireless"]

        sec = f'<div class="building-section">'
        sec += f"<h2>{net_name}</h2>"

        # Traffic path flow diagram
        path_parts = []
        if appliances:
            mx_name = appliances[0].get("name") or appliances[0].get(
                "serial", "MX Appliance"
            )
            path_parts.append(f"Internet &rarr; MX ({mx_name})")
        else:
            path_parts.append("Internet &rarr; [No MX]")
        if switches:
            path_parts.append(f"MS Switches ({len(switches)})")
        if aps:
            path_parts.append(f"MR APs ({len(aps)})")
        path_parts.append("Clients")

        sec += (
            f'<p class="traffic-path">Data path: '
            f'<span class="path-flow">{" &rarr; ".join(path_parts)}</span></p>'
        )

        # --- Per-switch analysis ---
        if switches:
            sec += "<h3>Switches</h3>"
            for sw in switches:
                serial = sw.get("serial", "")
                sw_name = sw.get("name") or sw.get("model") or serial
                sw_status = sw.get("status", "unknown")
                status_cls = "badge-ok" if sw_status == "online" else "badge-fail"
                poe_data = poe_by_serial.get(serial, {})
                poe_watts = float(poe_data.get("avgWatts", 0)) if poe_data else 0.0
                sw_issues = port_issues_by_switch.get(serial, [])

                sec += '<div class="device-card">'
                sec += (
                    f'<div class="device-card-header">'
                    f"<strong>{sw_name}</strong> "
                    f'<code class="serial">{serial}</code> '
                    f'<span class="badge {status_cls}">{sw_status}</span>'
                )
                if poe_watts > 0:
                    poe_cls = "badge-warn" if poe_watts > 60 else "badge-info"
                    sec += f' <span class="badge {poe_cls}">PoE avg {poe_watts:.0f} W</span>'
                sec += "</div>"

                if sw_issues:
                    sec += (
                        f'<div class="device-issues">'
                        f"<strong>&#9888; {len(sw_issues)} port issue(s) detected:</strong>"
                        f"<ul>"
                    )
                    for issue in sw_issues[:8]:
                        sec += (
                            f"<li>Port <strong>{issue['port']}</strong>: "
                            f"speed {issue['speed']}, "
                            f"duplex {issue['duplex']}, "
                            f"errors: {', '.join(issue['errors']) if issue['errors'] else 'none'}"
                            f"</li>"
                        )
                    if len(sw_issues) > 8:
                        sec += f"<li>&hellip; and {len(sw_issues) - 8} more</li>"
                    sec += "</ul></div>"
                else:
                    sec += '<div class="device-ok">&#10003; No port issues detected.</div>'

                # Bottleneck analysis
                bottlenecks = []
                def _speed_num(s):
                    try: return int(str(s).split()[0])
                    except (ValueError, IndexError): return None
                low_speed = [i for i in sw_issues if i.get("isUplink") and _speed_num(i.get("speed")) in [10, 100]]
                err_ports = [i for i in sw_issues if i.get("error_count", 0) > 0]
                if low_speed:
                    bottlenecks.append(
                        f"{len(low_speed)} uplink port(s) negotiating below 1 Gbps &mdash; "
                        f"review cabling, optics, or expected circuit handoff speed"
                    )
                if err_ports:
                    bottlenecks.append(
                        f"{len(err_ports)} port(s) with frame errors &mdash; "
                        f"likely cable degradation, bad SFP, or transceiver mismatch"
                    )
                if poe_watts > 60:
                    bottlenecks.append(
                        f"High PoE draw ({poe_watts:.0f} W avg) &mdash; "
                        f"verify remaining PoE budget to prevent power-limited port failures"
                    )

                if bottlenecks:
                    sec += '<div class="bottleneck-list"><strong>Bottlenecks / Concerns:</strong><ul>'
                    for b in bottlenecks:
                        sec += f"<li>{b}</li>"
                    sec += "</ul></div>"

                sec += "</div>"  # device-card

        # --- Per-AP analysis ---
        if aps:
            sec += "<h3>Access Points</h3>"
            for ap in aps:
                serial = ap.get("serial", "")
                ap_name = ap.get("name") or ap.get("model") or serial
                ap_status = ap.get("status", "unknown")
                status_cls = "badge-ok" if ap_status == "online" else "badge-fail"
                util_data = ap_util_by_serial.get(serial, {})
                total_util = float(util_data.get("utilizationTotal", 0)) if util_data else 0.0
                tx_util = float(util_data.get("utilization80211Tx", 0)) if util_data else 0.0
                rx_util = float(util_data.get("utilization80211Rx", 0)) if util_data else 0.0
                non80211 = float(util_data.get("utilizationNon80211", 0)) if util_data else 0.0

                if total_util > 70:
                    util_cls = "badge-fail"
                elif total_util > 30:
                    util_cls = "badge-warn"
                else:
                    util_cls = "badge-ok"

                sec += '<div class="device-card">'
                sec += (
                    f'<div class="device-card-header">'
                    f"<strong>{ap_name}</strong> "
                    f'<code class="serial">{serial}</code> '
                    f'<span class="badge {status_cls}">{ap_status}</span>'
                )
                if util_data:
                    sec += f' <span class="badge {util_cls}">Ch util {total_util:.0f}%</span>'
                sec += "</div>"

                if util_data:
                    sec += (
                        f'<div class="util-breakdown">'
                        f"Tx: {tx_util:.1f}% &nbsp;|&nbsp; "
                        f"Rx: {rx_util:.1f}% &nbsp;|&nbsp; "
                        f"Non-802.11 interference: {non80211:.1f}%"
                        f"</div>"
                    )

                # AP bottleneck analysis
                ap_issues = []
                if ap_status != "online":
                    ap_issues.append(
                        f"AP is <strong>{ap_status}</strong> &mdash; "
                        f"clients in coverage area have no wireless service"
                    )
                if total_util > 70:
                    ap_issues.append(
                        f"Channel utilization at {total_util:.0f}% &mdash; "
                        f"AP is near capacity; expect higher latency and reduced throughput"
                    )
                if non80211 > 20:
                    ap_issues.append(
                        f"Non-802.11 interference at {non80211:.0f}% &mdash; "
                        f"significant RF noise (Bluetooth, adjacent-channel sources, microwave)"
                    )
                if tx_util > 50:
                    ap_issues.append(
                        f"High Tx utilization ({tx_util:.0f}%) &mdash; "
                        f"consider adding APs or reducing SSID count to distribute load"
                    )

                if ap_issues:
                    sec += '<div class="bottleneck-list"><strong>Issues / Bottlenecks:</strong><ul>'
                    for b in ap_issues:
                        sec += f"<li>{b}</li>"
                    sec += "</ul></div>"
                elif ap_status == "online":
                    sec += '<div class="device-ok">&#10003; AP operating normally.</div>'

                sec += "</div>"  # device-card

        sec += "</div>"  # building-section
        traffic_sections_html.append(sec)

    traffic_html = f"""
    <section id="traffic-flows" class="report-section">
      <h1>4. Traffic Flows &amp; Bottleneck Analysis</h1>
      <p>Each site is presented in functional order: MX appliance (WAN edge) &rarr;
         MS switches (LAN distribution) &rarr; MR access points (wireless edge) &rarr;
         end clients. Issues and bottlenecks are called out at each layer.</p>
      {"".join(traffic_sections_html)}
    </section>
    """

    # =========================================================
    # SECTION 4: DEVICE HEALTH & ISSUES
    # =========================================================
    issues_html = """
    <section id="issues" class="report-section">
      <h1>5. Device Health &amp; Issues</h1>
    """

    if device_status_counts:
        issues_html += render_section(
            "Device Status Summary",
            [[status.title(), str(count)] for status, count in device_status_counts.items()],
        )

    if switch_port_issues:
        issues_html += """
        <h2>Switch Port Issues</h2>
        <table class="data">
          <thead>
            <tr>
              <th>Switch Serial</th><th>Port</th><th>Errors</th>
              <th>Speed</th><th>Duplex</th><th>PoE Mode</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
        """
        for issue in switch_port_issues[:25]:
            err_display = ", ".join(issue["errors"]) if issue["errors"] else "—"
            issues_html += (
                f"<tr>"
                f"<td>{issue['switch']}</td>"
                f"<td>{issue['port']}</td>"
                f"<td>{err_display}</td>"
                f"<td>{issue['speed']}</td>"
                f"<td>{issue['duplex']}</td>"
                f"<td>{issue['poeMode']}</td>"
                f"<td>{issue['status']}</td>"
                f"</tr>"
            )
        issues_html += "</tbody></table>"

    if config_issues:
        issues_html += """
        <h2>Configuration Issues</h2>
        <table class="data">
          <thead>
            <tr><th>Switch Serial</th><th>Port</th><th>Issue</th><th>Type</th></tr>
          </thead>
          <tbody>
        """
        for issue in config_issues[:15]:
            issues_html += (
                f"<tr>"
                f"<td>{issue['switch']}</td>"
                f"<td>{issue['port']}</td>"
                f"<td>{issue['issue']}</td>"
                f"<td>{issue['type']}</td>"
                f"</tr>"
            )
        issues_html += "</tbody></table>"

    if high_util_devices:
        issues_html += """
        <h2>High Utilization Access Points (&gt;70%)</h2>
        <table class="data">
          <thead>
            <tr>
              <th>AP Serial</th><th>Total Util</th>
              <th>Non-802.11</th><th>Tx</th><th>Rx</th>
            </tr>
          </thead>
          <tbody>
        """
        for device in high_util_devices[:20]:
            issues_html += (
                f"<tr>"
                f"<td>{device.get('serial', 'Unknown')}</td>"
                f"<td>{float(device.get('utilizationTotal', 0)):.1f}%</td>"
                f"<td>{float(device.get('utilizationNon80211', 0)):.1f}%</td>"
                f"<td>{float(device.get('utilization80211Tx', 0)):.1f}%</td>"
                f"<td>{float(device.get('utilization80211Rx', 0)):.1f}%</td>"
                f"</tr>"
            )
        issues_html += "</tbody></table>"

    if not switch_port_issues and not config_issues and not high_util_devices:
        issues_html += (
            '<div class="summary-card">'
            '<div class="summary-body">No significant issues detected in the current data snapshot.</div>'
            "</div>"
        )

    issues_html += "</section>"

    # =========================================================
    # SECTION 5: PoE POWER ANALYSIS
    # =========================================================
    poe_html = """
    <section id="poe-analysis" class="report-section">
      <h1>6. PoE Power Analysis</h1>
    """
    if poe_switches:
        poe_html += render_section(
            "PoE Consumption by Switch (24 h average)",
            [
                [
                    s.get("serial", ""),
                    f"{float(s.get('avgWatts', 0)):.1f} W",
                    f"{float(s.get('powerUsageInWh', 0)):.1f} Wh",
                ]
                for s in poe_switches[:20]
            ],
        )
    if poe_ports:
        poe_html += render_section(
            "Top PoE Ports by Energy (24 h)",
            [
                [
                    p.get("serial", ""),
                    p.get("portId", ""),
                    f"{float(p.get('powerUsageInWh', 0)):.1f} Wh",
                ]
                for p in poe_ports[:20]
            ],
        )
    if not poe_switches and not poe_ports:
        poe_html += (
            '<div class="summary-card">'
            '<div class="summary-body">No PoE data available in this backup.</div>'
            "</div>"
        )
    poe_html += "</section>"

    # =========================================================
    # SECTION 6: SECURITY & COMPLIANCE
    # =========================================================
    # Build category-level summary from baseline checks
    _sec_by_cat: dict[str, list] = {}
    for _chk in security_checks:
        _cat = _chk.get("check", "Other")
        _sec_by_cat.setdefault(_cat, []).append(_chk)

    # Per-category pass/fail summary rows
    _sec_cat_rows = ""
    for _cat, _items in sorted(_sec_by_cat.items()):
        _cat_pass = sum(1 for c in _items if c.get("status", "").lower() == "pass")
        _cat_fail = sum(1 for c in _items if c.get("status", "").lower() == "fail")
        _cat_warn = sum(1 for c in _items if c.get("status", "").lower() == "warning")
        if _cat_fail:
            _cat_cls = "check-fail"
        elif _cat_warn:
            _cat_cls = "check-warning"
        else:
            _cat_cls = "check-pass"
        _net_names = ", ".join(sorted({c.get("networkName", "Org") for c in _items}))
        _detail = _items[0].get("description", "") if len(_items) == 1 else f"{len(_items)} networks evaluated"
        _sec_cat_rows += (
            f"<tr>"
            f"<td><strong>{_he(_cat)}</strong></td>"
            f'<td class="{_cat_cls}">'
            f'{"❌ Fail" if _cat_fail else ("⚠ Warning" if _cat_warn else "✔ Pass")}'
            f"</td>"
            f"<td>{_cat_pass + _cat_warn + _cat_fail} sites</td>"
            f"<td>{_he(_detail)}</td>"
            f"</tr>"
        )

    # Port forwarding posture summary
    _pf_checks = [c for c in security_checks if "port forwarding" in c.get("check", "").lower()]
    _pf_exposed = [c for c in _pf_checks if c.get("status", "").lower() != "pass"]
    if _pf_exposed:
        _pf_note = (
            f"<strong class='text-crit'>{len(_pf_exposed)} site(s) have internet-exposed port "
            f"forwarding rules that may require review.</strong> Each exposed rule creates a "
            "direct inbound path from the internet to an internal host. Confirm all forwarding "
            "rules are intentional, access-controlled, and documented."
        )
    elif _pf_checks:
        _pf_note = (
            f"No unrestricted internet-exposed port forwarding rules were detected across "
            f"{len(_pf_checks)} site(s) evaluated. Continue to review forwarding rules "
            "periodically as application requirements change."
        )
    else:
        _pf_note = (
            "Port forwarding posture could not be evaluated — appliance baseline data not "
            "available in this backup set."
        )

    # Overall security posture framing
    _sec_summary = security_baseline.get("summary", {}) if isinstance(security_baseline, dict) else {}
    _sec_total = sum(_sec_summary.values()) if _sec_summary else len(security_checks)
    if _sec_fail > 0:
        _sec_posture = (
            f"<strong class='text-crit'>Action required</strong> — {_sec_fail} check(s) failing "
            f"out of {_sec_total} evaluated. Failing checks represent active exposure that should "
            "be addressed before the next maintenance window."
        )
    elif _sec_warn > 0:
        _sec_posture = (
            f"<strong>Attention advised</strong> — {_sec_warn} check(s) in warning state. "
            "No critical failures detected, but warning-level gaps should be scheduled for "
            "remediation to harden posture proactively."
        )
    else:
        _sec_posture = (
            f"<strong>Posture is satisfactory</strong> — {_sec_pass} check(s) passed with no "
            "failures or warnings detected. Maintain current configuration discipline and "
            "review this section after any major firmware or policy change."
        )

    security_html = f"""
    <section id="security-baseline" class="report-section">
      <h1>7. Security &amp; Compliance</h1>
      <p>This section evaluates security posture from two angles: an appliance-level baseline
         check (AMP, IDS/IPS, spoof protection, and internet exposure) and a CIS Controls
         mapping in the following section. Together they form the security health layer of
         this network audit.</p>

      <div class="summary-card">
        <div class="summary-title">Security Posture Summary</div>
        <div class="summary-body">
          {_sec_posture}
          <br><br>
          <strong>Firewall &amp; Internet Exposure:</strong> {_pf_note}
          <br><br>
          <em>Note: L3 inbound firewall rule detail requires a separate collection step
          (<code>GET /networks/&#123;id&#125;/appliance/firewall/inboundFirewallRules</code>).
          That data is not present in this backup set. Add it to the pipeline to surface
          specific rule-level exposure in future reports.</em>
        </div>
      </div>

      <table class="data">
        <thead>
          <tr>
            <th>Check Category</th>
            <th>Result</th>
            <th>Scope</th>
            <th>Finding</th>
          </tr>
        </thead>
        <tbody>{_sec_cat_rows}</tbody>
      </table>

      {render_security_baseline(security_checks)}
    </section>
    """

    # =========================================================
    # SECTION 7: RECOMMENDATIONS & IMPLEMENTATION PLAN
    # =========================================================
    rec_html = md_to_html(rec_md)
    recommendations_html = f"""
    <section id="recommendations" class="report-section">
      <h1>8. Recommendations &amp; Implementation Plan</h1>
      {rec_html}
      <h2>Prioritized Action Timeline</h2>
      <div class="summary-card">
        <div class="summary-body">
          <ol>
            <li><strong>Immediate (0&ndash;2 weeks):</strong>
                Resolve port frame errors, duplex mismatches, and sub-gigabit port speeds.
                Investigate any offline devices.</li>
            <li><strong>Short-term (2&ndash;6 weeks):</strong>
                Address high-utilization APs &mdash; adjust channels, reduce SSID count,
                add APs, or relocate to improve coverage distribution.</li>
            <li><strong>Medium-term (6&ndash;12 weeks):</strong>
                Audit PoE budgets on high-draw switches. Plan upgrades if budget is
                within 20% of capacity. Standardize port configurations.</li>
            <li><strong>Long-term (3&ndash;6 months):</strong>
                Evaluate hardware refresh for devices approaching end-of-life.
                Implement network segmentation and 802.1X port authentication.</li>
          </ol>
        </div>
      </div>
    </section>
    """

    # =========================================================
    # SECTION 8: CIS 8 CONTROLS ASSESSMENT
    # =========================================================
    cis8_checks = [
        ("CIS 1 — Inventory & Control of Enterprise Assets",
         "Partial",
         f"{total_devices} devices tracked via Meraki Dashboard. Ensure all unmanaged "
         "assets are also inventoried in a CMDB or equivalent."),
        ("CIS 2 — Inventory & Control of Software Assets",
         "Info",
         "Software inventory is outside the scope of Meraki telemetry. "
         "Integrate with endpoint management (MDM/EDR) to close this gap."),
        ("CIS 3 — Data Protection",
         "Info",
         "Meraki provides VLAN segmentation and content filtering. Confirm data-at-rest "
         "encryption and DLP policies are in place at the endpoint and cloud layers."),
        ("CIS 4 — Secure Configuration of Enterprise Assets",
         "Partial" if switch_port_issues or config_issues else "Pass",
         f"{len(switch_port_issues)} port issue(s) and {len(config_issues)} config "
         "anomaly(ies) detected. Harden switch port configurations and review default "
         "VLAN assignments."),
        ("CIS 5 — Account Management",
         "Info",
         "Meraki Dashboard SSO/SAML integration should be enforced. Review Dashboard "
         "admin roles and remove stale accounts."),
        ("CIS 6 — Access Control Management",
         "Partial",
         "VLAN-based segmentation is in use. Evaluate 802.1X port authentication "
         "and Group Policy enforcement for granular access control."),
        ("CIS 7 — Continuous Vulnerability Management",
         "Warning",
         "Meraki auto-firmware updates should be enabled. Confirm devices are not "
         "running EOL firmware versions and that update windows are configured."),
        ("CIS 9 — Email & Web Browser Protections",
         "Info",
         "Meraki MX content filtering and threat protection can address parts of this "
         "control. Verify AMP and IDS/IPS are enabled on MX appliances."),
        ("CIS 12 — Network Infrastructure Management",
         "Partial" if switch_port_issues else "Pass",
         "Network topology is centrally managed. Review port configurations and ensure "
         "management VLAN is isolated from user traffic."),
        ("CIS 13 — Network Monitoring & Defense",
         "Warning",
         "Meraki Dashboard provides basic alerting. Integrate syslog with a SIEM for "
         "centralized event correlation and anomaly detection."),
    ]
    cis8_rows = "".join(
        f"<tr>"
        f"<td>{c[0]}</td>"
        f'<td><span class="check-{"pass" if c[1] == "Pass" else "warning" if c[1] in ("Partial","Warning") else "unknown"}">{c[1]}</span></td>'
        f"<td>{c[2]}</td>"
        f"</tr>"
        for c in cis8_checks
    )
    cis8_html = f"""
    <section id="cis8" class="report-section">
      <h1>9. CIS 8 Controls Assessment</h1>
      <p>The following table maps observable Meraki network data to relevant CIS Controls v8
         sub-controls. Items marked <em>Info</em> require data from systems outside the Meraki
         platform to fully evaluate.</p>
      <table class="data">
        <thead>
          <tr>
            <th>CIS Control</th>
            <th>Status</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>{cis8_rows}</tbody>
      </table>
    </section>
    """

    # =========================================================
    # SECTION 9: LICENSING SUMMARY
    # =========================================================
    licensing_mode = (
        licensing_data.get("licenseMode")
        if isinstance(licensing_data, dict)
        else None
    )
    org_license_paths = [os.path.join(path, "licensing.json") for path in org_dirs]
    org_license_payloads = [load_json(path) for path in org_license_paths]
    coverage_total = len(org_license_payloads)
    coverage_ok = sum(
        1
        for payload in org_license_payloads
        if isinstance(payload, dict) and not payload.get("error")
    )

    # Build license rows — supports both co-term key lists and per-device status APIs.
    # co-term: licenses is a list of {key, expired (bool), counts, editions, startedAt, duration}
    # per-device: licenses is a list of {licenseType/productType, status (str), expirationDate, ...}
    _lic_rows_html = ""
    _raw_lic_list = (
        licensing_data.get("licenses", [])
        if isinstance(licensing_data, dict)
        else []
    )
    for _lic in _raw_lic_list:
        if not isinstance(_lic, dict):
            continue
        # Determine model / product from whichever fields are present
        _counts = _lic.get("counts") or []  # co-term: [{"count": N, "model": "MR Enterprise"}]
        _editions = _lic.get("editions") or []  # co-term: [{"edition": "Ent", "productType": "appliance"}]
        if _counts:
            _lic_type = ", ".join(
                f"{c.get('count', '?')}× {c.get('model', '?')}" for c in _counts
            )
        else:
            _lic_type = _lic.get("licenseType") or _lic.get("productType") or "—"
        # Status — co-term uses expired bool; per-device uses status string
        _is_expired = (
            _lic.get("expired") is True
            or str(_lic.get("status", "")).lower() in ("expired", "inactive")
        )
        _is_invalidated = bool(_lic.get("invalidated"))
        if _is_invalidated:
            _status_str = "Invalidated"
            _status_cls = "warning"
        elif _is_expired:
            _status_str = "Expired"
            _status_cls = "fail"
        else:
            _status_str = _lic.get("status") or "Active"
            _status_cls = "pass"
        # Expiry date — co-term calculates from startedAt + duration (days); per-device has expirationDate
        _exp_date = _lic.get("expirationDate") or _lic.get("expiration") or "—"
        if _exp_date == "—" and _lic.get("startedAt") and _lic.get("duration"):
            try:
                _started = datetime.fromisoformat(_lic["startedAt"].replace("Z", "+00:00"))
                _exp_dt = _started + timedelta(days=int(_lic["duration"]))
                _exp_date = _exp_dt.strftime("%Y-%m-%d")
            except Exception:
                pass
        _key = _he(_lic.get("key") or "—")
        _lic_rows_html += (
            f"<tr>"
            f"<td><code style='font-size:9px'>{_key}</code></td>"
            f"<td>{_he(_lic_type)}</td>"
            f'<td><span class="check-{_status_cls}">{_status_str}</span></td>'
            f"<td>{_he(str(_exp_date))}</td>"
            f"</tr>"
        )

    _active_count = sum(
        1 for _l in _raw_lic_list
        if isinstance(_l, dict) and not _l.get("invalidated") and (
            _l.get("expired") is False
            or str(_l.get("status", "")).lower() in ("ok", "active", "in compliance")
        )
    )
    _expired_count = sum(
        1 for _l in _raw_lic_list
        if isinstance(_l, dict) and (
            _l.get("expired") is True
            or str(_l.get("status", "")).lower() in ("expired", "inactive")
        )
    )
    _total_lic = len(_raw_lic_list)

    if isinstance(licensing_data, dict) and licensing_data.get("error"):
        _lic_summary_note = (
            "<strong>Licensing data unavailable</strong> — the API returned an error for this "
            "organization. Verify that the API key has <em>read</em> access to the licensing "
            "endpoints and re-run the backup pipeline."
        )
    elif licensing_mode:
        _lic_summary_note = (
            f"This organization uses the <strong>{_he(licensing_mode)}</strong> licensing model. "
            f"Licensing is tracked at the organization level — {_total_lic} license key(s) on "
            f"record: <strong>{_active_count} active</strong>, "
            f"<strong class='{'text-crit' if _expired_count else ''}'>{_expired_count} expired</strong>. "
            "Meraki co-term licenses do not map 1:1 to individual devices or networks; Dashboard "
            "determines overall compliance from the combined pool of active seat counts."
        )
    else:
        _lic_summary_note = (
            "Licensing scope could not be determined from the collected payload. "
            "This section should be treated as partial until the pipeline is validated against "
            "the <code>/organizations/{id}/licenses/overview</code> endpoint."
        )

    if _lic_rows_html:
        _licensing_table = f"""
        <table class="data dense">
          <thead>
            <tr>
              <th>License Key</th>
              <th>Coverage (Model / Count)</th>
              <th>Status</th>
              <th>Expiration</th>
            </tr>
          </thead>
          <tbody>{_lic_rows_html}</tbody>
        </table>"""
    else:
        _licensing_table = """
        <div class="summary-card">
          <div class="summary-body">
            No license records were found in the collected backup. Ensure the backup pipeline
            calls <code>GET /organizations/{id}/licenses</code> and stores the result as
            <code>licensing.json</code>.
          </div>
        </div>"""

    licensing_html = f"""
    <section id="licensing" class="report-section">
      <h1>10. Licensing Summary</h1>
      <p>Cisco Meraki devices require active cloud-managed licenses to maintain Dashboard
         visibility and security feature enforcement. Expired licenses can cause devices to
         enter limited mode. Review expirations and plan renewals at least 90 days in advance.</p>
      <div class="summary-card">
        <div class="summary-title">Licensing Status &amp; Scope</div>
        <div class="summary-body">
          {_lic_summary_note}
          <br><br>
          Org backup coverage: <strong>{coverage_ok}/{coverage_total}</strong> org(s) with
          licensing data collected.
        </div>
      </div>
      {_licensing_table}
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

    # =========================================================
    # SECTION 10: CLIENT ANALYSIS
    # =========================================================
    ssid_counts: Dict[str, int] = {}
    os_counts: Dict[str, int] = {}
    vlan_counts: Dict[str, int] = {}
    auth_counts: Dict[str, int] = {}
    rssi_buckets = {"Excellent (>-60)": 0, "Good (-60 to -70)": 0,
                    "Fair (-70 to -80)": 0, "Poor (<-80)": 0}

    for cl in wireless_clients:
        ssid = cl.get("ssid") or "Unknown"
        ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1

        os_raw = cl.get("os") or cl.get("deviceTypePrediction") or "Unknown"
        os_counts[os_raw] = os_counts.get(os_raw, 0) + 1

        vlan = str(cl.get("vlan") or cl.get("vlanId") or "—")
        vlan_counts[vlan] = vlan_counts.get(vlan, 0) + 1

        auth = cl.get("status") or cl.get("authType") or "Unknown"
        auth_counts[auth] = auth_counts.get(auth, 0) + 1

        rssi = cl.get("rssi")
        if rssi is not None:
            try:
                rssi_val = int(rssi)
                if rssi_val > -60:
                    rssi_buckets["Excellent (>-60)"] += 1
                elif rssi_val >= -70:
                    rssi_buckets["Good (-60 to -70)"] += 1
                elif rssi_val >= -80:
                    rssi_buckets["Fair (-70 to -80)"] += 1
                else:
                    rssi_buckets["Poor (<-80)"] += 1
            except (ValueError, TypeError):
                pass

    def _top_rows(d: Dict[str, int], limit: int = 10) -> str:
        rows = sorted(d.items(), key=lambda x: x[1], reverse=True)[:limit]
        return "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows)

    rssi_rows = "".join(
        f"<tr><td>{bucket}</td><td>{cnt}</td></tr>"
        for bucket, cnt in rssi_buckets.items()
    )

    if wireless_clients:
        client_tables = f"""
        <h2>Clients by SSID</h2>
        <table class="data">
          <thead><tr><th>SSID</th><th>Client Count</th></tr></thead>
          <tbody>{_top_rows(ssid_counts)}</tbody>
        </table>

        <h2>Clients by OS / Device Type</h2>
        <table class="data">
          <thead><tr><th>OS / Device Type</th><th>Client Count</th></tr></thead>
          <tbody>{_top_rows(os_counts)}</tbody>
        </table>

        <h2>Clients by VLAN</h2>
        <table class="data">
          <thead><tr><th>VLAN</th><th>Client Count</th></tr></thead>
          <tbody>{_top_rows(vlan_counts)}</tbody>
        </table>

        <h2>Signal Strength Distribution</h2>
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

    client_analysis_html = f"""
    <section id="client-analysis" class="report-section">
      <h1>13. Client Analysis</h1>
      <p>Analysis of <strong>{len(wireless_clients)}</strong> wireless client record(s) captured
         in this backup. Wired client detail requires switch port client data which is not
         collected in the current pipeline.</p>
      {client_tables}
    </section>
    """

    return (
        cover_html
        + toc_html
        + exec_html
        + network_overview_html
        + topology_html
        + traffic_html
        + issues_html
        + poe_html
        + security_html
        + recommendations_html
        + cis8_html
        + licensing_html
        + wan_capacity_html
        + ap_interference_html
        + client_analysis_html
        + switch_deep_dive_html
    )

def main() -> int:
    org_dirs = find_org_dirs(BACKUPS_DIR)
    if not org_dirs:
        log.error("No org directories found in %s/", BACKUPS_DIR)
        log.error("Run meraki_backup.py first.")
        return 1

    generated = 0
    for org_dir in org_dirs:
        # Read display name from org_name.txt; fall back to directory name
        name_file = os.path.join(org_dir, "org_name.txt")
        if os.path.exists(name_file):
            with open(name_file, "r", encoding="utf-8") as nf:
                org_name = nf.read().strip()
        else:
            # Legacy fallback: derive from recommendations.md header
            org_name = os.path.basename(org_dir)
            rec_path = os.path.join(org_dir, "recommendations.md")
            if os.path.exists(rec_path):
                with open(rec_path, "r", encoding="utf-8") as f:
                    first_line = f.readline().strip()
                    m = re.match(r"# Meraki Recommendations: (.+)$", first_line)
                    if m:
                        org_name = m.group(1)

        log.info("Generating report for: %s", org_name)
        _run_ts = datetime.now()
        body = build_org_report(org_dir, org_name)
        html = build_html(f"{org_name} — Network Health Report", body)

        _slug = re.sub(r"[^\w]+", "_", org_name).strip("_")
        _stamp = _run_ts.strftime("%Y-%m-%d_%H%M")
        html_path = os.path.join(org_dir, f"{_slug}_{_stamp}_report.html")
        pdf_path  = os.path.join(org_dir, f"{_slug}_{_stamp}_report.pdf")
        # Stable aliases so downstream scripts and run.sh always find report.html/pdf
        html_alias = os.path.join(org_dir, "report.html")
        pdf_alias  = os.path.join(org_dir, "report.pdf")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        # Overwrite alias (plain copy — no symlinks for cross-platform safety)
        with open(html_alias, "w", encoding="utf-8") as f:
            f.write(html)

        ok = write_pdf(html_path, pdf_path)
        if ok:
            import shutil
            shutil.copy2(pdf_path, pdf_alias)
            log.info("PDF → %s", pdf_path)
        else:
            log.info("HTML → %s  (no PDF tool found)", html_path)
        generated += 1

    log.info("Done — %d report(s) generated.", generated)
    return 0
