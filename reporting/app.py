#!/usr/bin/env python3
import logging
import os
from datetime import datetime
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

    # KPI items
    kpi_items = [
        ("Total Sites", str(len(networks) or len(devices_by_network))),
        ("Total Devices", str(total_devices)),
        ("Online", str(device_status_counts.get("online", 0))),
        (
            "Offline / Alert",
            str(sum(v for k, v in device_status_counts.items() if k != "online")),
        ),
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

    # =========================================================
    # COVER PAGE
    # =========================================================
    _report_date = datetime.now().strftime("%B %d, %Y")
    cover_html = f"""
    <section class="cover">
      <div class="cover-inner">
        <div class="cover-top">
          <div class="cover-brand">Techmore</div>
          <div class="cover-rule"></div>
          <div class="cover-title">Network Health &amp;<br>Optimization Report</div>
          <div class="cover-subtitle">{org_name}</div>
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

    # Optional LLM-generated purpose paragraph
    _purpose_block = ""
    if exec_purpose:
        _purpose_block = f"""
      <div class="summary-card exec-purpose-card">
        <div class="summary-title">Report Purpose</div>
        <div class="summary-body">{exec_purpose}</div>
      </div>"""
    else:
        _purpose_block = f"""
      <div class="summary-card exec-purpose-card">
        <div class="summary-title">Report Purpose</div>
        <div class="summary-body">
          This report provides a comprehensive assessment of the <strong>{org_name}</strong>
          Cisco Meraki network infrastructure. It is intended to give stakeholders and
          technical teams a clear picture of current network health, traffic patterns,
          device performance, security posture, and licensing status. Findings are
          prioritized by operational impact, and each section includes actionable
          recommendations to guide remediation, capacity planning, and strategic
          improvements over the next 3&ndash;6 months.
        </div>
      </div>"""

    exec_html = f"""
    <section id="executive-summary" class="report-section exec-full-page">
      <h1>1. Executive Summary</h1>
      {_purpose_block}

      <h2>Network Function</h2>
      <div class="summary-card">
        <div class="summary-body">
          The <strong>{org_name}</strong> Cisco Meraki infrastructure provides managed enterprise
          networking across <strong>{len(devices_by_network)}</strong> site(s). The network delivers
          secure internet access, segmented LAN connectivity, and wireless coverage for end users
          and devices. All infrastructure is cloud-managed via the Meraki Dashboard, providing
          centralized visibility, automated firmware management, and real-time alerting. From an
          architecture standpoint, the value of this environment depends heavily on orderly upgrade
          cycles and consistent hardware tiers: edge/security appliances should be refreshed before
          support windows become a risk, switching should be upgraded in coherent distribution/access
          phases, and wireless generations should remain reasonably aligned so client experience and
          RF behavior are predictable across buildings. {_hardware_consistency_note(top_models)}
        </div>
      </div>

      <div class="summary-card">
        <div class="summary-title">Lifecycle &amp; Upgrade Planning</div>
        <div class="summary-body">
          Meraki environments age unevenly when older MX, MS, and MR families remain in service
          beside newer platforms. That creates mismatched uplink speeds, inconsistent PoE behavior,
          mixed firmware support horizons, and uneven client capabilities. For this reason, upgrade
          planning should prioritize hardware consistency by role: keep core/distribution switching
          on the highest-capacity supported models, standardize access switching where possible, and
          refresh older AP generations in site-based waves so roaming, airtime policy, and client
          throughput remain predictable.
        </div>
      </div>

      <h2>Component Descriptions</h2>
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
                DHCP/DNS server, content filtering, and SD-WAN path selection.
                All traffic entering or leaving the site passes through the MX.</td>
          </tr>
          <tr>
            <td><strong>Distribution / Access</strong></td>
            <td>MS Ethernet Switch</td>
            <td>{inv_by_type.get("switch", 0)}</td>
            <td>Wired LAN switching, VLAN segmentation, 802.1Q trunking between switches,
                PoE power delivery for access points and IP devices, and port-level
                access control via ACLs or 802.1X.</td>
          </tr>
          <tr>
            <td><strong>Wireless</strong></td>
            <td>MR Access Point</td>
            <td>{inv_by_type.get("wireless", 0)}</td>
            <td>802.11 wireless access on 2.4 GHz and 5 GHz bands, automatic RF channel
                and transmit power management, seamless client roaming, and
                SSID-to-VLAN mapping for traffic segmentation.</td>
          </tr>
        </tbody>
      </table>

      <h2>Health at a Glance</h2>
      {render_kpi_row(kpi_items)}

      <div class="summary-card">
        <div class="summary-title">Key Findings</div>
        <div class="summary-body">
          <ul>
            <li><strong>{online_count}</strong> of <strong>{total_devices}</strong> devices
                are currently online ({availability_pct}% availability)</li>
            <li><strong>{len(high_util_devices)}</strong> access point(s) operating at high
                channel utilization (&gt;70%), which may degrade wireless throughput and latency</li>
            <li><strong>{len(switch_port_issues)}</strong> switch port issue(s) detected
                based primarily on errors and potentially constrained uplink speeds</li>
            <li><strong>{len(config_issues)}</strong> configuration
                anomal{'y' if len(config_issues) == 1 else 'ies'} found in switch port settings</li>
            <li><strong>{len(poe_switches)}</strong> switch(es) with active PoE loads
                tracked over 24 hours</li>
            <li><strong>{len(top_models)}</strong> distinct hardware model entries observed in the
                inventory summary, reinforcing the need for lifecycle standardization</li>
          </ul>
        </div>
      </div>
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
    # SECTION 6: SECURITY BASELINE
    # =========================================================
    security_html = f"""
    <section id="security-baseline" class="report-section">
      <h1>7. Security Baseline</h1>
      <p>This section uses appliance baseline data when available from the backup pipeline.
         Older backup sets fall back to heuristic checks derived from device and port telemetry.</p>
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
    licensing_data = load_json(os.path.join(org_dir, "licensing.json")) or {}
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
    current_license_count = (
        len(licensing_data.get("licenses", []))
        if isinstance(licensing_data, dict) and isinstance(licensing_data.get("licenses"), list)
        else 0
    )
    if isinstance(licensing_data, dict) and licensing_data.get("error"):
        licensing_scope_note = "Licensing data unavailable for this organization."
    elif licensing_mode:
        licensing_scope_note = (
            f"Licensing is reported at the organization level for this environment ({licensing_mode} model); "
            "Meraki does not expose a true per-network license inventory in this dataset."
        )
    else:
        licensing_scope_note = (
            "Licensing scope could not be determined from the current payload. Treat this section as partial until the collection path is validated."
        )
    license_rows_html = ""
    if isinstance(licensing_data, dict) and licensing_data:
        for lic_key, lic_val in licensing_data.items():
            if isinstance(lic_val, dict):
                status = lic_val.get("status", "Unknown")
                exp = lic_val.get("expirationDate", lic_val.get("expiration", "—"))
                seats = lic_val.get("licensedDevices", lic_val.get("seats", "—"))
                license_rows_html += (
                    f"<tr><td>{lic_key}</td>"
                    f'<td><span class="check-{"pass" if str(status).lower() == "ok" else "warning"}">{status}</span></td>'
                    f"<td>{seats}</td><td>{exp}</td></tr>"
                )
            elif isinstance(lic_val, list):
                for item in lic_val:
                    if isinstance(item, dict):
                        lic_type = item.get("licenseType", item.get("productType", lic_key))
                        status = item.get("status", "Unknown")
                        exp = item.get("expirationDate", item.get("expiration", "—"))
                        seats = item.get("licensedDevices", item.get("seatCount", "—"))
                        license_rows_html += (
                            f"<tr><td>{lic_type}</td>"
                            f'<td><span class="check-{"pass" if str(status).lower() in ("ok","active") else "warning"}">{status}</span></td>'
                            f"<td>{seats}</td><td>{exp}</td></tr>"
                        )

    if license_rows_html:
        licensing_table = f"""
        <table class="data">
          <thead>
            <tr><th>License Type</th><th>Status</th><th>Licensed Devices</th><th>Expiration</th></tr>
          </thead>
          <tbody>{license_rows_html}</tbody>
        </table>"""
    else:
        licensing_table = """
        <div class="summary-card">
          <div class="summary-body">
            Licensing data was not retrieved in this backup run. Add the
            <code>GET /administered/licensing/subscription/subscriptions</code> or
            <code>GET /organizations/{organizationId}/licenses/overview</code> API call
            to the backup pipeline to populate this section.
          </div>
        </div>"""

    licensing_html = f"""
    <section id="licensing" class="report-section">
      <h1>10. Licensing Summary</h1>
      <p>Cisco Meraki devices require active cloud-managed licenses. Expired or
         co-termination gaps can result in devices losing Dashboard management and some
         security features. Review expiration dates and plan renewals at least 90 days
         in advance.</p>
      <div class="summary-card">
        <div class="summary-title">Licensing Scope &amp; Coverage</div>
        <div class="summary-body">
          { _he(licensing_scope_note) }
          <br><br>
          Coverage across locally available org backups: <strong>{coverage_ok}/{coverage_total}</strong>.
          Current org license records captured: <strong>{current_license_count}</strong>.
        </div>
      </div>
      {licensing_table}
      <div class="summary-card">
        <div class="summary-title">Licensing Best Practices</div>
        <div class="summary-body">
          <ul>
            <li>Enable co-termination or Enterprise Agreement where possible to simplify renewal cycles</li>
            <li>Set Dashboard expiry alerts at 90, 60, and 30 days before license end</li>
            <li>Verify device count in Dashboard matches physical inventory to avoid over- or under-licensing</li>
            <li>Confirm Advanced Security (AMP, IDS/IPS) licenses are applied to all MX appliances</li>
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
        body = build_org_report(org_dir, org_name)
        html = build_html(f"{org_name} — Network Health Report", body)

        html_path = os.path.join(org_dir, "report.html")
        pdf_path = os.path.join(org_dir, "report.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        ok = write_pdf(html_path, pdf_path)
        if ok:
            log.info("PDF → %s", pdf_path)
        else:
            log.info("HTML → %s  (no PDF tool found)", html_path)
        generated += 1

    log.info("Done — %d report(s) generated.", generated)
    return 0
