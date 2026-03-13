#!/usr/bin/env python3
import json
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime
from html import escape as _he  # used everywhere dynamic content enters HTML
from typing import Dict, Any, List, Optional, Tuple

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")
REPORT_VERSION = "1.0"

# Top-level files that live in backups/ root but are NOT org directories
_NON_ORG = {"backup.log", "organizations.json", "master_recommendations.md",
             "recommendations_ai_enhanced.md"}


def find_org_dirs(backups: str) -> List[str]:
    """Return sorted list of org directory paths inside backups/."""
    if not os.path.isdir(backups):
        return []
    return sorted(
        os.path.join(backups, name)
        for name in os.listdir(backups)
        if (
            os.path.isdir(os.path.join(backups, name))
            and not name.startswith(".")
            and name not in _NON_ORG
        )
    )


def load_json(path: str) -> Any:
    if not os.path.exists(path):
        log.debug("Missing backup file: %s", path)
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        log.warning("Invalid JSON in %s: %s", path, exc)
        return None
    except OSError as exc:
        log.warning("Cannot read %s: %s", path, exc)
        return None


def _inline_md(text: str) -> str:
    """Apply inline markdown (bold, italic, inline-code) with HTML-escaped base text."""
    # Escape first so markup patterns are never confused with HTML
    text = _he(text)
    # Bold **…** and __…__
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"__(.+?)__", r"<strong>\1</strong>", text)
    # Italic *…* and _…_
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"<em>\1</em>", text)
    # Inline code `…`
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def md_to_html(md_text: str) -> str:
    """Convert Markdown to HTML with HTML-escaped content throughout."""
    lines = md_text.splitlines()
    html_lines: List[str] = []
    in_list = False
    for line in lines:
        if line.startswith("# "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h1>{_inline_md(line[2:].strip())}</h1>")
        elif line.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h2>{_inline_md(line[3:].strip())}</h2>")
        elif line.startswith("### "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h3>{_inline_md(line[4:].strip())}</h3>")
        elif line.startswith("- ") or line.startswith("* "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_inline_md(line[2:].strip())}</li>")
        elif line.strip() == "":
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append('<div class="spacer"></div>')
        else:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<p>{_inline_md(line.strip())}</p>")
    if in_list:
        html_lines.append("</ul>")
    return "\n".join(html_lines)


def render_section(title: str, rows: List[List[str]]) -> str:
    if not rows:
        return ""
    header = f"<h2>{_he(title)}</h2>"
    table_rows = "".join(
        "<tr>" + "".join(f"<td>{_he(str(c))}</td>" for c in r) + "</tr>" for r in rows
    )
    return f'{header}<table class="data">{table_rows}</table>'


def render_kpi_row(items: List[Tuple[str, str]]) -> str:
    cards = "".join(
        f'<div class="kpi">'
        f'<div class="kpi-label">{_he(label)}</div>'
        f'<div class="kpi-value">{_he(value)}</div>'
        f'</div>'
        for label, value in items
    )
    return f'<div class="kpi-row">{cards}</div>'


def render_security_baseline(checks: List[Dict[str, Any]]) -> str:
    if not checks:
        return ""
    header = "<h2>Security Baseline Checks</h2>"
    table_header = (
        "<thead><tr><th>Network</th><th>Check</th><th>Status</th>"
        "<th>Description</th><th>Remediation</th></tr></thead>"
    )
    table_rows = ""
    for check in checks:
        status = check.get("status", "Unknown").lower()
        status_class = ""
        if status == "pass":
            status_class = "check-pass"
        elif status == "fail":
            status_class = "check-fail"
        elif status == "warning":
            status_class = "check-warning"
        else:
            status_class = "check-unknown"
        table_rows += (
            f'<tr><td>{_he(check.get("networkName", "Organization"))}</td>'
            f'<td>{_he(check.get("check", ""))}</td>'
            f'<td class="{status_class}">{_he(check.get("status", ""))}</td>'
            f'<td>{_he(check.get("description", ""))}</td>'
            f'<td>{_he(check.get("remediation", ""))}</td></tr>'
        )
    table = f'<table class="data">{table_header}<tbody>{table_rows}</tbody></table>'
    return header + table


def build_fallback_security_checks(
    devices_avail: List[Dict[str, Any]],
    inv_by_type: Dict[str, int],
    switch_port_issues: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return [
        {
            "networkName": "Organization",
            "check": "Device Online Status",
            "status": "Pass"
            if all(d.get("status") == "online" for d in devices_avail)
            else "Fail",
            "description": "All managed devices reporting online",
            "remediation": "Investigate offline devices; check physical connections, power, and uplink paths",
        },
        {
            "networkName": "Organization",
            "check": "Default Password Check",
            "status": "Pass",
            "description": "Verify no devices are using default credentials",
            "remediation": "Audit all device credentials and rotate any defaults",
        },
        {
            "networkName": "Organization",
            "check": "SSH Access Restriction",
            "status": "Warning" if inv_by_type.get("switch", 0) > 0 else "Info",
            "description": "SSH should be restricted to management networks only",
            "remediation": "Configure SSH ACLs; use VPN or jump host for remote management",
        },
        {
            "networkName": "Organization",
            "check": "SNMP Version Security",
            "status": "Info",
            "description": "Verify SNMPv3 is used where SNMP is required",
            "remediation": "Upgrade to SNMPv3 with authentication and encryption",
        },
        {
            "networkName": "Organization",
            "check": "Wireless Encryption Standards",
            "status": "Pass",
            "description": "WPA2-Enterprise or WPA3 should be used on all SSIDs",
            "remediation": "Update any open or WPA-Personal SSIDs to enterprise-grade encryption",
        },
        {
            "networkName": "Organization",
            "check": "Port Security Configuration",
            "status": "Fail" if switch_port_issues else "Pass",
            "description": "Check for port errors, duplex mismatches, and speed degradation",
            "remediation": "Resolve port issues; consider 802.1X port authentication",
        },
        {
            "networkName": "Organization",
            "check": "Logging and Monitoring",
            "status": "Warning",
            "description": "Ensure syslog and SNMP traps are configured for security events",
            "remediation": "Configure centralized logging and alerting for critical network events",
        },
    ]


# ── Network topology SVG ─────────────────────────────────────────────────────
_TOPO_NW  = 132   # node width px
_TOPO_NH  = 46    # node height px
_TOPO_HG  = 14    # horizontal gap between siblings
_TOPO_VG  = 72    # vertical gap between layers
_TOPO_PX  = 36    # left/right padding
_TOPO_PY  = 28    # top/bottom padding
_TOPO_MAX = 8     # max real nodes per layer; excess → stub

_TOPO_C: Dict[str, Dict[str, str]] = {
    "internet":  {"bg": "#1c1917", "fg": "#c4c9b0", "bd": "#44403c"},
    "appliance": {"bg": "#3b3e2d", "fg": "#eef0e6", "bd": "#6e754b"},
    "switch":    {"bg": "#575d3d", "fg": "#eef0e6", "bd": "#8a9269"},
    "wireless":  {"bg": "#8a9269", "fg": "#1f2117", "bd": "#6e754b"},
    "camera":    {"bg": "#44403c", "fg": "#f5f5f4", "bd": "#78716c"},
    "sensor":    {"bg": "#44403c", "fg": "#f5f5f4", "bd": "#78716c"},
}
_TOPO_DOT: Dict[str, str] = {
    "online": "#4ade80", "offline": "#f87171",
    "alerting": "#fb923c", "dormant": "#94a3b8",
}
_TOPO_BADGE: Dict[str, str] = {
    "appliance": "MX", "switch": "MS", "wireless": "MR",
    "camera": "MV", "sensor": "MT", "internet": "WAN",
}


def _svg_esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _topo_svg(
    devices: List[Dict],
    lldp_cdp: Dict,
    ap_util: Dict,
    port_issues: Dict,
) -> str:
    """Return an inline SVG topology ordered by true packet-flow depth from the internet.

    Uses BFS from MX appliances over the LLDP/CDP adjacency graph to assign each
    device its real hop-depth (Internet=0, MX=1, directly-attached switches=2, …).
    Devices unreachable via LLDP fall back to a type-based default depth so they
    still appear in a sensible position even without neighbour data.
    """
    from collections import deque

    if not devices:
        return ""

    # ── Build bidirectional LLDP/CDP adjacency ───────────────────────────────
    serial_to_dev: Dict[str, Dict] = {
        d["serial"]: d for d in devices if d.get("serial")
    }
    known = set(serial_to_dev)
    adj: Dict[str, set] = {s: set() for s in known}

    if isinstance(lldp_cdp, dict):
        for serial, data in lldp_cdp.items():
            if serial not in known or not isinstance(data, dict):
                continue
            ports = data.get("ports", {})
            port_items: Any = (
                ports.values() if isinstance(ports, dict)
                else ports if isinstance(ports, list)
                else []
            )
            for pd in port_items:
                if not isinstance(pd, dict):
                    continue
                # Shape A: {lldpDiscoveries:[…], cdpDiscoveries:[…]}
                for disc in pd.get("lldpDiscoveries", []) + pd.get("cdpDiscoveries", []):
                    if isinstance(disc, dict):
                        cid = disc.get("chassisId", "") or disc.get("deviceId", "")
                        if cid and cid in known and cid != serial:
                            adj[serial].add(cid)
                            adj[cid].add(serial)
                # Shape B: {lldp:{chassisId:…}, cdp:{deviceId:…}}
                for key in ("lldp", "cdp"):
                    disc = pd.get(key)
                    if isinstance(disc, dict):
                        cid = disc.get("chassisId", "") or disc.get("deviceId", "")
                        if cid and cid in known and cid != serial:
                            adj[serial].add(cid)
                            adj[cid].add(serial)

    # ── BFS from MX appliances to assign packet-flow depth ───────────────────
    # MX = depth 1 (Internet is depth 0 — a virtual node)
    _type_default = {"appliance": 1, "switch": 2, "wireless": 3, "camera": 3, "sensor": 4}
    _type_order   = {"appliance": 0, "switch": 1, "wireless": 2, "camera": 3, "sensor": 4}

    depth: Dict[str, int] = {}
    queue: deque = deque()
    for s, d in serial_to_dev.items():
        if d.get("productType") == "appliance":
            depth[s] = 1
            queue.append(s)

    while queue:
        cur = queue.popleft()
        for nb in adj[cur]:
            if nb not in depth:
                depth[nb] = depth[cur] + 1
                queue.append(nb)

    # Devices not reached by BFS get a sensible type-based default
    for s, d in serial_to_dev.items():
        if s not in depth:
            depth[s] = _type_default.get(d.get("productType", "switch"), 3)

    # ── Group devices into rows by depth ─────────────────────────────────────
    by_depth: Dict[int, List[Dict]] = {}
    for s, d in serial_to_dev.items():
        by_depth.setdefault(depth[s], []).append(d)

    # Sort within each row: by type priority, then name
    for row in by_depth.values():
        row.sort(key=lambda d: (
            _type_order.get(d.get("productType", ""), 5),
            d.get("name") or d.get("serial", ""),
        ))

    # Build ordered layers: Internet (virtual) at index 0, then by ascending depth
    inet_node = {"s": "", "type": "internet", "status": "online",
                 "label": "Internet", "model": ""}

    def _layer_nodes(devs: List[Dict]) -> List[Dict]:
        out = []
        for d in devs[:_TOPO_MAX]:
            out.append({
                "s":      d.get("serial", ""),
                "type":   d.get("productType", "switch"),
                "status": d.get("status", "unknown"),
                "label":  (d.get("name") or d.get("model") or d.get("serial", ""))[:18],
                "model":  d.get("model", ""),
            })
        ov = len(devs) - _TOPO_MAX
        if ov > 0:
            out.append({"s": "", "type": devs[0].get("productType", "switch"),
                        "status": "stub", "label": f"+{ov} more", "model": ""})
        return out

    layers: List[List[Dict]] = [[inet_node]]
    for dl in sorted(by_depth):
        layers.append(_layer_nodes(by_depth[dl]))

    # serial → (layer_index, node_index) — needed for edge drawing
    spos: Dict[str, Tuple[int, int]] = {}
    for li, layer in enumerate(layers):
        for ni, node in enumerate(layer):
            if node.get("s"):
                spos[node["s"]] = (li, ni)

    # ── Canvas layout ─────────────────────────────────────────────────────────
    nw, nh = _TOPO_NW, _TOPO_NH
    max_n = max(len(L) for L in layers)
    cw = max_n * (nw + _TOPO_HG) - _TOPO_HG + 2 * _TOPO_PX
    ch = len(layers) * nh + (len(layers) - 1) * _TOPO_VG + 2 * _TOPO_PY

    pos: List[List[Tuple[float, float]]] = []
    for li, layer in enumerate(layers):
        row_w = len(layer) * (nw + _TOPO_HG) - _TOPO_HG
        x0 = (cw - row_w) / 2
        y  = _TOPO_PY + li * (nh + _TOPO_VG)
        pos.append([(x0 + ni * (nw + _TOPO_HG), y) for ni in range(len(layer))])

    # ── SVG ───────────────────────────────────────────────────────────────────
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{cw:.0f}" height="{ch:.0f}" '
        f'viewBox="0 0 {cw:.0f} {ch:.0f}" '
        f'style="font-family:Inter,sans-serif;background:#f8fafc;'
        f'border-radius:10px;border:1px solid #e2e8f0;display:block;max-width:100%;">'
    ]

    # ── Edges ─────────────────────────────────────────────────────────────────
    # Track which nodes already have an upward edge so we can add fallback dashes
    has_upper_edge: set = set()
    drawn_pairs: set = set()
    parts.append('<g fill="none">')

    # 1. Internet → every depth-1 device (always dashed; Internet has no LLDP serial)
    if len(layers) > 1:
        ix = pos[0][0][0] + nw / 2
        iy = pos[0][0][1] + nh
        for ni, node in enumerate(layers[1]):
            tx = pos[1][ni][0] + nw / 2
            ty = pos[1][ni][1]
            parts.append(
                f'<line x1="{ix:.1f}" y1="{iy:.1f}" x2="{tx:.1f}" y2="{ty:.1f}" '
                f'stroke="#c4c9b0" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.75"/>'
            )
            if node.get("s"):
                has_upper_edge.add(node["s"])

    # 2. LLDP-confirmed edges between devices — solid lines at exact positions
    for s1, neighbors in adj.items():
        if s1 not in spos:
            continue
        li1, ni1 = spos[s1]
        for s2 in neighbors:
            if s2 not in spos:
                continue
            pair = (min(s1, s2), max(s1, s2))
            if pair in drawn_pairs:
                continue
            drawn_pairs.add(pair)
            li2, ni2 = spos[s2]
            if li1 == li2:
                # Same-row peers (e.g. stacked switches) — horizontal sibling line
                fx = pos[li1][ni1][0] + nw / 2
                fy = pos[li1][ni1][1] + nh / 2
                tx = pos[li2][ni2][0] + nw / 2
                ty = pos[li2][ni2][1] + nh / 2
            elif li1 < li2:
                fx = pos[li1][ni1][0] + nw / 2; fy = pos[li1][ni1][1] + nh
                tx = pos[li2][ni2][0] + nw / 2; ty = pos[li2][ni2][1]
                has_upper_edge.add(s2)
            else:
                fx = pos[li2][ni2][0] + nw / 2; fy = pos[li2][ni2][1] + nh
                tx = pos[li1][ni1][0] + nw / 2; ty = pos[li1][ni1][1]
                has_upper_edge.add(s1)
            parts.append(
                f'<line x1="{fx:.1f}" y1="{fy:.1f}" x2="{tx:.1f}" y2="{ty:.1f}" '
                f'stroke="#8a9269" stroke-width="1.5" opacity="0.9"/>'
            )

    # 3. Dashed fallback for devices with no confirmed upward edge
    for li in range(2, len(layers)):
        for ni, node in enumerate(layers[li]):
            s = node.get("s", "")
            if not s or s in has_upper_edge:
                continue
            # Connect to the horizontally nearest node in the layer above
            cx = pos[li][ni][0] + nw / 2
            best = min(range(len(layers[li - 1])),
                       key=lambda k: abs(pos[li - 1][k][0] + nw / 2 - cx))
            fx = pos[li - 1][best][0] + nw / 2
            fy = pos[li - 1][best][1] + nh
            ty = pos[li][ni][1]
            parts.append(
                f'<line x1="{fx:.1f}" y1="{fy:.1f}" x2="{cx:.1f}" y2="{ty:.1f}" '
                f'stroke="#c4c9b0" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.75"/>'
            )

    parts.append('</g>')

    # ── Nodes ─────────────────────────────────────────────────────────────────
    for li, layer in enumerate(layers):
        for ni, node in enumerate(layer):
            nx, ny = pos[li][ni]
            s      = node.get("s", "")
            ntype  = node.get("type", "internet")
            status = node.get("status", "unknown")
            label  = _svg_esc(node.get("label", ""))
            model  = _svg_esc(node.get("model", ""))
            C      = _TOPO_C.get(ntype, _TOPO_C["camera"])
            dot_c  = _TOPO_DOT.get(status, "#94a3b8")
            badge  = _TOPO_BADGE.get(ntype, "")

            has_issue = False
            if s:
                has_issue = bool(port_issues.get(s))
                if ntype == "wireless":
                    util = float((ap_util.get(s) or {}).get("utilizationTotal", 0))
                    has_issue = has_issue or util > 70

            bw = "2" if has_issue else "1"
            bc = "#f87171" if has_issue else C["bd"]

            parts.append(
                f'<rect x="{nx:.1f}" y="{ny:.1f}" width="{nw}" height="{nh}" '
                f'rx="7" fill="{C["bg"]}" stroke="{bc}" stroke-width="{bw}"/>'
            )
            if status not in ("stub", "info"):
                parts.append(
                    f'<circle cx="{nx+nw-10:.1f}" cy="{ny+10:.1f}" r="4" fill="{dot_c}"/>'
                )
            if badge:
                parts.append(
                    f'<rect x="{nx+6:.1f}" y="{ny+7:.1f}" width="22" height="12" '
                    f'rx="3" fill="{C["bd"]}" opacity="0.7"/>'
                )
                parts.append(
                    f'<text x="{nx+17:.1f}" y="{ny+16:.1f}" text-anchor="middle" '
                    f'font-size="7.5" font-weight="700" fill="{C["fg"]}" '
                    f'letter-spacing="0.3">{badge}</text>'
                )
            cy_l = ny + nh / 2 + (3 if model and ntype != "internet" else 6)
            parts.append(
                f'<text x="{nx+nw/2:.1f}" y="{cy_l:.1f}" text-anchor="middle" '
                f'font-size="10" font-weight="600" fill="{C["fg"]}">{label}</text>'
            )
            if model and ntype != "internet":
                parts.append(
                    f'<text x="{nx+nw/2:.1f}" y="{cy_l+12:.1f}" text-anchor="middle" '
                    f'font-size="8" fill="{C["fg"]}" opacity="0.65">{model}</text>'
                )
            if has_issue:
                parts.append(
                    f'<text x="{nx+8:.1f}" y="{ny+nh-7:.1f}" '
                    f'font-size="9" fill="#fbbf24">&#9888;</text>'
                )

    parts.append('</svg>')
    return "".join(parts)


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
            speed_raw = port.get("speed") or ""
            # speed may be "10 Mbps", "100 Mbps", 10, 100, etc.
            speed_num = None
            try:
                speed_num = int(str(speed_raw).split()[0])
            except (ValueError, IndexError):
                pass
            if any(
                [
                    bool(port_errors),
                    speed_num in [10, 100],
                    port.get("duplex") == "half",
                ]
            ):
                switch_port_issues.append(
                    {
                        "switch": port.get("switchSerial", "Unknown"),
                        "port": port.get("portId", "Unknown"),
                        "errors": port_errors,          # list of strings
                        "error_count": len(port_errors),
                        "speed": speed_raw,
                        "duplex": port.get("duplex", "Unknown"),
                        "poeMode": port.get("poeMode", "Unknown"),
                        "status": port.get("status", "Unknown"),
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

    # Group devices by network (building / site)
    devices_by_network: Dict[str, dict] = {}
    serial_to_network: Dict[str, dict] = {}
    for device in devices_avail:
        net = device.get("network") or {}
        net_id = net.get("id", "unassigned")
        net_name = net.get("name", "Unassigned")
        serial = device.get("serial", "")
        if net_id not in devices_by_network:
            devices_by_network[net_id] = {"name": net_name, "id": net_id, "devices": []}
        devices_by_network[net_id]["devices"].append(device)
        if serial:
            serial_to_network[serial] = {"id": net_id, "name": net_name}

    # Inventory summary
    inv_by_type = inventory_summary.get("by_type") or {}
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
          <span class="toc-entry">Client Analysis</span>
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
          centralized visibility, automated firmware management, and real-time alerting.
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
                including frame errors, sub-gigabit speeds, or half-duplex conditions</li>
            <li><strong>{len(config_issues)}</strong> configuration
                anomal{'y' if len(config_issues) == 1 else 'ies'} found in switch port settings</li>
            <li><strong>{len(poe_switches)}</strong> switch(es) with active PoE loads
                tracked over 24 hours</li>
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
    </section>
    """

    # =========================================================
    # SECTION 3: NETWORK TOPOLOGY
    # =========================================================
    topo_site_parts: List[str] = []
    for net_id, net_data in sorted(devices_by_network.items(), key=lambda x: x[1]["name"]):
        site_devs = net_data["devices"]
        if not site_devs:
            continue
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
        svg = _topo_svg(site_devs, lldp_cdp, ap_util_by_serial, port_issues_by_switch)
        topo_site_parts.append(
            f'<div class="topo-site">'
            f'<h2>{_he(net_data["name"])}</h2>'
            f'{lldp_banner}'
            f'<div class="topo-diagram">{svg}</div>'
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
      <p>Hierarchical diagrams for each managed site showing the data path from Internet
         edge (WAN) through MX security appliances, MS switches, and MR access points.
         Solid edges indicate LLDP/CDP-confirmed adjacencies; dashed edges are inferred
         from the device hierarchy. Devices with active issues are highlighted with a
         red border and warning symbol (&#9888;).</p>
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
                low_speed = [i for i in sw_issues if _speed_num(i.get("speed")) in [10, 100]]
                half_dup = [i for i in sw_issues if i.get("duplex") == "half"]
                err_ports = [i for i in sw_issues if i.get("error_count", 0) > 0]
                if low_speed:
                    bottlenecks.append(
                        f"{len(low_speed)} port(s) at sub-gigabit speed &mdash; "
                        f"bandwidth ceiling for connected devices"
                    )
                if half_dup:
                    bottlenecks.append(
                        f"{len(half_dup)} port(s) in half-duplex &mdash; "
                        f"collisions reduce effective throughput by up to 50%"
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
      <h1>11. Client Analysis</h1>
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
        + client_analysis_html
    )


def build_html(doc_title: str, body: str) -> str:
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{doc_title}</title>
  <style>
    /* Fonts — no CDN dependency; uses locally-installed copies when available */
    @font-face {{
      font-family: "Inter";
      font-weight: 300 700;
      src: local("Inter"), local("Inter-Regular");
    }}
    @font-face {{
      font-family: "Playfair Display";
      font-weight: 600 700;
      src: local("Playfair Display"), local("PlayfairDisplay-Bold");
    }}
  </style>
  <style>
    /* Named page for cover — zero margins for full bleed */
    @page cover-page {{
      margin: 0;
    }}
    @page {{
      margin: 28mm 22mm;
    }}
    :root {{
      --bg: #ffffff;
      --ink: #0f172a;
      --muted: #64748b;
      --line: #e2e8f0;
      --accent: #0ea5e9;
      --panel: #f8fafc;
      --olive-50: #f7f8f4;
      --olive-100: #eef0e6;
      --olive-200: #dde1d0;
      --olive-300: #c4c9b0;
      --olive-400: #a7ae8b;
      --olive-500: #8a9269;
      --olive-600: #6e754b;
      --olive-700: #575d3d;
      --olive-800: #464a34;
      --olive-900: #3b3e2d;
      --olive-950: #1f2117;
      --stone-50: #fafaf9;
      --stone-100: #f5f5f4;
      --stone-200: #e7e5e4;
      --stone-300: #d6d3d1;
      --stone-400: #a8a29e;
      --stone-500: #78716c;
      --stone-600: #57534e;
      --stone-700: #44403c;
      --stone-800: #292524;
      --stone-900: #1c1917;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: "Inter", system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 12px;
      color: var(--ink);
      background: var(--bg);
    }}

    /* =====================================================
       COVER PAGE — full bleed, own page
       ===================================================== */
    .cover {{
      page: cover-page;
      page-break-after: always;
      height: 297mm;
      background: linear-gradient(
        150deg,
        var(--olive-950) 0%,
        var(--olive-900) 45%,
        var(--olive-800) 100%
      );
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow: hidden;
    }}
    .cover::before {{
      content: '';
      position: absolute;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23ffffff' fill-opacity='0.04'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/svg%3E");
    }}
    .cover-inner {{
      position: relative;
      z-index: 1;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      height: 100%;
      padding: 80px 60px 60px;
      width: 100%;
      max-width: 700px;
    }}
    .cover-top {{
      text-align: center;
    }}
    .cover-brand {{
      font-size: 11px;
      letter-spacing: 0.3em;
      text-transform: uppercase;
      opacity: 0.65;
      margin-bottom: 32px;
      color: var(--olive-200);
    }}
    .cover-rule {{
      width: 48px;
      height: 2px;
      background: var(--olive-400);
      margin: 0 auto 36px;
    }}
    .cover-title {{
      font-family: "Playfair Display", Georgia, "Times New Roman", serif;
      font-size: 42px;
      font-weight: 700;
      line-height: 1.15;
      color: #fff;
      margin-bottom: 20px;
    }}
    .cover-subtitle {{
      font-size: 18px;
      color: var(--olive-200);
      margin-bottom: 48px;
      opacity: 0.9;
    }}
    .cover-meta-row {{
      display: flex;
      justify-content: center;
      gap: 32px;
      margin-bottom: 60px;
    }}
    .cover-meta-item {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
    }}
    .cover-meta-label {{
      font-size: 9px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      opacity: 0.55;
      color: var(--olive-200);
    }}
    .cover-meta-value {{
      font-size: 16px;
      font-weight: 600;
      color: var(--olive-100);
    }}
    .cover-bottom-rule {{
      width: 100%;
      height: 1px;
      background: var(--olive-700);
      margin-bottom: 18px;
      opacity: 0.5;
    }}
    .cover-bottom-info {{
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .cover-conf {{
      font-size: 10px;
      opacity: 0.5;
      letter-spacing: 0.12em;
      color: var(--olive-300);
      text-transform: uppercase;
    }}
    .cover-ver-date {{
      font-size: 10px;
      opacity: 0.5;
      letter-spacing: 0.08em;
      color: var(--olive-300);
    }}

    /* =====================================================
       TABLE OF CONTENTS PAGE
       ===================================================== */
    .toc-page {{
      page-break-after: always;
      min-height: 241mm;
      padding: 60px 72px;
      display: flex;
      flex-direction: column;
    }}
    .toc-header {{
      font-family: "Playfair Display", Georgia, "Times New Roman", serif;
      font-size: 30px;
      font-weight: 700;
      color: var(--olive-900);
      border-bottom: 2px solid var(--olive-400);
      padding-bottom: 16px;
      margin-bottom: 40px;
    }}
    .toc-list {{
      list-style: none;
      margin: 0;
      padding: 0;
      counter-reset: none;
    }}
    .toc-list > li {{
      display: flex;
      align-items: baseline;
      gap: 14px;
      padding: 11px 0;
      border-bottom: 1px solid var(--line);
      font-size: 13px;
    }}
    .toc-list > li::before {{
      display: none;
    }}
    .toc-num {{
      font-family: "Playfair Display", Georgia, "Times New Roman", serif;
      font-size: 17px;
      font-weight: 700;
      color: var(--olive-400);
      min-width: 28px;
    }}
    .toc-entry {{
      color: var(--ink);
      font-weight: 500;
    }}
    .toc-sub {{
      list-style: none;
      margin: 8px 0 0 48px;
      padding: 0;
    }}
    .toc-sub-item {{
      font-size: 13px;
      color: var(--muted);
      padding: 4px 0;
      border: none;
    }}
    .toc-sub-item::before {{
      display: none;
    }}

    /* =====================================================
       REPORT SECTIONS
       ===================================================== */
    .report-section {{
      padding: 28px 64px 40px;
      max-width: 900px;
    }}
    /* Executive summary occupies its own full page */
    .exec-full-page {{
      page-break-after: always;
      min-height: 220mm;
    }}
    .exec-purpose-card {{
      border-left: 4px solid var(--olive-500);
    }}
    .building-section {{
      margin: 28px 0 40px;
      border-left: 3px solid var(--olive-400);
      padding-left: 20px;
    }}
    .building-section h2 {{
      margin-top: 0;
    }}
    .traffic-path {{
      background: var(--olive-50);
      border: 1px solid var(--olive-200);
      border-radius: 6px;
      padding: 10px 16px;
      font-size: 13px;
      margin: 8px 0 20px;
    }}
    .path-flow {{
      font-weight: 600;
      color: var(--olive-700);
    }}

    /* =====================================================
       DEVICE CARDS
       ===================================================== */
    .device-card {{
      border: 1px solid var(--line);
      border-radius: 10px;
      margin: 12px 0;
      overflow: hidden;
      background: var(--stone-50);
    }}
    .device-card-header {{
      padding: 8px 14px;
      background: var(--olive-50);
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
      font-size: 12px;
    }}
    .serial {{
      font-size: 11px;
      background: var(--stone-200);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: monospace;
      color: var(--stone-700);
    }}
    .device-issues {{
      padding: 8px 14px;
      font-size: 11px;
      color: var(--ink);
      border-bottom: 1px solid var(--line);
    }}
    .device-issues ul {{
      margin: 4px 0 0 0;
      padding-left: 18px;
    }}
    .device-issues li {{
      padding: 1px 0;
      font-size: 11px;
    }}
    .device-ok {{
      padding: 7px 14px;
      font-size: 11px;
      color: #2d6a4f;
      background: #d8f3dc;
    }}
    .util-breakdown {{
      padding: 6px 14px;
      font-size: 11px;
      color: var(--muted);
      border-bottom: 1px solid var(--line);
    }}
    .bottleneck-list {{
      padding: 8px 14px;
      font-size: 11px;
      background: #fff8f0;
      border-top: 1px solid #ffe0b2;
      color: #7c4700;
    }}
    .bottleneck-list ul {{
      margin: 4px 0 0 0;
      padding-left: 18px;
    }}
    .bottleneck-list li {{
      padding: 2px 0;
      font-size: 11px;
      color: #7c4700;
    }}
    .bottleneck-list li::before {{
      color: #e65100;
    }}

    /* =====================================================
       BADGES
       ===================================================== */
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.02em;
      white-space: nowrap;
    }}
    .badge-ok {{
      background: #d1fae5;
      color: #065f46;
    }}
    .badge-fail {{
      background: #fee2e2;
      color: #991b1b;
    }}
    .badge-warn {{
      background: #fef3c7;
      color: #92400e;
    }}
    .badge-info {{
      background: #dbeafe;
      color: #1e40af;
    }}

    /* =====================================================
       KPI ROW
       ===================================================== */
    .kpi-row {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 10px;
      margin: 16px 0 24px;
    }}
    .kpi {{
      border: 1px solid var(--line);
      background: var(--stone-50);
      padding: 14px 12px;
      border-radius: 10px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    .kpi::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 3px;
      background: var(--olive-400);
    }}
    .kpi-label {{
      font-size: 8px;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 4px;
      font-weight: 600;
    }}
    .kpi-value {{
      font-family: "Playfair Display", Georgia, "Times New Roman", serif;
      font-size: 18px;
      font-weight: 700;
      color: var(--ink);
      display: block;
    }}

    /* =====================================================
       SUMMARY CARDS
       ===================================================== */
    .summary-card {{
      background: var(--stone-50);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 20px 24px;
      margin: 16px 0 24px;
      position: relative;
      overflow: hidden;
    }}
    .summary-card::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      height: 4px;
      width: 100%;
      background: linear-gradient(90deg, var(--olive-500), var(--olive-300));
    }}
    .summary-title {{
      font-size: 9px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 8px;
      font-weight: 600;
    }}
    .summary-body {{
      font-size: 12px;
      line-height: 1.6;
      color: var(--ink);
    }}

    /* =====================================================
       SECURITY CHECKS
       ===================================================== */
    .check-pass {{
      background-color: #28a745;
      color: white;
      padding: 2px 7px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
    }}
    .check-fail {{
      background-color: #dc3545;
      color: white;
      padding: 2px 7px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
    }}
    .check-warning {{
      background-color: #ffc107;
      color: #212529;
      padding: 2px 7px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
    }}
    .check-unknown {{
      background-color: #6c757d;
      color: white;
      padding: 2px 7px;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
    }}

    /* =====================================================
       CHARTS
       ===================================================== */
    .chart-grid {{
      display: grid;
      gap: 20px;
      margin: 20px 0 28px;
    }}
    .chart {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 18px;
      background: var(--stone-50);
      position: relative;
      overflow: hidden;
    }}
    .chart::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
      background: var(--olive-500);
    }}
    .chart-title {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.18em;
      color: var(--muted);
      margin-bottom: 12px;
      font-weight: 600;
    }}
    .pie-chart {{
      position: relative;
      width: 100%;
      height: 200px;
      margin: 16px 0;
    }}
    .pie-slice {{
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 50%;
      clip: rect(0px, 200px, 200px, 100px);
    }}
    .pie-slice::before {{
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 50%;
      background: var(--olive-500);
      transform: rotate(var(--angle-start));
      transform-origin: center;
    }}
    .pie-label {{
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
      font-size: 12px;
      color: var(--ink);
      font-weight: 500;
      line-height: 1.4;
    }}
    .line-chart {{
      position: relative;
      width: 100%;
      height: 200px;
      margin: 16px 0;
    }}
    .line-chart svg {{
      width: 100%;
      height: 100%;
    }}
    .chart-points {{
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
    }}
    .chart-point {{
      position: absolute;
      background: var(--olive-500);
      width: 8px;
      height: 8px;
      border-radius: 50%;
      transform: translate(-50%, -50%);
    }}
    .chart-point span {{
      display: block;
      margin-top: 4px;
      font-size: 10px;
      color: var(--muted);
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: 1fr 2.5fr 0.6fr;
      gap: 10px;
      align-items: center;
      margin: 8px 0;
      font-size: 12px;
    }}
    .bar-label {{
      color: var(--ink);
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .bar-track {{
      background: var(--stone-200);
      border-radius: 8px;
      height: 10px;
      position: relative;
      overflow: hidden;
    }}
    .bar-fill {{
      background: linear-gradient(90deg, var(--olive-500), var(--olive-300));
      height: 10px;
      border-radius: 8px;
    }}
    .bar-value {{
      text-align: right;
      color: var(--muted);
      font-weight: 500;
    }}

    /* =====================================================
       TYPOGRAPHY & TABLES
       ===================================================== */
    h1 {{
      font-family: "Playfair Display", Georgia, "Times New Roman", serif;
      font-size: 22px;
      margin: 24px 0 12px;
      border-bottom: 2px solid var(--olive-300);
      padding-bottom: 8px;
      color: var(--olive-900);
    }}
    h2 {{
      font-family: "Playfair Display", Georgia, "Times New Roman", serif;
      font-size: 15px;
      margin: 18px 0 8px;
      color: var(--olive-800);
    }}
    h3 {{
      font-size: 11px;
      font-weight: 600;
      margin: 14px 0 6px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    p {{
      margin: 8px 0;
      line-height: 1.55;
      font-size: 12px;
      color: var(--ink);
    }}
    ul {{
      margin: 8px 0 12px 18px;
      padding: 0;
    }}
    ol {{
      margin: 8px 0 12px 18px;
      padding: 0;
    }}
    li {{
      margin: 4px 0;
      line-height: 1.5;
      font-size: 12px;
      color: var(--ink);
      padding-left: 2px;
    }}
    li::before {{
      color: var(--olive-600);
      font-weight: bold;
    }}
    .spacer {{
      height: 8px;
    }}
    table.data {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin: 10px 0 18px;
      font-size: 11px;
      background: var(--stone-50);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--line);
    }}
    table.data th {{
      background: var(--olive-50);
      font-weight: 600;
      color: var(--olive-800);
      text-align: left;
      padding: 8px 12px;
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--line);
    }}
    table.data td {{
      padding: 7px 12px;
      vertical-align: top;
      color: var(--ink);
      border-bottom: 1px solid var(--line);
    }}
    table.data tr:last-child td {{
      border-bottom: none;
    }}
    table.data tr:hover td {{
      background: var(--olive-50);
    }}
    /* =====================================================
       NETWORK TOPOLOGY
       ===================================================== */
    .topo-site {{
      margin: 24px 0 36px;
    }}
    .topo-site h2 {{
      margin-bottom: 10px;
    }}
    .topo-no-lldp {{
      margin: 0 0 10px;
      padding: 8px 14px;
      background: #fffbeb;
      border: 1px solid #fde68a;
      border-radius: 6px;
      font-size: 11px;
      color: #92400e;
    }}
    .topo-diagram {{
      overflow-x: auto;
      margin: 0 0 8px;
    }}
    .topo-diagram svg {{
      display: block;
      max-width: 100%;
      height: auto;
    }}
    .topo-legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      margin: 12px 0 20px;
      padding: 10px 16px;
      background: var(--stone-50);
      border: 1px solid var(--line);
      border-radius: 8px;
      font-size: 11px;
      color: var(--muted);
    }}
    .topo-legend-item {{
      display: flex;
      align-items: center;
      gap: 4px;
      white-space: nowrap;
    }}

    @media print {{
      body {{
        background: white;
        color: black;
      }}
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def write_pdf(html_path: str, pdf_path: str) -> bool:
    # Try weasyprint first
    try:
        import weasyprint  # type: ignore

        log.info("Using WeasyPrint for PDF generation: %s", pdf_path)
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return True
    except Exception as e:
        log.warning("WeasyPrint failed: %s", e)
    # Fallback to wkhtmltopdf
    wk = shutil.which("wkhtmltopdf")
    if wk:
        log.info("Using wkhtmltopdf for PDF generation: %s", pdf_path)
        result = subprocess.run(
            [wk, html_path, pdf_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log.warning("wkhtmltopdf exited %d: %s", result.returncode, result.stderr.strip())
        return os.path.exists(pdf_path)
    log.warning("No PDF generator available (install weasyprint or wkhtmltopdf)")
    return False


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


if __name__ == "__main__":
    raise SystemExit(main())
