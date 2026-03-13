#!/usr/bin/env python3
import json
import logging
import math
import os
import re
import shutil
import subprocess
from datetime import datetime
from html import escape as _he  # used everywhere dynamic content enters HTML
from collections import deque
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
_TOPO_NW        = 132    # node width px
_TOPO_NH        = 46     # node height px  (internet / default)
_TOPO_NH_MX     = 150    # appliance card height px
_TOPO_NH_SW     = 130    # switch card height px
_TOPO_HG        = 14     # horizontal gap between siblings
_TOPO_VG        = 72     # vertical gap between layers
_TOPO_PX        = 36     # left/right padding
_TOPO_PY        = 28     # top/bottom padding
_TOPO_MAX       = 8      # max real nodes per layer; excess → stub
_TOPO_SPLIT_THR = 8      # max switches in any layer before per-branch pagination

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


def _card_h(ntype: str) -> int:
    """Return card height in px for a given device type."""
    return {"appliance": _TOPO_NH_MX, "switch": _TOPO_NH_SW}.get(ntype, _TOPO_NH)


# ── Enrichment helpers ────────────────────────────────────────────────────────

def _mx_wan_lines(serial: str, uplink_statuses: List) -> List[str]:
    """Return display strings for each WAN interface on an MX (public IP + status)."""
    lines = []
    for entry in (uplink_statuses if isinstance(uplink_statuses, list) else []):
        if entry.get("serial") != serial:
            continue
        for ul in entry.get("uplinks", []):
            iface = ul.get("interface", "").upper()
            pub = ul.get("publicIp") or ul.get("ip") or ""
            status = ul.get("status", "")
            suffix = "" if status == "active" else f" ({status})"
            if pub:
                lines.append(f"{iface}: {pub}{suffix}")
    return lines[:2]


def _mx_peak_gbps(network_id: str, uplinks_usage: Any) -> Dict[str, float]:
    """Return {"wan1": peak_GB, "wan2": peak_GB} from hourly usage history."""
    entries = uplinks_usage.get(network_id, []) if isinstance(uplinks_usage, dict) else []
    peak: Dict[str, float] = {}
    for entry in (entries if isinstance(entries, list) else []):
        for iface in entry.get("byInterface", []):
            name = (iface.get("interface") or "").lower()
            gb = (iface.get("sent", 0) + iface.get("received", 0)) / 1e9
            if gb > peak.get(name, 0.0):
                peak[name] = gb
    return peak


def _switch_vlans(serial: str, port_configs_by_switch: Dict) -> str:
    """Compact VLAN summary for a switch from its port configs."""
    ports = port_configs_by_switch.get(serial, [])
    vlans: set = set()
    for p in (ports if isinstance(ports, list) else []):
        if not isinstance(p, dict):
            continue
        if p.get("type") == "access":
            v = p.get("vlan")
            if v and str(v).isdigit():
                vlans.add(int(v))
        elif p.get("type") == "trunk":
            for part in str(p.get("allowedVlans") or "").split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        a, b = part.split("-", 1)
                        vlans.update(range(int(a), min(int(b) + 1, int(a) + 64)))
                    except ValueError:
                        pass
                elif part.isdigit():
                    vlans.add(int(part))
    if not vlans:
        return ""
    s = sorted(vlans)
    if len(s) > 8:
        return f"{len(s)} VLANs"
    return "VLANs: " + ", ".join(str(v) for v in s)


def _switch_client_count(serial: str, port_statuses_by_switch: Dict) -> int:
    """Sum clientCount across all ports on a switch."""
    ports = port_statuses_by_switch.get(serial, {})
    if isinstance(ports, list):
        return sum(p.get("clientCount", 0) for p in ports if isinstance(p, dict))
    if isinstance(ports, dict):
        return sum(p.get("clientCount", 0) for p in ports.values() if isinstance(p, dict))
    return 0


def _switch_poe_str(serial: str, port_statuses_by_switch: Dict) -> str:
    """Average PoE draw in watts over the 24h collection window, or ''."""
    ports = port_statuses_by_switch.get(serial, {})
    port_list = ports if isinstance(ports, list) else list(ports.values()) if isinstance(ports, dict) else []
    total_wh = sum(p.get("powerUsageInWh", 0) for p in port_list if isinstance(p, dict))
    avg_w = total_wh / 24.0
    return f"{avg_w:.0f}W PoE" if avg_w >= 1 else ""


# ── Pagination helper ─────────────────────────────────────────────────────────

def _topo_pages(
    devices: List[Dict],
    lldp_cdp: Dict,
    ap_util: Dict,
    port_issues: Dict,
    switch_port_statuses_by_switch: Dict[str, Any],
    enrichment: Optional[Dict] = None,
) -> List[Dict[str, str]]:
    """
    Return a list of {"title": str, "svg": str} dicts — one per diagram page.

    Small sites (≤ _TOPO_SPLIT_THR switches in any layer) return a single entry.
    Large sites (WPC-style campuses) return an overview + one entry per tier-2 branch
    so each diagram fits comfortably on a PDF page.
    """
    if not devices:
        return [{"title": "", "svg": ""}]

    # ── Build adjacency (shared logic, duplicated minimally here) ────────────
    def _norm(v: Any) -> str:
        return "".join(c for c in str(v).lower() if c.isalnum())

    s2d: Dict[str, Dict] = {d["serial"]: d for d in devices if d.get("serial")}
    id2s: Dict[str, str] = {}
    for serial, dev in s2d.items():
        id2s[_norm(serial)] = serial
        if dev.get("mac"):
            id2s[_norm(dev["mac"])] = serial

    sw_status: Dict[str, Dict[str, Dict]] = {}
    if isinstance(switch_port_statuses_by_switch, dict):
        for serial, ports in switch_port_statuses_by_switch.items():
            if isinstance(ports, list):
                sw_status[serial] = {str(p.get("portId")): p for p in ports if isinstance(p, dict)}

    def _upstream_rank(serial: str) -> int:
        dev = s2d[serial]
        if dev.get("productType") == "appliance":
            return 1000
        ports = sw_status.get(serial, {})
        return (400
                + sum(20 for p in ports.values() if "10 Gbps" in str(p.get("speed") or ""))
                + sum(5 for p in ports.values() if p.get("isUplink"))
                + len(ports))

    links: List[Dict] = []
    seen: set = set()
    for local_s, data in (lldp_cdp.items() if isinstance(lldp_cdp, dict) else []):
        if local_s not in s2d or not isinstance(data, dict):
            continue
        ports = data.get("ports", {})
        if not isinstance(ports, dict):
            continue
        for local_port, pd in ports.items():
            if not isinstance(pd, dict):
                continue
            for disc in [pd.get("lldp"), pd.get("cdp")]:
                if not isinstance(disc, dict):
                    continue
                tgt = None
                for cand in (disc.get("chassisId"), disc.get("deviceId"), pd.get("deviceMac")):
                    tgt = id2s.get(_norm(cand))
                    if tgt:
                        break
                if not tgt or tgt == local_s:
                    continue
                key = (local_s, str(local_port), tgt)
                if key in seen:
                    continue
                seen.add(key)
                lst = sw_status.get(local_s, {}).get(str(local_port), {})
                links.append({"local": local_s, "local_port": str(local_port),
                               "local_is_uplink": bool(lst.get("isUplink")),
                               "local_speed": str(lst.get("speed") or ""),
                               "remote": tgt,
                               "remote_port": str(disc.get("portId") or "")})

    children: Dict[str, List[str]] = {}
    parent_of: Dict[str, str] = {}
    cands: Dict[str, List] = {}
    for lnk in links:
        lt = s2d[lnk["local"]].get("productType")
        rt = s2d[lnk["remote"]].get("productType")
        child = parent = ""
        score = 0
        if lnk["local_is_uplink"] and rt in ("switch", "appliance"):
            child, parent, score = lnk["local"], lnk["remote"], 100
        elif lt == "appliance" and rt != "appliance":
            child, parent, score = lnk["remote"], lnk["local"], 90
        elif rt == "appliance" and lt != "appliance":
            child, parent, score = lnk["local"], lnk["remote"], 90
        elif lt == "switch" and rt in ("wireless", "camera", "sensor"):
            child, parent, score = lnk["remote"], lnk["local"], 80
        elif rt == "switch" and lt in ("wireless", "camera", "sensor"):
            child, parent, score = lnk["local"], lnk["remote"], 80
        elif lt == "switch" and rt == "switch":
            if _upstream_rank(lnk["local"]) >= _upstream_rank(lnk["remote"]):
                child, parent, score = lnk["remote"], lnk["local"], 60
            else:
                child, parent, score = lnk["local"], lnk["remote"], 60
        if child and parent and child != parent:
            cands.setdefault(child, []).append((score, parent))

    for child, options in cands.items():
        options.sort(key=lambda x: (-x[0], -_upstream_rank(x[1])))
        parent = options[0][1]
        parent_of[child] = parent
        children.setdefault(parent, []).append(child)

    roots = [s for s, d in s2d.items() if d.get("productType") == "appliance" and s not in parent_of]
    if not roots:
        roots = [s for s, d in s2d.items() if d.get("productType") == "switch" and s not in parent_of]
    if not roots:
        roots = [next(iter(s2d))]

    depth: Dict[str, int] = {}

    def _assign(serial: str, val: int) -> None:
        if serial in depth and depth[serial] <= val:
            return
        depth[serial] = val
        for c in children.get(serial, []):
            _assign(c, val + 1)

    for r in roots:
        _assign(r, 1)
    _fallback = {"appliance": 1, "switch": 2, "wireless": 3, "camera": 3, "sensor": 4}
    for s, d in s2d.items():
        if s not in depth:
            depth[s] = _fallback.get(d.get("productType", ""), 3)

    sw_serials = [s for s, d in s2d.items()
                  if d.get("productType") in ("appliance", "switch")]
    by_depth: Dict[int, List[str]] = {}
    for s in sw_serials:
        by_depth.setdefault(depth[s], []).append(s)

    max_layer = max((len(v) for v in by_depth.values()), default=0)

    # ── Small site — single diagram ──────────────────────────────────────────
    if max_layer <= _TOPO_SPLIT_THR:
        return [{"title": "", "svg": _topo_svg(
            devices, lldp_cdp, ap_util, port_issues,
            switch_port_statuses_by_switch, enrichment=enrichment,
        )}]

    # ── Large site — overview + per-branch detail ────────────────────────────
    tier2 = [s for s, d in s2d.items()
             if depth.get(s) == 2 and d.get("productType") == "switch"]

    pages: List[Dict[str, str]] = []

    # Overview: MX + all tier-2 switches only
    overview_devs = [d for d in devices
                     if d.get("productType") == "appliance"
                     or d["serial"] in tier2]
    pages.append({"title": "Overview — Core / Distribution Layer",
                  "svg": _topo_svg(
                      overview_devs, lldp_cdp, ap_util, port_issues,
                      switch_port_statuses_by_switch, enrichment=enrichment,
                  )})

    # Per-branch detail: tier-2 switch + its full subtree + parent MX stub
    type_order = {"appliance": 0, "switch": 1, "wireless": 2, "camera": 3, "sensor": 4}
    tier2_sorted = sorted(tier2, key=lambda s: (
        type_order.get(s2d[s].get("productType", ""), 9),
        s2d[s].get("name") or s,
    ))

    for t2 in tier2_sorted:
        subtree: set = set()
        q: deque = deque([t2])
        while q:
            node = q.popleft()
            subtree.add(node)
            for c in children.get(node, []):
                q.append(c)
        # Branch diagram: tier-2 switch + its subtree only.
        # No Internet node, no MX stub — the tier-2 switch is the root.
        # Its card already shows "Above: MX_NAME" as context.
        branch_devs = [d for d in devices if d.get("serial") in subtree]
        branch_name = s2d[t2].get("name") or s2d[t2].get("model") or t2
        pages.append({"title": branch_name,
                      "svg": _topo_svg(
                          branch_devs, lldp_cdp, ap_util, port_issues,
                          switch_port_statuses_by_switch, enrichment=enrichment,
                          show_internet=False,
                      )})

    return pages


def _topo_svg(
    devices: List[Dict],
    lldp_cdp: Dict,
    ap_util: Dict,
    port_issues: Dict,
    switch_port_statuses_by_switch: Dict[str, Any],
    enrichment: Optional[Dict] = None,
    show_internet: bool = True,
) -> str:
    """Return an inline SVG topology using parent/child relationships from ports."""
    if not devices:
        return ""

    enr = enrichment or {}
    node_w = 196
    node_h = 108        # internet / default card height
    layer_gap = 104
    col_gap = 20
    pad_x = 28
    pad_y = 26

    def _norm(value: Any) -> str:
        return "".join(ch for ch in str(value).lower() if ch.isalnum())

    def _port_sort_key(value: Any) -> Tuple[int, str]:
        text = str(value)
        m = re.match(r"(\d+)", text)
        if m:
            return (0, f"{int(m.group(1)):05d}{text}")
        return (1, text)

    serial_to_dev: Dict[str, Dict[str, Any]] = {
        d["serial"]: d for d in devices if d.get("serial")
    }
    if not serial_to_dev:
        return ""

    id_to_serial: Dict[str, str] = {}
    for serial, dev in serial_to_dev.items():
        id_to_serial[_norm(serial)] = serial
        if dev.get("mac"):
            id_to_serial[_norm(dev.get("mac"))] = serial

    status_by_switch: Dict[str, Dict[str, Dict[str, Any]]] = {}
    if isinstance(switch_port_statuses_by_switch, dict):
        for serial, ports in switch_port_statuses_by_switch.items():
            if isinstance(ports, list):
                status_by_switch[serial] = {
                    str(p.get("portId")): p for p in ports if isinstance(p, dict)
                }

    links: List[Dict[str, Any]] = []
    link_seen: set = set()
    for local_serial, data in lldp_cdp.items() if isinstance(lldp_cdp, dict) else []:
        if local_serial not in serial_to_dev or not isinstance(data, dict):
            continue
        ports = data.get("ports", {})
        if not isinstance(ports, dict):
            continue
        for local_port, port_data in ports.items():
            if not isinstance(port_data, dict):
                continue
            candidates = []
            for key in ("lldp", "cdp"):
                disc = port_data.get(key)
                if isinstance(disc, dict):
                    candidates.append(disc)
            for disc in candidates:
                target_serial = None
                for candidate in (
                    disc.get("chassisId"),
                    disc.get("deviceId"),
                    port_data.get("deviceMac"),
                ):
                    target_serial = id_to_serial.get(_norm(candidate))
                    if target_serial:
                        break
                if not target_serial or target_serial == local_serial:
                    continue
                dedupe = (local_serial, str(local_port), target_serial)
                if dedupe in link_seen:
                    continue
                link_seen.add(dedupe)
                local_status = status_by_switch.get(local_serial, {}).get(str(local_port), {})
                links.append(
                    {
                        "local": local_serial,
                        "local_port": str(local_port),
                        "local_is_uplink": bool(local_status.get("isUplink")),
                        "local_speed": str(local_status.get("speed") or ""),
                        "remote": target_serial,
                        "remote_port": str(disc.get("portId") or ""),
                        "system_name": disc.get("systemName") or "",
                        "confirmed": True,
                    }
                )

    node_info: Dict[str, Dict[str, Any]] = {}
    children: Dict[str, List[str]] = {}
    parent_of: Dict[str, str] = {}
    parent_link_of: Dict[str, Dict[str, Any]] = {}

    def _upstream_rank(serial: str) -> int:
        dev = serial_to_dev[serial]
        if dev.get("productType") == "appliance":
            return 1000
        ports = status_by_switch.get(serial, {})
        port_count = len(ports)
        uplinks = sum(1 for p in ports.values() if p.get("isUplink"))
        ten_g = sum(1 for p in ports.values() if "10 Gbps" in str(p.get("speed") or ""))
        return 400 + ten_g * 20 + uplinks * 5 + port_count

    for serial, dev in serial_to_dev.items():
        node_info[serial] = {
            "serial": serial,
            "type": dev.get("productType", "switch"),
            "status": dev.get("status", "unknown"),
            "label": (dev.get("name") or dev.get("model") or serial)[:22],
            "model": dev.get("model", ""),
            "ports": sorted(status_by_switch.get(serial, {}).values(), key=lambda p: _port_sort_key(p.get("portId"))),
        }

    candidate_parents: Dict[str, List[Tuple[int, str, Dict[str, Any]]]] = {}
    for link in links:
        left = serial_to_dev[link["local"]]
        right = serial_to_dev[link["remote"]]
        ltype = left.get("productType")
        rtype = right.get("productType")

        child = ""
        parent = ""
        score = 0
        if link["local_is_uplink"] and rtype in ("switch", "appliance"):
            child, parent, score = link["local"], link["remote"], 100
        elif ltype == "appliance" and rtype != "appliance":
            child, parent, score = link["remote"], link["local"], 90
        elif rtype == "appliance" and ltype != "appliance":
            child, parent, score = link["local"], link["remote"], 90
        elif ltype == "switch" and rtype in ("wireless", "camera", "sensor"):
            child, parent, score = link["remote"], link["local"], 80
        elif rtype == "switch" and ltype in ("wireless", "camera", "sensor"):
            child, parent, score = link["local"], link["remote"], 80
        elif ltype == "switch" and rtype == "switch":
            if _upstream_rank(link["local"]) >= _upstream_rank(link["remote"]):
                child, parent, score = link["remote"], link["local"], 60
            else:
                child, parent, score = link["local"], link["remote"], 60

        if child and parent and child != parent:
            candidate_parents.setdefault(child, []).append((score, parent, link))

    for child, options in candidate_parents.items():
        options.sort(key=lambda item: (-item[0], -_upstream_rank(item[1]), item[1]))
        _, parent, link = options[0]
        parent_of[child] = parent
        parent_link_of[child] = link
        children.setdefault(parent, []).append(child)

    roots = [
        serial for serial, dev in serial_to_dev.items()
        if dev.get("productType") == "appliance" and serial not in parent_of
    ]
    if not roots:
        roots = [
            serial for serial, dev in serial_to_dev.items()
            if dev.get("productType") == "switch" and serial not in parent_of
        ]
    if not roots:
        roots = [next(iter(serial_to_dev))]

    depth: Dict[str, int] = {}

    def _assign_depth(serial: str, value: int) -> None:
        if serial in depth and depth[serial] <= value:
            return
        depth[serial] = value
        for child in children.get(serial, []):
            _assign_depth(child, value + 1)

    for root in roots:
        _assign_depth(root, 1)
    for serial, dev in serial_to_dev.items():
        if serial not in depth:
            fallback = {"appliance": 1, "switch": 2, "wireless": 3, "camera": 3, "sensor": 4}
            depth[serial] = fallback.get(dev.get("productType"), 3)

    display_serials = [
        serial for serial, dev in serial_to_dev.items()
        if dev.get("productType") in ("appliance", "switch")
    ]
    if not display_serials:
        display_serials = list(serial_to_dev.keys())

    by_depth: Dict[int, List[str]] = {}
    type_order = {"appliance": 0, "switch": 1, "wireless": 2, "camera": 3, "sensor": 4}
    for serial, value in depth.items():
        if serial not in display_serials:
            continue
        by_depth.setdefault(value, []).append(serial)
    for serials in by_depth.values():
        serials.sort(key=lambda serial: (
            type_order.get(serial_to_dev[serial].get("productType", ""), 9),
            serial_to_dev[serial].get("name") or serial,
        ))

    layers: List[List[str]] = ([["__internet__"]] if show_internet else [])
    for value in sorted(by_depth):
        layers.append(by_depth[value])

    def _lh(layer: List[str]) -> int:
        """Max card height in a layer."""
        return max(
            (_card_h("internet") if s == "__internet__"
             else _card_h(serial_to_dev[s].get("productType", "")))
            for s in layer
        )

    max_cols = max(len(layer) for layer in layers)
    canvas_w = max_cols * (node_w + col_gap) - col_gap + 2 * pad_x
    positions: Dict[str, Tuple[float, float]] = {}
    layer_bottom: Dict[int, float] = {}

    cur_y = float(pad_y)
    for layer_index, layer in enumerate(layers):
        lh = _lh(layer)
        row_w = len(layer) * (node_w + col_gap) - col_gap
        x0 = (canvas_w - row_w) / 2
        for idx, serial in enumerate(layer):
            positions[serial] = (x0 + idx * (node_w + col_gap), cur_y)
        layer_bottom[layer_index] = cur_y + lh
        cur_y += lh + layer_gap

    canvas_h = cur_y - layer_gap + pad_y

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_w:.0f}" height="{canvas_h:.0f}" '
        f'viewBox="0 0 {canvas_w:.0f} {canvas_h:.0f}" '
        f'style="font-family:Inter,sans-serif;background:#f8fafc;border-radius:10px;'
        f'border:1px solid #e2e8f0;display:block;max-width:100%;">'
    ]

    def _ntype(serial: str) -> str:
        if serial == "__internet__":
            return "internet"
        return serial_to_dev.get(serial, {}).get("productType", "")

    parts.append('<g fill="none">')
    if show_internet and "__internet__" in positions:
        internet_x = positions["__internet__"][0] + node_w / 2
        internet_y = positions["__internet__"][1] + _card_h("internet")
        for root in roots:
            rx, ry = positions[root]
            parts.append(
                f'<line x1="{internet_x:.1f}" y1="{internet_y:.1f}" x2="{rx + node_w/2:.1f}" y2="{ry:.1f}" '
                f'stroke="#c4c9b0" stroke-width="1.6" stroke-dasharray="4 3" opacity="0.8"/>'
            )

    for child, parent in parent_of.items():
        if child not in display_serials or parent not in display_serials:
            continue
        px, py = positions[parent]
        cx, cy = positions[child]
        p_bot = py + _card_h(_ntype(parent))
        link = parent_link_of.get(child, {})
        speed = _svg_esc(link.get("local_speed") or "")
        local_port = _svg_esc(link.get("local_port") or "")
        remote_port = _svg_esc(link.get("remote_port") or "")
        parts.append(
            f'<line x1="{px + node_w/2:.1f}" y1="{p_bot:.1f}" x2="{cx + node_w/2:.1f}" y2="{cy:.1f}" '
            f'stroke="#8a9269" stroke-width="1.8" opacity="0.95"/>'
        )
        if speed or local_port or remote_port:
            mid_y = (p_bot + cy) / 2
            parts.append(
                f'<text x="{px + node_w/2:.1f}" y="{mid_y:.1f}" '
                f'text-anchor="middle" font-size="8" fill="#57534e" '
                f'paint-order="stroke" stroke="#f8fafc" stroke-width="3">'
                f'{_svg_esc(local_port)}'
                f'{" -> " + remote_port if remote_port else ""}'
                f'{" · " + speed if speed else ""}</text>'
            )
    parts.append("</g>")

    def _draw_switch_ports(nx: float, ny: float, ports: List[Dict[str, Any]]) -> str:
        if not ports:
            return ""
        panel_x = nx + 10
        panel_y = ny + 88   # shifted down for enrichment lines
        panel_w = node_w - 20
        panel_h = 26
        cols = min(max(len(ports) // 2, 12), 24)
        rows = 2 if len(ports) > cols else 1
        slot_w = (panel_w - (cols - 1) * 2) / cols
        slot_h = 10
        svg = [
            f'<rect x="{panel_x:.1f}" y="{panel_y:.1f}" width="{panel_w:.1f}" height="{panel_h:.1f}" '
            f'rx="5" fill="rgba(15,23,42,0.18)" stroke="rgba(255,255,255,0.18)" stroke-width="0.8"/>'
        ]
        for idx, port in enumerate(ports[: cols * rows]):
            row = idx // cols
            col = idx % cols
            x = panel_x + col * (slot_w + 2)
            y = panel_y + 4 + row * 12
            if port.get("isUplink"):
                fill = "#fbbf24"
            elif port.get("status") == "Connected":
                fill = "#4ade80"
            elif port.get("status") == "Disabled":
                fill = "#475569"
            else:
                fill = "#cbd5e1"
            svg.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{slot_w:.1f}" height="{slot_h:.1f}" '
                f'rx="1.8" fill="{fill}" opacity="0.95"/>'
            )
        return "".join(svg)

    internet_layer = ["__internet__"] if show_internet else []
    for serial in internet_layer + [s for layer in (layers[1:] if show_internet else layers) for s in layer]:
        nx, ny = positions[serial]
        nh = _card_h("internet") if serial == "__internet__" else _card_h(_ntype(serial))

        if serial == "__internet__":
            parts.append(
                f'<rect x="{nx:.1f}" y="{ny:.1f}" width="{node_w}" height="{nh}" rx="10" '
                f'fill="#1c1917" stroke="#44403c" stroke-width="1.2"/>'
            )
            parts.append(
                f'<text x="{nx + node_w/2:.1f}" y="{ny + nh/2 - 6:.1f}" text-anchor="middle" '
                f'font-size="20" font-weight="700" fill="#eef0e6">Internet</text>'
            )
            parts.append(
                f'<text x="{nx + node_w/2:.1f}" y="{ny + nh/2 + 12:.1f}" text-anchor="middle" '
                f'font-size="10" fill="#c4c9b0">Packet entry point</text>'
            )
            continue

        info = node_info[serial]
        ntype_s = info["type"]
        status = info["status"]
        label = _svg_esc(info["label"])
        model = _svg_esc(info["model"])
        C = _TOPO_C.get(ntype_s, _TOPO_C["camera"])
        dot_c = _TOPO_DOT.get(status, "#94a3b8")
        has_issue = bool(port_issues.get(serial))
        if ntype_s == "wireless":
            util = float((ap_util.get(serial) or {}).get("utilizationTotal", 0))
            has_issue = has_issue or util > 70
        border = "#f87171" if has_issue else C["bd"]
        border_w = "2" if has_issue else "1.2"

        parts.append(
            f'<rect x="{nx:.1f}" y="{ny:.1f}" width="{node_w}" height="{nh}" rx="10" '
            f'fill="{C["bg"]}" stroke="{border}" stroke-width="{border_w}"/>'
        )
        parts.append(
            f'<circle cx="{nx + node_w - 12:.1f}" cy="{ny + 12:.1f}" r="4" fill="{dot_c}"/>'
        )
        badge = _TOPO_BADGE.get(ntype_s, "")
        if badge:
            parts.append(
                f'<rect x="{nx+8:.1f}" y="{ny+8:.1f}" width="28" height="14" rx="3" fill="{C["bd"]}" opacity="0.78"/>'
            )
            parts.append(
                f'<text x="{nx+22:.1f}" y="{ny+18.5:.1f}" text-anchor="middle" font-size="8" font-weight="700" fill="{C["fg"]}">{badge}</text>'
            )

        parts.append(
            f'<text x="{nx + node_w/2:.1f}" y="{ny + 28:.1f}" text-anchor="middle" '
            f'font-size="11" font-weight="700" fill="{C["fg"]}">{label}</text>'
        )
        parts.append(
            f'<text x="{nx + node_w/2:.1f}" y="{ny + 42:.1f}" text-anchor="middle" '
            f'font-size="8.5" fill="{C["fg"]}" opacity="0.72">{model}</text>'
        )

        ports = info["ports"]

        if ntype_s == "appliance":
            # ── MX enrichment: WAN IPs, peak throughput, client count ──────
            wan_lines = _mx_wan_lines(serial, enr.get("uplink_statuses") or [])
            net_id = serial_to_dev[serial].get("networkId", "")
            peak = _mx_peak_gbps(net_id, enr.get("uplinks_usage") or {})
            client_total = (enr.get("clients_overview") or {}).get(net_id, {})
            client_count = (client_total.get("counts") or {}).get("total") if isinstance(client_total, dict) else None

            line_y = ny + 55
            for wl in wan_lines:
                parts.append(
                    f'<text x="{nx + 10:.1f}" y="{line_y:.1f}" font-size="8" fill="{C["fg"]}" opacity="0.9">{_svg_esc(wl)}</text>'
                )
                line_y += 13
            if peak:
                wan1 = peak.get("wan1", 0)
                wan2 = peak.get("wan2", 0)
                peak_str = f"WAN1 {wan1:.1f} GB" + (f"  WAN2 {wan2:.1f} GB" if wan2 > 0.1 else "") + " peak 7d"
                parts.append(
                    f'<text x="{nx + 10:.1f}" y="{line_y:.1f}" font-size="8" fill="{C["fg"]}" opacity="0.82">{_svg_esc(peak_str)}</text>'
                )
                line_y += 13
            if client_count is not None:
                parts.append(
                    f'<text x="{nx + 10:.1f}" y="{line_y:.1f}" font-size="8" fill="{C["fg"]}" opacity="0.82">{client_count:,} clients</text>'
                )

        else:
            # ── Switch enrichment: mgmt IP, VLANs, clients, PoE ──────────
            mgmt_ip = (enr.get("device_ip") or {}).get(serial, "")
            vlan_str = _switch_vlans(serial, enr.get("port_configs") or {})
            client_cnt = _switch_client_count(serial, switch_port_statuses_by_switch)
            poe_str = _switch_poe_str(serial, switch_port_statuses_by_switch)

            if mgmt_ip:
                parts.append(
                    f'<text x="{nx + 10:.1f}" y="{ny + 55:.1f}" font-size="8" fill="{C["fg"]}" opacity="0.88">{_svg_esc(mgmt_ip)}</text>'
                )
            if vlan_str:
                parts.append(
                    f'<text x="{nx + 10:.1f}" y="{ny + 67:.1f}" font-size="7.5" fill="{C["fg"]}" opacity="0.82">{_svg_esc(vlan_str[:40])}</text>'
                )
            stats = f"{client_cnt} clients" + (f"  ·  {poe_str}" if poe_str else "")
            parts.append(
                f'<text x="{nx + 10:.1f}" y="{ny + 79:.1f}" font-size="8" fill="{C["fg"]}" opacity="0.82">{_svg_esc(stats)}</text>'
            )
            parts.append(_draw_switch_ports(nx, ny, ports))

        if has_issue:
            parts.append(
                f'<text x="{nx + node_w - 20:.1f}" y="{ny + nh - 8:.1f}" font-size="10" fill="#fbbf24">&#9888;</text>'
            )

    parts.append("</svg>")
    return "".join(parts)


def _topo_summary_rows(
    devices: List[Dict[str, Any]],
    lldp_cdp: Dict[str, Any],
    switch_port_statuses_by_switch: Dict[str, Any],
) -> List[List[str]]:
    serial_to_dev, _, parent_of, children_of, edge_counts = _build_topology_facts(
        devices, lldp_cdp, switch_port_statuses_by_switch
    )
    if not serial_to_dev:
        return []

    rows: List[List[str]] = []
    for serial, dev in sorted(
        serial_to_dev.items(),
        key=lambda item: (
            0 if item[1].get("productType") == "appliance" else 1,
            item[1].get("name") or item[0],
        ),
    ):
        if dev.get("productType") not in ("appliance", "switch"):
            continue
        parent = parent_of.get(serial)
        if parent:
            parent_name = serial_to_dev.get(parent[0], {}).get("name") or parent[0]
            upstream = f"{parent_name} ({parent[1]} -> {parent[2] or '?'})"
        else:
            upstream = "Internet edge"
        rows.append(
            [
                dev.get("name") or serial,
                dev.get("model") or "",
                upstream,
                str(len(children_of.get(serial, []))),
                str(edge_counts.get(serial, 0)),
            ]
        )
    return rows


def _build_topology_facts(
    devices: List[Dict[str, Any]],
    lldp_cdp: Dict[str, Any],
    switch_port_statuses_by_switch: Dict[str, Any],
) -> Tuple[
    Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Dict[str, Any]]],
    Dict[str, Tuple[str, str, str]],
    Dict[str, List[str]],
    Dict[str, int],
]:
    serial_to_dev = {
        d.get("serial"): d for d in devices if isinstance(d, dict) and d.get("serial")
    }
    if not serial_to_dev:
        return {}, {}, {}, {}, {}

    def _norm(value: Any) -> str:
        return "".join(ch for ch in str(value).lower() if ch.isalnum())

    id_to_serial: Dict[str, str] = {}
    for serial, dev in serial_to_dev.items():
        id_to_serial[_norm(serial)] = serial
        if dev.get("mac"):
            id_to_serial[_norm(dev.get("mac"))] = serial

    status_by_switch: Dict[str, Dict[str, Dict[str, Any]]] = {}
    if isinstance(switch_port_statuses_by_switch, dict):
        for serial, ports in switch_port_statuses_by_switch.items():
            if isinstance(ports, list):
                status_by_switch[serial] = {
                    str(p.get("portId")): p for p in ports if isinstance(p, dict)
                }

    parent_of: Dict[str, Tuple[str, str, str]] = {}
    children_of: Dict[str, List[str]] = {}
    edge_counts: Dict[str, int] = {}

    for local_serial, data in lldp_cdp.items() if isinstance(lldp_cdp, dict) else []:
        if local_serial not in serial_to_dev or not isinstance(data, dict):
            continue
        ports = data.get("ports", {})
        if not isinstance(ports, dict):
            continue
        for local_port, port_data in ports.items():
            if not isinstance(port_data, dict):
                continue
            port_status = status_by_switch.get(local_serial, {}).get(str(local_port), {})
            neighbor_serial = None
            neighbor_port = ""
            for key in ("lldp", "cdp"):
                disc = port_data.get(key)
                if not isinstance(disc, dict):
                    continue
                neighbor_port = str(disc.get("portId") or neighbor_port)
                for candidate in (
                    disc.get("chassisId"),
                    disc.get("deviceId"),
                    port_data.get("deviceMac"),
                ):
                    neighbor_serial = id_to_serial.get(_norm(candidate))
                    if neighbor_serial:
                        break
                if neighbor_serial:
                    break
            if not neighbor_serial or neighbor_serial == local_serial:
                continue

            local_type = serial_to_dev[local_serial].get("productType")
            neighbor_type = serial_to_dev[neighbor_serial].get("productType")
            if bool(port_status.get("isUplink")) and neighbor_type in ("switch", "appliance"):
                parent_of[local_serial] = (
                    neighbor_serial,
                    str(local_port),
                    neighbor_port,
                )
                children_of.setdefault(neighbor_serial, [])
                if local_serial not in children_of[neighbor_serial]:
                    children_of[neighbor_serial].append(local_serial)
            elif local_type == "switch" and neighbor_type in ("wireless", "camera", "sensor"):
                edge_counts[local_serial] = edge_counts.get(local_serial, 0) + 1

    return serial_to_dev, status_by_switch, parent_of, children_of, edge_counts


def _format_usage_kb(value: Any) -> str:
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        return "0 KB"
    units = ["KB", "MB", "GB", "TB"]
    idx = 0
    while amount >= 1024 and idx < len(units) - 1:
        amount /= 1024.0
        idx += 1
    return f"{amount:.1f} {units[idx]}" if idx else f"{int(amount)} {units[idx]}"


def _describe_port_neighbor(port: Dict[str, Any], serial_to_dev: Dict[str, Dict[str, Any]]) -> str:
    for key in ("lldp", "cdp"):
        disc = port.get(key)
        if not isinstance(disc, dict):
            continue
        label = (
            disc.get("systemName")
            or disc.get("deviceName")
            or disc.get("platform")
            or disc.get("deviceId")
            or disc.get("chassisId")
        )
        remote_port = disc.get("portId") or disc.get("portDescription")
        if label and remote_port:
            return f"{label} ({remote_port})"
        if label:
            return str(label)
    client_count = port.get("clientCount")
    if client_count:
        return f"{client_count} downstream client(s)"
    return "No neighbor data"


def _port_role_label(
    port: Dict[str, Any],
    port_config: Optional[Dict[str, Any]],
    serial_to_dev: Dict[str, Dict[str, Any]],
) -> str:
    if port.get("isUplink"):
        return "Uplink"
    for key in ("lldp", "cdp"):
        disc = port.get(key)
        if not isinstance(disc, dict):
            continue
        label = " ".join(
            str(disc.get(field) or "")
            for field in ("systemName", "platform", "deviceId", "systemDescription")
        ).lower()
        if " meraki mr" in f" {label}" or "ap " in label:
            return "Access point"
        if "phone" in label or "voip" in label or "sip-" in label:
            return "Phone"
        if "camera" in label or "mv" in label:
            return "Camera"
        if "switch" in label or "ms" in label:
            return "Downlink"
    if port.get("clientCount"):
        return "Endpoint"
    if isinstance(port_config, dict):
        if str(port_config.get("type") or "").lower() == "trunk":
            return "Trunk"
        if port_config.get("voiceVlan"):
            return "Voice endpoint"
        if port_config.get("vlan"):
            return "Access"
    return "Unknown"


def _switch_anchor(serial: str, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", f"{name}-{serial}".lower()).strip("-")
    return f"switch-{base}"


def _port_sort_key(port_id: Any) -> Tuple[int, int, str]:
    text = str(port_id or "")
    nums = [int(part) for part in re.findall(r"\d+", text)]
    primary = nums[-1] if nums else 0
    secondary = nums[-2] if len(nums) > 1 else 0
    return (secondary, primary, text)


def _port_group_label(port_id: Any) -> str:
    text = str(port_id or "")
    if "_" in text:
        return text.rsplit("_", 1)[0]
    return "Front Panel"


def _port_role_short(role: str) -> str:
    mapping = {
        "Uplink": "UP",
        "Downlink": "DN",
        "Access point": "AP",
        "Phone": "PH",
        "Camera": "CAM",
        "Voice endpoint": "VOI",
        "Access": "ACC",
        "Trunk": "TRK",
        "Endpoint": "END",
        "Unknown": "UNK",
    }
    return mapping.get(role, role[:3].upper())


def _describe_vlan_mode(port_config: Optional[Dict[str, Any]]) -> str:
    if not isinstance(port_config, dict):
        return "—"
    if str(port_config.get("type") or "").lower() == "trunk":
        native = port_config.get("vlan")
        allowed = port_config.get("allowedVlans") or "all"
        if native:
            return f"Trunk (native {native}; allowed {allowed})"
        return f"Trunk ({allowed})"
    access_vlan = port_config.get("vlan")
    voice_vlan = port_config.get("voiceVlan")
    if access_vlan or voice_vlan:
        text = f"Access {access_vlan or '—'}"
        if voice_vlan:
            text += f" / Voice {voice_vlan}"
        return text
    if port_config.get("name"):
        return str(port_config.get("name"))
    return "—"


def _build_switch_link_narrative(
    serial: str,
    parent: Optional[Tuple[str, str, str]],
    child_names: List[str],
    uplink_ports: List[Dict[str, Any]],
    edge_count: int,
    serial_to_dev: Dict[str, Dict[str, Any]],
) -> str:
    parts = []
    if parent:
        parent_name = serial_to_dev.get(parent[0], {}).get("name") or parent[0]
        parts.append(f"Upstream via port {parent[1]} to {parent_name} on remote port {parent[2] or '?'}")
    elif uplink_ports:
        parts.append(
            "Uplink-marked ports: " + ", ".join(str(port.get("portId")) for port in uplink_ports)
        )
    else:
        parts.append("No confirmed upstream switch link was discovered")
    if child_names:
        preview = ", ".join(child_names[:4])
        if len(child_names) > 4:
            preview += f", and {len(child_names) - 4} more"
        parts.append(f"Downstream switches: {preview}")
    if edge_count:
        parts.append(f"{edge_count} edge device link(s) inferred from LLDP/CDP")
    return ". ".join(parts) + "."


def _model_capability_summary(model: str) -> str:
    text = (model or "").upper()
    if text.startswith("MX"):
        return "Security gateway with firewalling, AutoVPN, WAN failover, and internet edge policy enforcement."
    if text.startswith("MS130") or text.startswith("MS120"):
        return "Access-layer switching with PoE variants, Layer 2 VLAN services, and campus edge connectivity."
    if text.startswith("MS2") or text.startswith("MS3") or text.startswith("MS4"):
        return "Switching platform for access/distribution roles with VLAN trunking, uplink aggregation, and PoE model options."
    if text.startswith("MR") or text.startswith("CW"):
        return "Cloud-managed wireless AP with RF management, roaming support, and modern client access capabilities."
    if text.startswith("MV"):
        return "Security camera with onboard retention and cloud-managed visibility."
    if text.startswith("MT"):
        return "Environmental / telemetry sensor integrated into the Meraki dashboard."
    return "Managed network device model present in the current inventory."


def _hardware_consistency_note(top_models: List[Any]) -> str:
    unique_models = len(top_models)
    if unique_models >= 10:
        return "The environment spans many hardware generations. Standardizing refresh waves and narrowing active model families will simplify spares, firmware planning, and supportability."
    if unique_models >= 5:
        return "The environment mixes several hardware generations. Aligning future upgrades by layer will improve lifecycle consistency and reduce operational variance."
    return "The hardware profile is relatively consistent. Preserve that consistency during refresh cycles so features, support windows, and operational behavior remain predictable."


def _port_heat_score(port: Dict[str, Any]) -> float:
    usage = port.get("usageInKb") or {}
    traffic = port.get("trafficInKbps") or {}
    total_usage = float((usage or {}).get("total") or 0)
    current_kbps = float((traffic or {}).get("total") or 0)
    score = 0.0
    if total_usage > 0:
        score += min(60.0, max(0.0, (math.log10(total_usage + 1) - 2.0) * 15.0))
    if current_kbps > 0:
        score += min(40.0, max(0.0, (math.log10(current_kbps + 1) - 1.0) * 20.0))
    if port.get("isUplink"):
        score += 10.0
    return round(min(100.0, score), 1)


def _port_heat_label(score: float) -> str:
    if score >= 75:
        return "Hot"
    if score >= 45:
        return "Warm"
    if score >= 15:
        return "Cool"
    return "Idle"


def _speed_label(speed: str) -> str:
    if speed.startswith("10 "):
        return "10M"
    if speed.startswith("100 "):
        return "100M"
    if speed.startswith("2.5 "):
        return "2.5G"
    if speed.startswith("5 "):
        return "5G"
    if speed.startswith("10 G"):
        return "10G"
    if speed.startswith("25 G"):
        return "25G"
    return "1G"


def _is_sfp_like_port(port_id: str) -> bool:
    text = str(port_id or "").upper()
    return "_" in text or text.startswith("SFP") or "NM" in text or text.startswith("X")


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
        groups_html.append(
            f'<div class="switch-port-group">'
            f'<div class="switch-port-group-title">{_he(label)} <span class="switch-port-group-kind">{_he(group_kind)}</span></div>'
            f'<div class="switch-port-face">'
            f'<div class="switch-port-row">{row_one}</div>'
            f'{f"<div class=\"switch-port-row\">{row_two}</div>" if row_two else ""}'
            f"</div></div>"
        )
    return summary + "".join(groups_html)


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
      <h1>14. Switch Deep Dive</h1>
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
      <h1>14. Switch Deep Dive</h1>
      <p>Port-level views for each MS switch, including link status, negotiated speed, traffic, PoE draw, inferred connected device, and upstream/downstream placement in the switching tree.</p>
    </section>
    """
    ]

    for site_name, serial, switch_name, model in switch_entries:
        switch = serial_to_dev.get(serial, {})
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
        poe_watts = float(poe_data.get("avgWatts", 0) or 0)
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
            errors = port.get("errors") or []
            if isinstance(errors, str):
                errors = [errors]
            warnings = port.get("warnings") or []
            if isinstance(warnings, str):
                warnings = [warnings]
            poe = port.get("poe") or {}
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
      <h1>{_he(switch_name)}</h1>
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
        <tbody>{''.join(table_rows) if table_rows else '<tr><td colspan=\"13\">No switch port status data available.</td></tr>'}</tbody>
      </table>
    </section>
    """
        )

    return "".join(section_parts), toc_items


def _build_ap_interference_section(
    devices_by_network: Dict[str, Dict[str, Any]],
    channel_util: Any,
    wireless_stats: Dict[str, Any],
    switch_port_statuses_by_switch: Dict[str, Any],
) -> str:
    if not isinstance(channel_util, list):
        return """
    <section id="ap-interference" class="report-section">
      <h1>11. AP Interference Audit</h1>
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
            wifi = float(((band.get("wifi") or {}).get("percentage")) or 0)
            non_wifi = float(((band.get("nonWifi") or {}).get("percentage")) or 0)
            total = float(((band.get("total") or {}).get("percentage")) or 0)
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
        avg_wifi = sum(item["wifi"] for item in stats) / len(stats)
        conn = None
        for item in wireless_stats.get(net_id, []) if isinstance(wireless_stats, dict) else []:
            if isinstance(item, dict) and item.get("serial") == serial:
                conn = item.get("connectionStats") or {}
                break
        assoc = int((conn or {}).get("assoc") or 0)
        auth = int((conn or {}).get("auth") or 0)
        success = int((conn or {}).get("success") or 0)
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
      <h1>11. AP Interference Audit</h1>
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
    for switch_serial, ports in switch_port_statuses_by_switch.items() if isinstance(switch_port_statuses_by_switch, dict) else []:
        if not isinstance(ports, list):
            continue
        for port in ports:
            if not isinstance(port, dict):
                continue
            for key in ("lldp", "cdp"):
                disc = port.get(key)
                if not isinstance(disc, dict):
                    continue
                neighbor_id = str(disc.get("chassisId") or disc.get("deviceId") or "").lower()
                for ap in hot_aps:
                    ap_mac = str(ap_by_serial.get(ap["serial"], {}).get("mac") or "").lower().replace(":", "")
                    if ap_mac and ap_mac in neighbor_id.replace(":", ""):
                        switch_ap_links.setdefault(switch_serial, []).append(
                            {
                                "switch_port": str(port.get("portId") or "?"),
                                "ap": ap,
                            }
                        )
                        break
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
        <h3>{_he(switch_serial)}</h3>
        <table class="data">
          <thead>
            <tr><th>Switch Port</th><th>AP</th><th>Severity</th><th>Worst Band</th><th>Non-WiFi</th><th>Total</th><th>Assoc</th><th>AP Findings</th></tr>
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
      <h1>12. AP Interference Audit</h1>
      <p>This section converts Meraki channel-utilization telemetry into an RF interference view by site and by AP. `non-Wi-Fi` represents likely external RF noise, while `Wi-Fi` represents airtime consumed by neighboring WLAN activity and co-channel contention. Where exact AP neighbor telemetry is unavailable, neighbor pressure is inferred from high Wi-Fi airtime on the affected band.</p>
      {''.join(site_cards)}
      <h2>Priority AP Findings</h2>
      <table class="data">
        <thead>
          <tr>
            <th>Site</th><th>AP</th><th>Severity</th><th>Worst Band</th><th>Non-WiFi</th>
            <th>WiFi</th><th>Total</th><th>Assoc</th><th>Findings</th><th>Recommendations</th>
          </tr>
        </thead>
        <tbody>{ap_findings_rows}</tbody>
      </table>
      <div class="summary-card">
        <div class="summary-title">RF Recommendations</div>
        <div class="summary-body"><ul>{''.join(f'<li>{_he(item)}</li>' for item in recommendations)}</ul></div>
      </div>
      <h2>AP Deep Dive By Switch</h2>
      {''.join(ap_deep_dive_parts) if ap_deep_dive_parts else '<div class="summary-card"><div class="summary-body">AP-to-switch mapping was not available in the current telemetry, so AP deep dives could not yet be grouped by switch.</div></div>'}
      <h2>Diagnostic Dump</h2>
      <table class="data">
        <thead>
          <tr><th>Site</th><th>AP</th><th>Serial</th><th>Avg Non-WiFi</th><th>Avg Total</th><th>Assoc</th><th>Auth</th><th>Success</th></tr>
        </thead>
        <tbody>{diagnostic_rows}</tbody>
      </table>
    </section>
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
      <h1>11. Internet Capacity &amp; Utilization</h1>
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
                    recv = float(point.get("receivedKbps") or 0)
                    sent = float(point.get("sentKbps") or 0)
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
      <h1>11. Internet Capacity &amp; Utilization</h1>
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
      margin: 18mm 12mm;
      background: var(--olive-100);
    }}
    :root {{
      --bg: #eef0e6;
      --ink: #0f172a;
      --muted: #64748b;
      --line: #e2e8f0;
      --accent: #0ea5e9;
      --panel: #f7f8f4;
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
    .toc-sub-item a {{
      color: inherit;
      text-decoration: none;
    }}
    .toc-sub-item a:hover {{
      text-decoration: underline;
    }}
    .toc-sub-item::before {{
      display: none;
    }}

    /* =====================================================
       REPORT SECTIONS
       ===================================================== */
    .report-section {{
      padding: 18px 18px 26px;
      max-width: none;
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
    .switch-detail-page {{
      page-break-before: always;
      max-width: none;
    }}
    .switch-detail-kicker {{
      margin-top: -8px;
      color: var(--muted);
      font-size: 12px;
    }}
    .switch-detail-stats {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin: 18px 0;
    }}
    .switch-detail-stat {{
      border: 1px solid var(--line);
      background: var(--stone-50);
      border-radius: 10px;
      padding: 12px 14px;
    }}
    .switch-detail-stat .label {{
      display: block;
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      color: var(--muted);
      margin-bottom: 6px;
      font-weight: 600;
    }}
    .switch-detail-stat .value {{
      display: block;
      font-size: 12px;
      color: var(--ink);
      line-height: 1.45;
      word-break: break-word;
    }}
    .switch-detail-card {{
      border: 1px solid var(--line);
      background: white;
      border-radius: 12px;
      padding: 16px 18px;
      margin: 16px 0 18px;
    }}
    .switch-detail-narrative {{
      margin-bottom: 10px;
      color: var(--ink);
    }}
    .switch-port-summary {{
      display: flex;
      flex-wrap: wrap;
      gap: 14px;
      font-size: 11px;
      color: var(--muted);
      margin: 2px 0 12px;
    }}
    .switch-port-group {{
      margin-top: 12px;
    }}
    .switch-port-group-title {{
      font-size: 10px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 7px;
      font-weight: 700;
    }}
    .switch-port-group-kind {{
      margin-left: 8px;
      letter-spacing: 0.08em;
      font-weight: 600;
      opacity: 0.7;
    }}
    .switch-port-face {{
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #f8fafc;
      padding: 10px;
    }}
    .switch-port-row {{
      display: grid;
      grid-auto-flow: column;
      grid-auto-columns: minmax(0, 1fr);
      gap: 6px;
      margin-top: 6px;
    }}
    .switch-port-row:first-child {{
      margin-top: 0;
    }}
    .switch-port-cell {{
      border-radius: 6px;
      min-height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      gap: 2px;
      font-size: 10px;
      font-weight: 700;
      border: 1px solid transparent;
      color: #1f2937;
      padding: 4px 2px;
      text-align: center;
    }}
    .switch-port-num {{
      display: block;
      line-height: 1.05;
    }}
    .switch-port-meta {{
      display: block;
      font-size: 8px;
      font-weight: 600;
      opacity: 0.78;
      line-height: 1.05;
    }}
    .switch-port-cell.ok {{ background: #e5efe5; border-color: #b7d2b7; }}
    .switch-port-cell.uplink {{ background: #dbeafe; border-color: #93c5fd; }}
    .switch-port-cell.poe {{ background: #dcfce7; border-color: #86efac; }}
    .switch-port-cell.warn {{ background: #fef3c7; border-color: #fcd34d; }}
    .switch-port-cell.issue {{ background: #fee2e2; border-color: #fca5a5; }}
    .switch-port-cell.down {{ background: #e5e7eb; border-color: #cbd5e1; color: #6b7280; }}
    .switch-port-cell.sfp-port {{
      border-style: dashed;
      border-width: 2px;
    }}
    .switch-port-cell.speed-mgig {{
      box-shadow: inset 0 0 0 2px rgba(14, 165, 233, 0.22);
    }}
    .switch-port-cell.speed-uplink {{
      box-shadow: inset 0 0 0 2px rgba(234, 88, 12, 0.24);
    }}
    .switch-detail-grid-empty {{
      color: var(--muted);
      font-size: 12px;
      padding: 8px 0 2px;
    }}
    .switch-detail-legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 12px;
      font-size: 11px;
      color: var(--muted);
    }}
    .switch-detail-legend span {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }}
    .switch-detail-legend .swatch {{
      width: 10px;
      height: 10px;
      border-radius: 2px;
      display: inline-block;
      border: 1px solid rgba(15, 23, 42, 0.08);
    }}
    .switch-detail-legend .swatch.ok {{ background: #e5efe5; }}
    .switch-detail-legend .swatch.uplink {{ background: #dbeafe; }}
    .switch-detail-legend .swatch.poe {{ background: #dcfce7; }}
    .switch-detail-legend .swatch.warn {{ background: #fef3c7; }}
    .switch-detail-legend .swatch.issue {{ background: #fee2e2; }}
    .switch-detail-legend .swatch.down {{ background: #e5e7eb; }}
    .switch-detail-legend .swatch.speed-mgig {{ background: #dbeafe; box-shadow: inset 0 0 0 2px rgba(14, 165, 233, 0.22); }}
    .switch-detail-legend .swatch.speed-uplink {{ background: #fed7aa; box-shadow: inset 0 0 0 2px rgba(234, 88, 12, 0.24); }}
    .switch-detail-legend .swatch.sfp {{ background: white; border-style: dashed; border-width: 2px; }}
    .switch-detail-table td {{
      vertical-align: top;
    }}
    .wan-capacity-chart {{
      margin: 16px 0 22px;
      display: grid;
      gap: 10px;
    }}
    .wan-capacity-row {{
      display: grid;
      grid-template-columns: minmax(200px, 280px) 1fr minmax(180px, 240px);
      gap: 12px;
      align-items: center;
      font-size: 11px;
    }}
    .wan-capacity-label {{
      color: var(--ink);
      font-weight: 600;
    }}
    .wan-capacity-meta {{
      color: var(--muted);
      text-align: right;
    }}
    .wan-capacity-bar {{
      height: 12px;
      background: #e5e7eb;
      border-radius: 999px;
      overflow: hidden;
    }}
    .wan-capacity-bar span {{
      display: block;
      height: 100%;
      background: linear-gradient(90deg, #94a3b8, #0ea5e9);
      border-radius: 999px;
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
    .topo-branch-title {{
      font-size: 13px;
      font-weight: 600;
      color: #57534e;
      margin: 12px 0 4px 0;
    }}
    .topo-branch-title:empty {{
      display: none;
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
        background: var(--bg);
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
