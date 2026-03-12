#!/usr/bin/env python3
import json
import os
import re
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = "/Users/seandolbec/Projects/Meraki-2026_planning"
BACKUP_PREFIX = "meraki_backup_"


def find_latest_backup(base: str) -> Optional[str]:
    candidates = []
    for name in os.listdir(base):
        if name.startswith(BACKUP_PREFIX) and os.path.isdir(os.path.join(base, name)):
            candidates.append(name)
    if not candidates:
        return None
    return os.path.join(base, sorted(candidates)[-1])


def load_json(path: str) -> Any:
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def md_to_html(md_text: str) -> str:
    # Minimal markdown converter (headings, lists, paragraphs)
    lines = md_text.splitlines()
    html_lines = []
    in_list = False
    for line in lines:
        if line.startswith("# "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h1>{line[2:].strip()}</h1>")
            continue
        if line.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h2>{line[3:].strip()}</h2>")
            continue
        if line.startswith("### "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h3>{line[4:].strip()}</h3>")
            continue
        if line.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{line[2:].strip()}</li>")
            continue
        if line.strip() == "":
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append('<div class="spacer"></div>')
            continue
        if in_list:
            html_lines.append("</ul>")
            in_list = False
        html_lines.append(f"<p>{line.strip()}</p>")
    if in_list:
        html_lines.append("</ul>")
    return "\n".join(html_lines)


def render_section(title: str, rows: List[List[str]]) -> str:
    if not rows:
        return ""
    header = f"<h2>{title}</h2>"
    table_rows = "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows
    )
    return f'{header}<table class="data">{table_rows}</table>'


def render_kpi_row(items: List[Tuple[str, str]]) -> str:
    cards = "".join(
        f'<div class="kpi"><div class="kpi-label">{label}</div><div class="kpi-value">{value}</div></div>'
        for label, value in items
    )
    return f'<div class="kpi-row">{cards}</div>'


def render_bar_chart(title: str, items: List[Tuple[str, float]], unit: str) -> str:
    if not items:
        return ""
    max_val = max(v for _, v in items) if items else 1
    bars = []
    for label, value in items[:10]:
        width = 0 if max_val == 0 else int((value / max_val) * 100)
        bars.append(
            (
                '<div class=\\"bar-row\\">'
                f'<div class=\\"bar-label\\">{label}</div>'
                '<div class=\\"bar-track\\">'
                f'<div class=\\"bar-fill\\" style=\\"width:{width}%\\"></div>'
                "</div>"
                f'<div class=\\"bar-value\\">{value:.1f} {unit}</div>'
                "</div>"
            )
        )
    return (
        '<div class=\\"chart\\">'
        f'<div class=\\"chart-title\\">{title}</div>' + "".join(bars) + "</div>"
    )


def render_pie_chart(title: str, items: List[Tuple[str, float]]) -> str:
    if not items:
        return ""
    total = sum(v for _, v in items)
    if total == 0:
        return ""

    slices = []
    cumulative = 0
    colors = [
        "--olive-500",
        "--olive-600",
        "--olive-700",
        "--olive-800",
        "--olive-300",
        "--olive-400",
        "--stone-600",
        "--stone-700",
    ]

    for i, (label, value) in enumerate(items):
        if value == 0:
            continue
        percentage = (value / total) * 100
        angle = cumulative * 360 / total
        next_angle = (cumulative + value) * 360 / total

        # Simplified pie representation using CSS
        slices.append(
            f'<div class="pie-slice" style="--angle-start: {angle}deg; --angle-end: {next_angle}deg; --color: var({colors[i % len(colors)]});">'
            f'<div class="pie-label">{label}<br>{value} ({percentage:.1f}%)</div>'
            "</div>"
        )
        cumulative += value

    return f"""
    <div class="chart">
        <div class="chart-title">{title}</div>
        <div class="pie-chart">
            {"".join(slices)}
        </div>
    </div>
    """


def render_line_chart(
    title: str, labels: List[str], values: List[float], unit: str = ""
) -> str:
    if not labels or not values:
        return ""

    max_val = max(values) if values else 1
    points = []

    for i, (label, value) in enumerate(zip(labels, values)):
        x_pos = (i / max(len(labels) - 1, 1)) * 100
        y_pos = 100 - ((value / max_val) * 100) if max_val > 0 else 0
        points.append(f"{x_pos}%,{y_pos}%")

    return f'''
    <div class="chart">
        <div class="chart-title">{title}</div>
        <div class="line-chart">
            <svg viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet">
                <polyline points="{" ".join(points)}" fill="none" stroke="var(--olive-500)" stroke-width="2"/>
                <rect x="0" y="0" width="100" height="100" fill="none" stroke="var(--line)" stroke-width="1"/>
            </svg>
            <div class="chart-points">
                {"".join([f'<div class="chart-point" style="left: {(i / max(len(labels) - 1, 1)) * 100}%; bottom: {100 - ((v / max_val) * 100) if max_val > 0 else 0}%;"><span>{label}</span><span>{v}{unit}</span></div>' for i, (label, v) in enumerate(zip(labels, values))])}
            </div>
        </div>
    </div>
    '''


def build_org_report(org_dir: str, org_name: str) -> str:
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
    switch_health = load_json(os.path.join(org_dir, "switch_health.json")) or {}
    lldp_cdp = load_json(os.path.join(org_dir, "lldp_cdp.json")) or {}
    wireless_stats = (
        load_json(os.path.join(org_dir, "wireless_connection_stats.json")) or {}
    )
    networks = load_json(os.path.join(org_dir, "networks.json")) or []

    # Device availability analysis
    device_status_counts = {}
    device_type_counts = {}
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

    # Channel utilization analysis
    if isinstance(channel_util, list):
        high_util_devices = [
            d for d in channel_util if float(d.get("utilizationTotal", 0)) > 70
        ]
        moderate_util_devices = [
            d for d in channel_util if 30 <= float(d.get("utilizationTotal", 0)) <= 70
        ]
        low_util_devices = [
            d for d in channel_util if float(d.get("utilizationTotal", 0)) < 30
        ]
    else:
        high_util_devices = []
        moderate_util_devices = []
        low_util_devices = []

    # Switch port analysis
    switch_ports_data = []
    if isinstance(lldp_cdp, dict):
        # Process LLDP/CDP data for port insights
        pass

    # KPI summary with more meaningful metrics
    inv_by_type = inventory_summary.get("by_type") or {}
    kpi_items = [
        ("Total Networks", str(len(networks))),
        ("Total Devices", str(sum(inv_by_type.values()) if inv_by_type else "0")),
        ("Online Devices", str(device_status_counts.get("online", 0))),
        ("Switches", str(inv_by_type.get("switch", 0))),
        ("Wireless APs", str(inv_by_type.get("wireless", 0))),
        ("Appliances", str(inv_by_type.get("appliance", 0))),
        ("PoE Switches", str(len(poe_switches))),
        ("High Util APs", str(len(high_util_devices))),
    ]

    # Build detailed sections
    extra_sections = ""

    # Device Status Overview
    if device_status_counts:
        status_rows = [
            [status.title(), str(count)]
            for status, count in device_status_counts.items()
        ]
        extra_sections += render_section("Device Status Overview", status_rows)
        extra_sections += render_pie_chart(
            "Device Status Distribution",
            [(status.title(), count) for status, count in device_status_counts.items()],
        )

    # Device Type Distribution
    if device_type_counts:
        type_rows = [
            [ptype.title(), str(count)] for ptype, count in device_type_counts.items()
        ]
        extra_sections += render_section("Device Type Inventory", type_rows)
        extra_sections += render_pie_chart(
            "Device Type Distribution",
            [(ptype.title(), count) for ptype, count in device_type_counts.items()],
        )

    # Top Models
    inv_rows = []
    for model, count in (inventory_summary.get("top_models") or [])[:10]:
        inv_rows.append([str(model), str(count)])
    if inv_rows:
        extra_sections += render_section("Top Device Models", inv_rows)

    # Detailed PoE Analysis
    if poe_switches:
        poe_rows = []
        for s in poe_switches[:10]:
            poe_rows.append(
                [
                    s.get("serial", ""),
                    f"{s.get('avgWatts', 0):.1f} W",
                    f"{s.get('powerUsageInWh', 0):.1f} Wh",
                ]
            )
        if poe_rows:
            extra_sections += render_section(
                "PoE Power Consumption by Switch (24h)", poe_rows
            )

    # Top PoE Ports
    if poe_ports:
        port_rows = []
        for p in poe_ports[:15]:  # Top 15 ports
            port_rows.append(
                [
                    p.get("serial", ""),
                    p.get("portId", ""),
                    f"{p.get('powerUsageInWh', 0):.1f} Wh",
                ]
            )
        if port_rows:
            extra_sections += render_section("Top PoE Ports by Usage", port_rows)

    # Channel Utilization Analysis
    if isinstance(channel_util, list) and channel_util:
        util_rows = []
        for device in channel_util[:10]:
            util_rows.append(
                [
                    device.get("serial", ""),
                    f"{float(device.get('utilizationTotal', 0)):.1f}%",
                    f"{float(device.get('utilizationNon80211', 0)):.1f}%",
                    f"{float(device.get('utilization80211Tx', 0)):.1f}%",
                    f"{float(device.get('utilization80211Rx', 0)):.1f}%",
                ]
            )
        if util_rows:
            extra_sections += render_section("Channel Utilization by Device", util_rows)

        # Utilization charts
        if len(channel_util) > 0:
            util_labels = [
                d.get("serial", f"Device {i}") for i, d in enumerate(channel_util[:8])
            ]
            util_values = [
                float(d.get("utilizationTotal", 0)) for d in channel_util[:8]
            ]
            extra_sections += render_line_chart(
                "Channel Utilization Trend", util_labels, util_values, "%"
            )

    # Wireless Analysis
    if isinstance(wireless_stats, dict) and wireless_stats:
        wireless_rows = []
        for key, value in wireless_stats.items():
            if isinstance(value, (int, float)):
                wireless_rows.append([key.replace("_", " ").title(), str(value)])
        if wireless_rows:
            extra_sections += render_section("Wireless Statistics", wireless_rows)

    # Recommendations
    rec_html = md_to_html(rec_md)

    # Charts
    model_chart = render_bar_chart(
        "Top Models by Count",
        [(m, float(c)) for m, c in (inventory_summary.get("top_models") or [])[:10]],
        "units",
    )
    poe_chart = render_bar_chart(
        "PoE Power Consumption (Watts)",
        [
            (s.get("serial", ""), float(s.get("avgWatts") or 0))
            for s in (poe_summary.get("switch_poe_totals") or [])[:10]
        ],
        "W",
    )

    # Utilization chart
    util_chart = ""
    if isinstance(channel_util, list) and len(channel_util) > 0:
        util_labels = [
            d.get("serial", f"Device {i}") for i, d in enumerate(channel_util[:8])
        ]
        util_values = [float(d.get("utilizationTotal", 0)) for d in channel_util[:8]]
        util_chart = render_line_chart(
            "Channel Utilization (%)", util_labels, util_values, "%"
        )

    return f"""
    <section class=\"cover\">
      <div class=\"brand\">
        <i data-lucide=\"network\"></i>
        Techmore
      </div>
      <div class=\"title\">Network Health & Optimization Report</div>
      <div class=\"subtitle\">{org_name}</div>
      <div class=\"meta\">Generated {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
    </section>
    <section class=\"content\">
      {render_kpi_row(kpi_items)}
      <div class=\"summary-card\">
        <div class=\"summary-title\">Executive Summary</div>
        <div class=\"summary-body\">
          Network analysis reveals <strong>{device_status_counts.get("online", 0)}</strong> online devices out of <strong>{sum(inv_by_type.values()) if inv_by_type else 0}</strong> total devices. 
          <strong>{len(high_util_devices)}</strong> access points showing high channel utilization (>70%) may require attention. 
          PoE power budget analysis shows <strong>{len([s for s in poe_switches if float(s.get("avgWatts", 0)) > 50])}</strong> switches with significant PoE draw.
        </div>
      </div>
      <div class=\"chart-grid\">
        {model_chart}
        {poe_chart}
        {util_chart}
      </div>
      {rec_html}
      {extra_sections}
    </section>
    """


def build_html(doc_title: str, body: str) -> str:
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{doc_title}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Playfair+Display:wght@600;700&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/lucide@latest"></script>
  <style>
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
      font-family: "Inter", sans-serif;
      color: var(--ink);
      background: var(--bg);
    }}
    .cover {{
      padding: 64px 72px 36px;
      background: linear-gradient(135deg, var(--olive-900) 0%, var(--olive-800) 55%, var(--olive-950) 100%);
      color: #fff;
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    .cover::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
    }}
    .brand {{
      font-size: 12px;
      letter-spacing: 0.24em;
      text-transform: uppercase;
      opacity: 0.75;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
    }}
    .brand i {{
      font-size: 16px;
    }}
    .title {{
      font-family: "Playfair Display", serif;
      font-size: 38px;
      font-weight: 700;
      margin-top: 12px;
      color: var(--olive-50);
      position: relative;
    }}
    .subtitle {{
      font-size: 18px;
      margin-top: 6px;
      opacity: 0.9;
      color: var(--olive-200);
      max-width: 600px;
      margin-left: auto;
      margin-right: auto;
    }}
    .meta {{
      margin-top: 18px;
      font-size: 11px;
      opacity: 0.75;
      color: var(--olive-200);
      letter-spacing: 0.5px;
    }}
    .content {{
      padding: 36px 72px 64px;
      max-width: 860px;
    }}
    .kpi-row {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin: 16px 0 24px;
    }}
    .kpi {{
      border: 1px solid var(--line);
      background: var(--stone-50);
      padding: 14px 16px;
      border-radius: 10px;
      text-align: center;
      transition: all 0.2s ease;
      position: relative;
      overflow: hidden;
    }}
    .kpi::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
      background: var(--olive-500);
    }}
    .kpi:hover {{
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }}
    .kpi-label {{
      font-size: 10px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
      font-weight: 600;
    }}
    .kpi-value {{
      font-family: "Playfair Display", serif;
      font-size: 20px;
      font-weight: 700;
      color: var(--ink);
      display: block;
    }}
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
      font-size: 12px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 8px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .summary-title i {{
      font-size: 14px;
      color: var(--olive-600);
    }}
    .summary-body {{
      font-size: 14px;
      line-height: 1.6;
      color: var(--ink);
    }}
    .chart-grid {{
      display: grid;
      gap: 20px;
      margin: 20px 0 28px;
    }}
    .chart-grid.two-col {{
      grid-template-columns: 1fr 1fr;
    }}
    .chart-grid.three-col {{
      grid-template-columns: repeat(3, 1fr);
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
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.18em;
      color: var(--muted);
      margin-bottom: 12px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .chart-title i {{
      font-size: 14px;
      color: var(--olive-600);
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
      transition: transform 0.3s ease;
    }}
    .pie-slice:nth-child(odd)::before {{
      background: var(--olive-300);
    }}
    .pie-slice:nth-child(even)::before {{
      background: var(--olive-500);
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
      font-size: 10px;
      text-align: center;
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
    .bar-track::before {{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(90deg, var(--olive-100), var(--olive-50));
    }}
    .bar-fill {{
      background: linear-gradient(90deg, var(--olive-500), var(--olive-300));
      height: 10px;
      border-radius: 8px;
      transition: width 0.3s ease;
    }}
    .bar-value {{
      text-align: right;
      color: var(--muted);
      font-weight: 500;
    }}
    h1 {{
      font-family: "Playfair Display", serif;
      font-size: 26px;
      margin: 24px 0 14px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 8px;
      color: var(--olive-900);
      position: relative;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    h1 i {{
      font-size: 18px;
      color: var(--olive-600);
    }}
    h2 {{
      font-family: "Playfair Display", serif;
      font-size: 20px;
      margin: 20px 0 12px;
      color: var(--olive-900);
      position: relative;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    h2 i {{
      font-size: 16px;
      color: var(--olive-600);
    }}
    h3 {{
      font-family: "Playfair Display", serif;
      font-size: 16px;
      margin: 16px 0 8px;
      color: var(--muted);
    }}
    p {{
      margin: 12px 0;
      line-height: 1.6;
      color: var(--ink);
    }}
    ul {{
      margin: 12px 0 16px 20px;
      padding: 0;
    }}
    li {{
      margin: 6px 0;
      line-height: 1.5;
      color: var(--ink);
      position: relative;
      padding-left: 12px;
    }}
    li::before {{
      content: "•";
      position: absolute;
      left: 0;
      color: var(--olive-600);
      font-weight: bold;
    }}
    .spacer {{
      height: 12px;
    }}
    table.data {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin: 16px 0 24px;
      font-size: 13px;
      background: var(--stone-50);
      border-radius: 10px;
      overflow: hidden;
    }}
    table.data th {{
      border: 1px solid var(--line);
      background: var(--olive-50);
      font-weight: 600;
      color: var(--olive-800);
      text-align: left;
      padding: 12px 16px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    table.data td {{
      border: 1px solid var(--line);
      padding: 12px 16px;
      vertical-align: top;
      color: var(--ink);
    }}
    table.data tr:last-child td {{
      border-bottom: none;
    }}
    table.data tr:hover td {{
      background: var(--olive-50);
    }}
    .no-print {{
      display: none;
    }}
    @media print {{
      .no-print {{
        display: none !important;
      }}
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

        print(f"Using WeasyPrint for PDF generation: {pdf_path}")
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return True
    except Exception as e:
        print(f"WeasyPrint failed: {e}")
        pass
    # Fallback to wkhtmltopdf
    wk = shutil.which("wkhtmltopdf")
    if wk:
        print(f"Using wkhtmltopdf for PDF generation: {pdf_path}")
        os.system(f"{wk} {html_path} {pdf_path}")
        return os.path.exists(pdf_path)
    print("No PDF generator available")
    return False


def main() -> int:
    backup_dir = find_latest_backup(BASE_DIR)
    if not backup_dir:
        print("No backup folder found.")
        return 1

    for name in sorted(os.listdir(backup_dir)):
        if not name.startswith("org_"):
            continue
        org_dir = os.path.join(backup_dir, name)
        rec_path = os.path.join(org_dir, "recommendations.md")
        if not os.path.exists(rec_path):
            continue

        org_name = name
        # Attempt to read org name from recommendations title
        with open(rec_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
            m = re.match(r"# Meraki Recommendations: (.+)$", first_line)
            if m:
                org_name = m.group(1)

        body = build_org_report(org_dir, org_name)
        html = build_html(f"{org_name} - Recommendations", body)

        html_path = os.path.join(org_dir, "report.html")
        pdf_path = os.path.join(org_dir, "report.pdf")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        ok = write_pdf(html_path, pdf_path)
        if ok:
            print(f"Report generated: {pdf_path}")
        else:
            print(f"HTML generated (PDF tool missing): {html_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
