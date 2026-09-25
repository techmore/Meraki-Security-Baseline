import json
import logging
import math
import os
import re
from datetime import datetime, timezone
from html import escape as _he
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")
REPORT_VERSION = "1.0"

# Must match BACKUP_SCHEMA_VERSION in meraki_backup.py.
# Increment here when report_generator.py adds new required fields/files.
EXPECTED_BACKUP_SCHEMA_VERSION = 1


def normalize_security_status(value: Any) -> str:
    """Return the canonical status used by security scoring and rendering.

    Backup producers persist human-readable values such as ``Pass`` and
    ``Warning``.  Missing or unfamiliar values are informational rather than
    successful so an incomplete collection cannot create false assurance.
    """
    status = re.sub(r"[\s_-]+", " ", str(value or "").strip().lower())
    aliases = {
        "pass": "pass",
        "passed": "pass",
        "ok": "pass",
        "healthy": "pass",
        "fail": "fail",
        "failed": "fail",
        "warning": "warning",
        "warn": "warning",
        "info": "info",
        "informational": "info",
        "unknown": "info",
        "not assessed": "info",
        "not evaluated": "info",
        "not available": "info",
        "unavailable": "info",
        "n/a": "info",
        "na": "info",
        "": "info",
    }
    return aliases.get(status, "info")


def safe_float(value: Any, default: Optional[float] = 0.0) -> Optional[float]:
    """Coerce API numeric values without allowing one malformed field to abort a report."""
    if isinstance(value, bool) or value is None or (isinstance(value, str) and not value.strip()):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def safe_int(value: Any, default: Optional[int] = 0) -> Optional[int]:
    """Coerce integer-like API values while preserving a caller-provided fallback."""
    if isinstance(value, bool) or value is None or (isinstance(value, str) and not value.strip()):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return default


def parse_datetime(value: Any) -> Optional[datetime]:
    """Parse API timestamps and normalize both naive and aware values to UTC."""
    if isinstance(value, datetime):
        parsed = value
    elif value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_json_checked(
    path: str,
    expected_type: Any,
    default: Any,
    warnings: Optional[List[str]] = None,
) -> Any:
    """Load one artifact and report invalid top-level data to the caller.

    Missing files remain ordinary coverage gaps. Existing invalid JSON, error
    envelopes, and unexpected top-level types are degraded to ``default`` and
    surfaced in the report instead of failing deep inside a section renderer.
    """
    value = load_json(path)
    if value is None:
        if os.path.exists(path) and warnings is not None:
            warnings.append(f"{os.path.basename(path)} is invalid JSON, unreadable, or null")
        return default
    if (
        isinstance(value, dict) and "error" in value
    ) or (
        isinstance(value, list)
        and any(isinstance(item, dict) and "error" in item for item in value)
    ):
        if warnings is not None:
            warnings.append(f"{os.path.basename(path)} contains an API error envelope")
        return default
    if not isinstance(value, expected_type):
        expected = expected_type if isinstance(expected_type, str) else ", ".join(
            t.__name__ for t in expected_type
        ) if isinstance(expected_type, tuple) else expected_type.__name__
        if warnings is not None:
            warnings.append(
                f"{os.path.basename(path)} has top-level type {type(value).__name__}; "
                f"expected {expected}"
            )
        return default
    return value


def read_backup_meta(org_dir: str) -> Dict[str, Any]:
    """Load backup_meta.json if present; return {} if missing (pre-versioning backup)."""
    path = os.path.join(org_dir, "backup_meta.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def check_backup_schema(org_dir: str) -> List[str]:
    """Return a list of warning strings if the backup schema is incompatible or unversioned.

    An empty list means the backup is compatible or unknown (pre-versioning).
    A non-empty list should be surfaced as a banner in the report and logged.
    """
    meta = read_backup_meta(org_dir)
    warnings: List[str] = []
    if not meta:
        warnings.append(
            "backup_meta.json not found — this backup predates schema versioning. "
            "Re-run meraki_backup.py to generate a versioned backup."
        )
        return warnings
    schema_ver = meta.get("schema_version")
    if schema_ver is None:
        warnings.append("backup_meta.json is missing schema_version field.")
    elif schema_ver < EXPECTED_BACKUP_SCHEMA_VERSION:
        warnings.append(
            f"Backup schema version {schema_ver} is older than expected "
            f"{EXPECTED_BACKUP_SCHEMA_VERSION}. Some report sections may be incomplete. "
            "Re-run meraki_backup.py to refresh."
        )
    elif schema_ver > EXPECTED_BACKUP_SCHEMA_VERSION:
        warnings.append(
            f"Backup schema version {schema_ver} is newer than this report generator "
            f"({EXPECTED_BACKUP_SCHEMA_VERSION}). Update report_generator.py to "
            "avoid missing new fields."
        )
    return warnings

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
        status = normalize_security_status(check.get("status"))
        status_class = ""
        if status == "pass":
            status_class = "check-pass"
        elif status == "fail":
            status_class = "check-fail"
        elif status == "warning":
            status_class = "check-warning"
        else:
            status_class = "check-unknown"
        status_label = status.title()
        table_rows += (
            f'<tr><td>{_he(check.get("networkName", "Organization"))}</td>'
            f'<td>{_he(check.get("check", ""))}</td>'
            f'<td class="{status_class}">{_he(status_label)}</td>'
            f'<td>{_he(check.get("description", ""))}</td>'
            f'<td>{_he(check.get("remediation", ""))}</td></tr>'
        )
    table = f'<table class="data">{table_header}<tbody>{table_rows}</tbody></table>'
    return header + table


def build_fallback_security_checks(
    devices_avail: List[Dict[str, Any]],
    inv_by_type: Dict[str, int],
    switch_port_issues: List[Dict[str, Any]],
    port_data_available: bool = False,
) -> List[Dict[str, Any]]:
    """Build conservative checks when an appliance baseline is unavailable.

    Only observations backed by collected telemetry receive Pass or Fail.  The
    remaining controls are explicitly informational so the report distinguishes
    an uncollected control from a verified healthy control.
    """
    valid_devices = [d for d in devices_avail if isinstance(d, dict)]
    device_statuses = {
        str(d.get("status", "")).strip().lower() for d in valid_devices
    }
    if not valid_devices:
        device_online_status = "Info"
        device_online_description = "Device availability data was not collected"
    elif device_statuses.intersection({"offline", "alerting", "down", "failed"}):
        device_online_status = "Fail"
        device_online_description = "One or more managed devices are not reporting healthy"
    elif device_statuses and device_statuses.issubset({"online"}):
        device_online_status = "Pass"
        device_online_description = "All managed devices reporting online"
    else:
        device_online_status = "Info"
        device_online_description = "Device availability includes unrecognized or incomplete statuses"

    return [
        {
            "networkName": "Organization",
            "check": "Device Online Status",
            "status": device_online_status,
            "description": device_online_description,
            "remediation": "Investigate offline devices; check physical connections, power, and uplink paths",
        },
        {
            "networkName": "Organization",
            "check": "Default Password Check",
            "status": "Info",
            "description": "Credential posture was not collected in this backup",
            "remediation": "Audit all device credentials and rotate any defaults",
        },
        {
            "networkName": "Organization",
            "check": "SSH Access Restriction",
            "status": "Info",
            "description": "SSH access policy was not collected in this backup",
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
            "status": "Info",
            "description": "Wireless encryption settings were not collected in this backup",
            "remediation": "Update any open or WPA-Personal SSIDs to enterprise-grade encryption",
        },
        {
            "networkName": "Organization",
            "check": "Port Security Configuration",
            "status": "Fail" if switch_port_issues else ("Pass" if port_data_available else "Info"),
            "description": (
                "Port telemetry was collected with no reported issues"
                if port_data_available and not switch_port_issues
                else "Check for port errors, duplex mismatches, and speed degradation"
            ),
            "remediation": "Resolve port issues; consider 802.1X port authentication",
        },
        {
            "networkName": "Organization",
            "check": "Logging and Monitoring",
            "status": "Info",
            "description": "Centralized logging and monitoring configuration was not collected",
            "remediation": "Configure centralized logging and alerting for critical network events",
        },
    ]

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
    total_usage = safe_float((usage or {}).get("total") if isinstance(usage, dict) else None)
    current_kbps = safe_float((traffic or {}).get("total") if isinstance(traffic, dict) else None)
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
