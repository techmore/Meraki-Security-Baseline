"""Validated input loading for report generation.

The report renderer should consume normalized data rather than owning all file
I/O.  This boundary keeps artifact defaults and data-quality warnings
consistent while allowing section builders to evolve independently.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List

from .common import load_json_checked


@dataclass
class ReportDataContext:
    """Raw and normalized artifacts used by the organization report."""

    recommendations_markdown: str
    data_quality_warnings: List[str]
    inventory_summary: Dict[str, Any]
    poe_summary: Dict[str, Any]
    channel_utilization: List[Any]
    devices_availability: List[Any]
    lldp_cdp: Dict[str, Any]
    wireless_stats: Dict[str, Any]
    wireless_clients: List[Dict[str, Any]]
    switch_port_statuses_by_switch: Any
    switch_port_configs_by_switch: Any
    switch_port_statuses: List[Dict[str, Any]]
    switch_port_configs: List[Dict[str, Any]]
    uplink_statuses: List[Any]
    appliance_uplinks_usage: Dict[str, Any]
    devices_statuses: List[Any]
    clients_overview: Dict[str, Any]
    licensing: Any
    rf_profiles: Dict[str, Any]
    inventory_devices: List[Any]
    firmware_upgrades: List[Any]
    wireless_settings: Dict[str, Any]
    wireless_ssids: Dict[str, Any]
    alerts_history: Dict[str, Any]
    wireless_mesh_statuses: Dict[str, Any]
    pricing: Dict[str, Any]
    networks: List[Any]
    security_baseline: Dict[str, Any]


def _flatten_ports(raw: Any, label: str, warnings: List[str]) -> List[Dict[str, Any]]:
    """Normalize either supported switch-port artifact shape."""
    if isinstance(raw, list):
        return [port for port in raw if isinstance(port, dict)]
    if not isinstance(raw, dict):
        warnings.append(f"{label} could not be normalized into port records")
        return []
    result: List[Dict[str, Any]] = []
    for serial, ports in raw.items():
        if isinstance(ports, list):
            for port in ports:
                if isinstance(port, dict):
                    port.setdefault("switchSerial", serial)
                    result.append(port)
    return result


def load_report_data(org_dir: str, base_dir: str) -> ReportDataContext:
    """Load and normalize report artifacts with explicit coverage warnings."""
    warnings: List[str] = []

    recommendations_markdown = ""
    rec_path = os.path.join(org_dir, "recommendations.md")
    if os.path.exists(rec_path):
        try:
            with open(rec_path, "r", encoding="utf-8") as file:
                recommendations_markdown = file.read()
        except (OSError, UnicodeError) as exc:
            warnings.append(f"recommendations.md could not be read: {exc}")

    def load_artifact(
        filename: str,
        expected_type: Any,
        default: Any,
        required: bool = False,
    ) -> Any:
        path = os.path.join(org_dir, filename)
        if required and not os.path.exists(path):
            warnings.append(
                f"{filename} is missing; associated report sections have incomplete coverage"
            )
        return load_json_checked(path, expected_type, default, warnings)

    inventory_summary = load_artifact("inventory_summary.json", dict, {}, required=True)
    poe_summary = load_artifact("poe_power_summary.json", dict, {})
    channel_utilization = load_artifact("channel_utilization_by_device.json", list, [])
    devices_availability = load_artifact(
        "devices_availabilities.json", list, [], required=True
    )
    lldp_cdp = load_artifact("lldp_cdp.json", dict, {})
    wireless_stats = load_artifact("wireless_connection_stats.json", dict, {})
    wireless_clients_raw = load_artifact("wireless_clients.json", (dict, list), {})
    if isinstance(wireless_clients_raw, dict):
        wireless_clients = [
            client
            for clients in wireless_clients_raw.values()
            if isinstance(clients, list)
            for client in clients
            if isinstance(client, dict)
        ]
    elif isinstance(wireless_clients_raw, list):
        wireless_clients = [client for client in wireless_clients_raw if isinstance(client, dict)]
    else:
        wireless_clients = []

    switch_port_statuses_by_switch = load_artifact(
        "switch_port_statuses.json", (dict, list), {}, required=True
    )
    switch_port_configs_by_switch = load_artifact(
        "switch_port_configs.json", (dict, list), {}
    )
    uplink_statuses = load_artifact("uplink_statuses.json", list, [], required=True)
    appliance_uplinks_usage = load_artifact("appliance_uplinks_usage.json", dict, {})
    devices_statuses = load_artifact("devices_statuses.json", list, [])
    clients_overview = load_artifact("clients_overview.json", dict, {})
    licensing = load_artifact("licensing.json", (list, dict), {})
    rf_profiles = load_artifact("wireless_rf_profiles.json", dict, {})
    inventory_devices = load_artifact("inventory_devices.json", list, [])
    firmware_upgrades = load_artifact("firmware_upgrades.json", list, [])
    wireless_settings = load_artifact("wireless_settings.json", dict, {})
    wireless_ssids = load_artifact("wireless_ssids.json", dict, {})
    alerts_history = load_artifact("alerts_history.json", dict, {})
    wireless_mesh_statuses = load_artifact("wireless_mesh_statuses.json", dict, {})
    pricing = load_artifact("pricing.json", dict, {})
    if not pricing:
        pricing = load_json_checked(
            os.path.join(base_dir, "pricing.json"),
            dict,
            {},
            warnings,
        )

    switch_port_configs = _flatten_ports(
        switch_port_configs_by_switch,
        "switch_port_configs.json",
        warnings,
    )
    switch_port_statuses = _flatten_ports(
        switch_port_statuses_by_switch,
        "switch_port_statuses.json",
        warnings,
    )
    networks = load_artifact("networks.json", list, [], required=True)
    security_baseline = load_artifact("security_baseline.json", dict, {}, required=True)

    return ReportDataContext(
        recommendations_markdown=recommendations_markdown,
        data_quality_warnings=warnings,
        inventory_summary=inventory_summary,
        poe_summary=poe_summary,
        channel_utilization=channel_utilization,
        devices_availability=devices_availability,
        lldp_cdp=lldp_cdp,
        wireless_stats=wireless_stats,
        wireless_clients=wireless_clients,
        switch_port_statuses_by_switch=switch_port_statuses_by_switch,
        switch_port_configs_by_switch=switch_port_configs_by_switch,
        switch_port_statuses=switch_port_statuses,
        switch_port_configs=switch_port_configs,
        uplink_statuses=uplink_statuses,
        appliance_uplinks_usage=appliance_uplinks_usage,
        devices_statuses=devices_statuses,
        clients_overview=clients_overview,
        licensing=licensing,
        rf_profiles=rf_profiles,
        inventory_devices=inventory_devices,
        firmware_upgrades=firmware_upgrades,
        wireless_settings=wireless_settings,
        wireless_ssids=wireless_ssids,
        alerts_history=alerts_history,
        wireless_mesh_statuses=wireless_mesh_statuses,
        pricing=pricing,
        networks=networks,
        security_baseline=security_baseline,
    )
