"""Shared report section definitions and assembly helpers.

Keeping section membership and ordering in one place prevents the table of
contents and report body from drifting as new report sections are added.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

from .common import _he


@dataclass(frozen=True)
class SectionDefinition:
    key: str
    title: str
    full: bool = True
    backup: bool = True
    executive: bool = False

    def included_in(self, variant: str) -> bool:
        return {
            "full": self.full,
            "backup": self.backup,
            "exec": self.executive,
        }.get(variant, False)


REPORT_SECTIONS: tuple[SectionDefinition, ...] = (
    SectionDefinition("executive_summary", "Executive Summary", backup=False, executive=True),
    SectionDefinition("network_overview", "Network Overview"),
    SectionDefinition("network_topology", "Network Topology"),
    SectionDefinition("traffic_flows", "Traffic Flows & Bottleneck Analysis"),
    SectionDefinition("device_issues", "Device Health & Issues"),
    SectionDefinition("poe_analysis", "PoE Power Analysis"),
    SectionDefinition("security_baseline", "Security Baseline"),
    SectionDefinition("recommendations", "Recommendations & Implementation Plan"),
    SectionDefinition("cis8", "CIS 8 Controls Assessment"),
    SectionDefinition("licensing", "Licensing Summary"),
    SectionDefinition("config_coverage", "Configuration Backup Coverage"),
    SectionDefinition("budget_forecast", "Hardware Cost & Refresh Plan"),
    SectionDefinition("wan_capacity", "Internet Capacity & Utilization"),
    SectionDefinition("ap_interference", "AP Interference Audit"),
    SectionDefinition("client_analysis", "Client Analysis"),
    SectionDefinition("switch_deep_dive", "Switch Deep Dive"),
    SectionDefinition("unifi_comparison", "UniFi Comparison & Refresh Planning"),
)


def _sections_for_variant(variant: str) -> Iterable[SectionDefinition]:
    return (section for section in REPORT_SECTIONS if section.included_in(variant))


def render_toc(
    variant: str,
    *,
    site_items: str = "",
    switch_subitems: str = "",
) -> str:
    """Render a TOC from the same ordered definitions used for body assembly."""
    entries: List[str] = []
    for number, section in enumerate(_sections_for_variant(variant), start=1):
        subitems = ""
        if section.key == "network_topology" and site_items:
            subitems = f'<ol class="toc-sub">{site_items}</ol>'
        elif section.key == "switch_deep_dive" and switch_subitems:
            subitems = f'<ol class="toc-sub">{switch_subitems}</ol>'
        entries.append(
            f'<li><span class="toc-num">{number}</span>'
            f'<span class="toc-entry">{_he(section.title)}</span>{subitems}</li>'
        )
    return f'''
    <section class="toc-page">
      <div class="toc-header">Table of Contents</div>
      <ol class="toc-list">{"".join(entries)}</ol>
    </section>
    '''


def render_report_sections(
    section_bodies: Dict[str, str],
    variant: str,
) -> str:
    """Concatenate section bodies in registry order for a report variant."""
    missing = [
        section.key
        for section in _sections_for_variant(variant)
        if section.key not in section_bodies
    ]
    if missing:
        raise KeyError(f"Missing report section bodies: {', '.join(missing)}")
    return "".join(
        section_bodies[section.key]
        for section in _sections_for_variant(variant)
    )
