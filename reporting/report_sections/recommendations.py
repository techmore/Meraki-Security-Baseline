"""Recommendations and implementation timeline report section."""

from typing import Any

from ..common import _he, md_to_html


def build_recommendations_section(
    recommendations_markdown: str,
    mixed_lifecycle_networks: list[str],
    rf_profiles: Any,
    network_names: dict[str, str],
) -> str:
    """Render recommendations alongside hardware lifecycle and RF profile notes."""
    rf_profile_notes = []
    if isinstance(rf_profiles, dict):
        for net_id, profiles in rf_profiles.items():
            if not isinstance(profiles, list) or not profiles:
                continue
            prof = profiles[0] if isinstance(profiles[0], dict) else None
            if not prof:
                continue
            notes = []
            ap_band = prof.get("apBandSettings") or {}
            if ap_band.get("bandSteeringEnabled") is False:
                notes.append("band steering disabled")
            min_24 = (prof.get("twoFourGhzSettings") or {}).get("minBitrate")
            if isinstance(min_24, (int, float)) and min_24 <= 11:
                notes.append("2.4 GHz min bitrate ≤ 11 Mbps")
            min_5 = (prof.get("fiveGhzSettings") or {}).get("minBitrate")
            if isinstance(min_5, (int, float)) and min_5 <= 12:
                notes.append("5 GHz min bitrate ≤ 12 Mbps")
            width_5 = (prof.get("fiveGhzSettings") or {}).get("channelWidth")
            if str(width_5).strip() in ("20", "20MHz"):
                notes.append("5 GHz channel width fixed at 20 MHz")
            if notes:
                rf_profile_notes.append(f"{network_names.get(net_id, net_id)}: " + "; ".join(notes))

    rec_html = md_to_html(recommendations_markdown)
    extra_recs_html = ""
    if mixed_lifecycle_networks or rf_profile_notes:
        extra_recs_html = (
            "<h3>Hardware Mix &amp; AP Profile Optimization</h3>"
            "<div class=\"summary-card\"><div class=\"summary-body\">"
        )
        if mixed_lifecycle_networks:
            extra_recs_html += (
                "<strong>Mixed hardware generations detected:</strong> "
                + _he(", ".join(sorted(mixed_lifecycle_networks)[:8]))
                + ". Align refresh cycles so upstream switching and downstream APs are on compatible lifecycle tiers."
                "<br><br>"
            )
        if rf_profile_notes:
            extra_recs_html += (
                "<strong>AP profile optimization opportunities:</strong><br>"
                + "<br>".join(_he(n) for n in rf_profile_notes[:10])
                + "<br>Consider raising minimum bitrates, enabling band steering, and widening 5 GHz channels where density allows."
            )
        extra_recs_html += "</div></div>"

    return f"""
    <section id="recommendations" class="report-section">
      <h2>8. Recommendations &amp; Implementation Plan</h2>
      {rec_html}
      {extra_recs_html}
      <h3>Prioritized Action Timeline</h3>
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
