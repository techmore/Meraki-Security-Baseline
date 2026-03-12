# Meraki Enhanced Report Generator

This repository contains an enhanced report generator for Meraki network data that creates professional, visually-rich PDF and HTML reports.

## Features

- **Professional Multi-Section Reports**: Cover page, table of contents, executive summary, technical breakdown, issues, recommendations, and implementation plan
- **Beautiful Styling**: Uses the same olive and stone color palette as the 2026-new_sites template
- **Interactive Elements**: Icons, hover effects, gradients, and visual hierarchy
- **Comprehensive Analytics**: 
  - Device status and inventory overviews
  - PoE power consumption analysis (switch and port level)
  - Channel utilization tracking with trending charts
  - Wireless statistics and configuration analysis
  - Port error and duplex mismatch detection
- **Multiple Chart Types**: Bar charts, line charts, and pie charts for data visualization
- **Actionable Insights**: Prioritized recommendations with implementation roadmap
- **Template Matching**: Designed to match the visual style of 2026-new_sites

## Usage

1. Place Meraki backup data in directories matching the pattern: `meraki_backup_*/org_*/`
2. Each org directory should contain:
   - `recommendations.md` (markdown formatted recommendations)
   - `inventory_summary.json` (device inventory data)
   - `poe_power_summary.json` (PoE power consumption data)
   - Optional: `devices_availabilities.json`, `channel_utilization_by_device.json`, etc.
3. Run the generator:
   ```bash
   python3 report_generator.py
   ```
4. Reports will be generated as both PDF and HTML in each org directory:
   - `report.pdf` - Professional PDF report
   - `report.html` - Beautifully styled HTML version

## Sample Data

Sample data for Contoso.net corporation is included in `sample_data/contoso_net/` to demonstrate the report generation capabilities.

## Repository Structure

- `report_generator.py` - Main report generation script
- `sample_data/` - Sample data sets for testing
- `2026-new_sites/` - Reference styling and template files
- `.gitignore` - Configured to exclude reports from version control

## Integration

This repository is designed to work alongside the Meraki Security Baseline repository:
- Add as upstream remote: `git remote add upstream https://github.com/techmore/Meraki-Security-Baseline.git`
- Work on feature branches (like `enhanced-reporting`)
- Periodically pull updates from upstream
- Push feature branches to your own origin

## Requirements

- Python 3.x
- WeasyPrint (for PDF generation): `pip install weasyprint`
- wkhtmltopdf (fallback option)

## Output Examples

Reports include:
- Cover page with organization branding and generation timestamp
- Interactive table of contents
- Executive summary with key metrics dashboard
- Visual charts showing device distribution, PoE consumption, and utilization trends
- Detailed sections covering device inventory, technical specifications, identified issues, and prioritized recommendations
- Implementation roadmap with hardware placement guidance and upgrade suggestions

All reports maintain consistent styling with the olive color scheme and professional typography.