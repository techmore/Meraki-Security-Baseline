# Meraki Security Baseline and Report Suite

This repository now combines two related workflows:

1. Legacy Meraki security baseline scripts for MX-focused best-practice checks.
2. An enhanced reporting pipeline that backs up Meraki org data, generates recommendations, optionally runs a local Ollama review, and renders HTML/PDF reports.

The current working branch is centered on the reporting pipeline while preserving the upstream baseline scripts so they can be integrated into future report sections.

## Components

- `Meraki-Baseline-Security.py`
- `mbsv2.py`, `v6_baseline.py`, `v6-mdm.py`, `v9.py`
- `networking-script-no-topography.py`
- `license.py`
- `orgs.sh`
- `meraki_backup.py`
- `meraki_query.py`
- `merge_recommendations.py`
- `ollama_review.py`
- `report_generator.py`
- `run.sh`

## Reporting Pipeline

The reporting workflow pulls Meraki API data into per-org backup directories, produces recommendations, optionally enhances them with Ollama, and generates HTML/PDF reports.

### Usage

1. Create a local `.env` from `.env.example`.
2. Set `MERAKI_API_KEY`.
3. Run:

```bash
./run.sh
```

Optional:

```bash
./run.sh --model qwen3.5:27b
```

### Output

- `backups/<org>/recommendations.md`
- `backups/<org>/report.html`
- `backups/<org>/report.pdf`
- `backups/master_recommendations.md`
- `backups/recommendations_ai_enhanced.md`

## Legacy Security Baseline

The original baseline scripts check Meraki MX firewall posture against Meraki best practices, including licensing, anti-malware, IDS/IPS, spoof protection, and exposed ports.

Basic usage for the original baseline script:

```bash
python Meraki-Baseline-Security.py
```

Those scripts currently coexist with the report generator and should be treated as source inputs for a later unified assessment flow.

## Requirements

- Python 3.x
- `meraki`
- `prettytable`
- WeasyPrint for PDF generation
- `wkhtmltopdf` as an optional PDF fallback
- Ollama for optional local review

## Current Direction

Near-term work for the integrated v1 release:

- merge baseline findings into the generated report
- harden handling of secrets and backup artifacts
- improve portability and dependency management
- add tests and CI coverage

## Security Notes

- Do not commit `.env`.
- Do not commit live backups or generated reports.
- Rotate any API key that was previously stored in the repo or shared history.

## License

The upstream baseline project includes GPL-3.0 licensed components. Review licensing obligations before redistributing a packaged v1 release.
