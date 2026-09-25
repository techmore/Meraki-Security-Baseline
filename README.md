# Meraki Security Baseline and Report Suite

A reporting pipeline that collects Meraki org data, generates network health and security recommendations, optionally enriches them with a local LLM review, and renders HTML/PDF reports.

## Components

| Script | Role |
|--------|------|
| `meraki_backup.py` | Pulls Meraki API data into per-org backup directories |
| `merge_recommendations.py` | Combines per-org recommendation files |
| `ollama_review.py` | Optional local LLM review stage |
| `report_generator.py` | Renders HTML/PDF reports |
| `run.sh` | Full pipeline orchestrator |
| `legacy/` | Original MX baseline scripts (reference only) |

## Quick Start

1. Copy `.env.example` to `.env` and set `MERAKI_API_KEY`.
2. Run the full pipeline:

```bash
./run.sh
```

Optional API client settings are also supported: `MERAKI_API_BASE`,
`MERAKI_REQUEST_TIMEOUT`, and `MERAKI_MAX_RETRIES`. Values already exported in
the shell take precedence over `.env`; the backup process loads these settings
before creating its shared API client configuration.

Optional — specify a local Ollama model for AI-enhanced recommendations:

```bash
./run.sh --model qwen3.5:27b
```

## Output

All output is written to `backups/<org>/` (gitignored):

- `recommendations.md` — per-org findings and recommendations
- `report.html` / `report.pdf` — full rendered report
- `reports/<revision_id>/` — immutable report set for one generation run
- `reports/<revision_id>/manifest.json` — report version, input fingerprint, schema version, and available variants
- `reports/index.json` — latest revision pointer and revision history
- `report_exec_summary.*` / `report_backup_settings.*` — latest split-report aliases
- `backups/master_recommendations.md` — combined across all orgs
- `backups/recommendations_ai_enhanced.md` — LLM-reviewed version

Each report generation keeps its full, executive, and backup-settings outputs in a
UTC, collision-resistant revision directory. The root-level report files remain
latest-run aliases for existing automation. Compare `input_fingerprint` values in
`reports/index.json` to determine whether the source backup changed between runs.

## Optional Pricing Input

To enable the Hardware Cost & Refresh Plan section, create a `pricing.json` at the repo root
or within a specific org backup directory. See `pricing.json.example` for the expected shape.
Set `unit_cost` and optional `replacement_cycle_years` per model.

## Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

- Python 3.10+
- WeasyPrint (PDF rendering)
- `wkhtmltopdf` (optional PDF fallback)
- Ollama (optional LLM review)

## Development

For local iteration without live Meraki access, use the committed fixture set in
`tests/fixtures/`.

Generate a report directly from fixture data:

```bash
python3 - <<'PY'
from reporting.app import build_org_report
from reporting.html_shell import build_html

body = build_org_report("tests/fixtures", "Fixture Org")
print(build_html("Fixture Org — Network Health Report", body)[:400])
PY
```

Run the script entrypoint against existing backups:

```bash
python3 scripts/generate_report.py
./run.sh --report-only --no-ai-review
```

Run tests:

```bash
pytest -q
```

## License

The upstream baseline project includes GPL-3.0 licensed components. Review licensing obligations before redistributing a packaged release.
