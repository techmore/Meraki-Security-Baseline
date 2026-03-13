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

Optional — specify a local Ollama model for AI-enhanced recommendations:

```bash
./run.sh --model qwen3.5:27b
```

## Output

All output is written to `backups/<org>/` (gitignored):

- `recommendations.md` — per-org findings and recommendations
- `report.html` / `report.pdf` — full rendered report
- `backups/master_recommendations.md` — combined across all orgs
- `backups/recommendations_ai_enhanced.md` — LLM-reviewed version

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

Use `sample_data/` for anonymised fixtures. Run the report generator directly against a backup directory for fast iteration:

```bash
python report_generator.py
```

## License

The upstream baseline project includes GPL-3.0 licensed components. Review licensing obligations before redistributing a packaged release.
