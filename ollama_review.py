#!/usr/bin/env python3
"""
Optional pipeline stage: Use local Ollama (gemma3:12b) to review and
enhance merged Meraki recommendations before PDF generation.

Exits 0 (non-fatal) if Ollama is unavailable so the pipeline continues.
Output: <backup_dir>/recommendations_ai_enhanced.md
"""
import json
import logging
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")
OLLAMA_URL = "http://localhost:11434"

# ── Model selection ──────────────────────────────────────────────────────────
# On M1 Pro / 32 GB RAM — all sizes fit at Q4 quantization:
#
#   qwen3.5:27b    ~17 GB  — RECOMMENDED: best capability/fit for 32 GB; 256K ctx
#   qwen3.5:9b     ~6.6 GB — faster, lower RAM; still very capable; 256K ctx
#   qwen3.5:35b    ~24 GB  — slightly better but leaves little RAM headroom
#   qwen2.5:14b    ~9 GB   — previous gen, still solid structured output
#   phi4:14b       ~9 GB   — strong instruction following
#   gemma3:12b     ~8 GB   — good all-rounder, weaker at strict output formats
#
# qwen3.5 advantages for this task:
#   - 256K context (vs 128K for qwen2.5) — full report fits without truncation
#   - RL-trained on agent/tool tasks — follows structured output reliably
#   - Hybrid MoE architecture — fast inference for its size
#
# Pull with: ollama pull qwen3.5:9b
# Override at runtime: OLLAMA_MODEL=qwen3.5:27b ./run.sh
#                  or: ./run.sh --model qwen3.5:27b
_DEFAULT_MODEL = "qwen3.5:9b"
MODEL = os.getenv("OLLAMA_MODEL", _DEFAULT_MODEL)

# With 256K context we can pass the full report without truncation.
# Reserve ~4K tokens (~3000 chars) for system prompt + output headroom.
MAX_INPUT_CHARS = 50_000

SYSTEM_PROMPT = """\
You are a senior network engineer with deep expertise in Cisco Meraki enterprise deployments, \
specifically in K-12 and education environments. You are performing a structured engineering \
review of live network health data exported from the Meraki API.

Rules:
- Be specific: reference device serials, network names, and metric values from the input.
- Prioritise findings by operational risk, not by how much text the input devoted to them.
- Distinguish between confirmed problems (data shows failure) and risks (data shows warning signs).
- For each finding, state: the observed fact, why it matters operationally, and the exact next action.
- Do NOT repeat sections of the input verbatim. Do NOT pad with generic best-practice boilerplate.
- Use concise, direct language. A bullet is better than a paragraph.
- Output clean Markdown only.\
"""

USER_PROMPT_TEMPLATE = """\
Below is a Meraki network health report generated from live API data. \
Produce a prioritised engineering review.

--- BEGIN REPORT ---
{content}
--- END REPORT ---

Respond using EXACTLY this structure (include all six sections even if empty):

## 🔴 Critical  (resolve within 48 hours)
Issues causing or likely to cause immediate outages, security exposure, or license failure.

## 🟠 High Priority  (resolve within 2 weeks)
Degraded performance, recurring errors, or capacity issues with measurable user impact.

## 🟡 Medium Priority  (resolve within 60 days)
Suboptimal configurations, growing risks, or items that need scheduled maintenance.

## 🔵 Long-term Improvements  (next planning cycle)
Architecture, hardware refresh, or strategic changes worth budgeting for.

## ✅ Quick Wins  (< 1 hour each, low risk)
Configuration changes or checks that are easy to do now and will reduce noise or risk.

## 📊 Risk Summary
2–4 sentence executive summary of overall network health and the top risk to address first.\
"""


def ollama_available() -> bool:
    """Return True if Ollama is running and the target model is present."""
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        model_base = MODEL.split(":")[0]
        names = [m.get("name", "").split(":")[0] for m in data.get("models", [])]
        if model_base not in names:
            log.warning("Model '%s' not found locally. Pull it first: ollama pull %s", MODEL, MODEL)
            return False
        return True
    except Exception as exc:
        log.warning("Ollama not reachable at %s (%s). Start it with: ollama serve", OLLAMA_URL, exc)
        return False


def stream_ollama(content: str) -> str:
    """Stream a generate request to Ollama and return the full response text."""
    payload = json.dumps(
        {
            "model": MODEL,
            "system": SYSTEM_PROMPT,
            "prompt": USER_PROMPT_TEMPLATE.format(content=content[:MAX_INPUT_CHARS]),
            "stream": True,
            "options": {
                "temperature": 0.3,   # lower = more factual
                "num_predict": 2048,
            },
        }
    ).encode()

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    tokens: list[str] = []
    dot_counter = 0
    print("  Generating", end="", flush=True)

    with urllib.request.urlopen(req, timeout=300) as resp:
        while True:
            line = resp.readline()
            if not line:
                break
            try:
                chunk = json.loads(line.decode())
            except json.JSONDecodeError:
                continue
            token = chunk.get("response", "")
            tokens.append(token)
            dot_counter += 1
            if dot_counter % 40 == 0:
                print(".", end="", flush=True)
            if chunk.get("done", False):
                break

    print(" done", flush=True)
    return "".join(tokens).strip()


def main() -> int:
    master_rec = os.path.join(BACKUPS_DIR, "master_recommendations.md")
    if not os.path.exists(master_rec):
        log.warning("master_recommendations.md not found at %s", master_rec)
        log.warning("Run merge_recommendations.py first — skipping AI review.")
        return 0

    log.info("Checking Ollama (%s)...", MODEL)
    if not ollama_available():
        log.info("Skipping AI review — Ollama unavailable.")
        return 0  # non-fatal: rest of pipeline continues

    with open(master_rec, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.strip():
        log.info("No recommendations content — skipping AI review.")
        return 0

    char_count = len(content)
    truncated = char_count > MAX_INPUT_CHARS
    log.info(
        "Input: %s chars%s",
        f"{char_count:,}",
        " (will be truncated to fit context)" if truncated else "",
    )

    enhanced = stream_ollama(content)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out_path = os.path.join(BACKUPS_DIR, "recommendations_ai_enhanced.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# AI-Enhanced Network Recommendations\n\n")
        f.write(f"_Model: {MODEL} · Generated: {ts}_\n\n")
        f.write("---\n\n")
        f.write(enhanced)
        f.write("\n")

    log.info("Saved → backups/%s", os.path.basename(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
