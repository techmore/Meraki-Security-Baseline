#!/usr/bin/env bash
# Meraki Network Report Suite — runner

set -uo pipefail
cd "$(dirname "$0")"

# ── Flag parsing ─────────────────────────────────────────────────────────────
CUSTOM_MODEL=""
REPORT_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --model|-m)
      CUSTOM_MODEL="${2:-}"
      shift 2
      ;;
    --report-only)
      REPORT_ONLY=1
      shift
      ;;
    --help|-h)
      echo "Usage: ./run.sh [--model <ollama-model>] [--report-only]"
      echo ""
      echo "  -m, --model    Override the Ollama model used for AI review"
      echo "                 Default: qwen3.5:9b"
      echo "      --report-only"
      echo "                 Skip API collection and build from existing backups/"
      echo ""
      echo "  Examples:"
      echo "    ./run.sh"
      echo "    ./run.sh --model qwen3.5:27b"
      echo "    ./run.sh -m gemma3:12b"
      echo "    ./run.sh --report-only"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$CUSTOM_MODEL" ]]; then
  export OLLAMA_MODEL="$CUSTOM_MODEL"
fi

# ── Color palette (256-color) ───────────────────────────────────────────────
R='\033[0m'         # reset
BOLD='\033[1m'
DIM='\033[2m'
BLU='\033[38;5;67m'    # steel blue
CYN='\033[38;5;73m'    # cyan
OLV='\033[38;5;143m'   # olive
GRN='\033[38;5;71m'    # green
YLW='\033[38;5;179m'   # amber
RED='\033[38;5;167m'   # red
MGT='\033[38;5;138m'   # muted rose (skip)
DIM2='\033[38;5;242m'  # dim gray

# ── Stage definitions: "label|script" ───────────────────────────────────────
STAGES=(
  "Environment Check|meraki_env.py"
  "Query Meraki API|meraki_query.py"
  "Backup Data|meraki_backup.py"
  "Merge Recommendations|merge_recommendations.py"
  "AI Review (Ollama)|ollama_review.py"
  "Generate Reports|report_generator.py"
)
TOTAL=${#STAGES[@]}

# ── Helpers ─────────────────────────────────────────────────────────────────
_hr() {
  # Print a horizontal rule of width $1 using char $2
  local width="${1:-60}" char="${2:--}"
  printf '%0.s'"$char" $(seq 1 "$width")
  echo
}

print_header() {
  local now model_line
  now=$(date '+%A, %-d %B %Y  %H:%M')
  model_line="AI model: ${OLLAMA_MODEL:-qwen3.5:9b (default)}"
  echo ""
  echo -e "${BLU}╭$(_hr 62 ─ | tr -d '\n')╮${R}"
  printf "${BLU}│${R}  ${BOLD}${OLV}%-58s${R}  ${BLU}│${R}\n" "MERAKI NETWORK REPORT SUITE  ·  v1.0"
  printf "${BLU}│${R}  ${DIM2}%-58s${R}  ${BLU}│${R}\n" "$now"
  printf "${BLU}│${R}  ${DIM2}%-58s${R}  ${BLU}│${R}\n" "$model_line"
  echo -e "${BLU}╰$(_hr 62 ─ | tr -d '\n')╯${R}"
  echo ""
}

_spinner() {
  # Background spinner — reads from a pipe to know when to stop
  local msg="$1"
  local frames=('⠋' '⠙' '⠸' '⠴' '⠦' '⠇')
  local i=0
  # shellcheck disable=SC2154
  while true; do
    printf "\r  ${YLW}%s${R}  ${DIM2}%s${R}  " "${frames[$i]}" "$msg"
    i=$(( (i+1) % 6 ))
    sleep 0.08
  done
}

_clear_line() {
  printf '\r%80s\r' ''
}

# ── Stage runner ─────────────────────────────────────────────────────────────
# Returns 0 on success, 1 on failure
# Globals written: STAGE_STATUS (ok|fail|skip), STAGE_DURATION
run_stage() {
  local label="$1"
  local script="$2"
  local step="$3"

  # Stage header
  echo ""
  printf "  ${BLU}${BOLD}[%d/%d]${R}  ${BOLD}%s${R}\n" "$step" "$TOTAL" "$label"
  echo -e "  ${DIM2}$(printf '─%.0s' $(seq 1 58))${R}"

  if [[ ! -f "$script" ]]; then
    printf "  ${MGT}⚡  Script not found: %s — skipping${R}\n" "$script"
    STAGE_STATUS="skip"
    STAGE_DURATION=0
    return 0
  fi

  # Capture output to temp file; show spinner while running
  local tmp
  tmp=$(mktemp)
  local t_start
  t_start=$(date +%s)

  _spinner "$script" &
  local spin_pid=$!

  set +e
  python3 "$script" > "$tmp" 2>&1
  local exit_code=$?
  set -e

  kill "$spin_pid" 2>/dev/null
  wait "$spin_pid" 2>/dev/null
  _clear_line

  local t_end
  t_end=$(date +%s)
  STAGE_DURATION=$(( t_end - t_start ))

  # Print captured output, indented
  if [[ -s "$tmp" ]]; then
    while IFS= read -r line; do
      printf "  ${DIM2}│${R}  %s\n" "$line"
    done < "$tmp"
  fi
  rm -f "$tmp"

  if (( exit_code == 0 )); then
    printf "\n  ${GRN}✓${R}  ${BOLD}%s${R}${DIM2}  completed in %ds${R}\n" \
      "$label" "$STAGE_DURATION"
    STAGE_STATUS="ok"
    return 0
  else
    printf "\n  ${RED}✗${R}  ${BOLD}%s${R}${RED}  failed${R}${DIM2}  after %ds${R}\n" \
      "$label" "$STAGE_DURATION"
    STAGE_STATUS="fail"
    return 1
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
print_header

SUITE_START=$(date +%s)
declare -a RESULTS   # "ok|fail|skip" per stage
declare -a DURATIONS # seconds per stage
FAIL_COUNT=0
SKIP_COUNT=0

for i in "${!STAGES[@]}"; do
  IFS='|' read -r label script <<< "${STAGES[$i]}"
  step=$(( i + 1 ))

  STAGE_STATUS="ok"
  STAGE_DURATION=0

  if (( REPORT_ONLY == 1 && i < 3 )); then
    echo ""
    printf "  ${BLU}${BOLD}[%d/%d]${R}  ${BOLD}%s${R}\n" "$step" "$TOTAL" "$label"
    echo -e "  ${DIM2}$(printf '─%.0s' $(seq 1 58))${R}"
    printf "  ${MGT}⚡${R}  ${BOLD}%s${R}${DIM2}  skipped in report-only mode${R}\n" "$label"
    RESULTS[$i]="skip"
    DURATIONS[$i]=0
    (( SKIP_COUNT++ )) || true
    continue
  fi

  if run_stage "$label" "$script" "$step"; then
    RESULTS[$i]="$STAGE_STATUS"
    DURATIONS[$i]=$STAGE_DURATION
  else
    RESULTS[$i]="fail"
    DURATIONS[$i]=$STAGE_DURATION
    (( FAIL_COUNT++ )) || true
    # Stop on hard failures (not skips)
    echo ""
    echo -e "  ${RED}${BOLD}Pipeline halted.${R}  Fix the error above and re-run."
    echo ""
    break
  fi

  [[ "${RESULTS[$i]}" == "skip" ]] && (( SKIP_COUNT++ )) || true
done

SUITE_END=$(date +%s)
SUITE_DURATION=$(( SUITE_END - SUITE_START ))

# ── Summary table ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BLU}╭$(_hr 62 ─ | tr -d '\n')╮${R}"
printf "${BLU}│${R}  ${BOLD}%-58s${R}  ${BLU}│${R}\n" "EXECUTION SUMMARY"
echo -e "${BLU}├$(_hr 62 ─ | tr -d '\n')┤${R}"

for i in "${!STAGES[@]}"; do
  IFS='|' read -r label script <<< "${STAGES[$i]}"
  status="${RESULTS[$i]:-—}"
  dur="${DURATIONS[$i]:-0}"

  case "$status" in
    ok)
      icon="${GRN}✓${R}"
      status_str="${GRN}OK${R}"
      ;;
    fail)
      icon="${RED}✗${R}"
      status_str="${RED}FAILED${R}"
      ;;
    skip)
      icon="${MGT}⚡${R}"
      status_str="${MGT}SKIPPED${R}"
      ;;
    *)
      icon="${DIM2}·${R}"
      status_str="${DIM2}—${R}"
      ;;
  esac

  printf "${BLU}│${R}  %b  ${DIM2}%-30s${R}  %b  ${DIM2}%4ds${R}  ${BLU}│${R}\n" \
    "$icon" "$label" "$status_str" "$dur"
done

echo -e "${BLU}├$(_hr 62 ─ | tr -d '\n')┤${R}"
printf "${BLU}│${R}  ${DIM2}%-40s${R}${BOLD}%15ss total${R}  ${BLU}│${R}\n" "" "$SUITE_DURATION"
echo -e "${BLU}╰$(_hr 62 ─ | tr -d '\n')╯${R}"
echo ""

if (( FAIL_COUNT == 0 )); then
  echo -e "  ${GRN}${BOLD}All stages passed.${R}  Reports written to backups/."
  echo ""

  # ── Auto-open generated reports ───────────────────────────────────────────
  BACKUPS_DIR="$(pwd)/backups"
  if [[ -d "$BACKUPS_DIR" ]]; then
   REPORT_FILES=()
   while IFS= read -r org_dir; do
     if [[ -f "$org_dir/report.pdf" ]]; then
       REPORT_FILES+=("$org_dir/report.pdf")
     elif [[ -f "$org_dir/report.html" ]]; then
       REPORT_FILES+=("$org_dir/report.html")
     fi
   done < <(find "$BACKUPS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)

    if (( ${#REPORT_FILES[@]} > 0 )); then
      echo -e "  ${OLV}Opening ${#REPORT_FILES[@]} report(s)…${R}"
      # Cross-platform file opener
      _open_file() {
        if command -v xdg-open &>/dev/null; then
          xdg-open "$1"
        elif command -v open &>/dev/null; then
          open "$1"
        elif command -v start &>/dev/null; then
          start "" "$1"
        else
          printf "  ${DIM2}(Cannot auto-open — no suitable opener found)${R}\n"
        fi
      }
      for f in "${REPORT_FILES[@]}"; do
        org_name=$(basename "$(dirname "$f")")
        printf "  ${DIM2}→${R}  %s  ${DIM2}(%s)${R}\n" "$org_name" "$(basename "$f")"
        _open_file "$f"
      done
    else
      echo -e "  ${DIM2}No report files found in backups/ — run the pipeline first.${R}"
    fi
  fi
else
  echo -e "  ${RED}${BOLD}${FAIL_COUNT} stage(s) failed.${R}  Review output above."
fi
echo ""
