#!/usr/bin/env bash
# run.sh - Execute zrok code review evaluations
#
# Usage:
#   ./eval/run.sh [options]
#
# Options:
#   -n NUM          Number of evaluation runs (default: 10)
#   -z PATH         Path to zrok binary (default: ./zrok)
#   -o DIR          Output directory for results (default: eval/results)
#   -f DIR          Path to fixture app (default: eval/fixtures/owasp-subset)
#   -g FILE         Path to ground truth (auto-detected from fixture)
#   --fixture NAME  Fixture preset: "owasp" or "vulnerable-app"
#   --baseline      After runs complete, generate baseline from results
#   --compare       Compare a single run against existing baseline
#   --dry-run       Show what would be done without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
NUM_RUNS=10
ZROK_BIN="${PROJECT_ROOT}/zrok"
OUTPUT_DIR=""
FIXTURE_DIR=""
GROUND_TRUTH=""
FIXTURE_PRESET="owasp"
GENERATE_BASELINE=false
COMPARE_MODE=false
DRY_RUN=false
MAX_RETRIES=3
CONSECUTIVE_QUOTA_FAILURES=0
MAX_CONSECUTIVE_QUOTA_FAILURES=3
# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n) NUM_RUNS="$2"; shift 2 ;;
        -z) ZROK_BIN="$2"; shift 2 ;;
        -o) OUTPUT_DIR="$2"; shift 2 ;;
        -f) FIXTURE_DIR="$2"; shift 2 ;;
        -g) GROUND_TRUTH="$2"; shift 2 ;;
        --fixture) FIXTURE_PRESET="$2"; shift 2 ;;
        --baseline) GENERATE_BASELINE=true; shift ;;
        --compare) COMPARE_MODE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Apply fixture preset defaults
case "$FIXTURE_PRESET" in
    owasp)
        FIXTURE_DIR="${FIXTURE_DIR:-${SCRIPT_DIR}/fixtures/owasp-subset}"
        GROUND_TRUTH="${GROUND_TRUTH:-${SCRIPT_DIR}/ground-truth-owasp.yaml}"
        OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results/owasp}"
        ;;
    vulnerable-app)
        FIXTURE_DIR="${FIXTURE_DIR:-${SCRIPT_DIR}/fixtures/vulnerable-app}"
        GROUND_TRUTH="${GROUND_TRUTH:-${SCRIPT_DIR}/ground-truth.yaml}"
        OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results/vulnerable-app}"
        ;;
    *)
        echo "Unknown fixture preset: $FIXTURE_PRESET (use 'owasp' or 'vulnerable-app')"
        exit 1
        ;;
esac

# Validate
if [[ ! -f "$ZROK_BIN" ]]; then
    echo "Error: zrok binary not found at $ZROK_BIN"
    echo "Run: go build -o zrok ."
    exit 1
fi

if [[ ! -d "$FIXTURE_DIR" ]]; then
    echo "Error: fixture directory not found at $FIXTURE_DIR"
    if [[ "$FIXTURE_PRESET" == "owasp" ]]; then
        echo "Run: git submodule update --init && eval/fixtures/owasp-subset/create-subset.sh"
    fi
    exit 1
fi

if [[ ! -f "$GROUND_TRUTH" ]]; then
    echo "Error: ground truth not found at $GROUND_TRUTH"
    if [[ "$FIXTURE_PRESET" == "owasp" ]]; then
        echo "Run: eval/generate-owasp-ground-truth.sh"
    fi
    exit 1
fi

# Build eval scorer
EVAL_BIN="${SCRIPT_DIR}/eval-scorer"
echo "Building eval scorer..."
(cd "$PROJECT_ROOT" && go build -o "$EVAL_BIN" ./eval/cmd/)

mkdir -p "$OUTPUT_DIR"

# Check if a claude stderr log indicates a quota/rate-limit error
is_quota_error() {
    local log_file="$1"
    [[ ! -f "$log_file" ]] && return 1
    grep -qiE '(rate.?limit|quota|too many requests|429|overloaded|capacity|billing|credit)' "$log_file"
}

run_single_eval() {
    local run_id="$1"
    local run_dir
    run_dir=$(mktemp -d)
    local result_file="${OUTPUT_DIR}/run-$(printf '%02d' "$run_id").json"

    echo "=== Run $run_id ==="
    echo "  Working directory: $run_dir"
    echo "  Fixture: $FIXTURE_PRESET"

    # Copy fixture to isolated directory
    cp -r "$FIXTURE_DIR"/* "$run_dir/"

    # Initialize zrok project
    (cd "$run_dir" && "$ZROK_BIN" init)

    # Run static onboarding (fast, no LLM needed for setup)
    (cd "$run_dir" && "$ZROK_BIN" onboard --static)

    # Restore pre-built semantic index if committed alongside fixture
    if [[ -d "${FIXTURE_DIR}/.zrok-index" ]]; then
        echo "  Restoring pre-built semantic index..."
        cp -r "${FIXTURE_DIR}/.zrok-index/"* "$run_dir/.zrok/index/"
        # Enable index config in project.yaml (points to pre-built data, no build needed)
        (cd "$run_dir" && "$ZROK_BIN" index enable --provider ollama) 2>/dev/null || true
    fi

    # Run the code review using Claude Code with the skill (with retry on quota errors)
    echo "  Running code review (this may take several minutes)..."
    local start_time
    start_time=$(date +%s)

    local attempt=0
    local claude_success=false

    while [[ $attempt -lt $MAX_RETRIES ]]; do
        attempt=$((attempt + 1))
        if [[ $attempt -gt 1 ]]; then
            local backoff=$(( (1 << (attempt - 1)) * 30 ))
            echo "  Retry $attempt/$MAX_RETRIES after ${backoff}s backoff..."
            sleep "$backoff"
        fi

        # Execute the review via claude CLI
        # Unset CLAUDECODE to allow nested invocation (safe: each run is isolated)
        if (cd "$run_dir" && unset CLAUDECODE && claude -p \
            "Run a code review of this project using zrok. The zrok binary is at ${ZROK_BIN}. Export findings as JSON when complete. Work autonomously and do not ask questions." \
            --allowedTools "Bash,Read,Write,Glob,Grep,Agent" \
            --output-format json \
            --permission-mode bypassPermissions \
            --max-budget-usd 5 \
            > "${run_dir}/claude-output.json" 2>"${run_dir}/claude-stderr.log"); then
            echo "  Claude review completed."
            claude_success=true
            CONSECUTIVE_QUOTA_FAILURES=0
            break
        else
            if is_quota_error "${run_dir}/claude-stderr.log"; then
                echo "  Quota/rate-limit error detected (attempt $attempt/$MAX_RETRIES)."
                tail -3 "${run_dir}/claude-stderr.log" 2>/dev/null || true
                if [[ $attempt -ge $MAX_RETRIES ]]; then
                    echo "  ERROR: Exhausted retries due to quota limits."
                    CONSECUTIVE_QUOTA_FAILURES=$((CONSECUTIVE_QUOTA_FAILURES + 1))
                fi
                continue
            else
                echo "  Warning: Claude review exited with non-zero status (non-quota error)."
                tail -5 "${run_dir}/claude-stderr.log" 2>/dev/null || true
                CONSECUTIVE_QUOTA_FAILURES=0
                break
            fi
        fi
    done

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "  Duration: ${duration}s"

    # Always export findings manually to ensure we capture them
    echo "  Exporting findings..."
    (cd "$run_dir" && "$ZROK_BIN" finding export --format json -o "eval-run.json") || true

    # Find the exported file (zrok puts bare filenames in .zrok/findings/exports/)
    local export_file
    export_file=$(find "$run_dir/.zrok/findings/exports" -name "*.json" -type f 2>/dev/null | head -1)

    if [[ -n "$export_file" && -f "$export_file" ]]; then
        cp "$export_file" "$result_file"
        echo "  Results: $result_file"
    else
        echo "  ERROR: No findings produced for run $run_id"
        echo '{"metadata":{"tool":"zrok"},"summary":{"total":0},"findings":[]}' > "$result_file"
    fi

    # Score this run
    echo "  Scoring..."
    "$EVAL_BIN" score --run "$result_file" --ground-truth "$GROUND_TRUTH" || true
    echo ""

    # Cleanup
    rm -rf "$run_dir"
}

if $DRY_RUN; then
    echo "Dry run mode - would execute:"
    echo "  $NUM_RUNS evaluation runs"
    echo "  Fixture: $FIXTURE_PRESET ($FIXTURE_DIR)"
    echo "  Output: $OUTPUT_DIR"
    echo "  Zrok: $ZROK_BIN"
    echo "  Ground truth: $GROUND_TRUTH"
    if $GENERATE_BASELINE; then
        echo "  Generate baseline after runs"
    fi
    exit 0
fi

if $COMPARE_MODE; then
    BASELINE_FILE="${SCRIPT_DIR}/baseline-${FIXTURE_PRESET}.json"
    if [[ ! -f "$BASELINE_FILE" ]]; then
        echo "Error: ${BASELINE_FILE} not found. Run with --baseline first."
        exit 1
    fi

    run_single_eval 0
    result_file="${OUTPUT_DIR}/run-00.json"

    if [[ $CONSECUTIVE_QUOTA_FAILURES -gt 0 ]]; then
        echo "ERROR: Comparison run failed due to quota limits after $MAX_RETRIES retries."
        echo "Wait for quota to reset and try again."
        exit 2
    fi

    echo "=== Comparing to baseline ==="
    "$EVAL_BIN" compare --run "$result_file" --baseline "$BASELINE_FILE" --ground-truth "$GROUND_TRUTH"
    exit $?
fi

# Main evaluation loop
echo "Starting $NUM_RUNS evaluation runs..."
echo "Fixture: $FIXTURE_PRESET ($FIXTURE_DIR)"
echo "Output: $OUTPUT_DIR"
echo ""

for i in $(seq 1 "$NUM_RUNS"); do
    run_single_eval "$i"

    if [[ $CONSECUTIVE_QUOTA_FAILURES -ge $MAX_CONSECUTIVE_QUOTA_FAILURES ]]; then
        echo ""
        echo "ERROR: $MAX_CONSECUTIVE_QUOTA_FAILURES consecutive runs failed due to quota limits."
        echo "Stopping early to avoid wasting resources. Completed $((i - CONSECUTIVE_QUOTA_FAILURES))/$NUM_RUNS runs successfully."
        echo "Consider waiting for quota to reset or increasing --max-budget-usd."
        exit 2
    fi
done

echo "=== All runs complete ==="

if $GENERATE_BASELINE; then
    echo ""
    echo "Generating baseline from results..."
    "$EVAL_BIN" baseline --runs "$OUTPUT_DIR" --ground-truth "$GROUND_TRUTH" -o "${SCRIPT_DIR}/baseline-${FIXTURE_PRESET}.json"
fi
