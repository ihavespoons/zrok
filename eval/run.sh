#!/usr/bin/env bash
# run.sh - Execute quokka code review evaluations
#
# Usage:
#   ./eval/run.sh [options]
#
# Options:
#   -n NUM          Number of evaluation runs (default: 10)
#   -z PATH         Path to quokka binary (default: ./quokka)
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
QUOKKA_BIN="${PROJECT_ROOT}/quokka"
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
ZERO_FINDING_RUNS=0

# Eval mirrors the dogfood orchestration so scores reflect production
# behavior. Override via env when measuring an alternative model/profile.
OPENCODE_MODEL="${OPENCODE_MODEL:-openrouter/deepseek/deepseek-v4-flash}"
EVAL_PROFILE="${EVAL_PROFILE:-fast}"

# (Eval synthesizes its own diff base per run; see run_single_eval below.)
# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n) NUM_RUNS="$2"; shift 2 ;;
        -z) QUOKKA_BIN="$2"; shift 2 ;;
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
if [[ ! -f "$QUOKKA_BIN" ]]; then
    echo "Error: quokka binary not found at $QUOKKA_BIN"
    echo "Run: go build -o quokka ."
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

    # Set up a synthetic two-commit git history so `quokka review pr setup`'s
    # diff plumbing works:
    #
    #   HEAD~1 = empty commit (no files, the "base")
    #   HEAD   = fixture as a single change (the "PR")
    #
    # Using `--base HEAD~1` then makes EVERY fixture file appear in
    # `git diff --name-only HEAD~1...HEAD`, reusing the PR-mode plumbing
    # for a whole-codebase review. The empty-tree SHA alone won't work
    # here: `git diff A...B` uses the merge-base, and the empty tree has
    # no shared history with HEAD.
    (cd "$run_dir" \
        && git init -q \
        && git -c user.email=eval@quokka -c user.name=eval commit --allow-empty -qm eval-baseline)
    cp -r "$FIXTURE_DIR"/* "$run_dir/"
    (cd "$run_dir" \
        && git -c user.email=eval@quokka -c user.name=eval add -A \
        && git -c user.email=eval@quokka -c user.name=eval commit -qm fixture)
    local eval_base_ref="HEAD~1"

    # Initialize quokka project
    (cd "$run_dir" && "$QUOKKA_BIN" init >/dev/null)

    # Run static onboarding (fast, no LLM needed for setup)
    (cd "$run_dir" && "$QUOKKA_BIN" onboard --static)

    # Restore pre-built semantic index if committed alongside fixture
    if [[ -d "${FIXTURE_DIR}/.quokka-index" ]]; then
        echo "  Restoring pre-built semantic index..."
        cp -r "${FIXTURE_DIR}/.quokka-index/"* "$run_dir/.quokka/index/"
        # Enable index config in project.yaml (points to pre-built data, no build needed)
        (cd "$run_dir" && "$QUOKKA_BIN" index enable --provider ollama) 2>/dev/null || true
    fi

    # Materialize OpenCode agent files (subagents + quokka-orchestrator primary)
    # via the same setup path the dogfood action uses. This keeps eval and
    # production aligned — improvements to the orchestrator prompt land in
    # both places automatically.
    # Materialize agent files for the same runner the dispatcher will
    # invoke; EVAL_RUNNER (opencode|claude) selects both.
    local eval_runner="${EVAL_RUNNER:-opencode}"
    echo "  Setting up $eval_runner agents (profile: $EVAL_PROFILE)..."
    if ! (cd "$run_dir" && "$QUOKKA_BIN" review pr setup \
            --base "$eval_base_ref" \
            --runner "$eval_runner" \
            --profile "$EVAL_PROFILE" \
            --json > "${run_dir}/setup.json" 2>"${run_dir}/setup-err.log"); then
        echo "  ERROR: quokka review pr setup failed:"
        cat "${run_dir}/setup-err.log" >&2
        return 1
    fi

    # Run opengrep before the orchestrator so SAST findings are in the
    # store when sast-triage-agent queries them. Mirrors the dogfood
    # action's separate opengrep step. Non-zero exits are tolerated.
    local sast_config="${EVAL_SAST_CONFIG:-p/python}"
    echo "  Running quokka sast (config: $sast_config)..."
    (cd "$run_dir" && "$QUOKKA_BIN" sast --config "$sast_config" > "${run_dir}/sast.log" 2>&1) || true
    local sast_count
    sast_count=$(cd "$run_dir" && "$QUOKKA_BIN" finding list --created-by opengrep --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("total",0))' 2>/dev/null || echo "?")
    echo "  SAST findings imported: $sast_count"

    # Run the orchestrator. opencode reads OPENROUTER_API_KEY from env and
    # uses its built-in openrouter provider — no opencode.json needed.
    echo "  Running review (mode: ${EVAL_DISPATCH_MODE:-orchestrator}, model: $OPENCODE_MODEL)..."
    local start_time
    start_time=$(date +%s)

    local attempt=0
    local opencode_success=false

    while [[ $attempt -lt $MAX_RETRIES ]]; do
        attempt=$((attempt + 1))
        if [[ $attempt -gt 1 ]]; then
            local backoff=$(( (1 << (attempt - 1)) * 30 ))
            echo "  Retry $attempt/$MAX_RETRIES after ${backoff}s backoff..."
            sleep "$backoff"
        fi

        # Put the quokka binary's directory on PATH so the orchestrator and
        # its subagents can call `quokka finding list` / `quokka rule add` /
        # etc. from inside the tmp working directory.
        local quokka_bin_dir
        quokka_bin_dir="$(cd "$(dirname "$QUOKKA_BIN")" && pwd)"

        # EVAL_DISPATCH_MODE toggles the dispatch path:
        #   - "orchestrator" (default): existing `opencode run --agent
        #     quokka-orchestrator` flow. The LLM is the orchestrator.
        #   - "dispatcher": new `quokka review pr run` flow. Deterministic
        #     code dispatches subagents in parallel; the LLM only does
        #     review work, not orchestration. Cheaper models do
        #     substantially better here.
        # Both modes coexist; the toggle is for A/B measurement.
        local dispatch_mode="${EVAL_DISPATCH_MODE:-orchestrator}"
        local run_ok=false
        local run_log="${run_dir}/opencode-output.log"

        case "$dispatch_mode" in
            orchestrator)
                if (cd "$run_dir" && PATH="${quokka_bin_dir}:${PATH}" opencode run --agent quokka-orchestrator \
                        --model "$OPENCODE_MODEL" \
                        "Run a security review of this codebase using the listed subagents. Scope: every file in your system prompt's Changed Files block. Work autonomously and exit when analysis dispatch completes." \
                        > "$run_log" 2>&1); then
                    run_ok=true
                fi
                ;;
            dispatcher)
                # The dispatcher reads .quokka/review/setup.json (written
                # unconditionally by `pr setup`). Per-agent logs land in
                # .quokka/review/agents/<name>.log inside run_dir; the
                # combined log captured here is the dispatcher's own
                # progress output, useful for the quota-error grep.
                #
                # --per-agent-timeout 10m caps any one subagent's
                # subprocess. Observed in OWASP runs that qwen3-coder-plus
                # occasionally hangs mid-conversation (the API connection
                # stalls and opencode silently waits); without a timeout
                # the dispatcher waits forever. 10m is well past the
                # typical 2-4min per-agent runtime so legitimate slow
                # responses still complete.
                # eval_runner (opencode|claude) is already populated above
                # from EVAL_RUNNER and passed to `pr setup`; reuse it here
                # so the dispatcher backend matches the materialized
                # agent files.
                run_log="${run_dir}/pr-run-output.log"
                if (cd "$run_dir" && PATH="${quokka_bin_dir}:${PATH}" "$QUOKKA_BIN" review pr run \
                        --runner "$eval_runner" \
                        --model "$OPENCODE_MODEL" \
                        --max-parallel 6 \
                        --per-agent-timeout 10m \
                        > "$run_log" 2>&1); then
                    run_ok=true
                fi
                ;;
            *)
                echo "  ERROR: unsupported EVAL_DISPATCH_MODE=$dispatch_mode (use orchestrator or dispatcher)"
                return 1
                ;;
        esac

        if $run_ok; then
            echo "  Review completed (mode: $dispatch_mode)."
            opencode_success=true
            CONSECUTIVE_QUOTA_FAILURES=0
            break
        else
            if is_quota_error "$run_log"; then
                echo "  Quota/rate-limit error detected (attempt $attempt/$MAX_RETRIES)."
                tail -3 "$run_log" 2>/dev/null || true
                if [[ $attempt -ge $MAX_RETRIES ]]; then
                    echo "  ERROR: Exhausted retries due to quota limits."
                    CONSECUTIVE_QUOTA_FAILURES=$((CONSECUTIVE_QUOTA_FAILURES + 1))
                fi
                continue
            else
                echo "  Warning: review exited non-zero (non-quota error). Last 10 lines of $run_log:"
                tail -10 "$run_log" 2>/dev/null || true
                CONSECUTIVE_QUOTA_FAILURES=0
                break
            fi
        fi
    done

    # Alias `claude_success` for downstream manifest code that still reads
    # this name — flip the variable so existing JSON shape stays stable.
    local claude_success="$opencode_success"

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "  Duration: ${duration}s"

    # Always export findings manually to ensure we capture them
    echo "  Exporting findings..."
    (cd "$run_dir" && "$QUOKKA_BIN" finding export --format json -o "eval-run.json") || true

    # Find the exported file (quokka puts bare filenames in .quokka/findings/exports/)
    local export_file
    export_file=$(find "$run_dir/.quokka/findings/exports" -name "*.json" -type f 2>/dev/null | head -1)

    if [[ -n "$export_file" && -f "$export_file" ]]; then
        cp "$export_file" "$result_file"
        echo "  Results: $result_file"
    else
        echo "  ERROR: No findings produced for run $run_id"
        echo '{"metadata":{"tool":"quokka"},"summary":{"total":0},"findings":[]}' > "$result_file"
    fi

    # Zero-findings fail-fast.
    #
    # Eval fixtures (vulnerable-app, owasp-subset) have KNOWN vulnerabilities
    # — non-zero ground truth. A run that produces zero findings means the
    # review didn't execute against the code: opencode auth failed silently,
    # the orchestrator hit a tool-schema error, the model never dispatched,
    # etc. Without this guard, the workflow's `compare` step happily passes
    # zero findings against a zero-threshold baseline and CI reports green
    # for a totally broken pipeline. Count zero-finding runs explicitly and
    # surface them at the end of the run loop.
    local finding_count
    finding_count=$(python3 -c "import json;print(len(json.load(open('$result_file')).get('findings',[])))" 2>/dev/null || echo 0)
    echo "  Findings produced: $finding_count"
    if [[ "$finding_count" == "0" ]]; then
        echo "  ::error::Run $run_id produced 0 findings against fixture '$FIXTURE_PRESET' (known-vulnerable)."
        echo "  Likely causes: opencode auth failed, model didn't dispatch agents,"
        echo "  orchestrator hit a tool-schema error. Inspect $run_dir/opencode-output.log"
        echo "  if it still exists, or re-run with EVAL_PROFILE=deep for more diagnostics."
        ZERO_FINDING_RUNS=$((ZERO_FINDING_RUNS + 1))
    fi

    # Capture run manifest (agent activity, memories, reasoning)
    local manifest_file="${OUTPUT_DIR}/run-$(printf '%02d' "$run_id")-manifest.json"
    echo "  Capturing run manifest..."
    {
        echo '{'

        # Which agents created findings (legacy field, kept for backward compatibility)
        echo '  "agents_used": ['
        if [[ -f "$result_file" ]]; then
            python3 -c "
import json, sys
with open('$result_file') as f:
    data = json.load(f)
agents = {}
for finding in data.get('findings', []):
    agent = finding.get('created_by', 'unknown')
    agents[agent] = agents.get(agent, 0) + 1
entries = [f'    {{\"name\": \"{a}\", \"findings\": {c}}}' for a, c in sorted(agents.items())]
print(',\n'.join(entries))
" 2>/dev/null || true
        fi
        echo '  ],'

        # Per-agent records: name, phase, findings_created, memories_created,
        # and (best-effort) start/end timing if .quokka/run-state.json was written.
        echo '  "agents": ['
        python3 - "$run_dir" "$result_file" "$PROJECT_ROOT" <<'PYEOF' 2>/dev/null || true
import json, os, sys, glob

run_dir = sys.argv[1]
result_file = sys.argv[2]
project_root = sys.argv[3]

# YAML may not be present; fall back to a minimal parser for created_by/phase fields.
def parse_yaml_field(path, field):
    try:
        with open(path) as f:
            for line in f:
                line = line.rstrip('\n')
                if line.startswith(field + ':'):
                    return line.split(':', 1)[1].strip().strip('"').strip("'")
    except Exception:
        return None
    return None

# Findings counts per agent (read from raw YAMLs; falls back to export JSON)
findings_by_agent = {}
raw_dir = os.path.join(run_dir, '.quokka', 'findings', 'raw')
if os.path.isdir(raw_dir):
    for f in glob.glob(os.path.join(raw_dir, '*.yaml')):
        agent = parse_yaml_field(f, 'created_by') or 'unknown'
        findings_by_agent[agent] = findings_by_agent.get(agent, 0) + 1
else:
    try:
        with open(result_file) as f:
            data = json.load(f)
        for finding in data.get('findings', []):
            agent = finding.get('created_by', 'unknown')
            findings_by_agent[agent] = findings_by_agent.get(agent, 0) + 1
    except Exception:
        pass

# Memories counts per agent
memories_by_agent = {}
mem_root = os.path.join(run_dir, '.quokka', 'memories')
if os.path.isdir(mem_root):
    for sub in ('context', 'patterns', 'stack'):
        for f in glob.glob(os.path.join(mem_root, sub, '*.yaml')):
            agent = parse_yaml_field(f, 'created_by') or 'unknown'
            memories_by_agent[agent] = memories_by_agent.get(agent, 0) + 1

# Optional timing data (only present if the skill called `quokka agent record-timing`)
timings = {}
state_path = os.path.join(run_dir, '.quokka', 'run-state.json')
if os.path.isfile(state_path):
    try:
        with open(state_path) as f:
            timings = (json.load(f) or {}).get('agents', {}) or {}
    except Exception:
        timings = {}

# Phase lookup: parse built-in agent YAMLs from the source tree.
phases = {}
agents_dir = os.path.join(project_root, 'internal', 'agent', 'configs', 'agents')
if os.path.isdir(agents_dir):
    for f in glob.glob(os.path.join(agents_dir, '*.yaml')):
        name = parse_yaml_field(f, 'name')
        phase = parse_yaml_field(f, 'phase')
        if name:
            phases[name] = phase or ''

names = set(findings_by_agent) | set(memories_by_agent) | set(timings.keys())
entries = []
for name in sorted(names):
    if name == 'unknown':
        continue
    rec = {
        'name': name,
        'phase': phases.get(name, ''),
        'findings_created': findings_by_agent.get(name, 0),
        'memories_created': memories_by_agent.get(name, 0),
    }
    t = timings.get(name)
    if t:
        if t.get('started_at'):
            rec['started_at'] = t['started_at']
        if t.get('ended_at'):
            rec['ended_at'] = t['ended_at']
        if t.get('duration_ms'):
            rec['duration_ms'] = t['duration_ms']
    entries.append('    ' + json.dumps(rec))

print(',\n'.join(entries))
PYEOF
        echo '  ],'

        # Memories created during the run (captures agent reasoning and discovered patterns)
        echo '  "memories": ['
        if [[ -d "$run_dir/.quokka/memories" ]]; then
            local first_mem=true
            for mem_file in "$run_dir"/.quokka/memories/*.yaml; do
                [[ -f "$mem_file" ]] || continue
                if $first_mem; then first_mem=false; else echo ','; fi
                python3 -c "
import yaml, json, sys
with open('$mem_file') as f:
    mem = yaml.safe_load(f)
print(f'    {json.dumps({\"name\": mem.get(\"name\",\"\"), \"type\": mem.get(\"type\",\"\"), \"content\": mem.get(\"content\",\"\")[:500]})}', end='')
" 2>/dev/null || true
            done
            echo ''
        fi
        echo '  ],'

        # Claude's approach and reasoning (truncated to key parts)
        echo '  "claude_output_summary": '
        if [[ -f "$run_dir/claude-output.json" ]]; then
            python3 -c "
import json
with open('$run_dir/claude-output.json') as f:
    data = json.load(f) if f.read(1) == '{' or True else {}
# Extract the result text, truncated
f.seek(0)
try:
    data = json.load(f)
    text = ''
    if isinstance(data, dict):
        text = data.get('result', data.get('content', str(data)))[:2000]
    elif isinstance(data, str):
        text = data[:2000]
    print(json.dumps(text))
except:
    print('null')
" 2>/dev/null || echo 'null'
        else
            echo 'null'
        fi
        echo ','

        # Run metadata
        echo "  \"duration_seconds\": $duration,"
        echo "  \"claude_success\": $claude_success,"
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
        echo '}'
    } > "$manifest_file" 2>/dev/null
    echo "  Manifest: $manifest_file"

    # Score this run
    echo "  Scoring..."
    "$EVAL_BIN" score --run "$result_file" --ground-truth "$GROUND_TRUTH" || true
    echo ""

    # Cleanup (skip when caller wants to inspect dispatcher / per-agent logs).
    if [[ "${EVAL_KEEP_RUN_DIR:-0}" == "1" ]]; then
        echo "  Preserved run dir (EVAL_KEEP_RUN_DIR=1): $run_dir"
    else
        rm -rf "$run_dir"
    fi
}

if $DRY_RUN; then
    echo "Dry run mode - would execute:"
    echo "  $NUM_RUNS evaluation runs"
    echo "  Fixture: $FIXTURE_PRESET ($FIXTURE_DIR)"
    echo "  Output: $OUTPUT_DIR"
    echo "  Quokka: $QUOKKA_BIN"
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

    # Hard fail on zero findings — fixtures have known vulnerabilities, so
    # zero findings means the review didn't actually execute. The baseline
    # `compare` step won't catch this because the baseline thresholds are
    # set to 0 by default; this guard is independent.
    if [[ $ZERO_FINDING_RUNS -gt 0 ]]; then
        echo "ERROR: Comparison run produced 0 findings against known-vulnerable fixture."
        echo "This indicates the review pipeline is broken, not a real regression."
        exit 3
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

if [[ $ZERO_FINDING_RUNS -gt 0 ]]; then
    echo ""
    echo "ERROR: $ZERO_FINDING_RUNS run(s) produced 0 findings against fixture '$FIXTURE_PRESET'."
    echo "This is treated as a hard failure regardless of baseline thresholds — the"
    echo "fixture has known vulnerabilities, so zero findings means the review"
    echo "pipeline is broken (auth, model, orchestration), not a real regression."
    if $GENERATE_BASELINE; then
        echo "Refusing to write a baseline that includes broken runs."
    fi
    exit 3
fi

if $GENERATE_BASELINE; then
    echo ""
    echo "Generating baseline from results..."
    "$EVAL_BIN" baseline --runs "$OUTPUT_DIR" --ground-truth "$GROUND_TRUTH" -o "${SCRIPT_DIR}/baseline-${FIXTURE_PRESET}.json"
fi
