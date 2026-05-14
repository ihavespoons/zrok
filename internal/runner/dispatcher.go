package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Classification of a subprocess outcome — drives the retry decision.
type failureCategory int

const (
	// failureNone: subprocess succeeded (exit 0, no parser/schema errors in log).
	failureNone failureCategory = iota

	// failureRecoverable: the subprocess hit a parser/schema/tool error that
	// a corrective re-prompt is likely to fix on the second try. Examples:
	// SchemaError on the Task tool, malformed YAML rejected by
	// `quokka finding create`, "tool not found" because the model spelled a
	// command wrong.
	failureRecoverable

	// failureHard: the subprocess failed in a way retrying won't help.
	// Quota/rate-limit, auth failure, network outage, OOM, ctx timeout.
	// Surfaced as an error to the caller; no retry.
	failureHard
)

// retryableLogPatterns matches subprocess output that indicates the agent
// hit a structural error (schema, parse, tool-shape) rather than a
// substantive review failure. Each pattern is OR'd; a single match
// triggers the retry path.
//
// Update this list when new failure modes surface in real runs — adding a
// pattern is much cheaper than tightening the retry decision logic.
var retryableLogPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SchemaError`),
	regexp.MustCompile(`(?i)failed to parse`),
	regexp.MustCompile(`(?i)invalid yaml`),
	regexp.MustCompile(`(?i)yaml: unmarshal errors`),
	regexp.MustCompile(`(?i)unexpected EOF`),
	regexp.MustCompile(`(?i)tool not found`),
	regexp.MustCompile(`(?i)Missing key at \[`),
	regexp.MustCompile(`(?i)quokka finding create.*failed`),
}

// hardLogPatterns matches output that classifies as a hard failure (no
// retry). Quota / auth / network. Mirrors the eval/run.sh is_quota_error
// classifier so the dispatcher behaves consistently with the eval driver.
var hardLogPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)rate.?limit`),
	regexp.MustCompile(`(?i)quota`),
	regexp.MustCompile(`(?i)too many requests`),
	regexp.MustCompile(`\b429\b`),
	regexp.MustCompile(`(?i)overloaded`),
	regexp.MustCompile(`(?i)capacity`),
	regexp.MustCompile(`(?i)billing`),
	regexp.MustCompile(`(?i)credit`),
	regexp.MustCompile(`(?i)401\b.*(unauth|invalid.?key)`),
	regexp.MustCompile(`(?i)403\b.*(forbidden|denied)`),
	// opencode prints this to stdout and exits 0 when an unknown model
	// id is passed via --model. Observed in v16 when qwen/qwen3.6-flash
	// (valid on OpenRouter but absent from opencode's bundled model
	// registry) produced 6 successful 1-second agent runs with zero work
	// done. Matching the literal opencode error string keeps the
	// detector targeted.
	regexp.MustCompile(`(?i)Model not found:`),
}

// DispatchConfig controls a single `Dispatch` invocation.
type DispatchConfig struct {
	// Runner is the agent invocation backend (opencode / claude).
	Runner Runner

	// Model passed to the runner per agent (e.g. "openrouter/qwen/qwen3-coder-plus").
	// Empty string is allowed — the runner / agent frontmatter decides
	// what to fall back to.
	Model string

	// WorkDir is the directory all subprocess invocations chdir to.
	// Typically the project root where .opencode/agents/ or .claude/agents/
	// live.
	WorkDir string

	// LogDir is where per-agent logs are written. Created if missing.
	// Each agent invocation writes to LogDir/<agentName>.log; on retry
	// the file is appended to with a separator line.
	LogDir string

	// MaxParallel caps concurrent subprocesses in `parallel` phases.
	// 0 means "no cap" — every Agents entry in a parallel phase spawns
	// concurrently. Sequential / gated / dynamic-fanout phases are
	// inherently 1-at-a-time.
	MaxParallel int

	// PerAgentTimeout caps each subprocess. 0 means no timeout. Quota
	// errors are handled separately by inspecting the log content after
	// the process exits.
	PerAgentTimeout time.Duration

	// UserTurn is the prompt passed to each agent invocation. The
	// dispatcher injects a phase-specific suffix (e.g. for dynamic-fanout,
	// the finding ID gets appended). When empty, a sensible default is
	// used per phase.
	UserTurn string

	// ChangedFiles is the in-scope file list, injected into the per-agent
	// user-turn so subagents know which files to review. In orchestrator
	// mode the orchestrator's system prompt carries this; in dispatcher
	// mode each subagent gets it directly in the user-turn since there's
	// no orchestrator-level prompt to inherit context from. Empty means
	// "no explicit scope" — agents will fall back to exploring on their
	// own (degraded recall on weaker models).
	ChangedFiles []string

	// Stdout is where progress lines ("=== phase N: analysis === ...")
	// are written. Defaults to os.Stdout if nil.
	Stdout io.Writer
}

// AgentResult is the outcome of a single agent invocation.
type AgentResult struct {
	Agent    string
	ExitCode int
	Duration time.Duration
	LogPath  string
	Err      error

	// Retries counts how many corrective re-invocations the dispatcher
	// performed for this agent. 0 means the first attempt succeeded (or
	// failed in a way that didn't qualify for retry). The dispatcher
	// caps retries at 1 today; the field is an int so a future cap
	// change doesn't reshape the result type.
	Retries int

	// RetryReason names the failure pattern that triggered the retry
	// (e.g. "SchemaError", "yaml unmarshal errors"). Empty when no
	// retry occurred. Useful for the run summary / manifest so we can
	// see which agents needed scaffolding and which didn't.
	RetryReason string
}

// PhaseResult is the outcome of one phase.
type PhaseResult struct {
	Name    string
	Skipped bool // true when a gated phase's Gate produced no results
	Agents  []AgentResult
}

// DispatchResult is the aggregate outcome of running a DispatchPlan.
type DispatchResult struct {
	Phases []PhaseResult
}

// Dispatch executes the given plan using cfg.
//
// Per-phase semantics:
//
//   - ModeParallel:     all Agents spawned concurrently (subject to
//                       MaxParallel). Phase completes when all return.
//   - ModeSequential:   Agents invoked one at a time in declared order.
//   - ModeGated:        Gate shell command is run first; if its JSON output
//                       indicates non-empty results (heuristic: `total > 0`
//                       in the parsed JSON, or any non-null `findings`
//                       array), the phase proceeds as Sequential. Otherwise
//                       the phase is marked Skipped and no agents run.
//   - ModeDynamicFanout: DynamicSource is run, its JSON output's findings
//                       list yields N items; DynamicAgent is invoked once
//                       per item with the item ID injected into the
//                       user-turn prompt.
//
// All subprocess errors are non-fatal at the dispatcher level —
// individual AgentResult.Err is populated and the dispatcher continues.
// The caller decides whether to abort the run based on the aggregate
// result. Phase-level errors (e.g. gate command itself failed) are
// returned from Dispatch immediately.
func Dispatch(ctx context.Context, plan DispatchPlan, cfg DispatchConfig) (DispatchResult, error) {
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.LogDir != "" {
		if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
			return DispatchResult{}, fmt.Errorf("create log dir: %w", err)
		}
	}

	var out DispatchResult
	for i, phase := range plan.Phases {
		fmt.Fprintf(cfg.Stdout, "=== Phase %d/%d: %s (%s) ===\n", i+1, len(plan.Phases), phase.Name, phase.Mode)

		switch phase.Mode {
		case ModeGated:
			ok, err := evaluateGate(ctx, phase.Gate, cfg.WorkDir)
			if err != nil {
				return out, fmt.Errorf("phase %q: gate failed: %w", phase.Name, err)
			}
			if !ok {
				fmt.Fprintf(cfg.Stdout, "  gate produced no results — skipping phase\n")
				out.Phases = append(out.Phases, PhaseResult{Name: phase.Name, Skipped: true})
				continue
			}
			results := runSequential(ctx, phase.Agents, cfg)
			out.Phases = append(out.Phases, PhaseResult{Name: phase.Name, Agents: results})

		case ModeSequential:
			results := runSequential(ctx, phase.Agents, cfg)
			out.Phases = append(out.Phases, PhaseResult{Name: phase.Name, Agents: results})

		case ModeParallel:
			results := runParallel(ctx, phase.Agents, cfg)
			out.Phases = append(out.Phases, PhaseResult{Name: phase.Name, Agents: results})

		case ModeDynamicFanout:
			ids, err := dynamicFanoutItems(ctx, phase.DynamicSource, cfg.WorkDir)
			if err != nil {
				return out, fmt.Errorf("phase %q: dynamic-source failed: %w", phase.Name, err)
			}
			if len(ids) == 0 {
				fmt.Fprintf(cfg.Stdout, "  dynamic-source produced no items — skipping phase\n")
				out.Phases = append(out.Phases, PhaseResult{Name: phase.Name, Skipped: true})
				continue
			}
			results := runFanout(ctx, phase.DynamicAgent, ids, cfg)
			out.Phases = append(out.Phases, PhaseResult{Name: phase.Name, Agents: results})

		default:
			return out, fmt.Errorf("phase %q: unknown mode %q", phase.Name, phase.Mode)
		}

		// Post-phase triage-plan apply: validation-agent and
		// sast-triage-agent emit JSON triage plans to disk rather than
		// calling `quokka finding update` (LLMs reliably emit JSON, do
		// not reliably execute update CLI calls — see commits c9639ec,
		// 437655c). After these phases complete, look for a triage
		// plan and apply it deterministically.
		if triageAuthor := triageAuthorForPhase(phase.Name); triageAuthor != "" {
			applyTriagePlan(ctx, cfg, triageAuthor)
		}
	}
	return out, nil
}

// triageAuthorForPhase maps a phase name to the agent identity that
// should be recorded as the triage plan author. Empty return means
// "no post-phase triage apply for this phase".
//
// Adding a new triage-phase in the future is just adding a case here.
func triageAuthorForPhase(phaseName string) string {
	switch phaseName {
	case "validation":
		return "validation-agent"
	case "sast-triage":
		return "sast-triage-agent"
	}
	return ""
}

// applyTriagePlan looks for .quokka/review/triage-plan.json under WorkDir
// and runs `quokka finding triage --plan <path>` to apply it. Missing
// file is logged as a warning, not a fatal error — the agent might
// have legitimately decided there was nothing to triage (e.g. zero
// open findings), or the agent might have failed to comply (still
// better to surface that as a one-line warning and continue than to
// abort the run).
func applyTriagePlan(ctx context.Context, cfg DispatchConfig, author string) {
	planPath := filepath.Join(cfg.WorkDir, ".quokka", "review", "triage-plan.json")
	if _, err := os.Stat(planPath); err != nil {
		fmt.Fprintf(cfg.Stdout, "  no triage plan written by %s (looked at %s) — skipping apply\n", author, planPath)
		return
	}
	fmt.Fprintf(cfg.Stdout, "  applying triage plan from %s (author=%s)\n", planPath, author)

	args := []string{"finding", "triage", "--plan", planPath, "--author", author}
	cmd := exec.CommandContext(ctx, "quokka", args...)
	cmd.Dir = cfg.WorkDir
	cmd.Env = os.Environ()
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(cfg.Stdout, "  triage apply failed (%v) — findings stay in their current state\n", err)
	}

	// Move the plan aside so the next phase's plan apply doesn't
	// double-process if the agent re-writes the same file. The
	// timestamp lets us inspect prior plans if a run misbehaved.
	stamped := planPath + "." + time.Now().Format("20060102-150405") + ".applied"
	if err := os.Rename(planPath, stamped); err != nil {
		// Non-fatal — worst case the next phase re-applies the same
		// plan, which the triage command tolerates (already-set
		// statuses are idempotent).
		fmt.Fprintf(cfg.Stdout, "  warning: couldn't archive applied plan to %s: %v\n", stamped, err)
	}
}

// evaluateGate runs the gate shell command and decides whether the phase
// should proceed. Returns true if the JSON output has any non-empty
// findings indicator. A non-zero exit is treated as "no results" rather
// than an error — gate commands are designed to be idempotent queries
// that can legitimately return empty.
func evaluateGate(ctx context.Context, gate, workDir string) (bool, error) {
	if gate == "" {
		return false, fmt.Errorf("gate command is empty")
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", gate)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		// `quokka finding list --created-by X --json` returns valid JSON
		// even when no findings exist; a real error here means something
		// else is wrong (quokka not on PATH, project not initialized).
		// Propagate so the user can see and fix it rather than silently
		// skipping the phase.
		return false, fmt.Errorf("run gate %q: %w", gate, err)
	}
	return jsonHasFindings(out), nil
}

// dynamicFanoutItems runs the dynamic-source command and extracts the
// finding IDs from its JSON output. Expects the standard quokka finding
// list JSON shape: {"findings": [{"id": "FIND-001", ...}, ...]}.
func dynamicFanoutItems(ctx context.Context, source, workDir string) ([]string, error) {
	if source == "" {
		return nil, fmt.Errorf("dynamic_source is empty")
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", source)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run dynamic-source %q: %w", source, err)
	}
	var parsed struct {
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parse dynamic-source JSON: %w", err)
	}
	ids := make([]string, 0, len(parsed.Findings))
	for _, f := range parsed.Findings {
		if f.ID != "" {
			ids = append(ids, f.ID)
		}
	}
	return ids, nil
}

// jsonHasFindings inspects the parsed JSON output of a gate command and
// returns true if it indicates non-empty results. Handles both shapes
// `quokka finding list` emits: {"total": N, "findings": [...]} and
// {"findings": null, "total": 0, "suppressed_count": 0}.
func jsonHasFindings(out []byte) bool {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return false
	}
	var parsed struct {
		Total    *int          `json:"total"`
		Findings []interface{} `json:"findings"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		// Couldn't parse — treat as "no results" rather than blowing up.
		// The downstream phase will run on an empty set and either also
		// produce nothing or error out clearly.
		return false
	}
	if parsed.Total != nil {
		return *parsed.Total > 0
	}
	return len(parsed.Findings) > 0
}

// runSequential dispatches agents one at a time, in declared order.
func runSequential(ctx context.Context, agents []string, cfg DispatchConfig) []AgentResult {
	results := make([]AgentResult, 0, len(agents))
	for _, name := range agents {
		results = append(results, runAgentWithRetry(ctx, name, defaultUserTurn(cfg.UserTurn, cfg.ChangedFiles), cfg))
	}
	return results
}

// runParallel dispatches agents concurrently, optionally capped by
// MaxParallel. Returns results in the same order as the input agent list
// for log readability.
func runParallel(ctx context.Context, agents []string, cfg DispatchConfig) []AgentResult {
	if len(agents) == 0 {
		return nil
	}
	results := make([]AgentResult, len(agents))
	var wg sync.WaitGroup
	var sem chan struct{}
	if cfg.MaxParallel > 0 {
		sem = make(chan struct{}, cfg.MaxParallel)
	}

	for i, name := range agents {
		i, name := i, name
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem != nil {
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			results[i] = runAgentWithRetry(ctx, name, defaultUserTurn(cfg.UserTurn, cfg.ChangedFiles), cfg)
		}()
	}
	wg.Wait()
	return results
}

// runFanout invokes DynamicAgent once per item id, with the id embedded in
// the user-turn prompt. Items are processed sequentially to keep cost
// bounded — fan-out is typically small (handful of critical findings) but
// per-item cost can be high (full LLM review).
func runFanout(ctx context.Context, agentName string, ids []string, cfg DispatchConfig) []AgentResult {
	results := make([]AgentResult, 0, len(ids))
	for _, id := range ids {
		turn := fmt.Sprintf("%s Specifically: review finding %s.", defaultUserTurn(cfg.UserTurn, cfg.ChangedFiles), id)
		results = append(results, runAgentWithRetry(ctx, agentName, turn, cfg))
	}
	return results
}

// runAgentWithRetry wraps runAgent with at most one corrective re-prompt
// for failures classified as recoverable. Hard failures (quota / auth /
// network) are surfaced as-is. Successes and "agent ran clean, just
// didn't file anything" outcomes are passed through unchanged — a
// legitimate empty review is not a retry trigger.
//
// The retry budget is hard-coded to 1. Beyond 1 the cost of "agent that
// can't follow the contract" exceeds the marginal yield; we'd rather
// surface the failure to a human (or an upstream eval signal) than burn
// dollars on a third attempt.
//
// On retry, the second invocation's log appends to the first via the
// dispatcher's separator (see appendRetryToLog). The combined log is what
// gets surfaced in the run summary so debugging shows both attempts.
func runAgentWithRetry(ctx context.Context, agentName, userTurn string, cfg DispatchConfig) AgentResult {
	res := runAgent(ctx, agentName, userTurn, cfg)

	// Successful first attempt — done.
	if res.Err == nil {
		return res
	}

	logBytes, _ := os.ReadFile(res.LogPath)
	category, reason := classifyFailure(res.ExitCode, logBytes)

	switch category {
	case failureRecoverable:
		fmt.Fprintf(cfg.Stdout, "    ↻ %s recoverable failure (%s) — retrying once\n", agentName, reason)
		appendRetryToLog(res.LogPath, reason)
		correctedTurn := correctiveUserTurn(userTurn, reason, agentName)
		retry := runAgent(ctx, agentName, correctedTurn, cfg)
		retry.Retries = 1
		retry.RetryReason = reason
		return retry

	default:
		// Hard failure or anything else — pass the first attempt's result
		// through unchanged so the caller sees the original error /
		// exit code.
		return res
	}
}

// classifyFailure inspects subprocess outcome and decides whether retry is
// warranted. Hard patterns are checked first — quota errors that also
// happen to contain a parser-error substring should be treated as hard.
func classifyFailure(exitCode int, logBytes []byte) (failureCategory, string) {
	if exitCode == 0 {
		// Exit 0 = clean run. No retry regardless of log content — if
		// the agent legitimately found nothing, retrying won't change
		// that.
		return failureNone, ""
	}
	for _, re := range hardLogPatterns {
		if m := re.Find(logBytes); m != nil {
			return failureHard, string(m)
		}
	}
	for _, re := range retryableLogPatterns {
		if m := re.Find(logBytes); m != nil {
			return failureRecoverable, string(m)
		}
	}
	// Non-zero exit but no recognized pattern — treat as hard so we don't
	// burn cost retrying an unknown failure mode. Patterns can be
	// expanded as new modes surface in real runs.
	return failureHard, fmt.Sprintf("exit=%d", exitCode)
}

// appendRetryToLog writes a visible separator to the agent's log file
// before the retry attempt overwrites it via os.Create. Without this, the
// retry's log content silently replaces the first attempt and debugging
// is harder.
//
// The actual log file gets truncated by runAgent's os.Create — so this
// function reads the current contents, prepends them to a saved
// `.attempt-1` file alongside the live log, and writes a header into the
// live log noting the retry. The saved file is opt-in archaeology for
// when something goes wrong post-mortem.
func appendRetryToLog(logPath, reason string) {
	first, err := os.ReadFile(logPath)
	if err != nil {
		return
	}
	archivePath := logPath + ".attempt-1"
	_ = os.WriteFile(archivePath, first, 0o644)
	// The live log will be re-truncated by os.Create in the retry's
	// runAgent. So we don't write anything here — the archive is the
	// preserved-record path.
	_ = reason // reason already surfaced via cfg.Stdout in runAgentWithRetry
}

// correctiveUserTurn builds the second-attempt prompt. Embeds the failure
// reason so the model sees what went wrong, plus an explicit reminder of
// the schema requirements that the centralized exemplar covers. Kept
// short — long retry prompts make small models more confused, not less.
//
// The agent name is passed through so the corrective prompt can defer
// to the agent's own system prompt for the --created-by value rather
// than supplying a placeholder the model might copy verbatim (observed
// in OWASP runs: dispatcher told agents "set --created-by to your agent
// name" without specifying which one; 13 of 36 findings landed with
// `created_by: opencode` because the model interpreted "agent name" as
// the runtime).
func correctiveUserTurn(originalTurn, reason, agentName string) string {
	creatorHint := "your agent's name (from your system prompt's frontmatter, not the runtime name)"
	if agentName != "" {
		creatorHint = "`" + agentName + "` (this is your agent name; do not substitute)"
	}
	return fmt.Sprintf(`Your previous attempt failed: %s

Re-run with these corrections:
- Task tool calls require BOTH "description" and "prompt" fields (no exceptions).
- quokka finding create requires --title, --severity, --confidence, --cwe (with CWE- prefix), --file (project-relative path, not absolute), --line, --description, --created-by, and at least one --tag.
- --created-by must be %s.
- All YAML output (for stdin mode) must parse cleanly.

This is your final retry. Original task: %s`, reason, creatorHint, originalTurn)
}

// defaultUserTurn returns the user-turn prompt the dispatcher passes when
// the caller hasn't set one. Kept short and runner-agnostic — the agent's
// own system prompt (loaded from .opencode/agents/<name>.md or
// .claude/agents/<name>.md by the runner) carries the bulk of context.
//
// When changedFiles is non-empty, the list is inlined verbatim so weak
// models that wouldn't otherwise explore the tree have an explicit scope
// to work through. Without this, an OWASP-eval-scale fixture (70 files)
// can produce widely different recall run-to-run depending on whether
// the model decides to enumerate the tree itself.
func defaultUserTurn(userTurn string, changedFiles []string) string {
	if userTurn != "" {
		return userTurn
	}
	var b strings.Builder
	b.WriteString("Run a security review per your agent system prompt. ")
	b.WriteString("File findings via `quokka finding create` EXACTLY as the Filing Protocol section of your system prompt describes — copy that exemplar; do not invent your own --created-by value. ")
	b.WriteString("Exit when analysis is complete.")
	if len(changedFiles) > 0 {
		b.WriteString("\n\n## In-scope files (review EVERY file in this list)\n")
		for _, f := range changedFiles {
			b.WriteString("- ")
			b.WriteString(f)
			b.WriteString("\n")
		}
		b.WriteString("\nDo NOT skip files because they look similar — each file is a distinct test case ")
		b.WriteString("and may contain different vulnerability patterns. Out-of-scope findings are filtered out by ")
		b.WriteString("the report step, so spending tokens on them is waste; in-scope findings missed cost recall directly.")
	}
	return b.String()
}

// runAgent invokes one subagent and returns the result. Logs are
// captured to LogDir/<agentName>.log (truncated on each invocation —
// retries append a separator). Subprocess failures are non-fatal:
// AgentResult.Err is populated and the dispatcher continues.
func runAgent(ctx context.Context, agentName, userTurn string, cfg DispatchConfig) AgentResult {
	res := AgentResult{Agent: agentName}

	logPath := filepath.Join(cfg.LogDir, agentName+".log")
	res.LogPath = logPath
	logFile, err := os.Create(logPath)
	if err != nil {
		res.Err = fmt.Errorf("open log file: %w", err)
		return res
	}
	defer logFile.Close()

	cmdCtx := ctx
	if cfg.PerAgentTimeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, cfg.PerAgentTimeout)
		defer cancel()
	}

	cmd := cfg.Runner.AgentInvocation(cmdCtx, cfg.WorkDir, agentName, cfg.Model, userTurn, logFile)
	start := time.Now()
	fmt.Fprintf(cfg.Stdout, "  → %s (logging to %s)\n", agentName, logPath)
	err = cmd.Run()
	res.Duration = time.Since(start)

	if err != nil {
		res.Err = err
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
		}
		fmt.Fprintf(cfg.Stdout, "    ✗ %s exit=%d after %s\n", agentName, res.ExitCode, res.Duration.Round(time.Second))
		return res
	}

	// Subprocess exited 0 — but opencode (and likely others) exit 0
	// even on provider-side errors like "Insufficient credits" or
	// "rate limit exceeded". The error text is in the log; the exit
	// code is a lie. Sweep the log for known hard-error patterns and
	// synthesise a failure when one matches, so the caller sees the
	// real issue instead of "succeeded in 4 seconds with no findings".
	if reason := scanLogForSilentError(logPath); reason != "" {
		res.Err = fmt.Errorf("provider error (silent: exit code 0): %s", reason)
		res.ExitCode = -2 // sentinel distinct from -1 (non-ExitError) and any real opencode code
		fmt.Fprintf(cfg.Stdout, "    ✗ %s silent provider error after %s — %s\n", agentName, res.Duration.Round(time.Second), reason)
		return res
	}

	fmt.Fprintf(cfg.Stdout, "    ✓ %s in %s\n", agentName, res.Duration.Round(time.Second))
	return res
}

// scanLogForSilentError reads an agent log file and returns a short
// reason string when the log contains a known provider-side error
// pattern despite the subprocess exiting 0. Empty return = clean.
//
// Observed silent failures (subprocess exit 0, no real work done):
//   - "Insufficient credits" — OpenRouter, when the account is exhausted
//   - "rate limit" / "429" — provider throttling on the first call
//
// Reads at most the first 16KiB of the log; opencode prints the error
// near the start of its output for these cases, so we don't need the
// whole file. Keeps the scan O(1) per agent.
func scanLogForSilentError(logPath string) string {
	f, err := os.Open(logPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 16*1024)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	content := string(buf[:n])
	// Reuse hardLogPatterns from the retry classifier — same set of
	// "provider broke" signals, just applied to a successful-exit log.
	for _, re := range hardLogPatterns {
		if m := re.FindString(content); m != "" {
			return strings.TrimSpace(m)
		}
	}
	return ""
}
