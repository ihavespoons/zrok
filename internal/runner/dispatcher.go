package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

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
	}
	return out, nil
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
		// `zrok finding list --created-by X --json` returns valid JSON
		// even when no findings exist; a real error here means something
		// else is wrong (zrok not on PATH, project not initialized).
		// Propagate so the user can see and fix it rather than silently
		// skipping the phase.
		return false, fmt.Errorf("run gate %q: %w", gate, err)
	}
	return jsonHasFindings(out), nil
}

// dynamicFanoutItems runs the dynamic-source command and extracts the
// finding IDs from its JSON output. Expects the standard zrok finding
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
// `zrok finding list` emits: {"total": N, "findings": [...]} and
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
		results = append(results, runAgent(ctx, name, defaultUserTurn(cfg.UserTurn), cfg))
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
			results[i] = runAgent(ctx, name, defaultUserTurn(cfg.UserTurn), cfg)
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
		turn := fmt.Sprintf("%s Specifically: review finding %s.", defaultUserTurn(cfg.UserTurn), id)
		results = append(results, runAgent(ctx, agentName, turn, cfg))
	}
	return results
}

// defaultUserTurn returns the user-turn prompt the dispatcher passes when
// the caller hasn't set one. Kept short and runner-agnostic — the agent's
// own system prompt (loaded from .opencode/agents/<name>.md or
// .claude/agents/<name>.md by the runner) carries the bulk of context.
func defaultUserTurn(userTurn string) string {
	if userTurn != "" {
		return userTurn
	}
	return "Run a security review of the codebase per your agent system prompt. Scope is the changed files block. File findings via zrok finding create. Exit when analysis is complete."
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
	} else {
		fmt.Fprintf(cfg.Stdout, "    ✓ %s in %s\n", agentName, res.Duration.Round(time.Second))
	}
	return res
}
