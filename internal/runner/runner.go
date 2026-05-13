package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Runner abstracts the per-agent subprocess invocation across opencode and
// claude. Both runners follow the same shape: pass an agent name, a model
// id, and a user-turn prompt; the runner constructs an exec.Cmd, hooks up
// stdout/stderr to the provided writer, and inherits the parent env so
// auth credentials (OPENROUTER_API_KEY, ANTHROPIC_API_KEY, etc.) propagate
// without explicit wiring.
//
// The Cmd is NOT started here — that's the dispatcher's job. Returning the
// configured Cmd lets the dispatcher own concurrency, logging, and the
// retry decision.
type Runner interface {
	// Name returns the runner identifier ("opencode" or "claude").
	Name() string

	// AgentInvocation builds the exec.Cmd that, when run, invokes the
	// named agent with the given model and user-turn prompt. workDir is
	// the directory the subprocess should chdir to (typically the
	// project root that contains `.opencode/agents/` or `.claude/agents/`).
	// logOut is wired to both stdout and stderr.
	AgentInvocation(ctx context.Context, workDir, agentName, model, userTurn string, logOut io.Writer) *exec.Cmd
}

// opencodeRunner shells out to `opencode run --agent <name> --model <m>`.
// The agent file is read from .opencode/agents/<name>.md in workDir;
// opencode finds it automatically.
type opencodeRunner struct{}

// NewOpenCodeRunner returns the opencode Runner.
func NewOpenCodeRunner() Runner { return opencodeRunner{} }

func (opencodeRunner) Name() string { return "opencode" }

func (opencodeRunner) AgentInvocation(ctx context.Context, workDir, agentName, model, userTurn string, logOut io.Writer) *exec.Cmd {
	args := []string{"run", "--agent", agentName}
	if model != "" {
		args = append(args, "--model", model)
	}
	args = append(args, userTurn)
	cmd := exec.CommandContext(ctx, "opencode", args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	cmd.Stdout = logOut
	cmd.Stderr = logOut
	return cmd
}

// claudeRunner shells out to `claude -p --agent <name> --model <m>`.
// The agent file is read from .claude/agents/<name>.md in workDir.
//
// Note on the --model flag: per Claude Code docs the resolution order is
// CLAUDE_CODE_SUBAGENT_MODEL env > per-invocation model param > frontmatter
// model > main session model. So passing --model here only wins if the
// agent file doesn't pin a model AND CLAUDE_CODE_SUBAGENT_MODEL is unset.
// We don't set model in the materialized frontmatter for that reason —
// keeps --model flag authoritative.
type claudeRunner struct{}

// NewClaudeRunner returns the claude Runner.
func NewClaudeRunner() Runner { return claudeRunner{} }

func (claudeRunner) Name() string { return "claude" }

func (claudeRunner) AgentInvocation(ctx context.Context, workDir, agentName, model, userTurn string, logOut io.Writer) *exec.Cmd {
	args := []string{"-p", "--agent", agentName}
	if model != "" {
		args = append(args, "--model", model)
	}
	args = append(args, userTurn)
	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	cmd.Stdout = logOut
	cmd.Stderr = logOut
	return cmd
}

// LookupRunner returns the Runner for the given name, or an error if
// the name is unrecognized.
func LookupRunner(name string) (Runner, error) {
	switch name {
	case "opencode":
		return NewOpenCodeRunner(), nil
	case "claude":
		return NewClaudeRunner(), nil
	default:
		return nil, fmt.Errorf("unsupported runner %q (supported: opencode, claude)", name)
	}
}
