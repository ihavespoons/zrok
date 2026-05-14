package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
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
	cmd.Env = agentEnv(agentName)
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
	cmd.Env = agentEnv(agentName)
	cmd.Stdout = logOut
	cmd.Stderr = logOut
	return cmd
}

// agentEnv builds the env slice for a per-agent subprocess. It inherits
// the parent's env (so OPENROUTER_API_KEY etc. propagate) and adds
// ZROK_AGENT_NAME=<agentName>. The CLI's `zrok finding create` reads
// this env to auto-default --created-by, which closes the entire class
// of "LLM forgets / guesses / fabricates its own name" attribution
// failures observed across OWASP v5-v9 (opencode, opencode-security-
// agent, opengrep, security-scanner — each iteration a new evasion).
// The dispatcher knows which agent is running; trusting the model to
// echo its name back into a flag is the unreliable step we now skip.
func agentEnv(agentName string) []string {
	parent := os.Environ()
	if agentName == "" {
		return parent
	}
	// Filter out any leaked ZROK_AGENT_NAME from the parent shell so the
	// dispatcher's value is authoritative. Build into a fresh slice
	// rather than reusing parent's backing array — `filtered := parent[:0]`
	// would alias the underlying array, and appends below would
	// overwrite entries the for-range still has to read. That bug
	// corrupted the env passed to opencode and produced 7-second
	// no-op dispatcher runs (OWASP v11).
	filtered := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if !strings.HasPrefix(kv, "ZROK_AGENT_NAME=") {
			filtered = append(filtered, kv)
		}
	}
	return append(filtered, "ZROK_AGENT_NAME="+agentName)
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
