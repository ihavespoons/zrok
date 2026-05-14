package agent

import (
	"strings"
	"testing"

	"github.com/ihavespoons/quokka/internal/memory"
)

// TestToolExamplesContainRequiredFlags asserts that every centralized
// exemplar contains the flags the corresponding CLI command actually
// requires. Catches "we added a required flag to quokka finding create and
// forgot to update the example" drift.
func TestToolExamplesContainRequiredFlags(t *testing.T) {
	type check struct {
		name        string
		got         string
		mustContain []string
	}

	cases := []check{
		{
			"FindingCreateExample",
			FindingCreateExample("test-agent"),
			[]string{
				"quokka finding create",
				"--title", "--severity", "--confidence",
				"--cwe", "--file", "--line",
				"--description", "--remediation",
				"--created-by test-agent",
				"--tag",
			},
		},
		{
			"FindingCreateYAMLExample",
			FindingCreateYAMLExample(),
			[]string{"title:", "severity:", "cwe:", "location:", "file:", "line_start:", "description:"},
		},
		{
			"FindingListExample",
			FindingListExample("test-agent"),
			[]string{"quokka finding list", "--created-by test-agent", "--json"},
		},
		{
			"FindingUpdateNoteExample",
			FindingUpdateNoteExample("test-agent"),
			[]string{"quokka finding update", "--note", "--note-author test-agent"},
		},
		{
			"RuleAddExample",
			RuleAddExample("test-agent"),
			[]string{"quokka rule add", "--created-by agent:test-agent", "--reasoning", "rules:", "pattern:"},
		},
		{
			"ExceptionAddFingerprintExample",
			ExceptionAddFingerprintExample("test-agent"),
			[]string{"quokka exception add", "--fingerprint", "--reason", "--expires", "--approved-by agent:test-agent"},
		},
		{
			"ExceptionAddPathGlobExample",
			ExceptionAddPathGlobExample("test-agent"),
			[]string{"quokka exception add", "--path-glob", "--cwe", "--reason", "--expires", "--approved-by agent:test-agent"},
		},
		{
			"TaskToolExample",
			TaskToolExample(),
			[]string{"Task(", "subagent_type", "description", "prompt"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, want := range c.mustContain {
				if !strings.Contains(c.got, want) {
					t.Errorf("%s missing required token %q\nGot:\n%s", c.name, want, c.got)
				}
			}
		})
	}
}

// TestFindingCreateExampleFieldFormats guards the two field-format rules
// that broke during the qwen3-coder-plus smoke test against vulnerable-app:
//   - --cwe values must include the "CWE-" prefix (bare numbers like "89"
//     were emitted and rejected silently).
//   - --file values must be project-relative (absolute paths from a tmp
//     working directory were echoed back into findings).
//
// These assertions are intentionally narrow: they catch drift on the exact
// formatting cues the prompt relies on to discipline weaker models.
func TestFindingCreateExampleFieldFormats(t *testing.T) {
	for _, name := range []string{"", "test-agent"} {
		name := name
		t.Run("agentName="+name, func(t *testing.T) {
			got := FindingCreateExample(name)
			// The CWE flag and value MUST appear together with the "CWE-"
			// prefix. Asserting on the literal "--cwe CWE-" rules out a
			// future edit that switches to "--cwe 89".
			if !strings.Contains(got, "--cwe CWE-") {
				t.Errorf("FindingCreateExample missing literal %q; bare-number CWEs break ground-truth matching and SARIF taxonomy refs.\nGot:\n%s", "--cwe CWE-", got)
			}

			// Extract the value passed to the --file flag (the first
			// occurrence; later NOTE comment lines also contain "--file"
			// in prose, which we must skip). The value MUST NOT start
			// with "/" — that would indicate an absolute filesystem path
			// like /private/var/folders/.../app.py crept into the
			// exemplar.
			fileValue := extractFlagValue(t, got, "--file")
			if strings.HasPrefix(fileValue, "/") {
				t.Errorf("FindingCreateExample --file value %q is absolute; must be project-relative (e.g. src/api/users.py)", fileValue)
			}
			if fileValue == "" {
				t.Errorf("FindingCreateExample --file value not found; example may be malformed\nGot:\n%s", got)
			}
		})
	}
}

// TestFindingCreateYAMLExampleFieldFormats applies the same two rules to
// the YAML exemplar so the stdin/file-mode path stays disciplined too.
func TestFindingCreateYAMLExampleFieldFormats(t *testing.T) {
	got := FindingCreateYAMLExample()
	// In YAML mode the key is `cwe:` and the value starts with "CWE-".
	if !strings.Contains(got, "cwe: CWE-") {
		t.Errorf("FindingCreateYAMLExample missing literal %q; bare-number CWEs break ground-truth matching.\nGot:\n%s", "cwe: CWE-", got)
	}
	// Extract the file: value (strip any trailing inline comment) and
	// reject absolute paths.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "file:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "file:"))
		if i := strings.Index(rest, "#"); i >= 0 {
			rest = strings.TrimSpace(rest[:i])
		}
		// Strip optional quotes.
		rest = strings.Trim(rest, `"'`)
		if strings.HasPrefix(rest, "/") {
			t.Errorf("FindingCreateYAMLExample file: value %q is absolute; must be project-relative", rest)
		}
		return
	}
	t.Errorf("FindingCreateYAMLExample has no file: key\nGot:\n%s", got)
}

// extractFlagValue scans `text` line-by-line for the first line whose first
// non-blank token equals `flag`, then returns the next whitespace-delimited
// token on that line (stripped of surrounding quotes and trailing backslash).
// Returns "" if not found. Lines beginning with "#" are skipped so trailing
// NOTE comment lines don't masquerade as flag occurrences.
func extractFlagValue(t *testing.T, text, flag string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != flag {
			continue
		}
		val := fields[1]
		val = strings.TrimSuffix(val, `\`)
		val = strings.Trim(val, `"'`)
		return val
	}
	return ""
}

// TestAgentNameOrPlaceholder verifies the empty-name fallback used by
// prompts that aren't scoped to a single agent.
func TestAgentNameOrPlaceholder(t *testing.T) {
	if got := agentNameOrPlaceholder(""); got != "<your-agent-name>" {
		t.Errorf("empty agentName: got %q, want %q", got, "<your-agent-name>")
	}
	if got := agentNameOrPlaceholder("foo"); got != "foo" {
		t.Errorf("non-empty agentName: got %q, want %q", got, "foo")
	}
}

// TestAnalysisAgentPromptsContainExemplars renders every built-in
// analysis-phase agent and asserts the centralized exemplars appear in the
// final prompt. Catches new agents added without referencing the templated
// {{.FindingCreateExample}} / {{.FindingListExample}} fields, and catches
// older agents that still have the prose form with `...` placeholders.
func TestAnalysisAgentPromptsContainExemplars(t *testing.T) {
	p, cleanup := setupTestProject(t)
	defer cleanup()

	memStore := memory.NewStore(p)
	gen := NewPromptGenerator(p, memStore)

	agents := GetBuiltinAgents()
	if len(agents) == 0 {
		t.Fatal("no built-in agents found — registry broken?")
	}

	mustContain := []string{
		"quokka finding create",
		"--title",
		"--severity",
		"--cwe",
		"--created-by",
		"quokka finding list",
	}
	// Anti-pattern: prose `...` placeholders mean we forgot to template the
	// exemplar in. This regex catches "create --title ..." style fragments.
	antiPattern := "--title ... --severity"

	for _, cfg := range agents {
		if cfg.Phase != PhaseAnalysis {
			continue
		}
		cfg := cfg
		t.Run(cfg.Name, func(t *testing.T) {
			prompt, err := gen.Generate(&cfg)
			if err != nil {
				t.Fatalf("Generate(%s): %v", cfg.Name, err)
			}
			for _, want := range mustContain {
				if !strings.Contains(prompt, want) {
					t.Errorf("%s prompt missing token %q (exemplar not templated?)", cfg.Name, want)
				}
			}
			if strings.Contains(prompt, antiPattern) {
				t.Errorf("%s prompt still contains prose placeholder %q — replace with {{.FindingCreateExample}}", cfg.Name, antiPattern)
			}
			// Created-by binding: each agent's exemplar should bind its own name.
			expectCreatedBy := "--created-by " + cfg.Name
			if !strings.Contains(prompt, expectCreatedBy) {
				t.Errorf("%s prompt missing %q — exemplar didn't bind to this agent's name", cfg.Name, expectCreatedBy)
			}
		})
	}
}
