package agent

import (
	"strings"
	"testing"

	"github.com/ihavespoons/zrok/internal/memory"
)

// TestToolExamplesContainRequiredFlags asserts that every centralized
// exemplar contains the flags the corresponding CLI command actually
// requires. Catches "we added a required flag to zrok finding create and
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
				"zrok finding create",
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
			[]string{"zrok finding list", "--created-by test-agent", "--json"},
		},
		{
			"FindingUpdateNoteExample",
			FindingUpdateNoteExample("test-agent"),
			[]string{"zrok finding update", "--note", "--note-author test-agent"},
		},
		{
			"RuleAddExample",
			RuleAddExample("test-agent"),
			[]string{"zrok rule add", "--created-by agent:test-agent", "--reasoning", "rules:", "pattern:"},
		},
		{
			"ExceptionAddFingerprintExample",
			ExceptionAddFingerprintExample("test-agent"),
			[]string{"zrok exception add", "--fingerprint", "--reason", "--expires", "--approved-by agent:test-agent"},
		},
		{
			"ExceptionAddPathGlobExample",
			ExceptionAddPathGlobExample("test-agent"),
			[]string{"zrok exception add", "--path-glob", "--cwe", "--reason", "--expires", "--approved-by agent:test-agent"},
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
		"zrok finding create",
		"--title",
		"--severity",
		"--cwe",
		"--created-by",
		"zrok finding list",
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
