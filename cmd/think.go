package cmd

import (
	"fmt"
	"strings"

	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/think"
	"github.com/spf13/cobra"
)

// thinkCmd represents the think command
var thinkCmd = &cobra.Command{
	Use:   "think",
	Short: "Structured analysis tools",
	Long: `Structured analysis tools that compute over project state.

Each verb runs an algorithmic analysis on real inputs (findings, memories,
agent configs, source code) and emits a structured report. Use --json for
machine-readable output.

Available verbs:
  collected  - Audit memory coherence against agent expectations
  adherence  - Check that an agent's findings fall in its declared CWE scope
  done       - Score an agent's completeness vs declared CWEs and memories
  next       - Rank next actions from current state
  hypothesis - Generate ranked CWE hypotheses from tech stack + memories
  validate   - Validate a specific finding against its code context
  dataflow   - Trace source-to-sink chains in project code`,
}

// ---- collected ----

var thinkCollectedCmd = &cobra.Command{
	Use:   "collected",
	Short: "Audit memory coherence",
	Long: `Audit the project's memory store against agent expectations.

Reports:
  - Present memories
  - Memories expected (by applicable agents' context_memories) but missing
  - Cross-references between memories
  - Orphan memories (present but neither expected nor referenced)`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		memories, _ := cmd.Flags().GetStringSlice("memory")
		report, err := think.AnalyzeCollected(p, think.CollectedOptions{Memories: memories})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbCollected,
			Prompt: think.RenderCollectedText(report),
			Data:   report,
		})
	},
}

// ---- adherence ----

var thinkAdherenceCmd = &cobra.Command{
	Use:   "adherence [task]",
	Short: "Check an agent's findings fall in its declared CWE scope",
	Long: `Check whether findings created by an agent fall inside that agent's
declared CWEChecklist scope. Use --agent to name the agent.

If --agent is omitted, an inventory of agents seen in findings is reported.

A free-form [task] argument may be supplied for context (echoed in output).`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		ag, _ := cmd.Flags().GetString("agent")
		task := strings.Join(args, " ")
		report, err := think.AnalyzeAdherence(p, think.AdherenceOptions{Agent: ag, Task: task})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbAdherence,
			Prompt: think.RenderAdherenceText(report),
			Data:   report,
		})
	},
}

// ---- done ----

var thinkDoneCmd = &cobra.Command{
	Use:   "done",
	Short: "Score an agent's completeness",
	Long: `Score how complete an agent's work is on its declared CWEs and
context_memories. Use --agent <name>.

Coverage rules:
  - A CWE is "covered" if at least one finding exists for it, OR a memory
    body explicitly records "no findings for CWE-XXX" (or similar).
  - A memory is "required" if the agent's context_memories list it.

Completeness is weighted 60% memories / 40% CWE coverage.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		ag, _ := cmd.Flags().GetString("agent")
		report, err := think.AnalyzeDone(p, think.DoneOptions{Agent: ag})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbDone,
			Prompt: think.RenderDoneText(report),
			Data:   report,
		})
	},
}

// ---- next ----

var thinkNextCmd = &cobra.Command{
	Use:   "next",
	Short: "Rank next actions from current state",
	Long: `Compute a ranked checklist of next actions from the current
state of the project: open high-severity findings, missing context memories,
uncovered CWEs declared by applicable agents, and findings missing CWE tags.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		max, _ := cmd.Flags().GetInt("max-steps")
		report, err := think.AnalyzeNext(p, think.NextOptions{MaxSteps: max})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbNext,
			Prompt: think.RenderNextText(report),
			Data:   report,
		})
	},
}

// ---- hypothesis ----

var thinkHypothesisCmd = &cobra.Command{
	Use:   "hypothesis",
	Short: "Generate ranked CWE hypotheses",
	Long: `Generate ranked CWE hypotheses from the project's tech stack and
memory content. Each hypothesis lists evidence (tech/memory keywords that
matched), a sink regex, and a concrete 'zrok think dataflow ...' command
to verify it.

Flags:
  --memory <name>   Restrict scan to one or more memory names (repeatable).
                    If omitted, all memories are scanned.
  --tech <hint>     Add an extra tech-stack hint (repeatable).`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		mems, _ := cmd.Flags().GetStringSlice("memory")
		tech, _ := cmd.Flags().GetStringSlice("tech")
		max, _ := cmd.Flags().GetInt("max")
		report, err := think.AnalyzeHypothesis(p, think.HypothesisOptions{
			Memories:      mems,
			Tech:          tech,
			MaxHypotheses: max,
		})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbHypothesis,
			Prompt: think.RenderHypothesisText(report),
			Data:   report,
		})
	},
}

// ---- validate ----

var thinkValidateCmd = &cobra.Command{
	Use:   "validate <finding-id>",
	Short: "Validate a finding against its code context",
	Long: `Read a finding's cited file, load ±10 lines of code context,
search the file for the source and sink patterns inferred from the finding
description and CWE, and check for any guard-like calls between them.

Emits a structured rubric and a verdict (likely_true_positive,
uncertain_guard_present, sink_present_source_missing, sink_missing,
inconclusive).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		ctxLines, _ := cmd.Flags().GetInt("context")
		report, err := think.AnalyzeValidate(p, think.ValidateOptions{
			FindingID:    args[0],
			ContextLines: ctxLines,
		})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbValidate,
			Prompt: think.RenderValidateText(report),
			Data:   report,
		})
	},
}

// ---- dataflow ----

var thinkDataflowCmd = &cobra.Command{
	Use:   "dataflow",
	Short: "Trace source-to-sink chains in project code",
	Long: `Trace source-to-sink data flow within files of the project.

Flags:
  --source <regex>    Source pattern (e.g. "request\\.form\\.get").
  --sink <regex>      Sink pattern (e.g. "cur\\.execute").
  --file <path>       Limit analysis to one file (project-relative).
  --from-finding ID   Load source/sink/file from finding FIND-XXX.
  --max-chains N      Cap reported chains per file (default 8).

The algorithm is intentionally simple: regex-based, intra-file, linear
between source and sink lines, with guard-shaped calls reported between
them. Use it to flag candidates, not to prove safety.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}
		source, _ := cmd.Flags().GetString("source")
		sink, _ := cmd.Flags().GetString("sink")
		file, _ := cmd.Flags().GetString("file")
		fromFinding, _ := cmd.Flags().GetString("from-finding")
		max, _ := cmd.Flags().GetInt("max-chains")

		report, err := think.AnalyzeDataflow(p, think.DataflowOptions{
			Source:      source,
			Sink:        sink,
			File:        file,
			FromFinding: fromFinding,
			MaxChains:   max,
		})
		if err != nil {
			exitError("%v", err)
		}
		emit(&think.ThinkingResult{
			Verb:   think.VerbDataflow,
			Prompt: think.RenderDataflowText(report),
			Data:   report,
		})
	},
}

// emit prints the result in text or JSON form.
func emit(result *think.ThinkingResult) {
	if jsonOutput {
		// When --json is set, prefer the structured Data payload if present.
		if result.Data != nil {
			if err := outputJSON(result.Data); err != nil {
				exitError("failed to encode JSON: %v", err)
			}
			return
		}
		if err := outputJSON(result); err != nil {
			exitError("failed to encode JSON: %v", err)
		}
		return
	}
	fmt.Println(result.Prompt)
}

func init() {
	rootCmd.AddCommand(thinkCmd)
	thinkCmd.AddCommand(thinkCollectedCmd)
	thinkCmd.AddCommand(thinkAdherenceCmd)
	thinkCmd.AddCommand(thinkDoneCmd)
	thinkCmd.AddCommand(thinkNextCmd)
	thinkCmd.AddCommand(thinkHypothesisCmd)
	thinkCmd.AddCommand(thinkValidateCmd)
	thinkCmd.AddCommand(thinkDataflowCmd)

	thinkCollectedCmd.Flags().StringSlice("memory", nil, "Restrict to one or more memory names (repeatable)")

	thinkAdherenceCmd.Flags().String("agent", "", "Agent name to check (e.g. injection-agent)")

	thinkDoneCmd.Flags().String("agent", "", "Agent name to score (required)")
	_ = thinkDoneCmd.MarkFlagRequired("agent")

	thinkNextCmd.Flags().Int("max-steps", 10, "Cap number of ranked steps")

	thinkHypothesisCmd.Flags().StringSlice("memory", nil, "Restrict to one or more memory names (repeatable)")
	thinkHypothesisCmd.Flags().StringSlice("tech", nil, "Extra tech-stack hint (repeatable)")
	thinkHypothesisCmd.Flags().Int("max", 10, "Cap number of hypotheses")

	thinkValidateCmd.Flags().Int("context", 10, "Lines of code context around the finding line")

	thinkDataflowCmd.Flags().String("source", "", "Source pattern (regex; e.g. 'request\\.form\\.get')")
	thinkDataflowCmd.Flags().String("sink", "", "Sink pattern (regex; e.g. 'cur\\.execute')")
	thinkDataflowCmd.Flags().String("file", "", "Limit analysis to one file (project-relative)")
	thinkDataflowCmd.Flags().String("from-finding", "", "Load source/sink/file from a finding (FIND-XXX)")
	thinkDataflowCmd.Flags().Int("max-chains", 8, "Cap reported chains per file")
}
