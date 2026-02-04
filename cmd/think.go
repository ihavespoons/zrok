package cmd

import (
	"fmt"
	"strings"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/think"
	"github.com/spf13/cobra"
)

// thinkCmd represents the think command
var thinkCmd = &cobra.Command{
	Use:   "think",
	Short: "Structured thinking tools",
	Long: `Structured thinking tools for maintaining analysis quality.

Available verbs:
  collected  - Evaluate collected information
  adherence  - Check task adherence
  done       - Assess if task is complete
  next       - Suggest next steps
  hypothesis - Generate security hypotheses
  validate   - Validate a specific finding`,
}

// thinkCollectedCmd represents the think collected command
var thinkCollectedCmd = &cobra.Command{
	Use:   "collected [context]",
	Short: "Evaluate collected information",
	Long:  `Generate a prompt to evaluate information collected so far.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		context := ""
		if len(args) > 0 {
			context = strings.Join(args, " ")
		}

		thinker := think.NewThinker(p)
		result := thinker.Collected(context)

		outputThinkResult(result)
	},
}

// thinkAdherenceCmd represents the think adherence command
var thinkAdherenceCmd = &cobra.Command{
	Use:   "adherence <task> [current-state]",
	Short: "Check task adherence",
	Long:  `Generate a prompt to check if current activities align with the assigned task.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		task := args[0]
		currentState := ""
		if len(args) > 1 {
			currentState = strings.Join(args[1:], " ")
		}

		thinker := think.NewThinker(p)
		result := thinker.Adherence(task, currentState)

		outputThinkResult(result)
	},
}

// thinkDoneCmd represents the think done command
var thinkDoneCmd = &cobra.Command{
	Use:   "done <task> [findings-summary]",
	Short: "Assess if task is complete",
	Long:  `Generate a prompt to assess whether the analysis task is complete.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		task := args[0]
		findings := ""
		if len(args) > 1 {
			findings = strings.Join(args[1:], " ")
		}

		thinker := think.NewThinker(p)
		result := thinker.Done(task, findings)

		outputThinkResult(result)
	},
}

// thinkNextCmd represents the think next command
var thinkNextCmd = &cobra.Command{
	Use:   "next [current-state]",
	Short: "Suggest next steps",
	Long:  `Generate a prompt suggesting next steps for the analysis.`,
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		currentState := ""
		findings := ""
		if len(args) > 0 {
			currentState = args[0]
		}
		if len(args) > 1 {
			findings = strings.Join(args[1:], " ")
		}

		thinker := think.NewThinker(p)
		result := thinker.Next(currentState, findings)

		outputThinkResult(result)
	},
}

// thinkHypothesisCmd represents the think hypothesis command
var thinkHypothesisCmd = &cobra.Command{
	Use:   "hypothesis <context>",
	Short: "Generate security hypotheses",
	Long:  `Generate testable security hypotheses based on the provided context.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		context := strings.Join(args, " ")
		thinker := think.NewThinker(p)
		result := thinker.Hypothesis(context)

		outputThinkResult(result)
	},
}

// thinkValidateCmd represents the think validate command
var thinkValidateCmd = &cobra.Command{
	Use:   "validate <finding-id>",
	Short: "Validate a finding",
	Long:  `Generate a prompt to validate a specific security finding.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		p, err := project.EnsureActive()
		if err != nil {
			exitError("%v", err)
		}

		store := finding.NewStore(p)
		f, err := store.Read(args[0])
		if err != nil {
			exitError("%v", err)
		}

		thinker := think.NewThinker(p)
		result := thinker.Validate(f)

		outputThinkResult(result)
	},
}

func outputThinkResult(result *think.ThinkingResult) {
	if jsonOutput {
		if err := outputJSON(result); err != nil {
			exitError("failed to encode JSON: %v", err)
		}
	} else {
		fmt.Println(result.Prompt)
	}
}

func init() {
	rootCmd.AddCommand(thinkCmd)
	thinkCmd.AddCommand(thinkCollectedCmd)
	thinkCmd.AddCommand(thinkAdherenceCmd)
	thinkCmd.AddCommand(thinkDoneCmd)
	thinkCmd.AddCommand(thinkNextCmd)
	thinkCmd.AddCommand(thinkHypothesisCmd)
	thinkCmd.AddCommand(thinkValidateCmd)
}
