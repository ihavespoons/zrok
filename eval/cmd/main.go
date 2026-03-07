// eval is the CLI tool for zrok evaluation scoring.
//
// Usage:
//
//	eval score --run results/run-01.json --ground-truth ground-truth.yaml
//	eval baseline --runs results/ --ground-truth ground-truth.yaml -o baseline.json
//	eval compare --run results/run-new.json --baseline baseline.json --ground-truth ground-truth.yaml
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/eval/scorer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "score":
		cmdScore()
	case "baseline":
		cmdBaseline()
	case "compare":
		cmdCompare()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: eval <command> [options]

Commands:
  score      Score a single run against ground truth
  baseline   Generate baseline from multiple runs
  compare    Compare a run against baseline thresholds

Examples:
  eval score --run results/run-01.json --ground-truth ground-truth.yaml
  eval baseline --runs results/ --ground-truth ground-truth.yaml -o baseline.json
  eval compare --run results/run-new.json --baseline baseline.json --ground-truth ground-truth.yaml
`)
}

func cmdScore() {
	var runPath, gtPath, outPath string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--run":
			i++
			runPath = args[i]
		case "--ground-truth":
			i++
			gtPath = args[i]
		case "-o", "--output":
			i++
			outPath = args[i]
		}
	}

	if runPath == "" || gtPath == "" {
		fmt.Fprintln(os.Stderr, "error: --run and --ground-truth are required")
		os.Exit(1)
	}

	gt, err := scorer.LoadGroundTruth(gtPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	findings, err := loadFindings(runPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	runID := strings.TrimSuffix(filepath.Base(runPath), filepath.Ext(runPath))
	score := scorer.ScoreRun(gt, findings, runID)

	output, _ := json.MarshalIndent(score, "", "  ")

	if outPath != "" {
		if err := os.WriteFile(outPath, output, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Score written to %s\n", outPath)
	}

	printScoreSummary(score)
}

func cmdBaseline() {
	var runsDir, gtPath, outPath string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--runs":
			i++
			runsDir = args[i]
		case "--ground-truth":
			i++
			gtPath = args[i]
		case "-o", "--output":
			i++
			outPath = args[i]
		}
	}

	if runsDir == "" || gtPath == "" {
		fmt.Fprintln(os.Stderr, "error: --runs and --ground-truth are required")
		os.Exit(1)
	}
	if outPath == "" {
		outPath = "baseline.json"
	}

	gt, err := scorer.LoadGroundTruth(gtPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	entries, err := os.ReadDir(runsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading runs directory: %v\n", err)
		os.Exit(1)
	}

	var scores []*scorer.RunScore
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(runsDir, entry.Name())
		findings, err := loadFindings(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), err)
			continue
		}
		runID := strings.TrimSuffix(entry.Name(), ".json")
		score := scorer.ScoreRun(gt, findings, runID)
		scores = append(scores, score)
	}

	if len(scores) == 0 {
		fmt.Fprintln(os.Stderr, "error: no valid run files found")
		os.Exit(1)
	}

	bl := scorer.ComputeBaseline(scores, gt)
	output, _ := json.MarshalIndent(bl, "", "  ")

	if err := os.WriteFile(outPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing baseline: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Baseline generated from %d runs\n", bl.NumRuns)
	fmt.Printf("  Mean Recall:    %.2f (std: %.2f)\n", bl.MeanRecall, bl.StdRecall)
	fmt.Printf("  Mean Precision: %.2f (std: %.2f)\n", bl.MeanPrecision, bl.StdPrecision)
	fmt.Printf("  Mean F1:        %.2f (std: %.2f)\n", bl.MeanF1, bl.StdF1)
	fmt.Printf("  Mean Weighted:  %.2f\n", bl.MeanWeighted)
	fmt.Printf("  Thresholds:\n")
	fmt.Printf("    Min Recall:    %.2f\n", bl.Thresholds.MinRecall)
	fmt.Printf("    Min F1:        %.2f\n", bl.Thresholds.MinF1)
	fmt.Printf("    Min Weighted:  %.2f\n", bl.Thresholds.MinWeighted)
	fmt.Printf("    Max FP Rate:   %.2f\n", bl.Thresholds.MaxFalsePositiveRate)
	fmt.Printf("\nVulnerability detection rates:\n")
	for id, rate := range bl.VulnDetectionRate {
		fmt.Printf("  %s: %.0f%%\n", id, rate*100)
	}
	fmt.Printf("\nBaseline written to %s\n", outPath)
}

func cmdCompare() {
	var runPath, blPath, gtPath string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--run":
			i++
			runPath = args[i]
		case "--baseline":
			i++
			blPath = args[i]
		case "--ground-truth":
			i++
			gtPath = args[i]
		}
	}

	if runPath == "" || blPath == "" || gtPath == "" {
		fmt.Fprintln(os.Stderr, "error: --run, --baseline, and --ground-truth are required")
		os.Exit(1)
	}

	gt, err := scorer.LoadGroundTruth(gtPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	findings, err := loadFindings(runPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	blData, err := os.ReadFile(blPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading baseline: %v\n", err)
		os.Exit(1)
	}
	var bl scorer.Baseline
	if err := json.Unmarshal(blData, &bl); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing baseline: %v\n", err)
		os.Exit(1)
	}

	runID := strings.TrimSuffix(filepath.Base(runPath), filepath.Ext(runPath))
	score := scorer.ScoreRun(gt, findings, runID)
	printScoreSummary(score)

	fmt.Println("\n--- Baseline Comparison ---")
	pass, failures := scorer.CompareToBaseline(score, &bl)

	if pass {
		fmt.Println("PASS: All metrics within baseline thresholds")
	} else {
		fmt.Println("FAIL: Metrics below baseline thresholds:")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
}

func loadFindings(path string) ([]scorer.RunFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var report scorer.RunFindings
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return report.Findings, nil
}

func printScoreSummary(score *scorer.RunScore) {
	fmt.Printf("=== Evaluation Score: %s ===\n", score.RunID)
	fmt.Printf("Total findings:    %d\n", score.TotalFindings)
	fmt.Printf("True positives:    %d\n", score.TruePositives)
	fmt.Printf("False positives:   %d", score.FalsePositives)
	if score.ConfirmedFP > 0 {
		fmt.Printf(" (%d confirmed against known FP files)", score.ConfirmedFP)
	}
	fmt.Println()
	fmt.Printf("False negatives:   %d\n", score.FalseNegatives)
	fmt.Printf("Precision:         %.2f\n", score.Precision)
	fmt.Printf("Recall:            %.2f\n", score.Recall)
	fmt.Printf("F1 Score:          %.2f\n", score.F1Score)
	fmt.Printf("Weighted Recall:   %.2f\n", score.WeightedRecall)
	fmt.Printf("Severity Accuracy: %.2f\n", score.SeverityAccuracy)

	if len(score.MissedVulns) > 0 {
		fmt.Printf("\nMissed vulnerabilities:\n")
		for _, v := range score.MissedVulns {
			fmt.Printf("  - %s\n", v)
		}
	}

	if len(score.BySeverity) > 0 {
		fmt.Printf("\nBy severity:\n")
		for sev, s := range score.BySeverity {
			fmt.Printf("  %s: %d/%d detected (%.0f%%)\n", sev, s.Detected, s.Expected, s.Recall*100)
		}
	}
}
