// Package scorer compares zrok findings against ground truth vulnerabilities
// and produces evaluation metrics.
package scorer

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// GroundTruth represents the expected vulnerabilities manifest
type GroundTruth struct {
	Vulnerabilities []Vulnerability    `yaml:"vulnerabilities"`
	FalsePositives  []FalsePositive    `yaml:"false_positives"`
	SeverityWeights map[string]float64 `yaml:"severity_weights"`
	Matching        MatchingConfig     `yaml:"matching"`
}

// FalsePositive represents a known non-vulnerable test case (OWASP Benchmark)
type FalsePositive struct {
	TestName string `yaml:"test_name"`
	Category string `yaml:"category"`
	CWE      string `yaml:"cwe"`
	File     string `yaml:"file"`
}

type Vulnerability struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Severity    string   `yaml:"severity"`
	CWE         string   `yaml:"cwe"`
	File        string   `yaml:"file"`
	LineStart   int      `yaml:"line_start"`
	Tags        []string `yaml:"tags"`
	Description string   `yaml:"description"`
}

type MatchingConfig struct {
	LineTolerance            int     `yaml:"line_tolerance"`
	CWEExactMatch            bool    `yaml:"cwe_exact_match"`
	TitleSimilarityThreshold float64 `yaml:"title_similarity_threshold"`
}

// RunFindings represents the JSON export from a single zrok run
type RunFindings struct {
	Metadata struct {
		Tool        string `json:"tool"`
		Version     string `json:"version"`
		GeneratedAt string `json:"generated_at"`
	} `json:"metadata"`
	Summary struct {
		Total      int            `json:"total"`
		BySeverity map[string]int `json:"by_severity"`
		ByStatus   map[string]int `json:"by_status"`
	} `json:"summary"`
	Findings []RunFinding `json:"findings"`
}

type RunFinding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	Exploitability string   `json:"exploitability"`
	FixPriority    string   `json:"fix_priority"`
	Status         string   `json:"status"`
	CWE            string   `json:"cwe"`
	Location       Location `json:"location"`
	Description    string   `json:"description"`
	Tags           []string `json:"tags"`
	CreatedBy      string   `json:"created_by"`
}

type Location struct {
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
}

// Match represents a mapping between a ground truth vuln and a detected finding
type Match struct {
	VulnID    string  `json:"vuln_id"`
	FindingID string  `json:"finding_id"`
	Score     float64 `json:"match_score"`
	Method    string  `json:"match_method"` // cwe, file+line, title, tags
}

// RunScore represents the evaluation score for a single run
type RunScore struct {
	RunID               string          `json:"run_id"`
	TotalFindings       int             `json:"total_findings"`
	TruePositives       int             `json:"true_positives"`
	FalsePositives      int             `json:"false_positives"`
	ConfirmedFP         int             `json:"confirmed_false_positives"`
	FalseNegatives      int             `json:"false_negatives"`
	Precision           float64         `json:"precision"`
	Recall              float64         `json:"recall"`
	F1Score             float64         `json:"f1_score"`
	WeightedRecall      float64         `json:"weighted_recall"`
	SeverityAccuracy    float64         `json:"severity_accuracy"`
	DetectedVulns       []string        `json:"detected_vulns"`
	MissedVulns         []string        `json:"missed_vulns"`
	ConfirmedFPFiles    []string        `json:"confirmed_fp_files,omitempty"`
	Matches             []Match         `json:"matches"`
	BySeverity          map[string]SeverityScore `json:"by_severity"`
}

type SeverityScore struct {
	Expected int     `json:"expected"`
	Detected int     `json:"detected"`
	Recall   float64 `json:"recall"`
}

// Baseline represents the aggregated baseline from multiple runs
type Baseline struct {
	Version         string             `json:"version"`
	NumRuns         int                `json:"num_runs"`
	MeanPrecision   float64            `json:"mean_precision"`
	MeanRecall      float64            `json:"mean_recall"`
	MeanF1          float64            `json:"mean_f1"`
	MeanWeighted    float64            `json:"mean_weighted_recall"`
	StdPrecision    float64            `json:"std_precision"`
	StdRecall       float64            `json:"std_recall"`
	StdF1           float64            `json:"std_f1"`
	VulnDetectionRate map[string]float64 `json:"vuln_detection_rate"`
	MeanFindingCount float64           `json:"mean_finding_count"`
	StdFindingCount  float64           `json:"std_finding_count"`
	Thresholds      Thresholds         `json:"thresholds"`
}

// Thresholds are computed from baseline stats for CI gating
type Thresholds struct {
	MinRecall       float64 `json:"min_recall"`
	MinF1           float64 `json:"min_f1"`
	MinWeighted     float64 `json:"min_weighted_recall"`
	MaxFalsePositiveRate float64 `json:"max_false_positive_rate"`
}

// LoadGroundTruth loads the ground truth YAML file
func LoadGroundTruth(path string) (*GroundTruth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ground truth: %w", err)
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(data, &gt); err != nil {
		return nil, fmt.Errorf("parsing ground truth: %w", err)
	}
	return &gt, nil
}

// ScoreRun evaluates a single run's findings against ground truth
func ScoreRun(gt *GroundTruth, findings []RunFinding, runID string) *RunScore {
	score := &RunScore{
		RunID:         runID,
		TotalFindings: len(findings),
		BySeverity:    make(map[string]SeverityScore),
	}

	// Count expected per severity
	expectedBySev := make(map[string]int)
	for _, v := range gt.Vulnerabilities {
		expectedBySev[v.Severity]++
	}

	// Try to match each ground truth vuln to a finding
	matched := make(map[int]bool) // index into findings that have been matched
	for _, vuln := range gt.Vulnerabilities {
		bestIdx := -1
		bestScore := 0.0
		bestMethod := ""

		for i, f := range findings {
			if matched[i] {
				continue
			}
			s, method := matchScore(vuln, f, gt.Matching)
			if s > bestScore {
				bestScore = s
				bestIdx = i
				bestMethod = method
			}
		}

		if bestIdx >= 0 && bestScore >= 0.3 {
			matched[bestIdx] = true
			score.TruePositives++
			score.DetectedVulns = append(score.DetectedVulns, vuln.ID)
			score.Matches = append(score.Matches, Match{
				VulnID:    vuln.ID,
				FindingID: findings[bestIdx].ID,
				Score:     bestScore,
				Method:    bestMethod,
			})

			// Check severity accuracy
			if findings[bestIdx].Severity == vuln.Severity {
				score.SeverityAccuracy++
			}
		} else {
			score.FalseNegatives++
			score.MissedVulns = append(score.MissedVulns, vuln.ID)
		}
	}

	score.FalsePositives = len(findings) - len(matched)

	// Check unmatched findings against known false positive files
	if len(gt.FalsePositives) > 0 {
		fpFiles := make(map[string]bool)
		for _, fp := range gt.FalsePositives {
			fpFiles[fp.File] = true
		}
		for i, f := range findings {
			if matched[i] {
				continue
			}
			for fpFile := range fpFiles {
				if fileMatch(fpFile, f.Location.File) {
					score.ConfirmedFP++
					score.ConfirmedFPFiles = append(score.ConfirmedFPFiles, f.Location.File)
					break
				}
			}
		}
	}

	// Calculate metrics
	totalVulns := len(gt.Vulnerabilities)
	if totalVulns > 0 {
		score.Recall = float64(score.TruePositives) / float64(totalVulns)
		score.SeverityAccuracy = score.SeverityAccuracy / float64(totalVulns)
	}
	if score.TotalFindings > 0 {
		score.Precision = float64(score.TruePositives) / float64(score.TotalFindings)
	}
	if score.Precision+score.Recall > 0 {
		score.F1Score = 2 * score.Precision * score.Recall / (score.Precision + score.Recall)
	}

	// Weighted recall (critical findings matter more)
	weightedDetected := 0.0
	weightedTotal := 0.0
	for _, vuln := range gt.Vulnerabilities {
		w := gt.SeverityWeights[vuln.Severity]
		weightedTotal += w
		if slices.Contains(score.DetectedVulns, vuln.ID) {
			weightedDetected += w
		}
	}
	if weightedTotal > 0 {
		score.WeightedRecall = weightedDetected / weightedTotal
	}

	// Per-severity breakdown
	detectedBySev := make(map[string]int)
	for _, m := range score.Matches {
		for _, v := range gt.Vulnerabilities {
			if v.ID == m.VulnID {
				detectedBySev[v.Severity]++
				break
			}
		}
	}
	for sev, expected := range expectedBySev {
		detected := detectedBySev[sev]
		recall := 0.0
		if expected > 0 {
			recall = float64(detected) / float64(expected)
		}
		score.BySeverity[sev] = SeverityScore{
			Expected: expected,
			Detected: detected,
			Recall:   recall,
		}
	}

	return score
}

// matchScore calculates how well a finding matches a ground truth vulnerability.
// Returns a score [0,1] and the primary matching method.
func matchScore(vuln Vulnerability, f RunFinding, cfg MatchingConfig) (float64, string) {
	score := 0.0
	method := ""

	// CWE match (strongest signal)
	if vuln.CWE != "" && f.CWE != "" {
		if strings.EqualFold(vuln.CWE, f.CWE) {
			score += 0.4
			method = "cwe"
		}
	}

	// File match
	if fileMatch(vuln.File, f.Location.File) {
		score += 0.2
		if method == "" {
			method = "file"
		}

		// Line proximity bonus
		if vuln.LineStart > 0 && f.Location.LineStart > 0 {
			diff := abs(vuln.LineStart - f.Location.LineStart)
			if diff <= cfg.LineTolerance {
				lineScore := 0.2 * (1.0 - float64(diff)/float64(cfg.LineTolerance))
				score += lineScore
				method = "file+line"
			}
		}
	}

	// Title similarity
	titleSim := titleSimilarity(vuln.Title, f.Title)
	if titleSim >= cfg.TitleSimilarityThreshold {
		score += 0.1 * titleSim
		if method == "" {
			method = "title"
		}
	}

	// Tag overlap
	tagOverlap := tagOverlapScore(vuln.Tags, f.Tags)
	if tagOverlap > 0 {
		score += 0.1 * tagOverlap
		if method == "" {
			method = "tags"
		}
	}

	return math.Min(score, 1.0), method
}

// fileMatch checks if a finding's file path ends with the ground truth filename
func fileMatch(gtFile, findingFile string) bool {
	return strings.HasSuffix(findingFile, gtFile) ||
		strings.HasSuffix(findingFile, "/"+gtFile)
}

// titleSimilarity computes word overlap between two titles
func titleSimilarity(a, b string) float64 {
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))
	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	matches := 0
	for _, wa := range wordsA {
		if slices.Contains(wordsB, wa) {
			matches++
		}
	}
	return float64(matches) / float64(max(len(wordsA), len(wordsB)))
}

// tagOverlapScore computes the Jaccard similarity of tag sets
func tagOverlapScore(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	setA := make(map[string]bool)
	for _, t := range a {
		setA[strings.ToLower(t)] = true
	}
	setB := make(map[string]bool)
	for _, t := range b {
		setB[strings.ToLower(t)] = true
	}

	intersection := 0
	for k := range setA {
		if setB[k] {
			intersection++
		}
	}
	union := len(setA)
	for k := range setB {
		if !setA[k] {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ComputeBaseline aggregates multiple run scores into a baseline
func ComputeBaseline(scores []*RunScore, gt *GroundTruth) *Baseline {
	n := float64(len(scores))
	bl := &Baseline{
		Version:           "1",
		NumRuns:           len(scores),
		VulnDetectionRate: make(map[string]float64),
	}

	// Aggregate means
	var precisions, recalls, f1s, weighteds, findingCounts []float64
	vulnDetected := make(map[string]int)

	for _, s := range scores {
		precisions = append(precisions, s.Precision)
		recalls = append(recalls, s.Recall)
		f1s = append(f1s, s.F1Score)
		weighteds = append(weighteds, s.WeightedRecall)
		findingCounts = append(findingCounts, float64(s.TotalFindings))

		for _, v := range s.DetectedVulns {
			vulnDetected[v]++
		}
	}

	bl.MeanPrecision = mean(precisions)
	bl.MeanRecall = mean(recalls)
	bl.MeanF1 = mean(f1s)
	bl.MeanWeighted = mean(weighteds)
	bl.StdPrecision = stddev(precisions)
	bl.StdRecall = stddev(recalls)
	bl.StdF1 = stddev(f1s)
	bl.MeanFindingCount = mean(findingCounts)
	bl.StdFindingCount = stddev(findingCounts)

	// Per-vuln detection rate
	for _, v := range gt.Vulnerabilities {
		bl.VulnDetectionRate[v.ID] = float64(vulnDetected[v.ID]) / n
	}

	// Thresholds: mean - 2*stddev (allows for LLM variance)
	bl.Thresholds = Thresholds{
		MinRecall:            math.Max(0, bl.MeanRecall-2*bl.StdRecall),
		MinF1:                math.Max(0, bl.MeanF1-2*bl.StdF1),
		MinWeighted:          math.Max(0, bl.MeanWeighted-2*stddev(weighteds)),
		MaxFalsePositiveRate: 0.5, // Allow up to 50% false positives (LLMs are noisy)
	}

	return bl
}

// CompareToBaseline checks if a run score meets baseline thresholds
func CompareToBaseline(score *RunScore, bl *Baseline) (pass bool, failures []string) {
	pass = true

	if score.Recall < bl.Thresholds.MinRecall {
		pass = false
		failures = append(failures, fmt.Sprintf(
			"recall %.2f < threshold %.2f (baseline mean: %.2f)",
			score.Recall, bl.Thresholds.MinRecall, bl.MeanRecall))
	}

	if score.F1Score < bl.Thresholds.MinF1 {
		pass = false
		failures = append(failures, fmt.Sprintf(
			"F1 %.2f < threshold %.2f (baseline mean: %.2f)",
			score.F1Score, bl.Thresholds.MinF1, bl.MeanF1))
	}

	if score.WeightedRecall < bl.Thresholds.MinWeighted {
		pass = false
		failures = append(failures, fmt.Sprintf(
			"weighted recall %.2f < threshold %.2f (baseline mean: %.2f)",
			score.WeightedRecall, bl.Thresholds.MinWeighted, bl.MeanWeighted))
	}

	if score.TotalFindings > 0 {
		fpRate := float64(score.FalsePositives) / float64(score.TotalFindings)
		if fpRate > bl.Thresholds.MaxFalsePositiveRate {
			pass = false
			failures = append(failures, fmt.Sprintf(
				"false positive rate %.2f > threshold %.2f",
				fpRate, bl.Thresholds.MaxFalsePositiveRate))
		}
	}

	return pass, failures
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddev(vals []float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	m := mean(vals)
	sum := 0.0
	for _, v := range vals {
		d := v - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(vals)-1))
}
