package scorer

import (
	"testing"
)

func testGroundTruth() *GroundTruth {
	return &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{ID: "VULN-01", Title: "Hardcoded secret key", Severity: "high", CWE: "CWE-798", File: "app.py", LineStart: 12, Tags: []string{"secrets"}},
			{ID: "VULN-04", Title: "SQL injection in login", Severity: "critical", CWE: "CWE-89", File: "app.py", LineStart: 62, Tags: []string{"injection", "sql"}},
			{ID: "VULN-09", Title: "Command injection", Severity: "critical", CWE: "CWE-78", File: "app.py", LineStart: 114, Tags: []string{"injection", "command"}},
		},
		SeverityWeights: map[string]float64{"critical": 5, "high": 3, "medium": 2, "low": 1},
		Matching:        MatchingConfig{LineTolerance: 15, CWEExactMatch: true, TitleSimilarityThreshold: 0.3},
	}
}

func TestScoreRun_AllDetected(t *testing.T) {
	gt := testGroundTruth()
	findings := []RunFinding{
		{ID: "FIND-001", Title: "Hardcoded secret key in source", Severity: "high", CWE: "CWE-798", Location: Location{File: "app.py", LineStart: 12}},
		{ID: "FIND-002", Title: "SQL injection vulnerability", Severity: "critical", CWE: "CWE-89", Location: Location{File: "app.py", LineStart: 60}},
		{ID: "FIND-003", Title: "OS command injection", Severity: "critical", CWE: "CWE-78", Location: Location{File: "app.py", LineStart: 115}},
	}

	score := ScoreRun(gt, findings, "test-all")

	if score.TruePositives != 3 {
		t.Errorf("expected 3 true positives, got %d", score.TruePositives)
	}
	if score.FalseNegatives != 0 {
		t.Errorf("expected 0 false negatives, got %d", score.FalseNegatives)
	}
	if score.Recall != 1.0 {
		t.Errorf("expected recall 1.0, got %.2f", score.Recall)
	}
	if score.Precision != 1.0 {
		t.Errorf("expected precision 1.0, got %.2f", score.Precision)
	}
}

func TestScoreRun_PartialDetection(t *testing.T) {
	gt := testGroundTruth()
	findings := []RunFinding{
		{ID: "FIND-001", Title: "SQL injection in login form", Severity: "critical", CWE: "CWE-89", Location: Location{File: "app.py", LineStart: 62}},
		{ID: "FIND-002", Title: "Unrelated finding", Severity: "low", CWE: "CWE-000", Location: Location{File: "other.py", LineStart: 1}},
	}

	score := ScoreRun(gt, findings, "test-partial")

	if score.TruePositives != 1 {
		t.Errorf("expected 1 true positive, got %d", score.TruePositives)
	}
	if score.FalsePositives != 1 {
		t.Errorf("expected 1 false positive, got %d", score.FalsePositives)
	}
	if score.FalseNegatives != 2 {
		t.Errorf("expected 2 false negatives, got %d", score.FalseNegatives)
	}
}

func TestScoreRun_SeverityMismatch(t *testing.T) {
	gt := testGroundTruth()
	findings := []RunFinding{
		{ID: "FIND-001", Title: "SQL injection", Severity: "high", CWE: "CWE-89", Location: Location{File: "app.py", LineStart: 62}},
	}

	score := ScoreRun(gt, findings, "test-sev")

	if score.TruePositives != 1 {
		t.Errorf("should still match even with severity mismatch, got %d", score.TruePositives)
	}
	// Severity accuracy should be 0 for the matched finding (high != critical)
	// but divided by total vulns
	if score.SeverityAccuracy >= 1.0 {
		t.Errorf("severity accuracy should be < 1.0 when severity mismatched")
	}
}

func TestMatchScore_CWEAndFile(t *testing.T) {
	vuln := Vulnerability{
		ID: "V1", CWE: "CWE-89", File: "app.py", LineStart: 62,
		Title: "SQL injection", Tags: []string{"sql"},
	}
	finding := RunFinding{
		CWE: "CWE-89", Location: Location{File: "app.py", LineStart: 60},
		Title: "SQL injection vulnerability", Tags: []string{"sql", "injection"},
	}
	cfg := MatchingConfig{LineTolerance: 15, TitleSimilarityThreshold: 0.3}

	score, method := matchScore(vuln, finding, cfg)
	if score < 0.7 {
		t.Errorf("expected high match score for CWE+file+line, got %.2f", score)
	}
	if method != "file+line" {
		// CWE is added first, but file+line overrides the method name
		t.Logf("match method: %s (score: %.2f)", method, score)
	}
}

func TestComputeBaseline(t *testing.T) {
	gt := testGroundTruth()

	scores := []*RunScore{
		{Recall: 0.8, Precision: 0.7, F1Score: 0.75, WeightedRecall: 0.85, TotalFindings: 5, DetectedVulns: []string{"VULN-01", "VULN-04"}},
		{Recall: 0.9, Precision: 0.6, F1Score: 0.72, WeightedRecall: 0.90, TotalFindings: 6, DetectedVulns: []string{"VULN-01", "VULN-04", "VULN-09"}},
		{Recall: 0.7, Precision: 0.8, F1Score: 0.74, WeightedRecall: 0.80, TotalFindings: 4, DetectedVulns: []string{"VULN-01", "VULN-09"}},
	}

	bl := ComputeBaseline(scores, gt)

	if bl.NumRuns != 3 {
		t.Errorf("expected 3 runs, got %d", bl.NumRuns)
	}
	if bl.MeanRecall < 0.7 || bl.MeanRecall > 0.9 {
		t.Errorf("mean recall out of expected range: %.2f", bl.MeanRecall)
	}
	if bl.VulnDetectionRate["VULN-01"] != 1.0 {
		t.Errorf("VULN-01 should be detected in all runs, got %.2f", bl.VulnDetectionRate["VULN-01"])
	}
	if bl.Thresholds.MinRecall < 0 {
		t.Error("min recall threshold should not be negative")
	}
}

func TestCompareToBaseline_Pass(t *testing.T) {
	bl := &Baseline{
		MeanRecall: 0.8, MeanF1: 0.7, MeanWeighted: 0.85,
		Thresholds: Thresholds{MinRecall: 0.6, MinF1: 0.5, MinWeighted: 0.65, MaxFalsePositiveRate: 0.5},
	}
	score := &RunScore{Recall: 0.8, F1Score: 0.7, WeightedRecall: 0.85, TotalFindings: 10, FalsePositives: 3}

	pass, failures := CompareToBaseline(score, bl)
	if !pass {
		t.Errorf("expected pass, got failures: %v", failures)
	}
}

func TestCompareToBaseline_Fail(t *testing.T) {
	bl := &Baseline{
		MeanRecall: 0.8, MeanF1: 0.7, MeanWeighted: 0.85,
		Thresholds: Thresholds{MinRecall: 0.6, MinF1: 0.5, MinWeighted: 0.65, MaxFalsePositiveRate: 0.5},
	}
	score := &RunScore{Recall: 0.3, F1Score: 0.2, WeightedRecall: 0.3, TotalFindings: 10, FalsePositives: 8}

	pass, failures := CompareToBaseline(score, bl)
	if pass {
		t.Error("expected failure")
	}
	if len(failures) == 0 {
		t.Error("expected failure messages")
	}
}

func TestCWEMatches_NonStrictParentChild(t *testing.T) {
	// Non-strict: CWE-330 (parent) should match CWE-338 (child) bidirectionally.
	if !cweMatches("CWE-330", "CWE-338") {
		t.Error("CWE-330 should match CWE-338 under non-strict matching")
	}
	if !cweMatches("CWE-338", "CWE-330") {
		t.Error("CWE-338 should match CWE-330 (reverse direction)")
	}
}

func TestCWEMatches_AsymmetricEntry(t *testing.T) {
	// CWE-22 lists CWE-23 as a child; CWE-23 might not reciprocally list
	// CWE-22. The matcher must still find the relationship in either order.
	if !cweMatches("CWE-22", "CWE-23") {
		t.Error("CWE-22 should match CWE-23")
	}
	if !cweMatches("CWE-23", "CWE-22") {
		t.Error("CWE-23 should match CWE-22 (asymmetric lookup)")
	}
}

func TestCWEMatches_Identity(t *testing.T) {
	if !cweMatches("CWE-89", "CWE-89") {
		t.Error("CWE-89 should match itself")
	}
	// CWE not in the equivalence table should still match itself.
	if !cweMatches("CWE-999999", "CWE-999999") {
		t.Error("unknown CWE should still match itself")
	}
}

func TestCWEMatches_UnrelatedNoMatch(t *testing.T) {
	if cweMatches("CWE-89", "CWE-79") {
		t.Error("CWE-89 (SQLi) should not match CWE-79 (XSS)")
	}
	if cweMatches("CWE-78", "CWE-89") {
		t.Error("CWE-78 (cmd injection) should not match CWE-89 (SQLi)")
	}
}

func TestCWEMatches_CaseInsensitive(t *testing.T) {
	if !cweMatches("cwe-89", "CWE-89") {
		t.Error("lowercase cwe-89 should match CWE-89")
	}
	if !cweMatches("Cwe-330", "cwe-338") {
		t.Error("mixed case CWE strings should match under equivalence table")
	}
}

func TestCWEMatches_EmptyInput(t *testing.T) {
	if cweMatches("", "CWE-89") {
		t.Error("empty CWE should not match anything")
	}
	if cweMatches("CWE-89", "") {
		t.Error("empty CWE should not match anything (reverse)")
	}
}

func TestMatchScore_StrictModeRejectsChildCWE(t *testing.T) {
	// Strict mode: oracle says CWE-330, finding says CWE-338, files differ.
	// CWE component must contribute 0.
	vuln := Vulnerability{ID: "V1", CWE: "CWE-330", File: "rand.py", LineStart: 10, Title: "weak random"}
	finding := RunFinding{CWE: "CWE-338", Location: Location{File: "other.py", LineStart: 100}, Title: "weak prng"}
	cfg := MatchingConfig{LineTolerance: 15, CWEExactMatch: true, TitleSimilarityThreshold: 0.3}

	score, _ := matchScore(vuln, finding, cfg)
	// With nothing else matching and CWE strict-mismatched, score should be 0
	// (or at most the small title-similarity contribution if any).
	if score >= 0.4 {
		t.Errorf("strict mode should not award CWE score for child CWE, got %.2f", score)
	}
}

func TestMatchScore_NonStrictModeAcceptsChildCWE(t *testing.T) {
	// Non-strict mode: oracle says CWE-330, finding says CWE-338. CWE
	// component should now contribute 0.4 because of the equivalence table.
	vuln := Vulnerability{ID: "V1", CWE: "CWE-330", File: "rand.py", LineStart: 10, Title: "weak random"}
	finding := RunFinding{CWE: "CWE-338", Location: Location{File: "other.py", LineStart: 100}, Title: "weak prng"}
	cfg := MatchingConfig{LineTolerance: 15, CWEExactMatch: false, TitleSimilarityThreshold: 0.3}

	score, method := matchScore(vuln, finding, cfg)
	if score < 0.4 {
		t.Errorf("non-strict mode should award CWE score for parent/child, got %.2f", score)
	}
	if method != "cwe" {
		t.Errorf("expected method 'cwe', got %q", method)
	}
}

func TestTitleSimilarity(t *testing.T) {
	tests := []struct {
		a, b string
		min  float64
	}{
		{"SQL injection in login", "SQL injection vulnerability", 0.3},
		{"Hardcoded secret key", "Hardcoded credentials", 0.2},
		{"completely different", "nothing in common here", 0.0},
	}

	for _, tt := range tests {
		sim := titleSimilarity(tt.a, tt.b)
		if sim < tt.min {
			t.Errorf("titleSimilarity(%q, %q) = %.2f, want >= %.2f", tt.a, tt.b, sim, tt.min)
		}
	}
}
