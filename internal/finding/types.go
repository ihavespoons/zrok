package finding

import (
	"time"
)

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ValidSeverities contains all valid severity levels
var ValidSeverities = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

// Confidence represents the confidence level of a finding
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Exploitability represents how easily a vulnerability can be exploited
type Exploitability string

const (
	ExploitabilityProven   Exploitability = "proven"   // Exploitation confirmed/demonstrated
	ExploitabilityLikely   Exploitability = "likely"   // Exploitation highly probable
	ExploitabilityPossible Exploitability = "possible" // Exploitation theoretically possible
	ExploitabilityUnlikely Exploitability = "unlikely" // Exploitation unlikely due to mitigations
	ExploitabilityUnknown  Exploitability = "unknown"  // Not yet assessed
)

// ValidExploitabilities contains all valid exploitability levels
var ValidExploitabilities = []Exploitability{
	ExploitabilityProven,
	ExploitabilityLikely,
	ExploitabilityPossible,
	ExploitabilityUnlikely,
	ExploitabilityUnknown,
}

// FixPriority represents the recommended priority for fixing a vulnerability
type FixPriority string

const (
	FixPriorityImmediate FixPriority = "immediate" // Fix ASAP, actively exploitable
	FixPriorityHigh      FixPriority = "high"      // Fix within days
	FixPriorityMedium    FixPriority = "medium"    // Fix within weeks
	FixPriorityLow       FixPriority = "low"       // Fix when convenient
	FixPriorityDefer     FixPriority = "defer"     // Technical debt, low risk
)

// ValidFixPriorities contains all valid fix priority levels
var ValidFixPriorities = []FixPriority{
	FixPriorityImmediate,
	FixPriorityHigh,
	FixPriorityMedium,
	FixPriorityLow,
	FixPriorityDefer,
}

// Status represents the status of a finding
type Status string

const (
	StatusOpen          Status = "open"
	StatusConfirmed     Status = "confirmed"
	StatusFalsePositive Status = "false_positive"
	StatusFixed         Status = "fixed"
)

// ValidStatuses contains all valid statuses
var ValidStatuses = []Status{
	StatusOpen,
	StatusConfirmed,
	StatusFalsePositive,
	StatusFixed,
}

// Location represents where a vulnerability was found
type Location struct {
	File      string `yaml:"file" json:"file"`
	LineStart int    `yaml:"line_start" json:"line_start"`
	LineEnd   int    `yaml:"line_end,omitempty" json:"line_end,omitempty"`
	Function  string `yaml:"function,omitempty" json:"function,omitempty"`
	Snippet   string `yaml:"snippet,omitempty" json:"snippet,omitempty"`
}

// CVSS represents CVSS scoring information
type CVSS struct {
	Score  float64 `yaml:"score" json:"score"`
	Vector string  `yaml:"vector" json:"vector"`
}

// Evidence represents supporting evidence for a finding
type Evidence struct {
	Type        string `yaml:"type" json:"type"`
	Description string `yaml:"description" json:"description"`
	Trace       []string `yaml:"trace,omitempty" json:"trace,omitempty"`
}

// FlowTrace represents a data flow trace from source to sink
type FlowTrace struct {
	Source    string   `yaml:"source" json:"source"`
	Sink      string   `yaml:"sink" json:"sink"`
	Path      []string `yaml:"path" json:"path"`
	Guards    []string `yaml:"guards,omitempty" json:"guards,omitempty"`
	Unguarded bool     `yaml:"unguarded" json:"unguarded"`
}

// Finding represents a security vulnerability finding
type Finding struct {
	ID             string         `yaml:"id" json:"id"`
	Title          string         `yaml:"title" json:"title"`
	Severity       Severity       `yaml:"severity" json:"severity"`
	Confidence     Confidence     `yaml:"confidence" json:"confidence"`
	Exploitability Exploitability `yaml:"exploitability,omitempty" json:"exploitability,omitempty"`
	FixPriority    FixPriority    `yaml:"fix_priority,omitempty" json:"fix_priority,omitempty"`
	Status         Status         `yaml:"status" json:"status"`
	CWE            string         `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	CVSS           *CVSS          `yaml:"cvss,omitempty" json:"cvss,omitempty"`
	Location       Location       `yaml:"location" json:"location"`
	Description    string         `yaml:"description" json:"description"`
	Impact         string         `yaml:"impact,omitempty" json:"impact,omitempty"`
	Remediation    string         `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	Evidence       []Evidence     `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	FlowTrace      *FlowTrace     `yaml:"flow_trace,omitempty" json:"flow_trace,omitempty"`
	References     []string       `yaml:"references,omitempty" json:"references,omitempty"`
	Tags           []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	ReviewedBy     []string       `yaml:"reviewed_by,omitempty" json:"reviewed_by,omitempty"`
	CreatedAt      time.Time      `yaml:"created_at" json:"created_at"`
	UpdatedAt      time.Time      `yaml:"updated_at" json:"updated_at"`
	CreatedBy      string         `yaml:"created_by,omitempty" json:"created_by,omitempty"`
}

// FindingList represents a list of findings with metadata
type FindingList struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
}

// FindingStats represents statistics about findings
type FindingStats struct {
	Total            int            `json:"total"`
	BySeverity       map[string]int `json:"by_severity"`
	ByStatus         map[string]int `json:"by_status"`
	ByConfidence     map[string]int `json:"by_confidence"`
	ByExploitability map[string]int `json:"by_exploitability"`
	ByFixPriority    map[string]int `json:"by_fix_priority"`
	ByCWE            map[string]int `json:"by_cwe"`
	ByCreatedBy      map[string]int `json:"by_created_by"`
	TopTags          []TagCount     `json:"top_tags"`
}

// TagCount represents a tag and its count
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// FilterOptions represents options for filtering findings
type FilterOptions struct {
	Severity       Severity
	Status         Status
	Confidence     Confidence
	Exploitability Exploitability
	FixPriority    FixPriority
	CWE            string
	Tag            string
	Limit          int
	Offset         int
}

// IsValidSeverity checks if a severity is valid
func IsValidSeverity(s Severity) bool {
	for _, valid := range ValidSeverities {
		if s == valid {
			return true
		}
	}
	return false
}

// IsValidStatus checks if a status is valid
func IsValidStatus(s Status) bool {
	for _, valid := range ValidStatuses {
		if s == valid {
			return true
		}
	}
	return false
}

// IsValidExploitability checks if an exploitability is valid
func IsValidExploitability(e Exploitability) bool {
	for _, valid := range ValidExploitabilities {
		if e == valid {
			return true
		}
	}
	return false
}

// IsValidFixPriority checks if a fix priority is valid
func IsValidFixPriority(p FixPriority) bool {
	for _, valid := range ValidFixPriorities {
		if p == valid {
			return true
		}
	}
	return false
}

// SeverityWeight returns a numeric weight for sorting by severity
func SeverityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
