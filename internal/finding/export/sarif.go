package export

import (
	"encoding/json"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
)

// SARIF format structures (SARIF 2.1.0)
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type SarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []SarifRun  `json:"runs"`
}

type SarifRun struct {
	Tool       SarifTool       `json:"tool"`
	Results    []SarifResult   `json:"results"`
	Invocations []SarifInvocation `json:"invocations,omitempty"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	InformationUri  string          `json:"informationUri,omitempty"`
	Rules           []SarifRule     `json:"rules,omitempty"`
}

type SarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription SarifMessage        `json:"shortDescription,omitempty"`
	FullDescription  SarifMessage        `json:"fullDescription,omitempty"`
	HelpUri          string              `json:"helpUri,omitempty"`
	Help             *SarifMessage       `json:"help,omitempty"`
	DefaultConfiguration *SarifReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type SarifReportingConfiguration struct {
	Level string `json:"level"`
}

type SarifResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex,omitempty"`
	Level      string                 `json:"level"`
	Message    SarifMessage           `json:"message"`
	Locations  []SarifLocation        `json:"locations,omitempty"`
	CodeFlows  []SarifCodeFlow        `json:"codeFlows,omitempty"`
	Fixes      []SarifFix             `json:"fixes,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SarifMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SarifRegion struct {
	StartLine   int    `json:"startLine,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
	Snippet     *SarifSnippet `json:"snippet,omitempty"`
}

type SarifSnippet struct {
	Text string `json:"text"`
}

type SarifFix struct {
	Description SarifMessage `json:"description"`
}

type SarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUtc          string `json:"endTimeUtc,omitempty"`
}

type SarifCodeFlow struct {
	ThreadFlows []SarifThreadFlow `json:"threadFlows"`
}

type SarifThreadFlow struct {
	Locations []SarifThreadFlowLocation `json:"locations"`
}

type SarifThreadFlowLocation struct {
	Location SarifLocation `json:"location"`
	Message  *SarifMessage `json:"message,omitempty"`
}

// SARIFExporter exports findings to SARIF format
type SARIFExporter struct {
	toolName    string
	toolVersion string
}

// NewSARIFExporter creates a new SARIF exporter
func NewSARIFExporter() *SARIFExporter {
	return &SARIFExporter{
		toolName:    "zrok",
		toolVersion: "1.0.0",
	}
}

// Export exports findings to SARIF format
func (e *SARIFExporter) Export(findings []finding.Finding) ([]byte, error) {
	// Build rules from unique CWEs
	ruleMap := make(map[string]int)
	var rules []SarifRule
	for _, f := range findings {
		ruleID := e.getRuleID(f)
		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = len(rules)
			rules = append(rules, e.buildRule(f))
		}
	}

	// Build results
	var results []SarifResult
	for _, f := range findings {
		results = append(results, e.buildResult(f, ruleMap))
	}

	log := SarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:    e.toolName,
						Version: e.toolVersion,
						Rules:   rules,
					},
				},
				Results: results,
				Invocations: []SarifInvocation{
					{
						ExecutionSuccessful: true,
						EndTimeUtc:          time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}

func (e *SARIFExporter) getRuleID(f finding.Finding) string {
	if f.CWE != "" {
		return f.CWE
	}
	return f.ID
}

func (e *SARIFExporter) buildRule(f finding.Finding) SarifRule {
	rule := SarifRule{
		ID:   e.getRuleID(f),
		Name: f.Title,
		ShortDescription: SarifMessage{
			Text: f.Title,
		},
		DefaultConfiguration: &SarifReportingConfiguration{
			Level: e.severityToLevel(f.Severity),
		},
		Properties: make(map[string]interface{}),
	}

	if f.Description != "" {
		rule.FullDescription = SarifMessage{
			Text: f.Description,
		}
	}

	if len(f.References) > 0 {
		rule.HelpUri = f.References[0]
	}

	if f.Remediation != "" {
		rule.Help = &SarifMessage{
			Text: f.Remediation,
		}
	}

	if len(f.Tags) > 0 {
		rule.Properties["tags"] = f.Tags
	}

	return rule
}

func (e *SARIFExporter) buildResult(f finding.Finding, ruleMap map[string]int) SarifResult {
	ruleID := e.getRuleID(f)

	result := SarifResult{
		RuleID:    ruleID,
		RuleIndex: ruleMap[ruleID],
		Level:     e.severityToLevel(f.Severity),
		Message: SarifMessage{
			Text: f.Description,
		},
		Properties: map[string]interface{}{
			"id":         f.ID,
			"confidence": string(f.Confidence),
			"status":     string(f.Status),
		},
	}

	// Add location
	loc := SarifLocation{
		PhysicalLocation: SarifPhysicalLocation{
			ArtifactLocation: SarifArtifactLocation{
				URI:       f.Location.File,
				URIBaseID: "%SRCROOT%",
			},
		},
	}

	if f.Location.LineStart > 0 {
		loc.PhysicalLocation.Region = &SarifRegion{
			StartLine: f.Location.LineStart,
		}
		if f.Location.LineEnd > 0 {
			loc.PhysicalLocation.Region.EndLine = f.Location.LineEnd
		}
		if f.Location.Snippet != "" {
			loc.PhysicalLocation.Region.Snippet = &SarifSnippet{
				Text: f.Location.Snippet,
			}
		}
	}

	result.Locations = []SarifLocation{loc}

	// Add fix suggestion if remediation exists
	if f.Remediation != "" {
		result.Fixes = []SarifFix{
			{
				Description: SarifMessage{
					Text: f.Remediation,
				},
			},
		}
	}

	// Add code flow from FlowTrace
	if f.FlowTrace != nil {
		var flowLocs []SarifThreadFlowLocation

		// Source
		flowLocs = append(flowLocs, SarifThreadFlowLocation{
			Location: SarifLocation{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{
						URI:       f.Location.File,
						URIBaseID: "%SRCROOT%",
					},
				},
			},
			Message: &SarifMessage{Text: "Source: " + f.FlowTrace.Source},
		})

		// Path steps
		for _, step := range f.FlowTrace.Path {
			flowLocs = append(flowLocs, SarifThreadFlowLocation{
				Location: SarifLocation{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI:       f.Location.File,
							URIBaseID: "%SRCROOT%",
						},
					},
				},
				Message: &SarifMessage{Text: step},
			})
		}

		// Sink
		flowLocs = append(flowLocs, SarifThreadFlowLocation{
			Location: SarifLocation{
				PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{
						URI:       f.Location.File,
						URIBaseID: "%SRCROOT%",
					},
				},
			},
			Message: &SarifMessage{Text: "Sink: " + f.FlowTrace.Sink},
		})

		result.CodeFlows = []SarifCodeFlow{
			{
				ThreadFlows: []SarifThreadFlow{
					{Locations: flowLocs},
				},
			},
		}
	}

	// Add CVSS if present
	if f.CVSS != nil {
		result.Properties["cvss"] = map[string]interface{}{
			"score":  f.CVSS.Score,
			"vector": f.CVSS.Vector,
		}
	}

	return result
}

func (e *SARIFExporter) severityToLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	case finding.SeverityLow, finding.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// ContentType returns the MIME type for SARIF
func (e *SARIFExporter) ContentType() string {
	return "application/sarif+json"
}

// FileExtension returns the file extension for SARIF
func (e *SARIFExporter) FileExtension() string {
	return ".sarif"
}

// FormatName returns the format name
func (e *SARIFExporter) FormatName() string {
	return "sarif"
}
