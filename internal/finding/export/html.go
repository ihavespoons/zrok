package export

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// HTMLExporter exports findings to HTML format
type HTMLExporter struct {
	toolName    string
	toolVersion string
	projectName string
}

// NewHTMLExporter creates a new HTML exporter
func NewHTMLExporter() *HTMLExporter {
	return &HTMLExporter{
		toolName:    "zrok",
		toolVersion: "1.0.0",
	}
}

// SetProjectName sets the project name for the report
func (e *HTMLExporter) SetProjectName(name string) {
	e.projectName = name
}

// Export exports findings to HTML format
func (e *HTMLExporter) Export(findings []finding.Finding) ([]byte, error) {
	var b strings.Builder

	title := "Security Findings Report"
	if e.projectName != "" {
		title = fmt.Sprintf("Security Findings Report: %s", html.EscapeString(e.projectName))
	}

	// Summary stats
	severityCounts := make(map[string]int)
	statusCounts := make(map[string]int)
	for _, f := range findings {
		severityCounts[string(f.Severity)]++
		statusCounts[string(f.Status)]++
	}

	// HTML document
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + html.EscapeString(title) + `</title>
    <style>
        :root {
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #16a34a;
            --info: #2563eb;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .meta { color: var(--text-muted); margin-bottom: 2rem; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 1rem;
            text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { color: var(--text-muted); font-size: 0.875rem; }
        .finding {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--high); }
        .severity-medium { background: var(--medium); }
        .severity-low { background: var(--low); }
        .severity-info { background: var(--info); }
        .finding-title { font-weight: 600; flex: 1; }
        .finding-id { color: var(--text-muted); font-family: monospace; font-size: 0.875rem; }
        .finding-body { padding: 1rem; }
        .finding-section { margin-bottom: 1rem; }
        .finding-section:last-child { margin-bottom: 0; }
        .finding-section h4 {
            font-size: 0.875rem;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }
        .location {
            font-family: monospace;
            background: var(--bg);
            padding: 0.5rem;
            border-radius: 0.25rem;
        }
        .snippet {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 0.25rem;
            font-family: monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
        }
        .meta-item {
            display: flex;
            gap: 0.5rem;
        }
        .meta-label { color: var(--text-muted); }
        .tags { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .tag {
            background: var(--bg);
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
        }
        a { color: var(--info); }
        .evidence-list { list-style-position: inside; }
    </style>
</head>
<body>
    <div class="container">
        <h1>` + html.EscapeString(title) + `</h1>
        <p class="meta">Generated by ` + html.EscapeString(e.toolName) + ` v` + html.EscapeString(e.toolVersion) + ` on ` + time.Now().Format("2006-01-02 15:04:05") + `</p>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">` + fmt.Sprintf("%d", len(findings)) + `</div>
                <div class="stat-label">Total Findings</div>
            </div>
`)

	// Severity stats
	for _, sev := range finding.ValidSeverities {
		if count := severityCounts[string(sev)]; count > 0 {
			b.WriteString(fmt.Sprintf(`            <div class="stat-card">
                <div class="stat-value" style="color: var(--%s)">%d</div>
                <div class="stat-label">%s</div>
            </div>
`, string(sev), count, cases.Title(language.English).String(string(sev))))
		}
	}

	b.WriteString(`        </div>

        <h2>Findings</h2>
`)

	// Render each finding
	for _, f := range findings {
		b.WriteString(e.renderFinding(f))
	}

	b.WriteString(`    </div>
</body>
</html>`)

	return []byte(b.String()), nil
}

func (e *HTMLExporter) renderFinding(f finding.Finding) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf(`        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge severity-%s">%s</span>
                <span class="finding-title">%s</span>
                <span class="finding-id">%s</span>
            </div>
            <div class="finding-body">
`,
		string(f.Severity),
		strings.ToUpper(string(f.Severity)),
		html.EscapeString(f.Title),
		html.EscapeString(f.ID),
	))

	// Metadata
	b.WriteString(`                <div class="finding-section">
                    <h4>Details</h4>
                    <div class="meta-grid">
`)
	b.WriteString(fmt.Sprintf(`                        <div class="meta-item"><span class="meta-label">Status:</span> %s</div>
`, html.EscapeString(string(f.Status))))
	b.WriteString(fmt.Sprintf(`                        <div class="meta-item"><span class="meta-label">Confidence:</span> %s</div>
`, html.EscapeString(string(f.Confidence))))
	if f.CWE != "" {
		cweNum := strings.TrimPrefix(f.CWE, "CWE-")
		b.WriteString(fmt.Sprintf(`                        <div class="meta-item"><span class="meta-label">CWE:</span> <a href="https://cwe.mitre.org/data/definitions/%s.html" target="_blank">%s</a></div>
`, html.EscapeString(cweNum), html.EscapeString(f.CWE)))
	}
	if f.CVSS != nil {
		b.WriteString(fmt.Sprintf(`                        <div class="meta-item"><span class="meta-label">CVSS:</span> %.1f (%s)</div>
`, f.CVSS.Score, html.EscapeString(f.CVSS.Vector)))
	}
	b.WriteString(`                    </div>
                </div>
`)

	// Location
	b.WriteString(`                <div class="finding-section">
                    <h4>Location</h4>
                    <div class="location">`)
	b.WriteString(html.EscapeString(f.Location.File))
	if f.Location.LineStart > 0 {
		if f.Location.LineEnd > 0 && f.Location.LineEnd != f.Location.LineStart {
			b.WriteString(fmt.Sprintf(":%d-%d", f.Location.LineStart, f.Location.LineEnd))
		} else {
			b.WriteString(fmt.Sprintf(":%d", f.Location.LineStart))
		}
	}
	if f.Location.Function != "" {
		b.WriteString(fmt.Sprintf(" (function: %s)", html.EscapeString(f.Location.Function)))
	}
	b.WriteString(`</div>
                </div>
`)

	// Snippet
	if f.Location.Snippet != "" {
		b.WriteString(fmt.Sprintf(`                <div class="finding-section">
                    <h4>Code</h4>
                    <pre class="snippet">%s</pre>
                </div>
`, html.EscapeString(f.Location.Snippet)))
	}

	// Description
	if f.Description != "" {
		b.WriteString(fmt.Sprintf(`                <div class="finding-section">
                    <h4>Description</h4>
                    <p>%s</p>
                </div>
`, html.EscapeString(f.Description)))
	}

	// Impact
	if f.Impact != "" {
		b.WriteString(fmt.Sprintf(`                <div class="finding-section">
                    <h4>Impact</h4>
                    <p>%s</p>
                </div>
`, html.EscapeString(f.Impact)))
	}

	// Remediation
	if f.Remediation != "" {
		b.WriteString(fmt.Sprintf(`                <div class="finding-section">
                    <h4>Remediation</h4>
                    <p>%s</p>
                </div>
`, html.EscapeString(f.Remediation)))
	}

	// Evidence
	if len(f.Evidence) > 0 {
		b.WriteString(`                <div class="finding-section">
                    <h4>Evidence</h4>
                    <ul class="evidence-list">
`)
		for _, ev := range f.Evidence {
			b.WriteString(fmt.Sprintf(`                        <li><strong>%s:</strong> %s`, html.EscapeString(ev.Type), html.EscapeString(ev.Description)))
			if len(ev.Trace) > 0 {
				b.WriteString(fmt.Sprintf(` (trace: %s)`, html.EscapeString(strings.Join(ev.Trace, " → "))))
			}
			b.WriteString(`</li>
`)
		}
		b.WriteString(`                    </ul>
                </div>
`)
	}

	// Flow Trace
	if f.FlowTrace != nil {
		b.WriteString(`                <div class="finding-section">
                    <h4>Data Flow Trace</h4>
                    <div class="location">
`)
		b.WriteString(fmt.Sprintf(`                        <strong>Source:</strong> %s<br>
`, html.EscapeString(f.FlowTrace.Source)))
		if len(f.FlowTrace.Path) > 0 {
			b.WriteString(`                        <strong>Path:</strong><br>
`)
			for i, step := range f.FlowTrace.Path {
				b.WriteString(fmt.Sprintf("                        %d. %s<br>\n", i+1, html.EscapeString(step)))
			}
		}
		if len(f.FlowTrace.Guards) > 0 {
			b.WriteString(`                        <strong>Guards:</strong><br>
`)
			for _, guard := range f.FlowTrace.Guards {
				b.WriteString(fmt.Sprintf("                        - %s<br>\n", html.EscapeString(guard)))
			}
		}
		b.WriteString(fmt.Sprintf(`                        <strong>Sink:</strong> %s<br>
`, html.EscapeString(f.FlowTrace.Sink)))
		if f.FlowTrace.Unguarded {
			b.WriteString(`                        <strong>Verdict:</strong> <span style="color: var(--critical)">UNGUARDED</span><br>
`)
		} else {
			b.WriteString(`                        <strong>Verdict:</strong> <span style="color: var(--low)">GUARDED</span><br>
`)
		}
		b.WriteString(`                    </div>
                </div>
`)
	}

	// References
	if len(f.References) > 0 {
		b.WriteString(`                <div class="finding-section">
                    <h4>References</h4>
                    <ul>
`)
		for _, ref := range f.References {
			b.WriteString(fmt.Sprintf(`                        <li><a href="%s" target="_blank">%s</a></li>
`, html.EscapeString(ref), html.EscapeString(ref)))
		}
		b.WriteString(`                    </ul>
                </div>
`)
	}

	// Tags
	if len(f.Tags) > 0 {
		b.WriteString(`                <div class="finding-section">
                    <h4>Tags</h4>
                    <div class="tags">
`)
		for _, tag := range f.Tags {
			b.WriteString(fmt.Sprintf(`                        <span class="tag">%s</span>
`, html.EscapeString(tag)))
		}
		b.WriteString(`                    </div>
                </div>
`)
	}

	b.WriteString(`            </div>
        </div>
`)

	return b.String()
}

// ContentType returns the MIME type for HTML
func (e *HTMLExporter) ContentType() string {
	return "text/html"
}

// FileExtension returns the file extension for HTML
func (e *HTMLExporter) FileExtension() string {
	return ".html"
}

// FormatName returns the format name
func (e *HTMLExporter) FormatName() string {
	return "html"
}
