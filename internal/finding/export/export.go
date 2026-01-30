package export

import (
	"fmt"

	"github.com/ihavespoons/zrok/internal/finding"
)

// Exporter is the interface for all export formats
type Exporter interface {
	Export(findings []finding.Finding) ([]byte, error)
	ContentType() string
	FileExtension() string
	FormatName() string
}

// ExporterWithProject is an exporter that can have a project name set
type ExporterWithProject interface {
	Exporter
	SetProjectName(name string)
}

// ValidFormats contains all supported export formats
var ValidFormats = []string{"sarif", "json", "md", "markdown", "html", "csv"}

// GetExporter returns an exporter for the given format
func GetExporter(format string) (Exporter, error) {
	switch format {
	case "sarif":
		return NewSARIFExporter(), nil
	case "json":
		return NewJSONExporter(), nil
	case "md", "markdown":
		return NewMarkdownExporter(), nil
	case "html":
		return NewHTMLExporter(), nil
	case "csv":
		return NewCSVExporter(), nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s (valid: %v)", format, ValidFormats)
	}
}

// ExportFindings exports findings to the specified format
func ExportFindings(findings []finding.Finding, format string, projectName string) ([]byte, error) {
	exporter, err := GetExporter(format)
	if err != nil {
		return nil, err
	}

	// Set project name if supported
	if exp, ok := exporter.(ExporterWithProject); ok {
		exp.SetProjectName(projectName)
	}

	return exporter.Export(findings)
}
