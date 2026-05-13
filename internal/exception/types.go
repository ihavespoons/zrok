// Package exception manages persistent suppressions for findings. Exceptions
// come in two shapes: per-finding (keyed by fingerprint) and pattern-based
// (path glob + CWE). Both require a reason, an expires date, and an
// approver — the goal is to make suppressions auditable and time-bounded
// rather than write-and-forget like older static-analysis ignore lists.
package exception

import (
	"fmt"
	"strings"
	"time"
)

// Exception is one entry in .zrok/exceptions.yaml. It can be keyed by
// Fingerprint XOR (PathGlob + CWE). The store enforces this exclusivity at
// write time so callers don't need to revalidate it.
type Exception struct {
	ID          string    `yaml:"id" json:"id"`
	Fingerprint string    `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	PathGlob    string    `yaml:"path_glob,omitempty" json:"path_glob,omitempty"`
	CWE         string    `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	Reason      string    `yaml:"reason" json:"reason"`
	Expires     time.Time `yaml:"expires" json:"expires"`
	ApprovedBy  string    `yaml:"approved_by" json:"approved_by"`
	ApprovedFor string    `yaml:"approved_for,omitempty" json:"approved_for,omitempty"`
	CreatedAt   time.Time `yaml:"created_at" json:"created_at"`
}

// IsFingerprint reports whether this exception targets a specific finding
// fingerprint (as opposed to a pattern).
func (e Exception) IsFingerprint() bool {
	return strings.TrimSpace(e.Fingerprint) != ""
}

// IsPattern reports whether this exception targets a path glob + CWE.
func (e Exception) IsPattern() bool {
	return strings.TrimSpace(e.PathGlob) != ""
}

// IsExpired reports whether the exception is past its expires date as of
// the given moment (typically time.Now). Exceptions with a zero expires
// time are treated as expired — the field is mandatory.
func (e Exception) IsExpired(now time.Time) bool {
	if e.Expires.IsZero() {
		return true
	}
	return now.After(e.Expires)
}

// Validate checks that the exception has the required fields and the
// fingerprint/pattern XOR constraint. Returns the first error encountered.
func (e Exception) Validate() error {
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if e.Expires.IsZero() {
		return fmt.Errorf("expires is required (suppressions must be time-bounded)")
	}
	if strings.TrimSpace(e.ApprovedBy) == "" {
		return fmt.Errorf("approved_by is required")
	}
	hasFP := e.IsFingerprint()
	hasPat := e.IsPattern()
	if hasFP && hasPat {
		return fmt.Errorf("exception cannot set both fingerprint and path_glob")
	}
	if !hasFP && !hasPat {
		return fmt.Errorf("exception must set either fingerprint or path_glob")
	}
	if hasPat && strings.TrimSpace(e.CWE) == "" {
		return fmt.Errorf("cwe is required for path-glob exceptions (suppressions are scoped to a vulnerability class)")
	}
	return nil
}
