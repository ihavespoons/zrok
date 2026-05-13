package exception

import (
	"os"
	"testing"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "zrok-exc-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	p, err := project.Initialize(dir)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("project init: %v", err)
	}
	return NewStore(p), func() { os.RemoveAll(dir) }
}

func futureDate() time.Time {
	return time.Now().Add(30 * 24 * time.Hour)
}

func pastDate() time.Time {
	return time.Now().Add(-24 * time.Hour)
}

func TestStore_AddFingerprintException(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	e := Exception{
		Fingerprint: "abc123",
		Reason:      "test fixture",
		Expires:     futureDate(),
		ApprovedBy:  "human:tester",
	}
	saved, err := s.Add(e)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if saved.ID != "EXC-001" {
		t.Errorf("expected EXC-001, got %q", saved.ID)
	}
	if saved.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set automatically")
	}
}

func TestStore_AddPatternException(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, err := s.Add(Exception{
		PathGlob:   "tests/*.py",
		CWE:        "CWE-89",
		Reason:     "test fixtures intentionally use raw SQL",
		Expires:    futureDate(),
		ApprovedBy: "human:tester",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
}

func TestStore_RejectsBothFingerprintAndGlob(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, err := s.Add(Exception{
		Fingerprint: "abc",
		PathGlob:    "tests/*",
		CWE:         "CWE-89",
		Reason:      "x",
		Expires:     futureDate(),
		ApprovedBy:  "h",
	})
	if err == nil {
		t.Fatal("expected error setting both fingerprint and path_glob")
	}
}

func TestStore_RejectsNeitherFingerprintNorGlob(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, err := s.Add(Exception{
		Reason:     "x",
		Expires:    futureDate(),
		ApprovedBy: "h",
	})
	if err == nil {
		t.Fatal("expected error when neither target is set")
	}
}

func TestStore_RequiresReason(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, err := s.Add(Exception{
		Fingerprint: "abc",
		Expires:     futureDate(),
		ApprovedBy:  "h",
	})
	if err == nil {
		t.Fatal("expected error when reason is missing")
	}
}

func TestStore_RequiresExpires(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, err := s.Add(Exception{
		Fingerprint: "abc",
		Reason:      "r",
		ApprovedBy:  "h",
	})
	if err == nil {
		t.Fatal("expected error when expires is missing (suppressions must be time-bounded)")
	}
}

func TestStore_RequiresCWEForGlob(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, err := s.Add(Exception{
		PathGlob:   "tests/*",
		Reason:     "r",
		Expires:    futureDate(),
		ApprovedBy: "h",
	})
	if err == nil {
		t.Fatal("expected error: glob exceptions need a CWE scope")
	}
}

func TestStore_ListExpired(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, _ = s.Add(Exception{Fingerprint: "alive", Reason: "r", Expires: futureDate(), ApprovedBy: "h"})
	_, _ = s.Add(Exception{Fingerprint: "dead", Reason: "r", Expires: pastDate(), ApprovedBy: "h"})

	live, _ := s.List(false)
	if len(live) != 1 || live[0].Fingerprint != "alive" {
		t.Errorf("expected only alive exception, got %+v", live)
	}
	all, _ := s.List(true)
	if len(all) != 2 {
		t.Errorf("expected 2 with includeExpired, got %d", len(all))
	}
}

func TestStore_Remove(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	saved, _ := s.Add(Exception{Fingerprint: "x", Reason: "r", Expires: futureDate(), ApprovedBy: "h"})
	if err := s.Remove(saved.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := s.Remove(saved.ID); err == nil {
		t.Fatal("second remove should error")
	}
}

func TestStore_Expire(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, _ = s.Add(Exception{Fingerprint: "alive", Reason: "r", Expires: futureDate(), ApprovedBy: "h"})
	_, _ = s.Add(Exception{Fingerprint: "dead1", Reason: "r", Expires: pastDate(), ApprovedBy: "h"})
	_, _ = s.Add(Exception{Fingerprint: "dead2", Reason: "r", Expires: pastDate(), ApprovedBy: "h"})

	removed, err := s.Expire()
	if err != nil {
		t.Fatalf("Expire: %v", err)
	}
	if len(removed) != 2 {
		t.Errorf("expected 2 removed, got %d", len(removed))
	}
	remaining, _ := s.List(true)
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestStore_MatchFingerprint(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	fp := "abcd1234"
	_, _ = s.Add(Exception{Fingerprint: fp, Reason: "r", Expires: futureDate(), ApprovedBy: "h"})

	f := finding.Finding{Fingerprint: fp, Location: finding.Location{File: "app.py", LineStart: 1}}
	match, err := s.Match(f)
	if err != nil || match == nil {
		t.Fatalf("expected match, got err=%v match=%v", err, match)
	}

	other := finding.Finding{Fingerprint: "different"}
	match, _ = s.Match(other)
	if match != nil {
		t.Errorf("non-matching fingerprint should not match")
	}
}

func TestStore_MatchPatternRequiresBothPathAndCWE(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	_, _ = s.Add(Exception{
		PathGlob: "*.py", CWE: "CWE-89",
		Reason: "tests intentionally use raw SQL", Expires: futureDate(), ApprovedBy: "h",
	})

	// Matches: path + CWE both align
	hit := finding.Finding{CWE: "CWE-89", Location: finding.Location{File: "test_foo.py", LineStart: 1}}
	match, _ := s.Match(hit)
	if match == nil {
		t.Errorf("expected pattern match on file+cwe")
	}

	// Same path, different CWE — should NOT match
	wrongCWE := finding.Finding{CWE: "CWE-78", Location: finding.Location{File: "test_foo.py", LineStart: 1}}
	match, _ = s.Match(wrongCWE)
	if match != nil {
		t.Errorf("CWE mismatch should not suppress")
	}

	// Same CWE, different path — should NOT match
	wrongPath := finding.Finding{CWE: "CWE-89", Location: finding.Location{File: "app.rb", LineStart: 1}}
	match, _ = s.Match(wrongPath)
	if match != nil {
		t.Errorf("non-matching path should not suppress")
	}
}

func TestStore_ExpiredDoesNotMatch(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	fp := "abcd"
	_, _ = s.Add(Exception{Fingerprint: fp, Reason: "r", Expires: pastDate(), ApprovedBy: "h"})

	match, _ := s.Match(finding.Finding{Fingerprint: fp})
	if match != nil {
		t.Errorf("expired exception should not match findings")
	}
}

func TestStore_NilStoreMatchesNothing(t *testing.T) {
	var s *Store
	match, err := s.Match(finding.Finding{Fingerprint: "any"})
	if err != nil {
		t.Errorf("nil store should not error: %v", err)
	}
	if match != nil {
		t.Error("nil store should never match")
	}
}

func TestStore_AutoIncrementID(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	first, _ := s.Add(Exception{Fingerprint: "1", Reason: "r", Expires: futureDate(), ApprovedBy: "h"})
	second, _ := s.Add(Exception{Fingerprint: "2", Reason: "r", Expires: futureDate(), ApprovedBy: "h"})
	if first.ID != "EXC-001" || second.ID != "EXC-002" {
		t.Errorf("expected EXC-001, EXC-002 got %q, %q", first.ID, second.ID)
	}
}
