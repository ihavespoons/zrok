package finding

import (
	"strings"
	"testing"
)

func base() Finding {
	return Finding{
		Title: "SQL Injection in getUser",
		CWE:   "CWE-89",
		Location: Location{
			File:      "internal/db/queries.go",
			LineStart: 42,
			LineEnd:   45,
			Function:  "GetUser",
		},
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	a := Fingerprint(base())
	b := Fingerprint(base())
	if a != b {
		t.Fatalf("non-deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64-char sha256 hex, got %d", len(a))
	}
}

func TestFingerprint_IgnoresLineShift(t *testing.T) {
	f1 := base()
	f2 := base()
	f2.Location.LineStart = 200
	f2.Location.LineEnd = 210
	if Fingerprint(f1) != Fingerprint(f2) {
		t.Fatal("fingerprint should not depend on line numbers")
	}
}

func TestFingerprint_IgnoresTitleNoise(t *testing.T) {
	f1 := base()
	f1.Title = "Possible SQL injection in getUser"
	f2 := base()
	f2.Title = "SQL Injection in getUser()"
	if Fingerprint(f1) != Fingerprint(f2) {
		t.Fatalf("normalized titles should match: %q vs %q", f1.Title, f2.Title)
	}
}

func TestFingerprint_ChangesWithCWE(t *testing.T) {
	f1 := base()
	f2 := base()
	f2.CWE = "CWE-78"
	if Fingerprint(f1) == Fingerprint(f2) {
		t.Fatal("changing CWE should change fingerprint")
	}
}

func TestFingerprint_ChangesWithFile(t *testing.T) {
	f1 := base()
	f2 := base()
	f2.Location.File = "internal/db/other.go"
	if Fingerprint(f1) == Fingerprint(f2) {
		t.Fatal("changing file should change fingerprint")
	}
}

func TestFingerprint_ChangesWithFunction(t *testing.T) {
	f1 := base()
	f2 := base()
	f2.Location.Function = "DeleteUser"
	if Fingerprint(f1) == Fingerprint(f2) {
		t.Fatal("changing function should change fingerprint")
	}
}

func TestFingerprint_MissingFunctionUsesSentinel(t *testing.T) {
	f1 := base()
	f1.Location.Function = ""
	f2 := base()
	f2.Location.Function = ""
	if Fingerprint(f1) != Fingerprint(f2) {
		t.Fatal("two findings with no function should fingerprint identically")
	}
	// And differ from one that does have a function.
	if Fingerprint(f1) == Fingerprint(base()) {
		t.Fatal("missing function should not collide with a real one")
	}
}

func TestFingerprint_CWECaseInsensitive(t *testing.T) {
	f1 := base()
	f1.CWE = "cwe-89"
	f2 := base()
	f2.CWE = "CWE-89"
	if Fingerprint(f1) != Fingerprint(f2) {
		t.Fatal("CWE comparison should be case-insensitive")
	}
}

func TestNormalizeTitle(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"SQL Injection", "sql injection"},
		{"Possible SQL injection!", "sql injection"},
		{"SQL  Injection  ", "sql injection"},
		{"A potential XSS vulnerability in the renderer", "xss renderer"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeTitle(c.in)
		if got != c.want {
			t.Errorf("normalizeTitle(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFingerprintKey_HasVersion(t *testing.T) {
	if !strings.Contains(FingerprintKey, FingerprintVersion) {
		t.Fatalf("FingerprintKey %q should embed version %q", FingerprintKey, FingerprintVersion)
	}
}
