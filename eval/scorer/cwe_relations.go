package scorer

import "strings"

// cweEquivalents maps a CWE to all CWEs that should match it bidirectionally
// (including itself) for scoring purposes. Used when an oracle uses a parent
// CWE and the agent files a child (or vice versa).
//
// Lookups via cweMatches are bidirectional: if either side has the other
// listed in its equivalence set, the pair is considered a match. This means
// not every entry needs to be reciprocally populated, but doing so makes the
// table easier to read and audit.
var cweEquivalents = map[string][]string{
	// CWE-330 (Use of Insufficiently Random Values) and its specializations.
	"CWE-330": {"CWE-330", "CWE-338", "CWE-331", "CWE-340"},
	"CWE-338": {"CWE-330", "CWE-338"},
	"CWE-331": {"CWE-330", "CWE-331"},
	"CWE-340": {"CWE-330", "CWE-340"},

	// CWE-89 (SQL Injection) and known specializations.
	"CWE-89":  {"CWE-89", "CWE-564", "CWE-943"},
	"CWE-564": {"CWE-89", "CWE-564"},
	"CWE-943": {"CWE-89", "CWE-943"},

	// CWE-22 (Path Traversal) and specific traversal variants.
	"CWE-22": {"CWE-22", "CWE-23", "CWE-24", "CWE-25", "CWE-36"},
	"CWE-23": {"CWE-22", "CWE-23"},
	"CWE-24": {"CWE-22", "CWE-24"},
	"CWE-25": {"CWE-22", "CWE-25"},
	"CWE-36": {"CWE-22", "CWE-36"},

	// CWE-79 (Cross-site Scripting) and reflection/stored/DOM variants.
	"CWE-79": {"CWE-79", "CWE-80", "CWE-83", "CWE-84"},
	"CWE-80": {"CWE-79", "CWE-80"},
	"CWE-83": {"CWE-79", "CWE-83"},
	"CWE-84": {"CWE-79", "CWE-84"},

	// CWE-94 (Code Injection) and its specializations.
	"CWE-94":  {"CWE-94", "CWE-95", "CWE-96", "CWE-917"},
	"CWE-95":  {"CWE-94", "CWE-95"},
	"CWE-96":  {"CWE-94", "CWE-96"},
	"CWE-917": {"CWE-94", "CWE-917"},

	// CWE-77 (Command Injection, parent) and CWE-78 (OS Command Injection).
	// Agents and oracles commonly use these interchangeably.
	"CWE-77": {"CWE-77", "CWE-78"},
	"CWE-78": {"CWE-77", "CWE-78"},

	// CWE-200 (Exposure of Sensitive Information) and disclosure variants.
	"CWE-200": {"CWE-200", "CWE-209", "CWE-532", "CWE-538"},
	"CWE-209": {"CWE-200", "CWE-209"},
	"CWE-532": {"CWE-200", "CWE-532"},
	"CWE-538": {"CWE-200", "CWE-538"},

	// CWE-352 (CSRF) and SameSite-cookie specialization.
	"CWE-352":  {"CWE-352", "CWE-1275"},
	"CWE-1275": {"CWE-352", "CWE-1275"},
}

// normalizeCWE upper-cases a CWE identifier so the equivalence lookup is
// case-insensitive. We deliberately do not try to reparse the numeric part;
// the only realistic variation is the `cwe-` prefix casing.
func normalizeCWE(c string) string {
	return strings.ToUpper(strings.TrimSpace(c))
}

// cweMatches returns true if a and b refer to the same CWE or are listed as
// equivalents in the cweEquivalents table. Matching is bidirectional: if
// either side's equivalence slice contains the other, the pair matches.
// Returns false if either input is empty.
func cweMatches(a, b string) bool {
	na := normalizeCWE(a)
	nb := normalizeCWE(b)
	if na == "" || nb == "" {
		return false
	}
	if na == nb {
		return true
	}
	if equivs, ok := cweEquivalents[na]; ok {
		for _, e := range equivs {
			if normalizeCWE(e) == nb {
				return true
			}
		}
	}
	if equivs, ok := cweEquivalents[nb]; ok {
		for _, e := range equivs {
			if normalizeCWE(e) == na {
				return true
			}
		}
	}
	return false
}
