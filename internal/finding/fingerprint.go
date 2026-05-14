package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// FingerprintVersion identifies the algorithm. Bump when the scheme changes
// so consumers (SARIF, dedup logic) can tell stale fingerprints from current.
const FingerprintVersion = "v1"

// FingerprintKey is the property name used in SARIF partialFingerprints.
const FingerprintKey = "quokkaFingerprint/" + FingerprintVersion

// noSymbolSentinel keeps the fingerprint stable when Location.Function is unset.
// Using a fixed token rather than "" makes accidental collisions less likely.
const noSymbolSentinel = "_"

// Tokens that frequently appear in LLM-generated finding titles but carry no
// semantic weight. Stripping them lets two phrasings of the same issue dedupe.
var titleStopwords = map[string]struct{}{
	"a": {}, "an": {}, "the": {},
	"in": {}, "on": {}, "at": {}, "of": {}, "to": {}, "for": {}, "with": {}, "via": {},
	"and": {}, "or": {},
	"is": {}, "are": {}, "was": {}, "were": {}, "be": {}, "been": {},
	"possible": {}, "potential": {}, "potentially": {},
	"vulnerability": {}, "vulnerable": {}, "issue": {}, "bug": {},
}

var nonAlphaNum = regexp.MustCompile(`[^a-z0-9 ]+`)
var multiSpace = regexp.MustCompile(`\s+`)

// Fingerprint returns a stable identifier for a finding suitable for matching
// the same issue across runs. The hash inputs are:
//
//	cwe ":" file ":" symbol ":" normalized_title
//
// Line numbers are deliberately excluded so a finding survives unrelated edits
// that shift its location. The symbol comes from Location.Function when present;
// when missing we fall back to a sentinel rather than reaching for the symbol
// extractor synchronously.
func Fingerprint(f Finding) string {
	parts := []string{
		strings.ToUpper(strings.TrimSpace(f.CWE)),
		strings.TrimSpace(f.Location.File),
		symbolFor(f),
		normalizeTitle(f.Title),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}

func symbolFor(f Finding) string {
	if s := strings.TrimSpace(f.Location.Function); s != "" {
		return s
	}
	return noSymbolSentinel
}

// normalizeTitle lowercases, drops punctuation, removes filler words, and
// collapses whitespace. The goal is that "Possible SQL injection in getUser"
// and "SQL injection in getUser()" hash the same.
func normalizeTitle(title string) string {
	t := strings.ToLower(title)
	t = nonAlphaNum.ReplaceAllString(t, " ")
	t = multiSpace.ReplaceAllString(t, " ")
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	tokens := strings.Split(t, " ")
	kept := tokens[:0]
	for _, tok := range tokens {
		if _, drop := titleStopwords[tok]; drop {
			continue
		}
		kept = append(kept, tok)
	}
	return strings.Join(kept, " ")
}
