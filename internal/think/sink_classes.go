package think

import (
	"sort"
	"strings"
)

// SinkClass is a named collection of sink regex alternatives covering one
// vulnerability family (e.g. deserialization, xxe, ldap).
//
// Each pattern is a regex fragment, NOT a compiled regex; combine them with
// `|` to build a single alternation. Patterns deliberately omit `(?i)` since
// AnalyzeDataflow prepends that flag when compiling the final sink pattern.
type SinkClass struct {
	Name        string
	Description string
	// Patterns are regex fragments. They are joined with "|" when building
	// a combined sink regex.
	Patterns []string
}

// sinkClasses maps short class names to their pattern sets. The set is
// intentionally conservative: each fragment targets a call shape (`.method(`
// or `\bname\(`) so it is less likely to match string literals or comments.
//
// Default behavior of `zrok think dataflow` is to use the union of the
// "common" classes (a broad mix across all CWE families). Users may narrow
// with `--sink-class deserialization,xxe` or override entirely with
// `--sink <regex>`.
var sinkClasses = map[string]SinkClass{
	"sqli": {
		Name:        "sqli",
		Description: "SQL injection sinks (CWE-89)",
		Patterns: []string{
			`cur\.execute\b`,
			`cursor\.execute\b`,
			`cur\.executemany\b`,
			`cursor\.executemany\b`,
			`session\.execute\b`,
			`db\.session\.execute\b`,
			`connection\.execute\b`,
			`sqlalchemy\.text\b`,
		},
	},
	"cmdi": {
		Name:        "cmdi",
		Description: "OS command injection sinks (CWE-78)",
		Patterns: []string{
			`os\.system\b`,
			`subprocess\.(Popen|run|call|check_output|check_call)\b`,
			`os\.popen\b`,
			`commands\.(getoutput|getstatusoutput)\b`,
			`pty\.spawn\b`,
		},
	},
	"codeexec": {
		Name:        "codeexec",
		Description: "Dynamic code execution sinks (CWE-94)",
		Patterns: []string{
			`\beval\s*\(`,
			`\bexec\s*\(`,
			`\bcompile\s*\(`,
			`\b__import__\s*\(`,
		},
	},
	"deserialization": {
		Name:        "deserialization",
		Description: "Insecure deserialization sinks (CWE-502)",
		Patterns: []string{
			`pickle\.loads?\b`,
			`cPickle\.loads?\b`,
			`_pickle\.loads?\b`,
			// yaml.load (NOT yaml.safe_load). Negative lookahead is not
			// supported by RE2; we anchor with \b and rely on the
			// safe_load guard pattern to mark it safe when present.
			`yaml\.load\b`,
			`jsonpickle\.(decode|loads)\b`,
			`marshal\.loads?\b`,
			`shelve\.open\b`,
		},
	},
	"xxe": {
		Name:        "xxe",
		Description: "XML external entity / XML parser sinks (CWE-611)",
		Patterns: []string{
			`xml\.etree\.ElementTree\.(parse|fromstring|XML|iterparse)\b`,
			`etree\.(fromstring|parse|XML|iterparse)\b`,
			`lxml\.etree\.(fromstring|parse|XML|iterparse)\b`,
			`xml\.sax\.make_parser\b`,
			`xml\.dom\.minidom\.parseString\b`,
			`xml\.dom\.minidom\.parse\b`,
			`xml\.dom\.pulldom\.parseString\b`,
			`xmltodict\.parse\b`,
		},
	},
	"xpath": {
		Name:        "xpath",
		Description: "XPath injection sinks (CWE-643)",
		Patterns: []string{
			`lxml\.etree\.XPath\b`,
			`etree\.XPath\b`,
			`elementpath\.select\b`,
			`\.xpath\s*\(`,
		},
	},
	"ldap": {
		Name:        "ldap",
		Description: "LDAP injection sinks (CWE-90)",
		Patterns: []string{
			`ldap[23]?\.(search|search_s|search_ext|search_ext_s)\b`,
			`ldap[23]?\.simple_bind(_s)?\b`,
			`\.search_s\s*\(`,
			`\.simple_bind_s\s*\(`,
		},
	},
	"redirect": {
		Name:        "redirect",
		Description: "Open-redirect sinks (CWE-601)",
		Patterns: []string{
			`flask\.redirect\b`,
			`werkzeug\.utils\.redirect\b`,
			`\bredirect\s*\(`,
			`HttpResponseRedirect\s*\(`,
		},
	},
	"template": {
		Name:        "template",
		Description: "Server-side template injection sinks (CWE-1336 / CWE-94)",
		Patterns: []string{
			`render_template_string\b`,
			`jinja2\.Template\b`,
			`Template\s*\(\s*["']`, // Template("user-controlled") shape
			`Environment\(\s*\)\.from_string\b`,
			`Markup\s*\(`,
		},
	},
	"xss": {
		Name:        "xss",
		Description: "Cross-site scripting sinks (CWE-79)",
		Patterns: []string{
			`render_template_string\b`,
			`Markup\s*\(`,
			`\|safe\b`,
			`dangerouslySetInnerHTML\b`,
		},
	},
	"pathtrav": {
		Name:        "pathtrav",
		Description: "Path traversal sinks (CWE-22). Opt-in: includes bare open() which is noisy.",
		Patterns: []string{
			`codecs\.open\s*\(`,
			`io\.open\s*\(`,
			`\bopen\s*\(`,
			`send_from_directory\s*\(`,
			`send_file\s*\(`,
			`os\.path\.join\s*\(`,
			`pathlib\.Path\s*\(`,
		},
	},
}

// defaultSinkClasses is the set of classes used when the user supplies
// neither `--sink` nor `--sink-class`. We deliberately omit `pathtrav`
// (bare open()) from the default mix because it generates too many hits
// on a typical project; users opt in via `--sink-class pathtrav`.
var defaultSinkClasses = []string{
	"sqli",
	"cmdi",
	"codeexec",
	"deserialization",
	"xxe",
	"xpath",
	"ldap",
	"redirect",
	"template",
	"xss",
}

// ListSinkClasses returns all known sink classes sorted by name. Callers
// (e.g. a future `--list-sink-classes` CLI flag) can use this to surface
// the catalog without reaching into package internals.
func ListSinkClasses() []SinkClass {
	names := make([]string, 0, len(sinkClasses))
	for n := range sinkClasses {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]SinkClass, 0, len(names))
	for _, n := range names {
		out = append(out, sinkClasses[n])
	}
	return out
}

// SinkClassPattern returns the combined regex (alternation) for a named
// sink class, or "" if the name is unknown.
func SinkClassPattern(name string) string {
	c, ok := sinkClasses[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return ""
	}
	return strings.Join(c.Patterns, "|")
}

// BuildSinkPatternFromClasses joins the requested classes' patterns into a
// single regex alternation. Unknown class names are returned as the second
// result so the caller can surface them. If `classes` is empty, the default
// class set is used.
func BuildSinkPatternFromClasses(classes []string) (string, []string) {
	if len(classes) == 0 {
		classes = defaultSinkClasses
	}
	var parts []string
	var unknown []string
	seen := make(map[string]bool)
	for _, raw := range classes {
		// Accept comma-separated input as well as repeated flags.
		for _, name := range strings.Split(raw, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			c, ok := sinkClasses[name]
			if !ok {
				unknown = append(unknown, name)
				continue
			}
			for _, p := range c.Patterns {
				if seen[p] {
					continue
				}
				seen[p] = true
				parts = append(parts, p)
			}
		}
	}
	return strings.Join(parts, "|"), unknown
}

// DefaultSinkPattern returns the combined regex alternation for the
// out-of-the-box default sink set. Useful for CLI --help text and for
// callers that want the same default the library uses.
func DefaultSinkPattern() string {
	pat, _ := BuildSinkPatternFromClasses(nil)
	return pat
}

// DefaultSinkClasses returns the names of classes included in the default
// sink set (i.e. when neither --sink nor --sink-class is supplied).
func DefaultSinkClasses() []string {
	out := make([]string, len(defaultSinkClasses))
	copy(out, defaultSinkClasses)
	return out
}
