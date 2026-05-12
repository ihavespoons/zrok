package think

import (
	"regexp"
	"testing"
)

// compileSinkClass compiles a named sink class with case-insensitive matching,
// mirroring AnalyzeDataflow's runtime behavior.
func compileSinkClass(t *testing.T, name string) *regexp.Regexp {
	t.Helper()
	pat := SinkClassPattern(name)
	if pat == "" {
		t.Fatalf("sink class %q resolved to empty pattern", name)
	}
	re, err := regexp.Compile("(?i)" + pat)
	if err != nil {
		t.Fatalf("compile sink class %q: %v", name, err)
	}
	return re
}

// F1 — XSS sink class must match f-string interpolation and .format()
// templates in addition to the legacy Markup/render_template_string/|safe
// hits. The f-string pattern is the one that appears in OWASP BT00096/97;
// the .format pattern matches BT00098.

func TestSinkClassXSS_FStringInterpolation(t *testing.T) {
	re := compileSinkClass(t, "xss")
	cases := map[string]bool{
		`return f'<html>{bar}</html>'`:               true,
		`RESPONSE += f'bar is {bar} done'`:           true,
		`x = f"hello {name}"`:                        true,
		// f-string with no interpolation — no `{` — must not match this rule.
		`label = f'static text'`:                     false,
		// Plain string with `{` but no f-prefix.
		`tpl = '{user}'`:                             false,
	}
	for line, want := range cases {
		got := re.MatchString(line)
		if got != want {
			t.Errorf("xss f-string: line=%q want=%v got=%v", line, want, got)
		}
	}
}

func TestSinkClassXSS_DotFormat(t *testing.T) {
	re := compileSinkClass(t, "xss")
	cases := map[string]bool{
		`RESPONSE += 'bar is {0[bar]}'.format(dict)`: true,
		`out = 'hi {name}'.format(name=x)`:           true,
		// .format on a non-template string (no braces inside the literal)
		// should not match this XSS rule — there's no interpolation site.
		`x = 'plain'.format()`: false,
	}
	for line, want := range cases {
		got := re.MatchString(line)
		if got != want {
			t.Errorf("xss .format: line=%q want=%v got=%v", line, want, got)
		}
	}
}

func TestSinkClassXSS_LegacyPatternsStillMatch(t *testing.T) {
	re := compileSinkClass(t, "xss")
	cases := []string{
		`out = render_template_string(template, bar=user_input)`,
		`return Markup(bar)`,
		`{{ user_input|safe }}`,
		`<div dangerouslySetInnerHTML={__html: x} />`,
	}
	for _, line := range cases {
		if !re.MatchString(line) {
			t.Errorf("xss legacy pattern did not match: %q", line)
		}
	}
}

// F2 — LDAP sink class must match ldap3-style Connection.search/add/modify
// in addition to the legacy ldap2-style module functions.

func TestSinkClassLDAP_Ldap3ConnectionSearch(t *testing.T) {
	re := compileSinkClass(t, "ldap")
	cases := map[string]bool{
		`conn.search(base, filter, attributes=ldap3.ALL_ATTRIBUTES)`:            true,
		`connection.search(search_base=base, search_filter=f"(uid={bar})")`:     true,
		`Connection.search(base, filter)`:                                       true,
		`client.search(base, filter)`:                                           true,
		`conn.add('cn=foo,ou=users', objectClass=['inetOrgPerson'])`:            true,
		`conn.modify('cn=foo', {'mail': [(MODIFY_REPLACE, ['x@y.com'])]})`:      true,
		`conn.simple_bind(user, password)`:                                      true,
		`conn.simple_bind_s(user, password)`:                                    true,
		// Module-level ldap2 calls must continue to match.
		`ldap.search_s(base, scope, filter)`:                                    true,
		`ldap2.search_s(base, scope, filter)`:                                   true,
		`results = ldap3.search(filter)`:                                        true,
		// Non-ldap calls must NOT match.
		`results = db.search(filter)`:                                           false,
		`results = elastic.search(query)`:                                       false,
		`print('hello')`:                                                         false,
	}
	for line, want := range cases {
		got := re.MatchString(line)
		if got != want {
			t.Errorf("ldap: line=%q want=%v got=%v", line, want, got)
		}
	}
}
