package agent

import "strings"

// Tool exemplars used in agent prompts.
//
// Why this file exists: weaker / cheaper LLM models reliably copy concrete
// command examples but routinely hallucinate field names, mis-order flags, or
// omit required arguments when given only prose like "call zrok finding create
// with all required fields". Centralising one canonical example per command
// keeps the orchestrator prompt, subagent prompts, and SKILL.md aligned and
// gives small models a copy-paste target.
//
// Convention: a single fixture CWE (CWE-89 SQL injection) is used across all
// finding examples regardless of which agent will render them. Per-agent
// contextualised exemplars (CWE-78 for injection-agent, CWE-352 for
// security-agent, etc.) would be more "realistic" but would multiply the
// surface that needs to stay in sync. Pattern-matching across one CWE is
// sufficient.

// agentNameOrPlaceholder returns agentName, or the literal placeholder
// `<your-agent-name>` when the caller doesn't have a specific agent in scope
// (e.g. the orchestrator prompt, SKILL.md).
func agentNameOrPlaceholder(agentName string) string {
	if agentName == "" {
		return "<your-agent-name>"
	}
	return agentName
}

// FindingCreateExample returns a complete shell invocation of
// `zrok finding create` in flag mode with every required field populated.
// Pass agentName="" when rendering for prompts that aren't scoped to a
// specific agent (orchestrator, SKILL.md).
func FindingCreateExample(agentName string) string {
	name := agentNameOrPlaceholder(agentName)
	return strings.TrimSpace(`
zrok finding create \
  --title "SQL injection in user lookup" \
  --severity high \
  --confidence high \
  --cwe CWE-89 \
  --file src/api/users.py \
  --line 42 \
  --description "User-supplied id is concatenated into the SQL query without parameterisation." \
  --remediation "Use parameterised queries: cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))" \
  --created-by ` + name + ` \
  --tag injection:sql
`)
}

// FindingCreateYAMLExample returns a YAML body suitable for piping into
// `zrok finding create -` (stdin mode) or writing to a file.
func FindingCreateYAMLExample() string {
	return strings.TrimSpace(`
title: "SQL injection in user lookup"
severity: high
confidence: high
cwe: CWE-89
location:
  file: src/api/users.py
  line_start: 42
description: "User-supplied id is concatenated into the SQL query without parameterisation."
remediation: "Use parameterised queries"
tags:
  - injection:sql
`)
}

// FindingListExample returns the common usage of `zrok finding list` agents
// use to verify their own filings.
func FindingListExample(agentName string) string {
	name := agentNameOrPlaceholder(agentName)
	return "zrok finding list --created-by " + name + " --json"
}

// FindingUpdateNoteExample returns an invocation of `zrok finding update`
// adding a cross-agent note to an existing finding.
func FindingUpdateNoteExample(agentName string) string {
	name := agentNameOrPlaceholder(agentName)
	return strings.TrimSpace(`
zrok finding update FIND-001 \
  --note "Same file also has an auth bypass at line 87 — see FIND-002." \
  --note-author ` + name + `
`)
}

// RuleAddExample returns an invocation of `zrok rule add` reading an
// opengrep YAML rule from stdin.
func RuleAddExample(agentName string) string {
	name := agentNameOrPlaceholder(agentName)
	return strings.TrimSpace(`
cat <<'EOF' | zrok rule add no-shell-true \
  --created-by agent:` + name + ` \
  --reasoning "subprocess.run with shell=True keeps causing CWE-78 findings; codify a pattern."
rules:
  - id: no-shell-true
    message: "subprocess.run with shell=True is command injection risk"
    pattern: "subprocess.run($X, shell=True, ...)"
    languages: [python]
    severity: WARNING
EOF
`)
}

// ExceptionAddFingerprintExample returns a `zrok exception add` invocation
// suppressing a single finding by its stable fingerprint.
func ExceptionAddFingerprintExample(agentName string) string {
	name := agentNameOrPlaceholder(agentName)
	return strings.TrimSpace(`
zrok exception add \
  --fingerprint a1b2c3d4e5f6 \
  --reason "Test fixture intentionally vulnerable for the eval harness." \
  --expires 2026-12-31 \
  --approved-by agent:` + name + `
`)
}

// ExceptionAddPathGlobExample returns a `zrok exception add` invocation
// suppressing every finding of a CWE under a path glob.
func ExceptionAddPathGlobExample(agentName string) string {
	name := agentNameOrPlaceholder(agentName)
	return strings.TrimSpace(`
zrok exception add \
  --path-glob "tests/**/*.py" \
  --cwe CWE-89 \
  --reason "Test fixtures contain intentional SQLi for repro; not shipped." \
  --expires 2026-12-31 \
  --approved-by agent:` + name + `
`)
}

// TaskToolExample returns the canonical shape of the opencode/Claude-Code
// Task tool call. Both runtimes accept the same JSON shape via their tool API
// even though their CLI flags differ. Including this in prompts that direct
// the model to dispatch subagents prevented the Gemma SchemaError class of
// failure where models omitted the required `description` field.
func TaskToolExample() string {
	return strings.TrimSpace(`
Task({
  "subagent_type": "injection-agent",
  "description": "Review user-input flow",
  "prompt": "Audit src/api/users.py for SQL injection in the user-lookup path. Trace the request -> query construction -> cursor.execute call. File findings via zrok finding create."
})
`)
}
