package think

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
)

//go:embed configs/prompts/*.tmpl
var embeddedPrompts embed.FS

// ThinkingVerb represents a type of structured thinking
type ThinkingVerb string

const (
	VerbCollected  ThinkingVerb = "collected"
	VerbAdherence  ThinkingVerb = "adherence"
	VerbDone       ThinkingVerb = "done"
	VerbNext       ThinkingVerb = "next"
	VerbHypothesis ThinkingVerb = "hypothesis"
	VerbValidate   ThinkingVerb = "validate"
	VerbDataflow   ThinkingVerb = "dataflow"
)

// ThinkingResult contains the output of a thinking operation
type ThinkingResult struct {
	Verb    ThinkingVerb `json:"verb"`
	Prompt  string       `json:"prompt"`
	Context string       `json:"context,omitempty"`
}

// templateCache holds parsed templates
var (
	templates     *template.Template
	templatesOnce sync.Once
	templatesErr  error
)

// loadTemplates loads all templates from embedded files
func loadTemplates() (*template.Template, error) {
	templatesOnce.Do(func() {
		templates, templatesErr = template.ParseFS(embeddedPrompts, "configs/prompts/*.tmpl")
	})
	return templates, templatesErr
}

// executeTemplate executes a named template with the given data
func executeTemplate(name string, data interface{}) (string, error) {
	tmpl, err := loadTemplates()
	if err != nil {
		return "", fmt.Errorf("failed to load templates: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", name, err)
	}
	return buf.String(), nil
}

// Thinker generates structured thinking prompts
type Thinker struct {
	project *project.Project
}

// NewThinker creates a new thinker for a project
func NewThinker(p *project.Project) *Thinker {
	return &Thinker{project: p}
}

// Collected generates a prompt to evaluate collected information
func (t *Thinker) Collected(context string) *ThinkingResult {
	data := map[string]string{
		"Context": context,
	}

	prompt, err := executeTemplate("thinking-collected.tmpl", data)
	if err != nil {
		// Fallback to inline template
		prompt = t.collectedFallback(context)
	}

	return &ThinkingResult{
		Verb:    VerbCollected,
		Prompt:  prompt,
		Context: context,
	}
}

func (t *Thinker) collectedFallback(context string) string {
	return `## Evaluate Collected Information

Review the information gathered so far and assess its quality and completeness.

### Questions to Consider:
1. **Coverage**: Have all relevant areas been explored?
2. **Depth**: Is the understanding sufficient for security analysis?
3. **Gaps**: What information is still missing?
4. **Relevance**: Is the collected information relevant to security?

### Collected Context:
` + context + `

### Assessment Format:
- **Coverage Score**: [1-5]
- **Identified Gaps**: [list any missing information]
- **Key Insights**: [summarize important findings]
- **Recommended Actions**: [what to collect next]`
}

// Adherence generates a prompt to check task adherence
func (t *Thinker) Adherence(task, currentState string) *ThinkingResult {
	data := map[string]string{
		"Task":         task,
		"CurrentState": currentState,
	}

	prompt, err := executeTemplate("thinking-adherence.tmpl", data)
	if err != nil {
		prompt = t.adherenceFallback(task, currentState)
	}

	return &ThinkingResult{
		Verb:   VerbAdherence,
		Prompt: prompt,
	}
}

func (t *Thinker) adherenceFallback(task, currentState string) string {
	return fmt.Sprintf(`## Check Task Adherence

Evaluate whether current activities align with the assigned task.

### Original Task:
%s

### Current State:
%s

### Assessment Questions:
1. **On Track**: Are we still working toward the original goal?
2. **Scope Creep**: Have we drifted into unrelated areas?
3. **Progress**: What percentage of the task is complete?
4. **Blockers**: What is preventing progress?

### Adherence Assessment:
- **Alignment Score**: [1-5]
- **Deviation Description**: [if any]
- **Corrective Actions**: [if needed]
- **Continue/Adjust/Reset**: [recommendation]`, task, currentState)
}

// Done generates a prompt to assess if a task is complete
func (t *Thinker) Done(task, findings string) *ThinkingResult {
	data := map[string]string{
		"Task":     task,
		"Findings": findings,
	}

	prompt, err := executeTemplate("thinking-done.tmpl", data)
	if err != nil {
		prompt = t.doneFallback(task, findings)
	}

	return &ThinkingResult{
		Verb:   VerbDone,
		Prompt: prompt,
	}
}

func (t *Thinker) doneFallback(task, findings string) string {
	return fmt.Sprintf(`## Task Completion Assessment

Determine if the security analysis task is complete.

### Original Task:
%s

### Findings Summary:
%s

### Completion Criteria:
1. **Coverage**: All specified areas have been analyzed
2. **Depth**: Analysis reached appropriate depth
3. **Documentation**: Findings are properly documented
4. **Validation**: Findings have been validated where possible

### Completion Assessment:
- **Complete**: [Yes/No]
- **Completion Percentage**: [0-100%%]
- **Outstanding Items**: [list any remaining work]
- **Quality Check**: [findings quality assessment]
- **Recommendation**: [proceed to report / continue analysis]`, task, findings)
}

// Next generates a prompt suggesting next steps
func (t *Thinker) Next(currentState, findingsSummary string) *ThinkingResult {
	var techContext string
	if t.project != nil && t.project.Config != nil {
		var techs []string
		for _, lang := range t.project.Config.TechStack.Languages {
			techs = append(techs, lang.Name)
			techs = append(techs, lang.Frameworks...)
		}
		if len(techs) > 0 {
			techContext = strings.Join(techs, ", ")
		}
	}

	data := map[string]string{
		"CurrentState": currentState,
		"TechContext":  techContext,
		"Findings":     findingsSummary,
	}

	prompt, err := executeTemplate("thinking-next.tmpl", data)
	if err != nil {
		prompt = t.nextFallback(currentState, techContext, findingsSummary)
	}

	return &ThinkingResult{
		Verb:   VerbNext,
		Prompt: prompt,
	}
}

func (t *Thinker) nextFallback(currentState, techContext, findingsSummary string) string {
	techSection := ""
	if techContext != "" {
		techSection = fmt.Sprintf("\n### Tech Stack:\n%s\n", techContext)
	}

	return fmt.Sprintf(`## Suggest Next Steps

Based on current progress, recommend the next actions for security analysis.

### Current State:
%s
%s
### Findings So Far:
%s

### Consider:
1. **Unexplored Areas**: What hasn't been analyzed yet?
2. **Deep Dives**: What findings need more investigation?
3. **Attack Vectors**: What attack paths should be explored?
4. **Validation**: What findings need validation?

### Recommended Next Steps:
1. [High Priority Action]
2. [Medium Priority Action]
3. [Low Priority Action]

### Rationale:
[Explain why these steps are recommended]`, currentState, techSection, findingsSummary)
}

// Hypothesis generates security hypotheses based on context
func (t *Thinker) Hypothesis(context string) *ThinkingResult {
	var techContext string
	if t.project != nil && t.project.Config != nil {
		stack := t.project.Config.TechStack
		if len(stack.Languages) > 0 || len(stack.Databases) > 0 {
			var parts []string
			for _, lang := range stack.Languages {
				part := lang.Name
				if len(lang.Frameworks) > 0 {
					part += fmt.Sprintf(" (%s)", strings.Join(lang.Frameworks, ", "))
				}
				parts = append(parts, "- "+part)
			}
			if len(stack.Databases) > 0 {
				parts = append(parts, fmt.Sprintf("- Databases: %s", strings.Join(stack.Databases, ", ")))
			}
			if len(stack.Auth) > 0 {
				parts = append(parts, fmt.Sprintf("- Auth: %s", strings.Join(stack.Auth, ", ")))
			}
			techContext = strings.Join(parts, "\n")
		}
	}

	data := map[string]string{
		"Context":     context,
		"TechContext": techContext,
	}

	prompt, err := executeTemplate("thinking-hypothesis.tmpl", data)
	if err != nil {
		prompt = t.hypothesisFallback(context, techContext)
	}

	return &ThinkingResult{
		Verb:    VerbHypothesis,
		Prompt:  prompt,
		Context: context,
	}
}

func (t *Thinker) hypothesisFallback(context, techContext string) string {
	techSection := ""
	if techContext != "" {
		techSection = fmt.Sprintf("\n### Known Tech Stack:\n%s\n", techContext)
	}

	return fmt.Sprintf(`## Generate Security Hypotheses

Based on the provided context, generate testable security hypotheses.

### Context:
%s
%s
### Hypothesis Framework:

For each hypothesis, consider:
1. **Vulnerability Class**: What type of vulnerability might exist?
2. **Attack Vector**: How could it be exploited?
3. **Impact**: What would be the consequence?
4. **Evidence Needed**: What would confirm/deny this hypothesis?

### Generate Hypotheses:

**Hypothesis 1:**
- Type: [vulnerability class]
- Location: [suspected location]
- Rationale: [why this might be vulnerable]
- Test: [how to verify]

**Hypothesis 2:**
- Type: [vulnerability class]
- Location: [suspected location]
- Rationale: [why this might be vulnerable]
- Test: [how to verify]

**Hypothesis 3:**
- Type: [vulnerability class]
- Location: [suspected location]
- Rationale: [why this might be vulnerable]
- Test: [how to verify]

### Priority Ranking:
[Order hypotheses by likelihood and impact]`, context, techSection)
}

// Validate generates a prompt to validate a finding
func (t *Thinker) Validate(f *finding.Finding) *ThinkingResult {
	var findingDesc strings.Builder
	findingDesc.WriteString(fmt.Sprintf("**ID:** %s\n", f.ID))
	findingDesc.WriteString(fmt.Sprintf("**Title:** %s\n", f.Title))
	findingDesc.WriteString(fmt.Sprintf("**Severity:** %s\n", f.Severity))
	findingDesc.WriteString(fmt.Sprintf("**CWE:** %s\n", f.CWE))
	findingDesc.WriteString(fmt.Sprintf("**Location:** %s:%d\n", f.Location.File, f.Location.LineStart))
	findingDesc.WriteString(fmt.Sprintf("**Description:** %s\n", f.Description))
	if f.Location.Snippet != "" {
		findingDesc.WriteString(fmt.Sprintf("\n**Code:**\n```\n%s\n```\n", f.Location.Snippet))
	}
	if len(f.Evidence) > 0 {
		findingDesc.WriteString("\n**Evidence:**\n")
		for _, ev := range f.Evidence {
			findingDesc.WriteString(fmt.Sprintf("- %s: %s\n", ev.Type, ev.Description))
		}
	}

	data := map[string]string{
		"FindingDetails": findingDesc.String(),
	}

	prompt, err := executeTemplate("thinking-validate.tmpl", data)
	if err != nil {
		prompt = t.validateFallback(findingDesc.String())
	}

	return &ThinkingResult{
		Verb:   VerbValidate,
		Prompt: prompt,
	}
}

func (t *Thinker) validateFallback(findingDesc string) string {
	return fmt.Sprintf(`## Validate Security Finding

Critically evaluate this security finding for accuracy and completeness.

### Finding Details:
%s

### Validation Checklist:

**1. Vulnerability Existence**
- [ ] Is this actually a vulnerability?
- [ ] Could this be a false positive?
- [ ] Is the code reachable?

**2. Severity Assessment**
- [ ] Is the severity rating accurate?
- [ ] What is the realistic impact?
- [ ] Are there mitigating factors?

**3. Evidence Quality**
- [ ] Is the evidence sufficient?
- [ ] Can the issue be reproduced?
- [ ] Is the data flow clear?

**4. Completeness**
- [ ] Is the description clear?
- [ ] Is the remediation actionable?
- [ ] Are there related issues?

### Validation Result:
- **Valid**: [Yes/No/Needs More Evidence]
- **Severity Adjustment**: [if needed]
- **Additional Evidence Needed**: [list]
- **Related Findings**: [if any]
- **Recommended Status**: [open/confirmed/false_positive]`, findingDesc)
}

// Dataflow generates a structured source-to-sink data flow tracing prompt
func (t *Thinker) Dataflow(source, sink, context string) *ThinkingResult {
	data := map[string]string{
		"Source":  source,
		"Sink":    sink,
		"Context": context,
	}

	prompt, err := executeTemplate("thinking-dataflow.tmpl", data)
	if err != nil {
		prompt = t.dataflowFallback(source, sink, context)
	}

	return &ThinkingResult{
		Verb:   VerbDataflow,
		Prompt: prompt,
	}
}

func (t *Thinker) dataflowFallback(source, sink, context string) string {
	contextSection := ""
	if context != "" {
		contextSection = fmt.Sprintf("\n### Additional Context:\n%s\n", context)
	}

	return fmt.Sprintf(`## Data Flow Analysis: Source to Sink

Trace the data flow from source to sink and identify all guards along the path.

### Source (untrusted data entry):
%s

### Sink (security-sensitive operation):
%s
%s
### Tracing Protocol:

**Step 1: Identify the Source**
- Where does the untrusted data originate?
- What is the data type and format?
- Can the attacker fully control this input?

**Step 2: Trace the Path**
For each step along the path, document:
- File and line number
- What transformation occurs
- Does the data type change?
- Is the data stored and retrieved later? (second-order flows)

**Step 3: Identify Guards**
At each step, check for:
- Input validation (type, format, length, range)
- Sanitization (encoding, escaping, filtering)
- Authorization checks (who can trigger this flow?)
- Framework protections (auto-escaping, parameterization)

**Step 4: Evaluate the Sink**
- What security-sensitive operation does the data reach?
- Does the sink have its own protections?
- What is the impact if unguarded data reaches the sink?

### Output Format:

` + "```" + `
SOURCE: [file:line] [description]
  -> STEP: [file:line] [transformation]
  -> GUARD: [file:line] [validation type] [effective: yes/no]
  -> STEP: [file:line] [transformation]
  -> SINK: [file:line] [operation]

VERDICT: [unguarded | partially-guarded | fully-guarded]
CONFIDENCE: [high | medium | low]
REASONING: [why this verdict]
` + "```", source, sink, contextSection)
}

// GetPrompt returns a thinking prompt for the given verb
func (t *Thinker) GetPrompt(verb ThinkingVerb, args ...string) (*ThinkingResult, error) {
	switch verb {
	case VerbCollected:
		context := ""
		if len(args) > 0 {
			context = args[0]
		}
		return t.Collected(context), nil

	case VerbAdherence:
		task := ""
		currentState := ""
		if len(args) > 0 {
			task = args[0]
		}
		if len(args) > 1 {
			currentState = args[1]
		}
		return t.Adherence(task, currentState), nil

	case VerbDone:
		task := ""
		findings := ""
		if len(args) > 0 {
			task = args[0]
		}
		if len(args) > 1 {
			findings = args[1]
		}
		return t.Done(task, findings), nil

	case VerbNext:
		currentState := ""
		findings := ""
		if len(args) > 0 {
			currentState = args[0]
		}
		if len(args) > 1 {
			findings = args[1]
		}
		return t.Next(currentState, findings), nil

	case VerbHypothesis:
		context := ""
		if len(args) > 0 {
			context = args[0]
		}
		return t.Hypothesis(context), nil

	case VerbDataflow:
		source := ""
		sink := ""
		context := ""
		if len(args) > 0 {
			source = args[0]
		}
		if len(args) > 1 {
			sink = args[1]
		}
		if len(args) > 2 {
			context = args[2]
		}
		return t.Dataflow(source, sink, context), nil

	default:
		return nil, fmt.Errorf("unknown thinking verb: %s", verb)
	}
}

// ValidVerbs returns all valid thinking verbs
func ValidVerbs() []ThinkingVerb {
	return []ThinkingVerb{
		VerbCollected,
		VerbAdherence,
		VerbDone,
		VerbNext,
		VerbHypothesis,
		VerbValidate,
		VerbDataflow,
	}
}
