package think

import (
	"fmt"
	"strings"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/project"
)

// ThinkingVerb represents a type of structured thinking
type ThinkingVerb string

const (
	VerbCollected  ThinkingVerb = "collected"
	VerbAdherence  ThinkingVerb = "adherence"
	VerbDone       ThinkingVerb = "done"
	VerbNext       ThinkingVerb = "next"
	VerbHypothesis ThinkingVerb = "hypothesis"
	VerbValidate   ThinkingVerb = "validate"
)

// ThinkingResult contains the output of a thinking operation
type ThinkingResult struct {
	Verb    ThinkingVerb `json:"verb"`
	Prompt  string       `json:"prompt"`
	Context string       `json:"context,omitempty"`
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
	prompt := `## Evaluate Collected Information

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

	return &ThinkingResult{
		Verb:    VerbCollected,
		Prompt:  prompt,
		Context: context,
	}
}

// Adherence generates a prompt to check task adherence
func (t *Thinker) Adherence(task, currentState string) *ThinkingResult {
	prompt := fmt.Sprintf(`## Check Task Adherence

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

	return &ThinkingResult{
		Verb:   VerbAdherence,
		Prompt: prompt,
	}
}

// Done generates a prompt to assess if a task is complete
func (t *Thinker) Done(task, findings string) *ThinkingResult {
	prompt := fmt.Sprintf(`## Task Completion Assessment

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

	return &ThinkingResult{
		Verb:   VerbDone,
		Prompt: prompt,
	}
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
			techContext = fmt.Sprintf("\n### Tech Stack:\n%s\n", strings.Join(techs, ", "))
		}
	}

	prompt := fmt.Sprintf(`## Suggest Next Steps

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
[Explain why these steps are recommended]`, currentState, techContext, findingsSummary)

	return &ThinkingResult{
		Verb:   VerbNext,
		Prompt: prompt,
	}
}

// Hypothesis generates security hypotheses based on context
func (t *Thinker) Hypothesis(context string) *ThinkingResult {
	var techContext string
	if t.project != nil && t.project.Config != nil {
		stack := t.project.Config.TechStack
		if len(stack.Languages) > 0 || len(stack.Databases) > 0 {
			techContext = "\n### Known Tech Stack:\n"
			for _, lang := range stack.Languages {
				techContext += fmt.Sprintf("- %s", lang.Name)
				if len(lang.Frameworks) > 0 {
					techContext += fmt.Sprintf(" (%s)", strings.Join(lang.Frameworks, ", "))
				}
				techContext += "\n"
			}
			if len(stack.Databases) > 0 {
				techContext += fmt.Sprintf("- Databases: %s\n", strings.Join(stack.Databases, ", "))
			}
			if len(stack.Auth) > 0 {
				techContext += fmt.Sprintf("- Auth: %s\n", strings.Join(stack.Auth, ", "))
			}
		}
	}

	prompt := fmt.Sprintf(`## Generate Security Hypotheses

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
[Order hypotheses by likelihood and impact]`, context, techContext)

	return &ThinkingResult{
		Verb:    VerbHypothesis,
		Prompt:  prompt,
		Context: context,
	}
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

	prompt := fmt.Sprintf(`## Validate Security Finding

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
- **Recommended Status**: [open/confirmed/false_positive]`, findingDesc.String())

	return &ThinkingResult{
		Verb:   VerbValidate,
		Prompt: prompt,
	}
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
	}
}
