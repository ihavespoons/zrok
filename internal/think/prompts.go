// Package think provides parametric analyses over the project state
// (findings, memories, agent configs, source code). Each verb has its own
// implementation file: dataflow.go, validate.go, hypothesis.go,
// collected.go, adherence.go, done.go, next.go.
//
// This file defines the shared result type and verb constants. The legacy
// prompt-template machinery has been removed; verbs now compute structured
// reports algorithmically.
package think

// ThinkingVerb names a thinking analysis.
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

// ThinkingResult is what each verb returns.
//
// Data carries the structured analysis result (intended for --json mode).
// Prompt is the human-readable text rendering (used by default).
// Context is an optional free-text echo of caller input, kept for
// backward compatibility with the previous prompt-template shape.
type ThinkingResult struct {
	Verb    ThinkingVerb `json:"verb"`
	Prompt  string       `json:"prompt"`
	Context string       `json:"context,omitempty"`
	Data    interface{}  `json:"data,omitempty"`
}

// ValidVerbs returns all valid thinking verbs.
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
