// Package runner implements the deterministic dispatcher consumed by
// `quokka review pr run`. It takes a DispatchPlan (emitted by `quokka review pr
// setup`) and shells out to opencode or claude to invoke each subagent.
// Replaces the orchestrator-LLM pattern for callers that want predictable,
// model-agnostic dispatch. The orchestrator-LLM pattern remains supported
// for callers who prefer emergent / adaptive flow.
package runner

// DispatchPlan is the static execution schedule consumed by
// `quokka review pr run`. Walked phase-by-phase, top to bottom.
type DispatchPlan struct {
	Profile string          `json:"profile"`
	Phases  []DispatchPhase `json:"phases"`
}

// DispatchPhase is one step in a DispatchPlan. The Mode field determines
// how Agents are invoked:
//
//   - "parallel":       all Agents dispatched concurrently
//   - "sequential":     Agents dispatched one at a time, in order
//   - "gated":          dispatched only if the Gate shell command produces
//                       non-empty JSON output (used to skip SAST triage
//                       when no opengrep findings exist)
//   - "dynamic-fanout": run DynamicSource, parse JSON list of items, invoke
//                       DynamicAgent once per item with the item id injected
//                       into the user-turn prompt
type DispatchPhase struct {
	Name          string   `json:"name"`
	Mode          string   `json:"mode"`
	Agents        []string `json:"agents,omitempty"`
	Gate          string   `json:"gate,omitempty"`
	DynamicSource string   `json:"dynamic_source,omitempty"`
	DynamicAgent  string   `json:"dynamic_agent,omitempty"`
}

// Mode constants — kept as strings rather than typed enum for ease of
// JSON round-tripping with external drivers.
const (
	ModeParallel       = "parallel"
	ModeSequential     = "sequential"
	ModeGated          = "gated"
	ModeDynamicFanout  = "dynamic-fanout"
)
