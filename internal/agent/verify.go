package agent

import (
	"time"

	"github.com/ihavespoons/zrok/internal/memory"
)

// MemoryStoreReader is the subset of memory.Store needed for verification.
// Defined as an interface for testability.
type MemoryStoreReader interface {
	ReadByName(name string) (*memory.Memory, error)
}

// MemoryStatus represents the verification status of a single expected memory.
type MemoryStatus struct {
	Name      string    `json:"name"`
	Present   bool      `json:"present"`
	Type      string    `json:"type,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// AgentVerification represents the result of verifying one agent's context_memories.
type AgentVerification struct {
	Agent    string         `json:"agent"`
	Phase    string         `json:"phase"`
	Expected int            `json:"expected"`
	Present  int            `json:"present"`
	Missing  int            `json:"missing"`
	Memories []MemoryStatus `json:"memories"`
	Pass     bool           `json:"pass"`
}

// AggregateVerification is the result for a `--all` run across multiple agents.
type AggregateVerification struct {
	Agents       []AgentVerification `json:"agents"`
	TotalAgents  int                 `json:"total_agents"`
	PassingCount int                 `json:"passing"`
	FailingCount int                 `json:"failing"`
	Pass         bool                `json:"pass"`
}

// VerifyAgentMemories checks that every entry in cfg.ContextMemories is present
// in the given memory store. Returns a structured report.
func VerifyAgentMemories(cfg *AgentConfig, store MemoryStoreReader) *AgentVerification {
	report := &AgentVerification{
		Agent:    cfg.Name,
		Phase:    string(cfg.Phase),
		Expected: len(cfg.ContextMemories),
		Memories: make([]MemoryStatus, 0, len(cfg.ContextMemories)),
	}

	for _, name := range cfg.ContextMemories {
		status := MemoryStatus{Name: name}
		mem, err := store.ReadByName(name)
		if err == nil && mem != nil {
			status.Present = true
			status.Type = string(mem.Type)
			status.UpdatedAt = mem.UpdatedAt
			report.Present++
		} else {
			report.Missing++
		}
		report.Memories = append(report.Memories, status)
	}

	report.Pass = report.Missing == 0
	return report
}

// VerifyAnalysisAgents runs VerifyAgentMemories against every analysis-phase
// agent returned by the manager's List().
func VerifyAnalysisAgents(manager *ConfigManager, store MemoryStoreReader) (*AggregateVerification, error) {
	list, err := manager.List()
	if err != nil {
		return nil, err
	}

	agg := &AggregateVerification{}
	for i := range list.Agents {
		cfg := list.Agents[i]
		if cfg.Phase != PhaseAnalysis {
			continue
		}
		rpt := VerifyAgentMemories(&cfg, store)
		agg.Agents = append(agg.Agents, *rpt)
		agg.TotalAgents++
		if rpt.Pass {
			agg.PassingCount++
		} else {
			agg.FailingCount++
		}
	}

	agg.Pass = agg.FailingCount == 0
	return agg, nil
}
