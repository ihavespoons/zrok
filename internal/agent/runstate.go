package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ihavespoons/quokka/internal/project"
)

// RunStateFile is the JSON file where per-agent timing data is persisted.
const RunStateFile = "run-state.json"

// AgentTiming represents the recorded timing for a single agent invocation.
type AgentTiming struct {
	Name            string    `json:"name"`
	Phase           string    `json:"phase,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	EndedAt         time.Time `json:"ended_at,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
	FindingsCreated int       `json:"findings_created,omitempty"`
	MemoriesCreated int       `json:"memories_created,omitempty"`
}

// RunState is the on-disk representation of per-agent execution timings.
type RunState struct {
	Agents map[string]*AgentTiming `json:"agents"`
}

// runStatePath returns the path to the run-state file for the given project.
func runStatePath(p *project.Project) string {
	return filepath.Join(p.GetQuokkaPath(), RunStateFile)
}

// LoadRunState reads the run-state file. Missing file is not an error;
// returns an empty RunState.
func LoadRunState(p *project.Project) (*RunState, error) {
	path := runStatePath(p)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &RunState{Agents: map[string]*AgentTiming{}}, nil
		}
		return nil, fmt.Errorf("reading run-state: %w", err)
	}

	var rs RunState
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parsing run-state: %w", err)
	}
	if rs.Agents == nil {
		rs.Agents = map[string]*AgentTiming{}
	}
	return &rs, nil
}

// SaveRunState writes the run-state file.
func SaveRunState(p *project.Project, rs *RunState) error {
	path := runStatePath(p)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating run-state directory: %w", err)
	}
	data, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling run-state: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing run-state: %w", err)
	}
	return nil
}

// RecordStart records the start time for an agent invocation.
func RecordStart(p *project.Project, name, phase string) error {
	rs, err := LoadRunState(p)
	if err != nil {
		return err
	}
	t := rs.Agents[name]
	if t == nil {
		t = &AgentTiming{Name: name}
		rs.Agents[name] = t
	}
	t.Phase = phase
	t.StartedAt = time.Now().UTC()
	return SaveRunState(p, rs)
}

// RecordEnd records the end time (and optional metadata) for an agent invocation.
func RecordEnd(p *project.Project, name, phase string, findingsCreated, memoriesCreated int) error {
	rs, err := LoadRunState(p)
	if err != nil {
		return err
	}
	t := rs.Agents[name]
	if t == nil {
		t = &AgentTiming{Name: name}
		rs.Agents[name] = t
	}
	if phase != "" {
		t.Phase = phase
	}
	t.EndedAt = time.Now().UTC()
	if !t.StartedAt.IsZero() {
		t.DurationMS = t.EndedAt.Sub(t.StartedAt).Milliseconds()
	}
	if findingsCreated > 0 {
		t.FindingsCreated = findingsCreated
	}
	if memoriesCreated > 0 {
		t.MemoriesCreated = memoriesCreated
	}
	return SaveRunState(p, rs)
}
