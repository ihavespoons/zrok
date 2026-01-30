package memory

import (
	"time"
)

// MemoryType represents the type of memory
type MemoryType string

const (
	MemoryTypeContext  MemoryType = "context"
	MemoryTypePattern  MemoryType = "pattern"
	MemoryTypeStack    MemoryType = "stack"
)

// ValidMemoryTypes contains all valid memory types
var ValidMemoryTypes = []MemoryType{
	MemoryTypeContext,
	MemoryTypePattern,
	MemoryTypeStack,
}

// Memory represents a stored memory item
type Memory struct {
	Name        string     `yaml:"name" json:"name"`
	Type        MemoryType `yaml:"type" json:"type"`
	Content     string     `yaml:"content" json:"content"`
	Description string     `yaml:"description,omitempty" json:"description,omitempty"`
	Tags        []string   `yaml:"tags,omitempty" json:"tags,omitempty"`
	CreatedAt   time.Time  `yaml:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `yaml:"updated_at" json:"updated_at"`
	CreatedBy   string     `yaml:"created_by,omitempty" json:"created_by,omitempty"`
}

// MemoryList represents a list of memories with metadata
type MemoryList struct {
	Memories []Memory `json:"memories"`
	Total    int      `json:"total"`
	Type     string   `json:"type,omitempty"`
}

// IsValidType checks if a memory type is valid
func IsValidType(t MemoryType) bool {
	for _, valid := range ValidMemoryTypes {
		if t == valid {
			return true
		}
	}
	return false
}

// ParseMemoryType parses a string into a MemoryType
func ParseMemoryType(s string) (MemoryType, bool) {
	t := MemoryType(s)
	return t, IsValidType(t)
}

// GetTypeDir returns the directory name for a memory type
func GetTypeDir(t MemoryType) string {
	switch t {
	case MemoryTypeContext:
		return "context"
	case MemoryTypePattern:
		return "patterns"
	case MemoryTypeStack:
		return "stack"
	default:
		return "context"
	}
}
