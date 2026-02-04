package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ChunkType represents the type of code chunk
type ChunkType string

const (
	// ChunkFunction represents a function definition
	ChunkFunction ChunkType = "function"
	// ChunkMethod represents a method definition
	ChunkMethod ChunkType = "method"
	// ChunkClass represents a class definition
	ChunkClass ChunkType = "class"
	// ChunkStruct represents a struct definition
	ChunkStruct ChunkType = "struct"
	// ChunkInterface represents an interface definition
	ChunkInterface ChunkType = "interface"
	// ChunkModule represents a module/namespace
	ChunkModule ChunkType = "module"
	// ChunkEnum represents an enumeration
	ChunkEnum ChunkType = "enum"
	// ChunkConstant represents a constant block
	ChunkConstant ChunkType = "constant"
	// ChunkVariable represents a variable block
	ChunkVariable ChunkType = "variable"
	// ChunkBlock represents a generic code block
	ChunkBlock ChunkType = "block"
)

// ValidChunkTypes contains all valid chunk types
var ValidChunkTypes = []ChunkType{
	ChunkFunction,
	ChunkMethod,
	ChunkClass,
	ChunkStruct,
	ChunkInterface,
	ChunkModule,
	ChunkEnum,
	ChunkConstant,
	ChunkVariable,
	ChunkBlock,
}

// IsValidChunkType checks if a chunk type is valid
func IsValidChunkType(t ChunkType) bool {
	for _, valid := range ValidChunkTypes {
		if t == valid {
			return true
		}
	}
	return false
}

// Chunk represents a semantic code chunk extracted from source files
type Chunk struct {
	// ID is a unique identifier (hash of content + file path)
	ID string `json:"id" yaml:"id"`
	// File is the relative file path
	File string `json:"file" yaml:"file"`
	// Language is the programming language
	Language string `json:"language" yaml:"language"`
	// Type is the chunk type (function, method, class, etc.)
	Type ChunkType `json:"type" yaml:"type"`
	// Name is the symbol name
	Name string `json:"name" yaml:"name"`
	// Content is the source code
	Content string `json:"content" yaml:"content"`
	// StartLine is the 1-indexed start line
	StartLine int `json:"start_line" yaml:"start_line"`
	// EndLine is the 1-indexed end line
	EndLine int `json:"end_line" yaml:"end_line"`
	// ParentID is the ID of the parent chunk (for nested symbols)
	ParentID string `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`
	// ParentName is the name of the parent symbol
	ParentName string `json:"parent_name,omitempty" yaml:"parent_name,omitempty"`
	// Signature is the function/method signature
	Signature string `json:"signature,omitempty" yaml:"signature,omitempty"`
	// ContentHash is for change detection
	ContentHash string `json:"content_hash" yaml:"content_hash"`
}

// ChunkList contains a list of chunks with metadata
type ChunkList struct {
	Chunks []*Chunk `json:"chunks" yaml:"chunks"`
	File   string   `json:"file,omitempty" yaml:"file,omitempty"`
	Total  int      `json:"total" yaml:"total"`
}

// GenerateID generates a unique ID for a chunk based on file path and content
func GenerateID(file, content string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", file, content)))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes (32 hex chars)
}

// GenerateContentHash generates a hash of the content for change detection
func GenerateContentHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes (16 hex chars)
}

// NewChunk creates a new chunk with computed ID and content hash
func NewChunk(file, language string, chunkType ChunkType, name, content string, startLine, endLine int) *Chunk {
	c := &Chunk{
		File:        file,
		Language:    language,
		Type:        chunkType,
		Name:        name,
		Content:     content,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: GenerateContentHash(content),
	}
	c.ID = GenerateID(file, content)
	return c
}

// LineCount returns the number of lines in the chunk
func (c *Chunk) LineCount() int {
	return c.EndLine - c.StartLine + 1
}

// String returns a human-readable representation of the chunk
func (c *Chunk) String() string {
	return fmt.Sprintf("%s:%s %s (%s) [%d-%d]", c.File, c.Name, c.Type, c.Language, c.StartLine, c.EndLine)
}

// SetParent sets the parent chunk information
func (c *Chunk) SetParent(parentID, parentName string) {
	c.ParentID = parentID
	c.ParentName = parentName
}

// FilterByType filters chunks by type
func FilterByType(chunks []*Chunk, chunkType ChunkType) []*Chunk {
	var result []*Chunk
	for _, c := range chunks {
		if c.Type == chunkType {
			result = append(result, c)
		}
	}
	return result
}

// FilterByFile filters chunks by file path
func FilterByFile(chunks []*Chunk, file string) []*Chunk {
	var result []*Chunk
	for _, c := range chunks {
		if c.File == file {
			result = append(result, c)
		}
	}
	return result
}

// FilterByLanguage filters chunks by language
func FilterByLanguage(chunks []*Chunk, language string) []*Chunk {
	var result []*Chunk
	for _, c := range chunks {
		if c.Language == language {
			result = append(result, c)
		}
	}
	return result
}
