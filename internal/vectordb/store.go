package vectordb

import (
	"github.com/ihavespoons/zrok/internal/chunk"
)

// Filter represents filtering options for vector search
type Filter struct {
	// Files filters by file paths (glob patterns supported)
	Files []string
	// Types filters by chunk types
	Types []chunk.ChunkType
	// Languages filters by programming language
	Languages []string
	// MinScore filters results below this similarity score
	MinScore float32
}

// SearchResult represents a single search result
type SearchResult struct {
	// Chunk is the matched code chunk
	Chunk *chunk.Chunk
	// Score is the similarity score (0-1, higher is more similar)
	Score float32
	// Distance is the vector distance (lower is more similar)
	Distance float32
}

// SearchResults contains multiple search results
type SearchResults struct {
	Results []*SearchResult
	Total   int
	Query   string
}

// Store is the interface for vector storage backends
type Store interface {
	// Insert adds a chunk with its embedding to the store
	Insert(chunk *chunk.Chunk, embedding []float32) error

	// InsertBatch adds multiple chunks with their embeddings
	InsertBatch(chunks []*chunk.Chunk, embeddings [][]float32) error

	// Search finds the k most similar chunks to the query embedding
	Search(query []float32, k int, filter *Filter) (*SearchResults, error)

	// Update updates an existing chunk's embedding
	Update(chunk *chunk.Chunk, embedding []float32) error

	// Delete removes a chunk by ID
	Delete(id string) error

	// DeleteByFile removes all chunks for a file
	DeleteByFile(file string) error

	// Get retrieves a chunk by ID
	Get(id string) (*chunk.Chunk, error)

	// GetByFile retrieves all chunks for a file
	GetByFile(file string) ([]*chunk.Chunk, error)

	// Count returns the total number of chunks
	Count() (int, error)

	// CountByFile returns the number of chunks for a file
	CountByFile(file string) (int, error)

	// Files returns all indexed file paths
	Files() ([]string, error)

	// Clear removes all data from the store
	Clear() error

	// Close closes the store and releases resources
	Close() error
}

// StoreConfig contains configuration for the vector store
type StoreConfig struct {
	// Path is the directory for store data
	Path string
	// Dimension is the embedding dimension
	Dimension int
	// MaxElements is the maximum number of elements (for HNSW)
	MaxElements int
	// M is the HNSW construction parameter (number of connections)
	M int
	// EfConstruction is the HNSW construction parameter
	EfConstruction int
	// EfSearch is the HNSW search parameter
	EfSearch int
}

// DefaultStoreConfig returns default configuration
func DefaultStoreConfig(path string, dimension int) *StoreConfig {
	return &StoreConfig{
		Path:           path,
		Dimension:      dimension,
		MaxElements:    100000,
		M:              16,
		EfConstruction: 200,
		EfSearch:       50,
	}
}
