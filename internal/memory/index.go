package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
)

// SearchIndex manages the bleve full-text search index for memories
type SearchIndex struct {
	index bleve.Index
	path  string
	mu    sync.RWMutex
}

// MemoryDocument represents a memory document for indexing
type MemoryDocument struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Content     string   `json:"content"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

// SearchResult represents a search result
type SearchResult struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Score   float64 `json:"score"`
	Snippet string  `json:"snippet,omitempty"`
}

// NewSearchIndex creates or opens a search index at the given path
func NewSearchIndex(basePath string) (*SearchIndex, error) {
	indexPath := filepath.Join(basePath, ".index")

	var index bleve.Index
	var err error

	// Try to open existing index
	index, err = bleve.Open(indexPath)
	if err == bleve.ErrorIndexPathDoesNotExist {
		// Create new index
		index, err = bleve.New(indexPath, buildIndexMapping())
		if err != nil {
			return nil, fmt.Errorf("failed to create search index: %w", err)
		}
	} else if err != nil {
		// Try to recover by deleting and recreating
		_ = os.RemoveAll(indexPath)
		index, err = bleve.New(indexPath, buildIndexMapping())
		if err != nil {
			return nil, fmt.Errorf("failed to create search index: %w", err)
		}
	}

	return &SearchIndex{
		index: index,
		path:  indexPath,
	}, nil
}

// buildIndexMapping creates the bleve index mapping for memories
func buildIndexMapping() mapping.IndexMapping {
	// Text field mapping for full-text search
	textFieldMapping := bleve.NewTextFieldMapping()
	textFieldMapping.Analyzer = "en"

	// Keyword field mapping for exact matches
	keywordFieldMapping := bleve.NewTextFieldMapping()
	keywordFieldMapping.Analyzer = "keyword"

	// Memory document mapping
	memoryMapping := bleve.NewDocumentMapping()
	memoryMapping.AddFieldMappingsAt("name", keywordFieldMapping)
	memoryMapping.AddFieldMappingsAt("type", keywordFieldMapping)
	memoryMapping.AddFieldMappingsAt("content", textFieldMapping)
	memoryMapping.AddFieldMappingsAt("description", textFieldMapping)
	memoryMapping.AddFieldMappingsAt("tags", keywordFieldMapping)

	// Index mapping
	indexMapping := bleve.NewIndexMapping()
	indexMapping.DefaultMapping = memoryMapping
	indexMapping.DefaultAnalyzer = "en"

	return indexMapping
}

// Index indexes a memory document
func (s *SearchIndex) Index(mem *Memory) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc := MemoryDocument{
		Name:        mem.Name,
		Type:        string(mem.Type),
		Content:     mem.Content,
		Description: mem.Description,
		Tags:        mem.Tags,
	}

	// Use name as document ID
	return s.index.Index(mem.Name, doc)
}

// Delete removes a memory from the index
func (s *SearchIndex) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.index.Delete(name)
}

// Search performs a full-text search on the index
func (s *SearchIndex) Search(query string, limit int) ([]SearchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 20
	}

	// Create a match query for full-text search
	matchQuery := bleve.NewMatchQuery(query)
	matchQuery.SetFuzziness(1) // Allow fuzzy matching

	// Create search request
	searchRequest := bleve.NewSearchRequest(matchQuery)
	searchRequest.Size = limit
	searchRequest.Fields = []string{"name", "type", "content", "description"}
	searchRequest.Highlight = bleve.NewHighlight()

	// Execute search
	searchResult, err := s.index.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Convert results
	results := make([]SearchResult, 0, len(searchResult.Hits))
	for _, hit := range searchResult.Hits {
		result := SearchResult{
			Name:  hit.ID,
			Score: hit.Score,
		}

		// Get type from fields
		if typeField, ok := hit.Fields["type"].(string); ok {
			result.Type = typeField
		}

		// Get highlighted snippet
		if len(hit.Fragments) > 0 {
			for _, fragments := range hit.Fragments {
				if len(fragments) > 0 {
					result.Snippet = fragments[0]
					break
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// SearchByType searches within a specific memory type
func (s *SearchIndex) SearchByType(query string, memType MemoryType, limit int) ([]SearchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 20
	}

	// Create query that matches both the text and the type
	textQuery := bleve.NewMatchQuery(query)
	textQuery.SetFuzziness(1)

	typeQuery := bleve.NewTermQuery(string(memType))
	typeQuery.SetField("type")

	// Combine queries
	conjunctionQuery := bleve.NewConjunctionQuery(textQuery, typeQuery)

	// Create search request
	searchRequest := bleve.NewSearchRequest(conjunctionQuery)
	searchRequest.Size = limit
	searchRequest.Fields = []string{"name", "type", "content", "description"}
	searchRequest.Highlight = bleve.NewHighlight()

	// Execute search
	searchResult, err := s.index.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Convert results
	results := make([]SearchResult, 0, len(searchResult.Hits))
	for _, hit := range searchResult.Hits {
		result := SearchResult{
			Name:  hit.ID,
			Score: hit.Score,
			Type:  string(memType),
		}

		// Get highlighted snippet
		if len(hit.Fragments) > 0 {
			for _, fragments := range hit.Fragments {
				if len(fragments) > 0 {
					result.Snippet = fragments[0]
					break
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// Reindex rebuilds the entire index from the given memories
func (s *SearchIndex) Reindex(memories []Memory) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a batch for efficient indexing
	batch := s.index.NewBatch()

	for _, mem := range memories {
		doc := MemoryDocument{
			Name:        mem.Name,
			Type:        string(mem.Type),
			Content:     mem.Content,
			Description: mem.Description,
			Tags:        mem.Tags,
		}
		if err := batch.Index(mem.Name, doc); err != nil {
			return fmt.Errorf("failed to index memory %s: %w", mem.Name, err)
		}
	}

	return s.index.Batch(batch)
}

// Close closes the search index
func (s *SearchIndex) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.index.Close()
}

// DocCount returns the number of documents in the index
func (s *SearchIndex) DocCount() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.index.DocCount()
}
