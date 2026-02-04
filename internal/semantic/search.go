package semantic

import (
	"context"
	"fmt"
	"time"

	"github.com/ihavespoons/zrok/internal/chunk"
	"github.com/ihavespoons/zrok/internal/embedding"
	"github.com/ihavespoons/zrok/internal/vectordb"
)

// SearchOptions configures semantic search behavior
type SearchOptions struct {
	// Limit is the maximum number of results (default: 10)
	Limit int
	// MultiHop enables multi-hop exploration
	MultiHop bool
	// MaxHops is the maximum iterations for multi-hop (default: 3)
	MaxHops int
	// Threshold is the minimum similarity score (0-1)
	Threshold float32
	// TimeLimit is the maximum search time (default: 5s)
	TimeLimit time.Duration
	// Filter contains file/type filters
	Filter *vectordb.Filter
}

// DefaultSearchOptions returns default search options
func DefaultSearchOptions() *SearchOptions {
	return &SearchOptions{
		Limit:     10,
		MultiHop:  false,
		MaxHops:   3,
		Threshold: 0.0,
		TimeLimit: 5 * time.Second,
	}
}

// SearchResult represents a semantic search result
type SearchResult struct {
	// Chunk is the matched code chunk
	Chunk *chunk.Chunk `json:"chunk"`
	// Score is the similarity score (0-1, higher is more similar)
	Score float32 `json:"score"`
	// Hop is the iteration this result was found in (for multi-hop)
	Hop int `json:"hop,omitempty"`
}

// SearchResults contains search results with metadata
type SearchResults struct {
	// Results are the matched chunks
	Results []*SearchResult `json:"results"`
	// Query is the original query text
	Query string `json:"query"`
	// TotalHops is the number of hops performed
	TotalHops int `json:"total_hops,omitempty"`
	// Duration is how long the search took
	Duration time.Duration `json:"duration"`
}

// Searcher performs semantic searches against the code index
type Searcher struct {
	store    vectordb.Store
	provider embedding.Provider
}

// NewSearcher creates a new semantic searcher
func NewSearcher(store vectordb.Store, provider embedding.Provider) *Searcher {
	return &Searcher{
		store:    store,
		provider: provider,
	}
}

// Search performs a semantic search for the given query
func (s *Searcher) Search(ctx context.Context, query string, opts *SearchOptions) (*SearchResults, error) {
	if opts == nil {
		opts = DefaultSearchOptions()
	}

	startTime := time.Now()

	// Create context with timeout
	if opts.TimeLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.TimeLimit)
		defer cancel()
	}

	// Generate query embedding
	queryEmbedding, err := s.provider.Embed(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to embed query: %w", err)
	}

	var results *SearchResults

	if opts.MultiHop {
		results, err = s.multiHopSearch(ctx, query, queryEmbedding, opts)
	} else {
		results, err = s.singleHopSearch(ctx, query, queryEmbedding, opts)
	}

	if err != nil {
		return nil, err
	}

	results.Duration = time.Since(startTime)
	return results, nil
}

// singleHopSearch performs a simple single-hop semantic search
func (s *Searcher) singleHopSearch(ctx context.Context, query string, queryEmbedding []float32, opts *SearchOptions) (*SearchResults, error) {
	// Search vector store
	storeResults, err := s.store.Search(queryEmbedding, opts.Limit, opts.Filter)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Convert to SearchResults
	results := make([]*SearchResult, 0, len(storeResults.Results))
	for _, r := range storeResults.Results {
		if opts.Threshold > 0 && r.Score < opts.Threshold {
			continue
		}
		results = append(results, &SearchResult{
			Chunk: r.Chunk,
			Score: r.Score,
			Hop:   1,
		})
	}

	return &SearchResults{
		Results:   results,
		Query:     query,
		TotalHops: 1,
	}, nil
}

// multiHopSearch performs iterative multi-hop semantic search
func (s *Searcher) multiHopSearch(ctx context.Context, query string, queryEmbedding []float32, opts *SearchOptions) (*SearchResults, error) {
	mh := NewMultiHop(s.store, s.provider)
	return mh.Search(ctx, query, queryEmbedding, opts)
}

// SearchByFile searches for code similar to a given file's content
func (s *Searcher) SearchByFile(ctx context.Context, filePath string, opts *SearchOptions) (*SearchResults, error) {
	// Get chunks for the file
	chunks, err := s.store.GetByFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file chunks: %w", err)
	}

	if len(chunks) == 0 {
		return &SearchResults{
			Results: []*SearchResult{},
			Query:   filePath,
		}, nil
	}

	// Combine content for embedding
	var content string
	for _, c := range chunks {
		content += c.Content + "\n"
	}

	// Embed the combined content
	embedding, err := s.provider.Embed(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("failed to embed file content: %w", err)
	}

	// Search excluding the source file
	filter := opts.Filter
	if filter == nil {
		filter = &vectordb.Filter{}
	}
	// We'd need to exclude the source file, but for now just search
	results, err := s.store.Search(embedding, opts.Limit, filter)
	if err != nil {
		return nil, err
	}

	// Convert and filter out same file
	searchResults := make([]*SearchResult, 0)
	for _, r := range results.Results {
		if r.Chunk.File == filePath {
			continue
		}
		if opts.Threshold > 0 && r.Score < opts.Threshold {
			continue
		}
		searchResults = append(searchResults, &SearchResult{
			Chunk: r.Chunk,
			Score: r.Score,
			Hop:   1,
		})
	}

	return &SearchResults{
		Results: searchResults,
		Query:   filePath,
	}, nil
}

// FindRelated finds code related to a specific chunk
func (s *Searcher) FindRelated(ctx context.Context, chunkID string, limit int) (*SearchResults, error) {
	// Get the chunk
	c, err := s.store.Get(chunkID)
	if err != nil {
		return nil, fmt.Errorf("chunk not found: %w", err)
	}

	// Embed its content
	embedding, err := s.provider.Embed(ctx, c.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to embed chunk: %w", err)
	}

	// Search for similar chunks
	results, err := s.store.Search(embedding, limit+1, nil) // +1 to account for self
	if err != nil {
		return nil, err
	}

	// Filter out self
	searchResults := make([]*SearchResult, 0)
	for _, r := range results.Results {
		if r.Chunk.ID == chunkID {
			continue
		}
		searchResults = append(searchResults, &SearchResult{
			Chunk: r.Chunk,
			Score: r.Score,
			Hop:   1,
		})
	}

	return &SearchResults{
		Results: searchResults,
		Query:   c.Name,
	}, nil
}

// Count returns the number of indexed chunks
func (s *Searcher) Count() (int, error) {
	return s.store.Count()
}

// Files returns all indexed file paths
func (s *Searcher) Files() ([]string, error) {
	return s.store.Files()
}
