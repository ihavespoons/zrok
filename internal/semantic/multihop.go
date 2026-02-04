package semantic

import (
	"context"
	"sort"

	"github.com/ihavespoons/zrok/internal/chunk"
	"github.com/ihavespoons/zrok/internal/embedding"
	"github.com/ihavespoons/zrok/internal/vectordb"
)

const (
	// DefaultConvergenceThreshold is the minimum score improvement to continue
	DefaultConvergenceThreshold = 0.15
	// DefaultCandidateMultiplier is how many extra candidates to retrieve
	DefaultCandidateMultiplier = 3
)

// MultiHop performs iterative multi-hop semantic search
type MultiHop struct {
	store                 vectordb.Store
	provider              embedding.Provider
	convergenceThreshold  float32
	candidateMultiplier   int
}

// NewMultiHop creates a new multi-hop searcher
func NewMultiHop(store vectordb.Store, provider embedding.Provider) *MultiHop {
	return &MultiHop{
		store:                store,
		provider:             provider,
		convergenceThreshold: DefaultConvergenceThreshold,
		candidateMultiplier:  DefaultCandidateMultiplier,
	}
}

// SetConvergenceThreshold sets the score improvement threshold for stopping
func (m *MultiHop) SetConvergenceThreshold(threshold float32) {
	m.convergenceThreshold = threshold
}

// Search performs multi-hop semantic search
//
// Algorithm:
// 1. Embed query
// 2. Retrieve 3x candidates
// 3. Use top-k as seeds, find their neighbors
// 4. Rerank all against original query
// 5. Check convergence (score improvement < threshold or time limit)
// 6. Return ranked results
func (m *MultiHop) Search(ctx context.Context, query string, queryEmbedding []float32, opts *SearchOptions) (*SearchResults, error) {
	seen := make(map[string]bool)
	allResults := make(map[string]*rankedResult)
	hop := 0

	// Initial search with extra candidates
	candidateCount := opts.Limit * m.candidateMultiplier
	if candidateCount < 20 {
		candidateCount = 20
	}

	prevBestScore := float32(0.0)

	for hop < opts.MaxHops {
		select {
		case <-ctx.Done():
			// Time limit reached, return what we have
			return m.buildResults(query, allResults, opts, hop), nil
		default:
		}

		hop++

		// Search for candidates
		storeResults, err := m.store.Search(queryEmbedding, candidateCount, opts.Filter)
		if err != nil {
			return nil, err
		}

		// Process results
		newChunks := make([]*chunk.Chunk, 0)
		for _, r := range storeResults.Results {
			if seen[r.Chunk.ID] {
				continue
			}
			seen[r.Chunk.ID] = true

			allResults[r.Chunk.ID] = &rankedResult{
				chunk: r.Chunk,
				score: r.Score,
				hop:   hop,
			}

			// Collect new chunks for neighbor exploration
			if len(newChunks) < opts.Limit {
				newChunks = append(newChunks, r.Chunk)
			}
		}

		// Check if we have enough results
		if len(allResults) >= opts.Limit*2 {
			// Get best score
			bestScore := float32(0.0)
			for _, r := range allResults {
				if r.score > bestScore {
					bestScore = r.score
				}
			}

			// Check convergence
			improvement := bestScore - prevBestScore
			if improvement < m.convergenceThreshold {
				break
			}
			prevBestScore = bestScore
		}

		// Explore neighbors of top results
		if hop < opts.MaxHops && len(newChunks) > 0 {
			neighborResults, err := m.exploreNeighbors(ctx, newChunks, queryEmbedding, opts, seen)
			if err != nil {
				// Continue without neighbors on error
				continue
			}

			for _, r := range neighborResults {
				if !seen[r.chunk.ID] {
					seen[r.chunk.ID] = true
					r.hop = hop + 1
					allResults[r.chunk.ID] = r
				}
			}
		}
	}

	return m.buildResults(query, allResults, opts, hop), nil
}

// exploreNeighbors finds related chunks for the given seed chunks
func (m *MultiHop) exploreNeighbors(ctx context.Context, seeds []*chunk.Chunk, queryEmbedding []float32, opts *SearchOptions, seen map[string]bool) ([]*rankedResult, error) {
	var results []*rankedResult

	for _, seed := range seeds {
		select {
		case <-ctx.Done():
			return results, nil
		default:
		}

		// Find related chunks by:
		// 1. Same file (architectural context)
		// 2. Same parent (sibling methods)
		// 3. Similar embedding

		// Get chunks from same file
		fileChunks, err := m.store.GetByFile(seed.File)
		if err == nil {
			for _, c := range fileChunks {
				if !seen[c.ID] && c.ID != seed.ID {
					// Rerank against original query
					embedding, err := m.provider.Embed(ctx, c.Content)
					if err != nil {
						continue
					}
					score := cosineSimilarity(queryEmbedding, embedding)

					results = append(results, &rankedResult{
						chunk: c,
						score: score,
					})
				}
			}
		}

		// Find semantically similar chunks
		seedEmbedding, err := m.provider.Embed(ctx, seed.Content)
		if err != nil {
			continue
		}

		storeResults, err := m.store.Search(seedEmbedding, opts.Limit, opts.Filter)
		if err != nil {
			continue
		}

		for _, r := range storeResults.Results {
			if !seen[r.Chunk.ID] {
				// Rerank against original query
				embedding, err := m.provider.Embed(ctx, r.Chunk.Content)
				if err != nil {
					continue
				}
				score := cosineSimilarity(queryEmbedding, embedding)

				results = append(results, &rankedResult{
					chunk: r.Chunk,
					score: score,
				})
			}
		}
	}

	return results, nil
}

// buildResults converts the accumulated results into SearchResults
func (m *MultiHop) buildResults(query string, allResults map[string]*rankedResult, opts *SearchOptions, totalHops int) *SearchResults {
	// Convert to slice for sorting
	results := make([]*rankedResult, 0, len(allResults))
	for _, r := range allResults {
		if opts.Threshold > 0 && r.score < opts.Threshold {
			continue
		}
		results = append(results, r)
	}

	// Sort by score (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	// Limit results
	if len(results) > opts.Limit {
		results = results[:opts.Limit]
	}

	// Convert to SearchResult
	searchResults := make([]*SearchResult, len(results))
	for i, r := range results {
		searchResults[i] = &SearchResult{
			Chunk: r.chunk,
			Score: r.score,
			Hop:   r.hop,
		}
	}

	return &SearchResults{
		Results:   searchResults,
		Query:     query,
		TotalHops: totalHops,
	}
}

// rankedResult is an internal type for tracking results
type rankedResult struct {
	chunk *chunk.Chunk
	score float32
	hop   int
}

// cosineSimilarity computes the cosine similarity between two vectors
func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0.0
	}

	var dot, normA, normB float32
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	// Use sqrt approximation for performance
	normA = sqrtApprox(normA)
	normB = sqrtApprox(normB)

	return dot / (normA * normB)
}

// sqrtApprox provides a fast approximation of square root
func sqrtApprox(x float32) float32 {
	// Use Go's standard library for now - could optimize later
	return float32(sqrt64(float64(x)))
}

// sqrt64 computes square root
func sqrt64(x float64) float64 {
	if x < 0 {
		return 0
	}
	// Newton-Raphson iteration
	z := x / 2
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}
