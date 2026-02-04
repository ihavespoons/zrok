package vectordb

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/ihavespoons/zrok/internal/chunk"
	"github.com/viterin/vek/vek32"
)

// HNSWStore implements Store using HNSW for vector search and SQLite for metadata
type HNSWStore struct {
	config   *StoreConfig
	meta     *SQLiteMetaStore
	index    *hnswIndex
	mu       sync.RWMutex
	nextIdx  int
	freeList []int // Reusable indices from deleted vectors
}

// NewHNSWStore creates a new HNSW-backed vector store
func NewHNSWStore(config *StoreConfig) (*HNSWStore, error) {
	// Ensure directory exists
	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Create metadata store
	metaPath := filepath.Join(config.Path, "chunks.db")
	meta, err := NewSQLiteMetaStore(metaPath)
	if err != nil {
		return nil, err
	}

	// Create HNSW index
	index := newHNSWIndex(config.Dimension, config.M, config.EfConstruction, config.EfSearch)

	store := &HNSWStore{
		config:   config,
		meta:     meta,
		index:    index,
		nextIdx:  0,
		freeList: []int{},
	}

	// Try to load existing index
	indexPath := filepath.Join(config.Path, "vectors.bin")
	if _, err := os.Stat(indexPath); err == nil {
		if err := store.loadIndex(indexPath); err != nil {
			// Log warning but continue with empty index
			fmt.Printf("Warning: failed to load index: %v\n", err)
		}
	}

	return store, nil
}

// Insert adds a chunk with its embedding to the store
func (s *HNSWStore) Insert(c *chunk.Chunk, embedding []float32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(embedding) != s.config.Dimension {
		return fmt.Errorf("embedding dimension mismatch: got %d, expected %d", len(embedding), s.config.Dimension)
	}

	// Get vector index (reuse from free list or allocate new)
	var vectorIdx int
	if len(s.freeList) > 0 {
		vectorIdx = s.freeList[len(s.freeList)-1]
		s.freeList = s.freeList[:len(s.freeList)-1]
	} else {
		vectorIdx = s.nextIdx
		s.nextIdx++
	}

	// Insert into HNSW index
	s.index.insert(vectorIdx, embedding)

	// Insert into metadata store
	if err := s.meta.Insert(c, vectorIdx); err != nil {
		return err
	}

	return nil
}

// InsertBatch adds multiple chunks with their embeddings
func (s *HNSWStore) InsertBatch(chunks []*chunk.Chunk, embeddings [][]float32) error {
	if len(chunks) != len(embeddings) {
		return fmt.Errorf("chunks and embeddings count mismatch")
	}

	for i, c := range chunks {
		if err := s.Insert(c, embeddings[i]); err != nil {
			return fmt.Errorf("failed to insert chunk %s: %w", c.ID, err)
		}
	}

	return nil
}

// Search finds the k most similar chunks to the query embedding
func (s *HNSWStore) Search(query []float32, k int, filter *Filter) (*SearchResults, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(query) != s.config.Dimension {
		return nil, fmt.Errorf("query dimension mismatch: got %d, expected %d", len(query), s.config.Dimension)
	}

	// Get filter set if applicable
	var filterSet map[int]bool
	if filter != nil {
		var err error
		filterSet, err = s.meta.FilteredChunkIDs(filter)
		if err != nil {
			return nil, err
		}
	}

	// Search HNSW index (get more candidates if filtering)
	searchK := k
	if filterSet != nil {
		searchK = k * 3 // Get extra candidates for filtering
	}

	candidates := s.index.search(query, searchK)

	// Filter and convert results
	var results []*SearchResult
	for _, candidate := range candidates {
		// Apply filter
		if filterSet != nil && !filterSet[candidate.idx] {
			continue
		}

		// Apply score threshold
		if filter != nil && filter.MinScore > 0 && candidate.score < filter.MinScore {
			continue
		}

		// Get chunk metadata
		c, err := s.meta.GetByVectorIdx(candidate.idx)
		if err != nil {
			continue // Skip if not found
		}

		results = append(results, &SearchResult{
			Chunk:    c,
			Score:    candidate.score,
			Distance: candidate.distance,
		})

		if len(results) >= k {
			break
		}
	}

	return &SearchResults{
		Results: results,
		Total:   len(results),
	}, nil
}

// Update updates an existing chunk's embedding
func (s *HNSWStore) Update(c *chunk.Chunk, embedding []float32) error {
	// Delete old entry and insert new one
	if err := s.Delete(c.ID); err != nil {
		return err
	}
	return s.Insert(c, embedding)
}

// Delete removes a chunk by ID
func (s *HNSWStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get vector index
	_, vectorIdx, err := s.meta.Get(id)
	if err != nil {
		return err
	}

	// Mark index as deleted (HNSW doesn't support true deletion, so we mark for reuse)
	s.index.delete(vectorIdx)
	s.freeList = append(s.freeList, vectorIdx)

	// Delete from metadata
	return s.meta.Delete(id)
}

// DeleteByFile removes all chunks for a file
func (s *HNSWStore) DeleteByFile(file string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get all vector indices for this file
	indices, err := s.meta.DeleteByFile(file)
	if err != nil {
		return err
	}

	// Mark indices as deleted
	for _, idx := range indices {
		s.index.delete(idx)
		s.freeList = append(s.freeList, idx)
	}

	return nil
}

// Get retrieves a chunk by ID
func (s *HNSWStore) Get(id string) (*chunk.Chunk, error) {
	c, _, err := s.meta.Get(id)
	return c, err
}

// GetByFile retrieves all chunks for a file
func (s *HNSWStore) GetByFile(file string) ([]*chunk.Chunk, error) {
	return s.meta.GetByFile(file)
}

// Count returns the total number of chunks
func (s *HNSWStore) Count() (int, error) {
	return s.meta.Count()
}

// CountByFile returns the number of chunks for a file
func (s *HNSWStore) CountByFile(file string) (int, error) {
	return s.meta.CountByFile(file)
}

// Files returns all indexed file paths
func (s *HNSWStore) Files() ([]string, error) {
	return s.meta.Files()
}

// GetStats returns statistics about the store
func (s *HNSWStore) GetStats() (*StoreStats, error) {
	return s.meta.GetStats()
}

// Clear removes all data from the store
func (s *HNSWStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear metadata
	if err := s.meta.Clear(); err != nil {
		return err
	}

	// Reset HNSW index
	s.index = newHNSWIndex(s.config.Dimension, s.config.M, s.config.EfConstruction, s.config.EfSearch)
	s.nextIdx = 0
	s.freeList = []int{}

	// Remove index file
	indexPath := filepath.Join(s.config.Path, "vectors.bin")
	_ = os.Remove(indexPath)

	return nil
}

// Close closes the store and saves the index
func (s *HNSWStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Save index
	indexPath := filepath.Join(s.config.Path, "vectors.bin")
	if err := s.saveIndex(indexPath); err != nil {
		// Log warning but continue
		fmt.Printf("Warning: failed to save index: %v\n", err)
	}

	return s.meta.Close()
}

// saveIndex saves the HNSW index to disk
func (s *HNSWStore) saveIndex(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Write header
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], uint32(s.config.Dimension))
	binary.LittleEndian.PutUint32(header[4:8], uint32(s.nextIdx))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(s.freeList)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(s.index.numVectors()))
	binary.LittleEndian.PutUint32(header[16:20], uint32(s.config.M))
	binary.LittleEndian.PutUint32(header[20:24], uint32(s.config.EfConstruction))

	if _, err := f.Write(header); err != nil {
		return err
	}

	// Write free list
	for _, idx := range s.freeList {
		if err := binary.Write(f, binary.LittleEndian, int32(idx)); err != nil {
			return err
		}
	}

	// Write vectors
	return s.index.save(f)
}

// loadIndex loads the HNSW index from disk
func (s *HNSWStore) loadIndex(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Read header
	header := make([]byte, 24)
	if _, err := f.Read(header); err != nil {
		return err
	}

	dimension := int(binary.LittleEndian.Uint32(header[0:4]))
	nextIdx := int(binary.LittleEndian.Uint32(header[4:8]))
	freeListLen := int(binary.LittleEndian.Uint32(header[8:12]))
	//numVectors := int(binary.LittleEndian.Uint32(header[12:16]))
	m := int(binary.LittleEndian.Uint32(header[16:20]))
	efConstruction := int(binary.LittleEndian.Uint32(header[20:24]))

	if dimension != s.config.Dimension {
		return fmt.Errorf("dimension mismatch: file has %d, config has %d", dimension, s.config.Dimension)
	}

	s.nextIdx = nextIdx
	s.config.M = m
	s.config.EfConstruction = efConstruction

	// Read free list
	s.freeList = make([]int, freeListLen)
	for i := range s.freeList {
		var idx int32
		if err := binary.Read(f, binary.LittleEndian, &idx); err != nil {
			return err
		}
		s.freeList[i] = int(idx)
	}

	// Read vectors
	return s.index.load(f, dimension)
}

// hnswIndex is a simple HNSW-like index implementation
type hnswIndex struct {
	dimension      int
	m              int
	efConstruction int
	efSearch       int
	vectors        map[int][]float32
	deleted        map[int]bool
	neighbors      map[int][]int // Simple flat index for now
	mu             sync.RWMutex
}

func newHNSWIndex(dimension, m, efConstruction, efSearch int) *hnswIndex {
	return &hnswIndex{
		dimension:      dimension,
		m:              m,
		efConstruction: efConstruction,
		efSearch:       efSearch,
		vectors:        make(map[int][]float32),
		deleted:        make(map[int]bool),
		neighbors:      make(map[int][]int),
	}
}

func (h *hnswIndex) insert(idx int, vector []float32) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Store vector
	h.vectors[idx] = vector
	delete(h.deleted, idx)

	// Update neighbor graph (simplified: connect to nearest existing vectors)
	if len(h.vectors) > 1 {
		var candidates []searchCandidate
		for existingIdx, existingVec := range h.vectors {
			if existingIdx == idx || h.deleted[existingIdx] {
				continue
			}
			dist := cosineDistance(vector, existingVec)
			candidates = append(candidates, searchCandidate{idx: existingIdx, distance: dist})
		}

		// Sort by distance and keep top M neighbors
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].distance < candidates[j].distance
		})

		neighbors := make([]int, 0, h.m)
		for i := 0; i < len(candidates) && i < h.m; i++ {
			neighbors = append(neighbors, candidates[i].idx)
			// Also add this node as neighbor to the existing nodes
			h.neighbors[candidates[i].idx] = append(h.neighbors[candidates[i].idx], idx)
			if len(h.neighbors[candidates[i].idx]) > h.m*2 {
				h.neighbors[candidates[i].idx] = h.neighbors[candidates[i].idx][:h.m*2]
			}
		}
		h.neighbors[idx] = neighbors
	}
}

type searchCandidate struct {
	idx      int
	distance float32
	score    float32
}

func (h *hnswIndex) search(query []float32, k int) []searchCandidate {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Brute force search (simplified; real HNSW would use graph traversal)
	var candidates []searchCandidate
	for idx, vec := range h.vectors {
		if h.deleted[idx] {
			continue
		}
		dist := cosineDistance(query, vec)
		score := 1.0 - dist // Convert distance to similarity score
		candidates = append(candidates, searchCandidate{
			idx:      idx,
			distance: dist,
			score:    score,
		})
	}

	// Sort by distance (ascending)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].distance < candidates[j].distance
	})

	if len(candidates) > k {
		candidates = candidates[:k]
	}

	return candidates
}

func (h *hnswIndex) delete(idx int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleted[idx] = true
}

func (h *hnswIndex) numVectors() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	count := 0
	for idx := range h.vectors {
		if !h.deleted[idx] {
			count++
		}
	}
	return count
}

func (h *hnswIndex) save(f *os.File) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Write number of vectors
	if err := binary.Write(f, binary.LittleEndian, int32(len(h.vectors))); err != nil {
		return err
	}

	// Write each vector
	for idx, vec := range h.vectors {
		if err := binary.Write(f, binary.LittleEndian, int32(idx)); err != nil {
			return err
		}
		if err := binary.Write(f, binary.LittleEndian, h.deleted[idx]); err != nil {
			return err
		}
		for _, v := range vec {
			if err := binary.Write(f, binary.LittleEndian, v); err != nil {
				return err
			}
		}
	}

	return nil
}

func (h *hnswIndex) load(f *os.File, dimension int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Read number of vectors
	var numVectors int32
	if err := binary.Read(f, binary.LittleEndian, &numVectors); err != nil {
		return err
	}

	// Read each vector
	for i := int32(0); i < numVectors; i++ {
		var idx int32
		if err := binary.Read(f, binary.LittleEndian, &idx); err != nil {
			return err
		}

		var deleted bool
		if err := binary.Read(f, binary.LittleEndian, &deleted); err != nil {
			return err
		}

		vec := make([]float32, dimension)
		for j := range vec {
			if err := binary.Read(f, binary.LittleEndian, &vec[j]); err != nil {
				return err
			}
		}

		h.vectors[int(idx)] = vec
		if deleted {
			h.deleted[int(idx)] = true
		}
	}

	// Rebuild neighbor graph
	for idx, vec := range h.vectors {
		if h.deleted[idx] {
			continue
		}

		var candidates []searchCandidate
		for existingIdx, existingVec := range h.vectors {
			if existingIdx == idx || h.deleted[existingIdx] {
				continue
			}
			dist := cosineDistance(vec, existingVec)
			candidates = append(candidates, searchCandidate{idx: existingIdx, distance: dist})
		}

		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].distance < candidates[j].distance
		})

		neighbors := make([]int, 0, h.m)
		for i := 0; i < len(candidates) && i < h.m; i++ {
			neighbors = append(neighbors, candidates[i].idx)
		}
		h.neighbors[idx] = neighbors
	}

	return nil
}

// cosineDistance computes the cosine distance between two vectors
func cosineDistance(a, b []float32) float32 {
	if len(a) != len(b) {
		return 1.0 // Maximum distance for mismatched dimensions
	}

	// Use SIMD-optimized operations from vek32
	dot := vek32.Dot(a, b)
	normA := float32(math.Sqrt(float64(vek32.Dot(a, a))))
	normB := float32(math.Sqrt(float64(vek32.Dot(b, b))))

	if normA == 0 || normB == 0 {
		return 1.0
	}

	similarity := dot / (normA * normB)
	// Clamp to [-1, 1] to handle floating point errors
	if similarity > 1.0 {
		similarity = 1.0
	} else if similarity < -1.0 {
		similarity = -1.0
	}

	return 1.0 - similarity
}
