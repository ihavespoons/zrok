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

// InsertBatch adds multiple chunks with their embeddings using a transaction
func (s *HNSWStore) InsertBatch(chunks []*chunk.Chunk, embeddings [][]float32) error {
	if len(chunks) != len(embeddings) {
		return fmt.Errorf("chunks and embeddings count mismatch")
	}

	if len(chunks) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Start a transaction for batch insert
	tx, err := s.meta.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is rolled back on error
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for i, c := range chunks {
		embedding := embeddings[i]

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

		// Insert into metadata store using transaction
		if err := s.meta.InsertWithTx(tx, c, vectorIdx); err != nil {
			return fmt.Errorf("failed to insert chunk %s: %w", c.ID, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	committed = true

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

// SaveIndex saves the current index to disk without closing
// Can be called periodically during long operations to persist state
func (s *HNSWStore) SaveIndex() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	indexPath := filepath.Join(s.config.Path, "vectors.bin")
	return s.saveIndex(indexPath)
}

// EnableDiskMode switches to disk-backed storage for low-memory indexing
// This dramatically reduces memory usage during large index builds
func (s *HNSWStore) EnableDiskMode() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vectorPath := filepath.Join(s.config.Path, "vectors_temp.bin")
	return s.index.EnableDiskMode(vectorPath)
}

// DisableDiskMode switches back to memory mode, loading vectors from disk
func (s *HNSWStore) DisableDiskMode() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.index.DisableDiskMode()
}

// IsDiskMode returns whether the store is in disk-backed mode
func (s *HNSWStore) IsDiskMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.index.diskMode
}

// ReleaseMemory forces SQLite to release memory and checkpoints WAL
func (s *HNSWStore) ReleaseMemory() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Checkpoint WAL to release pages
	if err := s.meta.Checkpoint(); err != nil {
		return err
	}

	// Ask SQLite to release unused memory
	return s.meta.ShrinkMemory()
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
// Supports two modes:
// - Memory mode: vectors stored in map (fast search, high memory)
// - Disk mode: vectors stored on disk, only offsets in memory (slow search, low memory)
type hnswIndex struct {
	dimension      int
	m              int
	efConstruction int
	efSearch       int
	vectors        map[int][]float32
	deleted        map[int]bool
	neighbors      map[int][]int // Simple flat index for now
	mu             sync.RWMutex

	// Disk-backed mode fields
	diskMode       bool
	vectorFile     *os.File
	vectorOffsets  map[int]int64 // vector_idx -> file offset
	graphBuilt     bool          // Whether neighbor graph has been built
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
		vectorOffsets:  make(map[int]int64),
		graphBuilt:     true, // Memory mode has graph built on insert
	}
}

// EnableDiskMode switches to disk-backed storage for low-memory indexing
func (h *hnswIndex) EnableDiskMode(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.diskMode {
		return nil // Already in disk mode
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create vector file: %w", err)
	}

	h.vectorFile = f
	h.diskMode = true
	h.graphBuilt = false // Graph will be built on first search
	h.vectorOffsets = make(map[int]int64)

	return nil
}

// DisableDiskMode switches back to memory mode, loading vectors from disk
func (h *hnswIndex) DisableDiskMode() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.diskMode {
		return nil
	}

	// Load all vectors from disk into memory
	if err := h.loadVectorsFromDisk(); err != nil {
		return err
	}

	if h.vectorFile != nil {
		_ = h.vectorFile.Close()
		h.vectorFile = nil
	}

	h.diskMode = false
	h.graphBuilt = true

	return nil
}

// loadVectorsFromDisk loads vectors from disk file into memory map
func (h *hnswIndex) loadVectorsFromDisk() error {
	if h.vectorFile == nil {
		return nil
	}

	for idx, offset := range h.vectorOffsets {
		vec, err := h.readVectorAt(offset)
		if err != nil {
			return fmt.Errorf("failed to read vector %d: %w", idx, err)
		}
		h.vectors[idx] = vec
	}

	return nil
}

// readVectorAt reads a vector from the given file offset
func (h *hnswIndex) readVectorAt(offset int64) ([]float32, error) {
	if h.vectorFile == nil {
		return nil, fmt.Errorf("vector file not open")
	}

	vec := make([]float32, h.dimension)
	_, err := h.vectorFile.Seek(offset, 0)
	if err != nil {
		return nil, err
	}

	for i := range vec {
		if err := binary.Read(h.vectorFile, binary.LittleEndian, &vec[i]); err != nil {
			return nil, err
		}
	}

	return vec, nil
}

// writeVectorToDisk writes a vector to disk and returns its offset
func (h *hnswIndex) writeVectorToDisk(vector []float32) (int64, error) {
	if h.vectorFile == nil {
		return 0, fmt.Errorf("vector file not open")
	}

	// Get current position (end of file)
	offset, err := h.vectorFile.Seek(0, 2)
	if err != nil {
		return 0, err
	}

	// Write vector
	for _, v := range vector {
		if err := binary.Write(h.vectorFile, binary.LittleEndian, v); err != nil {
			return 0, err
		}
	}

	return offset, nil
}

func (h *hnswIndex) insert(idx int, vector []float32) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.deleted, idx)

	if h.diskMode {
		// Disk mode: write vector to disk, store only offset
		offset, err := h.writeVectorToDisk(vector)
		if err != nil {
			// Fall back to memory mode on error
			h.vectors[idx] = vector
		} else {
			h.vectorOffsets[idx] = offset
		}
		// Skip neighbor building in disk mode - deferred until search
		return
	}

	// Memory mode: store vector and build neighbors
	h.vectors[idx] = vector

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
	h.mu.Lock() // Use write lock in case we need to load vectors
	defer h.mu.Unlock()

	// If in disk mode and vectors not loaded, load them for search
	if h.diskMode && len(h.vectors) == 0 && len(h.vectorOffsets) > 0 {
		if err := h.loadVectorsFromDisk(); err != nil {
			// Return empty results on error
			return nil
		}
	}

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

	// Count from disk offsets if in disk mode
	if h.diskMode && len(h.vectorOffsets) > 0 {
		count := 0
		for idx := range h.vectorOffsets {
			if !h.deleted[idx] {
				count++
			}
		}
		return count
	}

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

	// Determine total vectors (memory + disk)
	totalVectors := len(h.vectors)
	if h.diskMode && len(h.vectorOffsets) > 0 {
		totalVectors = len(h.vectorOffsets)
	}

	// Write number of vectors
	if err := binary.Write(f, binary.LittleEndian, int32(totalVectors)); err != nil {
		return err
	}

	// Write neighbor graph header
	if err := binary.Write(f, binary.LittleEndian, int32(len(h.neighbors))); err != nil {
		return err
	}

	// Write neighbor graph
	for idx, neighbors := range h.neighbors {
		if err := binary.Write(f, binary.LittleEndian, int32(idx)); err != nil {
			return err
		}
		if err := binary.Write(f, binary.LittleEndian, int32(len(neighbors))); err != nil {
			return err
		}
		for _, neighborIdx := range neighbors {
			if err := binary.Write(f, binary.LittleEndian, int32(neighborIdx)); err != nil {
				return err
			}
		}
	}

	// Write vectors from memory
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

	// Write vectors from disk (if in disk mode and vectors not in memory)
	if h.diskMode && h.vectorFile != nil {
		for idx, offset := range h.vectorOffsets {
			// Skip if already written from memory
			if _, exists := h.vectors[idx]; exists {
				continue
			}

			if err := binary.Write(f, binary.LittleEndian, int32(idx)); err != nil {
				return err
			}
			if err := binary.Write(f, binary.LittleEndian, h.deleted[idx]); err != nil {
				return err
			}

			// Read vector from disk file
			vec, err := h.readVectorAt(offset)
			if err != nil {
				return fmt.Errorf("failed to read vector %d from disk: %w", idx, err)
			}

			for _, v := range vec {
				if err := binary.Write(f, binary.LittleEndian, v); err != nil {
					return err
				}
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

	// Read number of neighbor entries
	var numNeighbors int32
	if err := binary.Read(f, binary.LittleEndian, &numNeighbors); err != nil {
		// Old format without neighbor graph - fall back to rebuild
		numNeighbors = 0
		// Seek back to read vectors
		_, _ = f.Seek(-4, 1)
	}

	// Read neighbor graph if present (for compatibility with saved files)
	if numNeighbors > 0 {
		h.neighbors = make(map[int][]int)
		for i := int32(0); i < numNeighbors; i++ {
			var idx, count int32
			if err := binary.Read(f, binary.LittleEndian, &idx); err != nil {
				return err
			}
			if err := binary.Read(f, binary.LittleEndian, &count); err != nil {
				return err
			}

			neighbors := make([]int, count)
			for j := int32(0); j < count; j++ {
				var neighborIdx int32
				if err := binary.Read(f, binary.LittleEndian, &neighborIdx); err != nil {
					return err
				}
				neighbors[j] = int(neighborIdx)
			}
			h.neighbors[int(idx)] = neighbors
		}
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

	// Skip neighbor graph rebuild - search uses brute force anyway, so the graph isn't needed
	// The O(n²) rebuild was causing index load to hang for large indices

	h.graphBuilt = true
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
