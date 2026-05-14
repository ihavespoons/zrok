package semantic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/diffsec/quokka/internal/chunk"
	"github.com/diffsec/quokka/internal/embedding"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/vectordb"
)

// IndexStats contains statistics about the index
type IndexStats struct {
	TotalChunks    int                         `json:"total_chunks"`
	TotalFiles     int                         `json:"total_files"`
	TypeCounts     map[chunk.ChunkType]int     `json:"type_counts"`
	LanguageCounts map[string]int              `json:"language_counts"`
	IndexPath      string                      `json:"index_path"`
	LastUpdated    time.Time                   `json:"last_updated,omitempty"`
}

// IndexProgress reports progress during indexing
type IndexProgress struct {
	Phase       string `json:"phase"`
	File        string `json:"file,omitempty"`
	FilesTotal  int    `json:"files_total"`
	FilesDone   int    `json:"files_done"`
	ChunksTotal int    `json:"chunks_total,omitempty"`
	ChunksDone  int    `json:"chunks_done,omitempty"`
}

// ProgressCallback is called with progress updates during indexing
type ProgressCallback func(progress *IndexProgress)

// Indexer manages the semantic search index
type Indexer struct {
	project    *project.Project
	store      vectordb.Store
	provider   embedding.Provider
	extractor  *chunk.Extractor
	watcher    *fsnotify.Watcher
	watcherMu  sync.Mutex
	watching   bool
	stopWatch  chan struct{}
	excludes   []string
}

// IndexerConfig contains configuration for the indexer
type IndexerConfig struct {
	// StorePath is the path for the vector store
	StorePath string
	// Provider is the embedding provider configuration
	ProviderConfig *embedding.Config
	// ChunkStrategy is "treesitter" or "regex"
	ChunkStrategy string
	// MaxChunkLines is the maximum lines per chunk
	MaxChunkLines int
	// ExcludePatterns are file patterns to exclude
	ExcludePatterns []string
}

// NewIndexer creates a new semantic indexer
func NewIndexer(p *project.Project, config *IndexerConfig) (*Indexer, error) {
	// Create embedding provider
	provider, err := embedding.NewProvider(config.ProviderConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedding provider: %w", err)
	}

	// Create vector store
	storeConfig := vectordb.DefaultStoreConfig(config.StorePath, provider.Dimension())
	store, err := vectordb.NewHNSWStore(storeConfig)
	if err != nil {
		_ = provider.Close()
		return nil, fmt.Errorf("failed to create vector store: %w", err)
	}

	// Create chunk extractor
	extractor := chunk.NewExtractor(p)
	switch config.ChunkStrategy {
	case "regex":
		extractor.SetMethod(chunk.MethodRegex)
	case "treesitter":
		extractor.SetMethod(chunk.MethodTreeSitter)
	case "lsp":
		extractor.SetMethod(chunk.MethodLSP)
	default:
		extractor.SetMethod(chunk.MethodAuto)
	}

	if config.MaxChunkLines > 0 {
		extractor.SetMaxChunkLines(config.MaxChunkLines)
	}

	return &Indexer{
		project:   p,
		store:     store,
		provider:  provider,
		extractor: extractor,
		excludes:  config.ExcludePatterns,
	}, nil
}

// Build builds or rebuilds the entire index
func (idx *Indexer) Build(ctx context.Context, force bool, progress ProgressCallback) error {
	// Clear existing index if force
	if force {
		if err := idx.store.Clear(); err != nil {
			return fmt.Errorf("failed to clear index: %w", err)
		}
	}

	// Find all files to index
	files, err := idx.findFiles()
	if err != nil {
		return fmt.Errorf("failed to find files: %w", err)
	}

	// Enable disk mode for large index builds to reduce memory usage
	// Threshold: 50+ files likely means many chunks
	useDiskMode := len(files) >= 50
	if useDiskMode {
		if hnswStore, ok := idx.store.(*vectordb.HNSWStore); ok {
			if err := hnswStore.EnableDiskMode(); err != nil {
				fmt.Printf("Warning: failed to enable disk mode, using memory mode: %v\n", err)
				useDiskMode = false
			}
		}
	}

	// Ensure disk mode is disabled at the end
	defer func() {
		if useDiskMode {
			if hnswStore, ok := idx.store.(*vectordb.HNSWStore); ok {
				_ = hnswStore.DisableDiskMode()
			}
		}
	}()

	if progress != nil {
		progress(&IndexProgress{
			Phase:      "scanning",
			FilesTotal: len(files),
			FilesDone:  0,
		})
	}

	// Process files with parallel workers
	numWorkers := getFileWorkers()
	fileBatchSize := getFileBatchSize()
	saveInterval := fileBatchSize * 4
	lspResetInterval := getLSPResetInterval()

	// Enable memory profiling if QUOKKA_PROFILE_MEMORY is set
	profileMemory := os.Getenv("QUOKKA_PROFILE_MEMORY") != ""
	debugVerbose := os.Getenv("QUOKKA_DEBUG_VERBOSE") != ""
	if profileMemory {
		printMemStats("start")
	}

	// Create worker pool with separate extractors for each worker
	type workItem struct {
		index int
		file  string
	}

	workChan := make(chan workItem, numWorkers*2)
	var wg sync.WaitGroup
	var filesDone int64
	var storeMu sync.Mutex // Protect store writes

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Each worker gets its own extractor with its own LSP clients
			workerExtractor := chunk.NewExtractor(idx.project)
			defer func() {
				if err := workerExtractor.Close(); err != nil {
					fmt.Printf("Warning: failed to close extractor: %v\n", err)
				}
			}()

			var localFilesProcessed int

			for work := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Extract chunks using worker's own extractor
				chunks, err := idx.extractAndEmbed(ctx, work.file, workerExtractor, debugVerbose)
				if err != nil {
					fmt.Printf("Warning: failed to index %s: %v\n", work.file, err)
				} else if len(chunks) > 0 {
					// Insert into store (protected by mutex)
					storeMu.Lock()
					insertOK := true
					for _, ce := range chunks {
						if err := idx.store.InsertBatch(ce.chunks, ce.embeddings); err != nil {
							fmt.Printf("Warning: failed to store chunks for %s: %v\n", work.file, err)
							insertOK = false
						}
					}
					storeMu.Unlock()

					// Record the file-level fingerprint so the next
					// `quokka index update` can fast-path-skip this file
					// without reading it. We compute the hash AFTER the
					// store insert succeeds; if any batch failed we skip,
					// because storing a fingerprint for a partially-indexed
					// file would suppress future re-indexing of missing
					// chunks.
					if insertOK {
						if fh, herr := idx.computeFileHash(work.file); herr == nil {
							storeMu.Lock()
							idx.recordFileHash(fh)
							storeMu.Unlock()
						} else if debugVerbose {
							fmt.Printf("[DEBUG] failed to compute file hash for %s: %v\n", work.file, herr)
						}
					}
				}

				localFilesProcessed++

				// Reset LSP clients periodically per worker
				if lspResetInterval > 0 && localFilesProcessed%lspResetInterval == 0 {
					if debugVerbose {
						fmt.Printf("[LSP-RESET] Worker %d resetting LSP clients after %d files\n", workerID, localFilesProcessed)
					}
					_ = workerExtractor.ResetClients(ctx)
				}
			}
		}(w)
	}

	// Send work to workers
	for i, file := range files {
		select {
		case <-ctx.Done():
			close(workChan)
			wg.Wait()
			return ctx.Err()
		default:
		}

		if progress != nil {
			done := int(filesDone)
			progress(&IndexProgress{
				Phase:      "indexing",
				File:       file,
				FilesTotal: len(files),
				FilesDone:  done,
			})
		}

		workChan <- workItem{index: i, file: file}

		// Increment counter atomically
		newDone := int(filesDone) + 1
		filesDone = int64(newDone)

		// Periodic maintenance (approximate, since workers are parallel)
		if newDone%fileBatchSize == 0 {
			if hnswStore, ok := idx.store.(*vectordb.HNSWStore); ok {
				storeMu.Lock()
				_ = hnswStore.ReleaseMemory()
				storeMu.Unlock()
			}
			releaseMemory()

			if profileMemory {
				printMemStats(fmt.Sprintf("after-%d-files", newDone))
			}
		}

		if newDone%saveInterval == 0 {
			if hnswStore, ok := idx.store.(*vectordb.HNSWStore); ok {
				storeMu.Lock()
				_ = hnswStore.SaveIndex()
				storeMu.Unlock()
			}
		}
	}

	close(workChan)
	wg.Wait()

	if progress != nil {
		progress(&IndexProgress{
			Phase:      "complete",
			FilesTotal: len(files),
			FilesDone:  len(files),
		})
	}

	return nil
}

// Update performs an incremental update for changed files
func (idx *Indexer) Update(ctx context.Context, progress ProgressCallback) (int, error) {
	// Get indexed files
	indexedFiles, err := idx.store.Files()
	if err != nil {
		return 0, fmt.Errorf("failed to get indexed files: %w", err)
	}
	indexedSet := make(map[string]bool)
	for _, f := range indexedFiles {
		indexedSet[f] = true
	}

	// Find current files
	currentFiles, err := idx.findFiles()
	if err != nil {
		return 0, fmt.Errorf("failed to find files: %w", err)
	}
	currentSet := make(map[string]bool)
	for _, f := range currentFiles {
		currentSet[f] = true
	}

	var updated int

	// Remove deleted files (and their cached file-hash rows so the sidecar
	// doesn't grow stale and a future re-add still looks "new").
	for _, file := range indexedFiles {
		if !currentSet[file] {
			if err := idx.store.DeleteByFile(file); err != nil {
				fmt.Printf("Warning: failed to remove %s: %v\n", file, err)
			} else {
				if err := idx.store.DeleteFileHash(file); err != nil {
					fmt.Printf("Warning: failed to remove file hash for %s: %v\n", file, err)
				}
				updated++
			}
		}
	}

	// Add new or modified files
	for _, file := range currentFiles {
		select {
		case <-ctx.Done():
			return updated, ctx.Err()
		default:
		}

		// fileNeedsUpdate consults the file-hash sidecar; it handles both
		// the "never indexed" and "stale fingerprint" cases internally.
		needsUpdate, fh, err := idx.fileNeedsUpdate(file)
		if err != nil {
			// Be conservative on errors: try to re-index, but don't trust
			// any partially-computed fingerprint.
			needsUpdate = true
			fh = nil
		}

		if !needsUpdate {
			// Touch-only edit detected: the sidecar may need its mtime/size
			// refreshed so we don't re-read on the next Update.
			if fh != nil {
				idx.recordFileHash(fh)
			}
			continue
		}

		if progress != nil {
			progress(&IndexProgress{
				Phase: "updating",
				File:  file,
			})
		}

		// Remove old chunks for this file (if any). DeleteByFile is a
		// no-op when there are no rows, so it's safe regardless.
		if indexedSet[file] {
			if err := idx.store.DeleteByFile(file); err != nil {
				fmt.Printf("Warning: failed to remove old chunks for %s: %v\n", file, err)
			}
		}

		// Re-index file
		if err := idx.indexFile(ctx, file); err != nil {
			fmt.Printf("Warning: failed to index %s: %v\n", file, err)
			continue
		}
		updated++

		// Persist the fingerprint so the next Update fast-paths this file.
		// Prefer the FileHash already computed by fileNeedsUpdate (avoids
		// a redundant stat+read); fall back to recomputing if it's nil
		// (first-time-index branch).
		if fh == nil {
			fh, err = idx.computeFileHash(file)
			if err != nil {
				fmt.Printf("Warning: failed to compute file hash for %s: %v\n", file, err)
				continue
			}
		}
		idx.recordFileHash(fh)
	}

	return updated, nil
}

// embeddingBatchSize is the number of chunks to embed at once
// Can be overridden via QUOKKA_EMBEDDING_BATCH_SIZE env var
// HuggingFace and OpenAI can handle large batches efficiently
const defaultEmbeddingBatchSize = 64

// fileBatchSize is the number of files to process before forcing GC
// Can be overridden via QUOKKA_FILE_BATCH_SIZE env var
const defaultFileBatchSize = 50

// maxChunksPerFile limits chunks from a single file to prevent huge bundled files from dominating
// Can be overridden via QUOKKA_MAX_CHUNKS_PER_FILE env var (0 = unlimited)
const defaultMaxChunksPerFile = 500

// embeddingConcurrency is the number of concurrent embedding API requests
// Higher values speed up indexing but may hit API rate limits
// Can be overridden via QUOKKA_EMBEDDING_CONCURRENCY env var
const defaultEmbeddingConcurrency = 4


func getEmbeddingBatchSize() int {
	if envVal := os.Getenv("QUOKKA_EMBEDDING_BATCH_SIZE"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size > 0 {
			return size
		}
	}
	return defaultEmbeddingBatchSize
}

func getFileBatchSize() int {
	if envVal := os.Getenv("QUOKKA_FILE_BATCH_SIZE"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size > 0 {
			return size
		}
	}
	return defaultFileBatchSize
}

func getMaxChunksPerFile() int {
	if envVal := os.Getenv("QUOKKA_MAX_CHUNKS_PER_FILE"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size >= 0 {
			return size
		}
	}
	return defaultMaxChunksPerFile
}

func getEmbeddingConcurrency() int {
	if envVal := os.Getenv("QUOKKA_EMBEDDING_CONCURRENCY"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size > 0 {
			return size
		}
	}
	return defaultEmbeddingConcurrency
}

func getFileWorkers() int {
	// Check for explicit override first
	if envVal := os.Getenv("QUOKKA_FILE_WORKERS"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size > 0 {
			return size
		}
	}

	// Tree-sitter is lightweight (~10MB per worker), so base on CPU count
	numCPU := runtime.NumCPU()
	workers := numCPU / 2
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}

	return workers
}

// defaultLSPResetInterval is the number of files to process before restarting LSP clients
// LSP servers like solargraph accumulate ~25MB per file; restarting releases it
// Set to 0 to disable. Can be overridden via QUOKKA_LSP_RESET_INTERVAL env var
const defaultLSPResetInterval = 25

func getLSPResetInterval() int {
	if envVal := os.Getenv("QUOKKA_LSP_RESET_INTERVAL"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size >= 0 {
			return size
		}
	}
	return defaultLSPResetInterval
}

// releaseMemory aggressively releases memory back to the OS
func releaseMemory() {
	runtime.GC()
	debug.FreeOSMemory() // Force return memory to OS
}

// printMemStats prints current memory statistics
func printMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("[MEM %s] Alloc: %d MB, TotalAlloc: %d MB, Sys: %d MB, NumGC: %d\n",
		label,
		m.Alloc/1024/1024,
		m.TotalAlloc/1024/1024,
		m.Sys/1024/1024,
		m.NumGC)
}

// indexFile indexes a single file
func (idx *Indexer) indexFile(ctx context.Context, file string) error {
	debugVerbose := os.Getenv("QUOKKA_DEBUG_VERBOSE") != ""

	if debugVerbose {
		fmt.Printf("[DEBUG] Extracting chunks from: %s\n", file)
	}

	// Extract chunks
	chunks, err := idx.extractor.Extract(ctx, file)
	if err != nil {
		return fmt.Errorf("failed to extract chunks: %w", err)
	}

	if len(chunks.Chunks) == 0 {
		if debugVerbose {
			fmt.Printf("[DEBUG] No chunks extracted from: %s\n", file)
		}
		return nil
	}

	// Limit chunks per file to prevent huge bundled/minified files from dominating
	maxChunks := getMaxChunksPerFile()
	if maxChunks > 0 && len(chunks.Chunks) > maxChunks {
		if debugVerbose {
			fmt.Printf("[DEBUG] Limiting %d chunks to %d for: %s\n", len(chunks.Chunks), maxChunks, file)
		}
		chunks.Chunks = chunks.Chunks[:maxChunks]
	}

	if debugVerbose {
		fmt.Printf("[DEBUG] Got %d chunks from: %s\n", len(chunks.Chunks), file)
	}

	// Process chunks in batches with concurrent embedding requests
	batchSize := getEmbeddingBatchSize()
	concurrency := getEmbeddingConcurrency()
	allChunks := chunks.Chunks
	chunks = nil // Release reference to allow GC of ChunkList struct

	// Split into batches
	var batches []struct {
		start  int
		chunks []*chunk.Chunk
		texts  []string
	}

	for start := 0; start < len(allChunks); start += batchSize {
		end := start + batchSize
		if end > len(allChunks) {
			end = len(allChunks)
		}
		batchChunks := allChunks[start:end]
		texts := make([]string, len(batchChunks))
		for i, c := range batchChunks {
			texts[i] = formatChunkForEmbedding(c)
		}
		batches = append(batches, struct {
			start  int
			chunks []*chunk.Chunk
			texts  []string
		}{start, batchChunks, texts})
	}

	// Process batches concurrently
	type result struct {
		batchIdx   int
		chunks     []*chunk.Chunk
		embeddings [][]float32
		err        error
	}

	// Use semaphore pattern for controlled concurrency
	sem := make(chan struct{}, concurrency)
	results := make(chan result, len(batches))

	for i, batch := range batches {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		sem <- struct{}{} // Acquire semaphore
		go func(batchNum int, b struct {
			start  int
			chunks []*chunk.Chunk
			texts  []string
		}) {
			defer func() { <-sem }() // Release semaphore

			if debugVerbose {
				fmt.Printf("[DEBUG] Embedding batch %d-%d for: %s\n", b.start, b.start+len(b.chunks), file)
			}

			embeddings, err := idx.provider.EmbedBatch(ctx, b.texts)
			if err != nil {
				results <- result{batchIdx: batchNum, err: fmt.Errorf("batch %d: %w", batchNum, err)}
				return
			}

			if debugVerbose {
				fmt.Printf("[DEBUG] Got %d embeddings for: %s\n", len(embeddings), file)
			}

			results <- result{batchIdx: batchNum, chunks: b.chunks, embeddings: embeddings}
		}(i, batch)
	}

	// Collect results and insert in order
	resultMap := make(map[int]result)
	var firstErr error
	for range batches {
		r := <-results
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		resultMap[r.batchIdx] = r
	}

	if firstErr != nil {
		return fmt.Errorf("failed to generate embeddings: %w", firstErr)
	}

	// Insert results in order to maintain consistency
	for i := 0; i < len(batches); i++ {
		r := resultMap[i]
		if err := idx.store.InsertBatch(r.chunks, r.embeddings); err != nil {
			return fmt.Errorf("failed to insert chunks: %w", err)
		}
	}

	// Release references
	allChunks = nil
	batches = nil

	return nil
}

// formatChunkForEmbedding formats a chunk for embedding generation
func formatChunkForEmbedding(c *chunk.Chunk) string {
	var parts []string

	// Add type and name
	parts = append(parts, fmt.Sprintf("%s %s", c.Type, c.Name))

	// Add signature if available
	if c.Signature != "" && c.Signature != c.Name {
		parts = append(parts, c.Signature)
	}

	// Add parent context
	if c.ParentName != "" {
		parts = append(parts, fmt.Sprintf("in %s", c.ParentName))
	}

	// Add content (truncated if too long)
	content := c.Content
	if len(content) > 2000 {
		content = content[:2000] + "..."
	}
	parts = append(parts, content)

	return strings.Join(parts, "\n")
}

// chunkEmbedding holds chunks with their embeddings for batch insertion
type chunkEmbedding struct {
	chunks     []*chunk.Chunk
	embeddings [][]float32
}

// extractAndEmbed extracts chunks from a file and generates embeddings
// Uses the provided extractor (for parallel processing with separate parsers)
func (idx *Indexer) extractAndEmbed(ctx context.Context, file string, extractor *chunk.Extractor, debugVerbose bool) ([]chunkEmbedding, error) {
	if debugVerbose {
		fmt.Printf("[DEBUG] Extracting chunks from: %s\n", file)
	}

	// Extract chunks
	chunks, err := extractor.Extract(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("failed to extract chunks: %w", err)
	}

	if len(chunks.Chunks) == 0 {
		if debugVerbose {
			fmt.Printf("[DEBUG] No chunks extracted from: %s\n", file)
		}
		return nil, nil
	}

	// Limit chunks per file
	maxChunks := getMaxChunksPerFile()
	if maxChunks > 0 && len(chunks.Chunks) > maxChunks {
		if debugVerbose {
			fmt.Printf("[DEBUG] Limiting %d chunks to %d for: %s\n", len(chunks.Chunks), maxChunks, file)
		}
		chunks.Chunks = chunks.Chunks[:maxChunks]
	}

	if debugVerbose {
		fmt.Printf("[DEBUG] Got %d chunks from: %s\n", len(chunks.Chunks), file)
	}

	// Process chunks in batches
	batchSize := getEmbeddingBatchSize()
	var results []chunkEmbedding

	for start := 0; start < len(chunks.Chunks); start += batchSize {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		end := start + batchSize
		if end > len(chunks.Chunks) {
			end = len(chunks.Chunks)
		}

		batchChunks := chunks.Chunks[start:end]
		texts := make([]string, len(batchChunks))
		for i, c := range batchChunks {
			texts[i] = formatChunkForEmbedding(c)
		}

		if debugVerbose {
			fmt.Printf("[DEBUG] Embedding batch %d-%d for: %s\n", start, end, file)
		}

		embeddings, err := idx.provider.EmbedBatch(ctx, texts)
		if err != nil {
			return nil, fmt.Errorf("failed to generate embeddings: %w", err)
		}

		if debugVerbose {
			fmt.Printf("[DEBUG] Got %d embeddings for: %s\n", len(embeddings), file)
		}

		results = append(results, chunkEmbedding{
			chunks:     batchChunks,
			embeddings: embeddings,
		})
	}

	return results, nil
}

// fileNeedsUpdate decides whether `file` needs re-indexing by consulting a
// file-level hash sidecar in the metastore (see vectordb.FileHash). The hot
// path — files whose (mtime, size) pair is unchanged since they were last
// indexed — performs a single os.Stat and a single sidecar lookup; the file
// itself is NEVER read in that case.
//
// Returned *vectordb.FileHash:
//   - When needs=false: nil (caller has nothing to record).
//   - When needs=true and we already computed the sha256 (steps 5/6): a
//     fully-populated FileHash with the freshly-computed sha256 the caller
//     can hand to SetFileHash after a successful re-index, avoiding a
//     redundant stat+read.
//   - When needs=true and no sha256 was computed (steps 1, 3): nil. The
//     caller must compute and record it from scratch after re-indexing.
//
// Decision tree (matches the spec):
//  1. os.Stat fails  → (true, nil, err)         // surface error to caller
//  2. no stored row  → (true, nil, nil)         // first-time index
//  3. mtime+size match stored → (false, nil, nil)  // fast path, no read
//  4. mtime or size differs, but freshly-computed sha256 matches stored
//     → (false, &FileHash{...with new mtime/size, same sha256}, nil)
//     // touch-only edit; caller may update the sidecar to refresh
//     // mtime/size and avoid re-reading next time
//  5. sha256 differs → (true, &FileHash{...freshly computed}, nil)
func (idx *Indexer) fileNeedsUpdate(file string) (bool, *vectordb.FileHash, error) {
	fullPath := filepath.Join(idx.project.RootPath, file)
	fi, err := os.Stat(fullPath)
	if err != nil {
		// Step 1: stat failure — caller decides policy.
		return true, nil, err
	}

	// Step 2: consult the file-hash sidecar.
	stored, err := idx.store.GetFileHash(file)
	if err != nil {
		// Conservative on metadata error: re-index, but signal the error.
		return true, nil, err
	}
	if stored == nil {
		// Never indexed → needs (initial) index.
		return true, nil, nil
	}

	// Step 3: fast path — mtime+size match, no read needed.
	if stored.Mtime == fi.ModTime().UnixNano() && stored.Size == fi.Size() {
		return false, nil, nil
	}

	// Steps 4/5: mtime or size changed; the contents MAY or MAY NOT have
	// changed (could be a touch, a clobber-with-identical-content, or an
	// actual edit). Read the file once and hash it to find out.
	data, err := os.ReadFile(fullPath)
	if err != nil {
		// Couldn't read → caller will surface the error via indexFile.
		return true, nil, err
	}
	sum := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sum[:])

	freshFH := &vectordb.FileHash{
		Path:      file,
		Mtime:     fi.ModTime().UnixNano(),
		Size:      fi.Size(),
		SHA256:    hashHex,
		IndexedAt: time.Now().UnixNano(),
	}

	if hashHex == stored.SHA256 {
		// Step 4: touch-only edit. Return the fresh FileHash so the caller
		// can refresh mtime/size in the sidecar and avoid this read next
		// time.
		return false, freshFH, nil
	}

	// Step 5: content really changed.
	return true, freshFH, nil
}

// computeFileHash returns a FileHash describing `file` right now. Used by
// Build()/Watch()/Update() to record a fingerprint after a successful
// (re-)index of a file when fileNeedsUpdate didn't already compute one
// (i.e. the "first-time index" branch).
func (idx *Indexer) computeFileHash(file string) (*vectordb.FileHash, error) {
	fullPath := filepath.Join(idx.project.RootPath, file)
	fi, err := os.Stat(fullPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &vectordb.FileHash{
		Path:      file,
		Mtime:     fi.ModTime().UnixNano(),
		Size:      fi.Size(),
		SHA256:    hex.EncodeToString(sum[:]),
		IndexedAt: time.Now().UnixNano(),
	}, nil
}

// recordFileHash persists a FileHash if non-nil. Centralized so callers
// don't litter `if fh != nil { Set... }` blocks.
func (idx *Indexer) recordFileHash(fh *vectordb.FileHash) {
	if fh == nil {
		return
	}
	if err := idx.store.SetFileHash(fh); err != nil {
		fmt.Printf("Warning: failed to persist file hash for %s: %v\n", fh.Path, err)
	}
}

// findFiles finds all files to index
func (idx *Indexer) findFiles() ([]string, error) {
	var files []string

	err := filepath.Walk(idx.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			name := info.Name()
			// Skip hidden directories and common ignores
			if strings.HasPrefix(name, ".") || idx.shouldIgnoreDir(name) {
				return filepath.SkipDir
			}
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(idx.project.RootPath, path)
		if err != nil {
			return nil
		}

		// Check exclusions
		if idx.shouldExclude(relPath) {
			return nil
		}

		// Check if supported file type
		ext := strings.ToLower(filepath.Ext(path))
		if !idx.isSupportedExtension(ext) {
			return nil
		}

		files = append(files, relPath)
		return nil
	})

	return files, err
}

func (idx *Indexer) shouldIgnoreDir(name string) bool {
	ignores := []string{
		"node_modules", "vendor", ".git", ".quokka",
		"__pycache__", "target", "dist", "build",
		".idea", ".vscode", ".bundle", "coverage",
		"tmp", "log", "logs", "cache", ".cache",
		"public/assets", "public/packs", // Rails compiled assets
		"assets/builds", // Rails asset pipeline output
	}
	for _, ignore := range ignores {
		if name == ignore {
			return true
		}
	}
	return false
}

func (idx *Indexer) shouldExclude(path string) bool {
	// Check user-specified exclusions
	for _, pattern := range idx.excludes {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return true
		}
		// Also check if the pattern matches any component
		if strings.Contains(path, strings.TrimPrefix(strings.TrimSuffix(pattern, "*"), "*")) {
			return true
		}
	}

	// Built-in exclusions for common non-source files
	baseName := filepath.Base(path)
	lowerName := strings.ToLower(baseName)

	// Skip minified/bundled files
	if strings.Contains(lowerName, ".min.") ||
		strings.Contains(lowerName, ".bundle.") ||
		strings.Contains(lowerName, ".standalone.") ||
		strings.Contains(lowerName, ".packed.") ||
		strings.HasSuffix(lowerName, "-min.js") ||
		strings.HasSuffix(lowerName, "-bundle.js") {
		return true
	}

	// Skip common vendor/third-party files by name patterns
	vendorPatterns := []string{
		"jquery", "bootstrap", "react.production",
		"vue.runtime", "angular", "lodash", "moment",
		"popper", "chart.js", "d3.js", "three.js",
	}
	for _, pattern := range vendorPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	// Skip files in vendor-like paths
	lowerPath := strings.ToLower(path)
	vendorPaths := []string{
		"/vendor/", "/vendors/", "/third_party/", "/third-party/",
		"/external/", "/lib/assets/", "/public/assets/",
		"/node_modules/", "/.bundle/",
	}
	for _, vp := range vendorPaths {
		if strings.Contains(lowerPath, vp) {
			return true
		}
	}

	return false
}

func (idx *Indexer) isSupportedExtension(ext string) bool {
	supported := map[string]bool{
		".go":   true,
		".py":   true,
		".js":   true,
		".ts":   true,
		".jsx":  true,
		".tsx":  true,
		".java": true,
		".rs":   true,
		".rb":   true,
		".c":    true,
		".cpp":  true,
		".cc":   true,
		".h":    true,
		".hpp":  true,
	}
	return supported[ext]
}

// Watch starts watching for file changes and updates the index
func (idx *Indexer) Watch(ctx context.Context) error {
	idx.watcherMu.Lock()
	if idx.watching {
		idx.watcherMu.Unlock()
		return fmt.Errorf("already watching")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		idx.watcherMu.Unlock()
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	idx.watcher = watcher
	idx.watching = true
	idx.stopWatch = make(chan struct{})
	idx.watcherMu.Unlock()

	// Add directories to watch
	if err := idx.addWatchDirs(); err != nil {
		idx.StopWatch()
		return fmt.Errorf("failed to add watch directories: %w", err)
	}

	// Debounce timer for batching updates
	var debounceTimer *time.Timer
	pendingFiles := make(map[string]bool)
	var pendingMu sync.Mutex

	// Process file change
	processChange := func(file string) {
		relPath, err := filepath.Rel(idx.project.RootPath, file)
		if err != nil {
			return
		}

		// Check if this file should be indexed
		if idx.shouldExclude(relPath) {
			return
		}
		ext := strings.ToLower(filepath.Ext(file))
		if !idx.isSupportedExtension(ext) {
			return
		}

		pendingMu.Lock()
		pendingFiles[relPath] = true
		pendingMu.Unlock()

		// Reset debounce timer
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
		debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
			pendingMu.Lock()
			files := make([]string, 0, len(pendingFiles))
			for f := range pendingFiles {
				files = append(files, f)
			}
			pendingFiles = make(map[string]bool)
			pendingMu.Unlock()

			for _, f := range files {
				// Check if file still exists
				fullPath := filepath.Join(idx.project.RootPath, f)
				if _, err := os.Stat(fullPath); os.IsNotExist(err) {
					// File deleted: drop chunks AND the file-hash sidecar
					// row so a future re-create looks "new" to Update().
					if err := idx.store.DeleteByFile(f); err != nil {
						fmt.Printf("Warning: failed to remove %s from index: %v\n", f, err)
					}
					if err := idx.store.DeleteFileHash(f); err != nil {
						fmt.Printf("Warning: failed to remove file hash for %s: %v\n", f, err)
					}
				} else {
					// File created or modified
					if err := idx.store.DeleteByFile(f); err != nil {
						fmt.Printf("Warning: failed to remove old %s: %v\n", f, err)
					}
					if err := idx.indexFile(ctx, f); err != nil {
						fmt.Printf("Warning: failed to re-index %s: %v\n", f, err)
						continue
					}
					// Refresh the fingerprint so a subsequent `quokka index
					// update` can fast-path-skip this file.
					if fh, herr := idx.computeFileHash(f); herr == nil {
						idx.recordFileHash(fh)
					} else {
						fmt.Printf("Warning: failed to compute file hash for %s: %v\n", f, herr)
					}
				}
			}
		})
	}

	// Watch loop
	go func() {
		for {
			select {
			case <-idx.stopWatch:
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
					processChange(event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("Watcher error: %v\n", err)
			}
		}
	}()

	return nil
}

// addWatchDirs adds directories to the watcher recursively
func (idx *Indexer) addWatchDirs() error {
	return filepath.Walk(idx.project.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || idx.shouldIgnoreDir(name) {
				return filepath.SkipDir
			}
			if err := idx.watcher.Add(path); err != nil {
				return err
			}
		}
		return nil
	})
}

// StopWatch stops watching for file changes
func (idx *Indexer) StopWatch() {
	idx.watcherMu.Lock()
	defer idx.watcherMu.Unlock()

	if !idx.watching {
		return
	}

	close(idx.stopWatch)
	if idx.watcher != nil {
		_ = idx.watcher.Close()
	}
	idx.watching = false
}

// IsWatching returns whether the watcher is running
func (idx *Indexer) IsWatching() bool {
	idx.watcherMu.Lock()
	defer idx.watcherMu.Unlock()
	return idx.watching
}

// Stats returns statistics about the index
func (idx *Indexer) Stats() (*IndexStats, error) {
	stats, err := idx.store.(*vectordb.HNSWStore).GetStats()
	if err != nil {
		return nil, err
	}

	return &IndexStats{
		TotalChunks:    stats.TotalChunks,
		TotalFiles:     stats.TotalFiles,
		TypeCounts:     stats.TypeCounts,
		LanguageCounts: stats.LanguageCounts,
	}, nil
}

// Clear clears the entire index
func (idx *Indexer) Clear() error {
	return idx.store.Clear()
}

// Close closes the indexer and releases resources
func (idx *Indexer) Close() error {
	idx.StopWatch()

	if err := idx.extractor.Close(); err != nil {
		fmt.Printf("Warning: failed to close extractor: %v\n", err)
	}

	if err := idx.provider.Close(); err != nil {
		fmt.Printf("Warning: failed to close provider: %v\n", err)
	}

	return idx.store.Close()
}

// Searcher returns a searcher for this index
func (idx *Indexer) Searcher() *Searcher {
	return NewSearcher(idx.store, idx.provider)
}
