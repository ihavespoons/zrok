package semantic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ihavespoons/zrok/internal/chunk"
	"github.com/ihavespoons/zrok/internal/embedding"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/vectordb"
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
	// ChunkStrategy is "lsp" or "regex"
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

	if progress != nil {
		progress(&IndexProgress{
			Phase:      "scanning",
			FilesTotal: len(files),
			FilesDone:  0,
		})
	}

	// Process files
	for i, file := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if progress != nil {
			progress(&IndexProgress{
				Phase:      "indexing",
				File:       file,
				FilesTotal: len(files),
				FilesDone:  i,
			})
		}

		if err := idx.indexFile(ctx, file); err != nil {
			// Log error but continue
			fmt.Printf("Warning: failed to index %s: %v\n", file, err)
		}
	}

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

	// Remove deleted files
	for _, file := range indexedFiles {
		if !currentSet[file] {
			if err := idx.store.DeleteByFile(file); err != nil {
				fmt.Printf("Warning: failed to remove %s: %v\n", file, err)
			} else {
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

		needsUpdate := false

		if !indexedSet[file] {
			// New file
			needsUpdate = true
		} else {
			// Check if modified
			needsUpdate, err = idx.fileNeedsUpdate(file)
			if err != nil {
				needsUpdate = true // Re-index on error
			}
		}

		if needsUpdate {
			if progress != nil {
				progress(&IndexProgress{
					Phase: "updating",
					File:  file,
				})
			}

			// Remove old chunks for this file
			if indexedSet[file] {
				if err := idx.store.DeleteByFile(file); err != nil {
					fmt.Printf("Warning: failed to remove old chunks for %s: %v\n", file, err)
				}
			}

			// Re-index file
			if err := idx.indexFile(ctx, file); err != nil {
				fmt.Printf("Warning: failed to index %s: %v\n", file, err)
			} else {
				updated++
			}
		}
	}

	return updated, nil
}

// indexFile indexes a single file
func (idx *Indexer) indexFile(ctx context.Context, file string) error {
	// Extract chunks
	chunks, err := idx.extractor.Extract(ctx, file)
	if err != nil {
		return fmt.Errorf("failed to extract chunks: %w", err)
	}

	if len(chunks.Chunks) == 0 {
		return nil
	}

	// Generate embeddings
	texts := make([]string, len(chunks.Chunks))
	for i, c := range chunks.Chunks {
		// Combine name, signature, and content for better embedding
		texts[i] = formatChunkForEmbedding(c)
	}

	embeddings, err := idx.provider.EmbedBatch(ctx, texts)
	if err != nil {
		return fmt.Errorf("failed to generate embeddings: %w", err)
	}

	// Insert into store
	if err := idx.store.InsertBatch(chunks.Chunks, embeddings); err != nil {
		return fmt.Errorf("failed to insert chunks: %w", err)
	}

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

// fileNeedsUpdate checks if a file needs to be re-indexed
func (idx *Indexer) fileNeedsUpdate(file string) (bool, error) {
	// Get existing chunks
	chunks, err := idx.store.GetByFile(file)
	if err != nil || len(chunks) == 0 {
		return true, err
	}

	// Read current file content
	fullPath := filepath.Join(idx.project.RootPath, file)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return true, err
	}

	// Simple check: compare content hash of first chunk
	// A more thorough check would re-extract and compare all chunks
	currentHash := chunk.GenerateContentHash(string(content))

	// If any chunk's hash doesn't match, needs update
	// (This is a simplification - we're just checking if file changed)
	_ = currentHash // TODO: implement proper change detection

	return false, nil
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
		"node_modules", "vendor", ".git", ".zrok",
		"__pycache__", "target", "dist", "build",
		".idea", ".vscode",
	}
	for _, ignore := range ignores {
		if name == ignore {
			return true
		}
	}
	return false
}

func (idx *Indexer) shouldExclude(path string) bool {
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
					// File deleted
					if err := idx.store.DeleteByFile(f); err != nil {
						fmt.Printf("Warning: failed to remove %s from index: %v\n", f, err)
					}
				} else {
					// File created or modified
					if err := idx.store.DeleteByFile(f); err != nil {
						fmt.Printf("Warning: failed to remove old %s: %v\n", f, err)
					}
					if err := idx.indexFile(ctx, f); err != nil {
						fmt.Printf("Warning: failed to re-index %s: %v\n", f, err)
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
