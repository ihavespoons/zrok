package semantic

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ihavespoons/zrok/internal/chunk"
	"github.com/ihavespoons/zrok/internal/project"
	"github.com/ihavespoons/zrok/internal/vectordb"
)

// newTestIndexer builds an Indexer without an embedding provider. The
// embedding path isn't exercised by fileNeedsUpdate, so we can leave
// idx.provider nil; the extractor and store are real.
func newTestIndexer(t *testing.T) (*Indexer, func()) {
	t.Helper()

	tmp, err := os.MkdirTemp("", "zrok-semantic-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	p, err := project.Initialize(tmp)
	if err != nil {
		cleanup()
		t.Fatalf("project init: %v", err)
	}

	storePath := filepath.Join(tmp, ".zrok", "index")
	cfg := vectordb.DefaultStoreConfig(storePath, 4) // tiny dimension is fine
	store, err := vectordb.NewHNSWStore(cfg)
	if err != nil {
		cleanup()
		t.Fatalf("hnsw store: %v", err)
	}

	idx := &Indexer{
		project:   p,
		store:     store,
		provider:  nil,
		extractor: chunk.NewExtractor(p),
	}
	t.Cleanup(func() { _ = idx.extractor.Close() })
	t.Cleanup(func() { _ = store.Close() })
	return idx, cleanup
}

// writeGoFile writes a Go file with one function and returns its relative path.
func writeGoFile(t *testing.T, root, rel, body string) string {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return rel
}

// TestFileNeedsUpdateNoStoredChunks: a file not yet indexed must return
// true (needs update). Conservative behavior.
func TestFileNeedsUpdateNoStoredChunks(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)

	needs, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if !needs {
		t.Error("expected fileNeedsUpdate=true for unindexed file (no stored chunks)")
	}
}

// TestFileNeedsUpdateHashMatches: index a file, then re-check without
// modifying it. fileNeedsUpdate must return false — the chunk hashes match.
func TestFileNeedsUpdateHashMatches(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)

	// Extract current chunks and insert them directly with dummy embeddings
	// so the store has the same set of ContentHash values fileNeedsUpdate
	// would compute.
	chunks, err := idx.extractor.Extract(t.Context(), rel)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(chunks.Chunks) == 0 {
		t.Skip("extractor returned no chunks for trivial Go file (tree-sitter unavailable?)")
	}
	dim := 4
	embeddings := make([][]float32, len(chunks.Chunks))
	for i := range embeddings {
		embeddings[i] = []float32{0.1, 0.2, 0.3, 0.4}
	}
	_ = dim
	if err := idx.store.InsertBatch(chunks.Chunks, embeddings); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	needs, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if needs {
		t.Error("expected fileNeedsUpdate=false when file unchanged after indexing")
	}
}

// TestFileNeedsUpdateHashDiffers: index a file, then modify it. The new
// content yields different chunk content hashes, so fileNeedsUpdate must
// return true.
func TestFileNeedsUpdateHashDiffers(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)

	chunks, err := idx.extractor.Extract(t.Context(), rel)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(chunks.Chunks) == 0 {
		t.Skip("extractor returned no chunks for trivial Go file")
	}
	embeddings := make([][]float32, len(chunks.Chunks))
	for i := range embeddings {
		embeddings[i] = []float32{0.1, 0.2, 0.3, 0.4}
	}
	if err := idx.store.InsertBatch(chunks.Chunks, embeddings); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	// Modify the file: change function body so its chunk content hash changes.
	modified := `package a

func Hello() string { return "hello world" }
`
	if err := os.WriteFile(filepath.Join(idx.project.RootPath, rel), []byte(modified), 0644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	needs, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if !needs {
		t.Error("expected fileNeedsUpdate=true after content modification")
	}
}

// TestFileNeedsUpdateChunkCountChanges: when a new function is added so
// the file produces more chunks than the stored set, fileNeedsUpdate must
// return true even before comparing individual hashes.
func TestFileNeedsUpdateChunkCountChanges(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)

	chunks, err := idx.extractor.Extract(t.Context(), rel)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(chunks.Chunks) == 0 {
		t.Skip("extractor returned no chunks")
	}
	embeddings := make([][]float32, len(chunks.Chunks))
	for i := range embeddings {
		embeddings[i] = []float32{0.1, 0.2, 0.3, 0.4}
	}
	if err := idx.store.InsertBatch(chunks.Chunks, embeddings); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	// Add a new function: chunk count goes up.
	expanded := `package a

func Hello() string { return "hi" }

func Goodbye() string { return "bye" }
`
	if err := os.WriteFile(filepath.Join(idx.project.RootPath, rel), []byte(expanded), 0644); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}

	needs, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if !needs {
		t.Error("expected fileNeedsUpdate=true after adding a new function")
	}
}
