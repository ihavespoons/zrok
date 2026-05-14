package chunk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/project"
)

// TestExtractTreeSitterSkipsOversizedFiles verifies the chunk extractor
// treats a tree-sitter SkippedFileError as a soft skip (empty chunks, no
// error) so the indexer keeps processing other files. This protects the
// indexer against pathological multi-GB inputs.
func TestExtractTreeSitterSkipsOversizedFiles(t *testing.T) {
	tmp := t.TempDir()
	p, err := project.Initialize(tmp)
	if err != nil {
		t.Fatalf("init project: %v", err)
	}

	// Write a Go file >2 KB.
	rel := "big.go"
	body := "package x\n" + strings.Repeat("// padding line\n", 200)
	if err := os.WriteFile(filepath.Join(tmp, rel), []byte(body), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	e := NewExtractor(p)
	defer func() { _ = e.Close() }()
	e.SetMethod(MethodTreeSitter)
	// Force the underlying parser to skip via a tight cap.
	e.tsParser.SetMaxFileSize(1024)

	chunks, err := e.Extract(context.Background(), rel)
	if err != nil {
		t.Fatalf("Extract should not error on skipped file, got: %v", err)
	}
	if chunks == nil {
		t.Fatal("expected non-nil ChunkList even when skipped")
	}
	if len(chunks.Chunks) != 0 {
		t.Errorf("expected 0 chunks for skipped file, got %d", len(chunks.Chunks))
	}
}
