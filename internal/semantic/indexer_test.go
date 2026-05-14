package semantic

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ihavespoons/quokka/internal/chunk"
	"github.com/ihavespoons/quokka/internal/project"
	"github.com/ihavespoons/quokka/internal/vectordb"
)

// newTestIndexer builds an Indexer without an embedding provider. The
// embedding path isn't exercised by fileNeedsUpdate, so we can leave
// idx.provider nil; the extractor and store are real.
func newTestIndexer(t *testing.T) (*Indexer, func()) {
	t.Helper()

	tmp, err := os.MkdirTemp("", "quokka-semantic-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	p, err := project.Initialize(tmp)
	if err != nil {
		cleanup()
		t.Fatalf("project init: %v", err)
	}

	storePath := filepath.Join(tmp, ".quokka", "index")
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

// writeGoFile writes a file with the given body and returns its relative path.
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

// statHash returns mtime, size, and sha256 for a file (used to seed the
// file_hashes sidecar in tests).
func statHash(t *testing.T, full string) (int64, int64, string) {
	t.Helper()
	fi, err := os.Stat(full)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sum := sha256.Sum256(data)
	return fi.ModTime().UnixNano(), fi.Size(), hex.EncodeToString(sum[:])
}

// TestFileNeedsUpdateFirstTime: no row in file_hashes → file must be
// flagged as needing update, and no FileHash should be returned (caller
// will compute it after a successful index).
func TestFileNeedsUpdateFirstTime(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)

	needs, fh, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if !needs {
		t.Error("expected needs=true for never-indexed file")
	}
	if fh != nil {
		t.Errorf("expected fh=nil on first-time index, got %+v", fh)
	}
}

// TestFileNeedsUpdateFastPath: mtime+size match the stored fingerprint →
// returns (false, nil, nil). The fast path performs an os.Stat + sidecar
// lookup only; the file body is NOT read and the extractor is NOT invoked.
//
// We prove the body isn't read by making the file unreadable (chmod 000):
// the fast path returns success despite the file being inaccessible to
// read(), which would have failed if the implementation tried to slurp it.
func TestFileNeedsUpdateFastPath(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)
	full := filepath.Join(idx.project.RootPath, rel)
	mtime, size, sha := statHash(t, full)

	// Seed the file-hash sidecar so the fast path can hit.
	if err := idx.store.SetFileHash(&vectordb.FileHash{
		Path:      rel,
		Mtime:     mtime,
		Size:      size,
		SHA256:    sha,
		IndexedAt: time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("SetFileHash: %v", err)
	}

	// Strip read permission. os.Stat still works (needs only directory
	// search permission), but os.ReadFile would fail. If the fast path
	// stays fast, we never touch the bytes and the test passes.
	if err := os.Chmod(full, 0); err != nil {
		t.Fatalf("chmod 0: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(full, 0644) })

	needs, fh, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v (fast path should not read the file)", err)
	}
	if needs {
		t.Error("expected needs=false on mtime+size match (fast path)")
	}
	if fh != nil {
		t.Errorf("expected fh=nil on fast path (no read happened), got %+v", fh)
	}
}

// TestFileNeedsUpdateTouchOnly: mtime differs but sha256 still matches →
// touch-only edit. Returns (false, freshFH, nil) so caller can refresh
// the stored fingerprint and avoid re-reading next time.
func TestFileNeedsUpdateTouchOnly(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)
	full := filepath.Join(idx.project.RootPath, rel)
	_, size, sha := statHash(t, full)

	// Seed with a stale mtime (1 hour ago) but the correct sha256+size.
	staleMtime := time.Now().Add(-1 * time.Hour).UnixNano()
	if err := idx.store.SetFileHash(&vectordb.FileHash{
		Path:      rel,
		Mtime:     staleMtime,
		Size:      size,
		SHA256:    sha,
		IndexedAt: staleMtime,
	}); err != nil {
		t.Fatalf("SetFileHash: %v", err)
	}

	needs, fh, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if needs {
		t.Error("expected needs=false when sha256 still matches (touch-only)")
	}
	if fh == nil {
		t.Fatal("expected non-nil fh so caller can refresh mtime/size")
	}
	if fh.SHA256 != sha {
		t.Errorf("expected fresh sha256 to match stored: got %q want %q", fh.SHA256, sha)
	}
	if fh.Mtime == staleMtime {
		t.Error("expected fh.Mtime to reflect current file mtime, not the stale stored value")
	}
}

// TestFileNeedsUpdateContentChanged: mtime AND sha256 both differ →
// returns (true, freshFH, nil). The freshFH lets the caller skip a
// redundant stat+read after re-indexing.
func TestFileNeedsUpdateContentChanged(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	rel := writeGoFile(t, idx.project.RootPath, "a.go", `package a

func Hello() string { return "hi" }
`)
	full := filepath.Join(idx.project.RootPath, rel)
	oldMtime, oldSize, oldSha := statHash(t, full)

	if err := idx.store.SetFileHash(&vectordb.FileHash{
		Path:      rel,
		Mtime:     oldMtime,
		Size:      oldSize,
		SHA256:    oldSha,
		IndexedAt: oldMtime,
	}); err != nil {
		t.Fatalf("SetFileHash: %v", err)
	}

	// Sleep enough for mtime resolution to advance on all filesystems
	// (HFS+ on macOS has 1-second resolution; ext4 has nanosecond-ish).
	time.Sleep(1100 * time.Millisecond)

	// Rewrite the file with different content.
	if err := os.WriteFile(full, []byte(`package a

func Hello() string { return "hello world" }
`), 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	_, _, newSha := statHash(t, full)
	if newSha == oldSha {
		t.Fatal("test setup error: new sha matches old; content didn't change")
	}

	needs, fh, err := idx.fileNeedsUpdate(rel)
	if err != nil {
		t.Fatalf("fileNeedsUpdate: %v", err)
	}
	if !needs {
		t.Error("expected needs=true after content change")
	}
	if fh == nil {
		t.Fatal("expected non-nil fh (fresh hash) for caller to reuse")
	}
	if fh.SHA256 != newSha {
		t.Errorf("expected fh.SHA256 to be freshly computed: got %q want %q", fh.SHA256, newSha)
	}
}

// TestFileNeedsUpdateMissingFile: os.Stat fails → returns (true, nil, err).
// Caller decides policy (e.g. surface the error and skip).
func TestFileNeedsUpdateMissingFile(t *testing.T) {
	idx, cleanup := newTestIndexer(t)
	defer cleanup()

	needs, fh, err := idx.fileNeedsUpdate("does-not-exist.go")
	if err == nil {
		t.Error("expected error from os.Stat on missing file")
	}
	if !needs {
		t.Error("expected needs=true to surface the error to caller")
	}
	if fh != nil {
		t.Errorf("expected fh=nil on stat error, got %+v", fh)
	}
}
