package vectordb

import (
	"path/filepath"
	"testing"
)

func newTestMetaStore(t *testing.T) *SQLiteMetaStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewSQLiteMetaStore(filepath.Join(dir, "chunks.db"))
	if err != nil {
		t.Fatalf("NewSQLiteMetaStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestGetFileHashEmpty: GetFileHash on a path with no row must return
// (nil, nil), NOT an error. This is load-bearing — the indexer's
// fileNeedsUpdate treats nil as "never indexed" and would otherwise be
// poisoned into re-indexing every file on every Update.
func TestGetFileHashEmpty(t *testing.T) {
	store := newTestMetaStore(t)

	fh, err := store.GetFileHash("anything.go")
	if err != nil {
		t.Fatalf("GetFileHash on empty table: got error %v, want nil", err)
	}
	if fh != nil {
		t.Errorf("GetFileHash on empty table: got %+v, want nil", fh)
	}
}

// TestSetAndGetFileHash: round-trip a FileHash through Set then Get and
// confirm every field survives.
func TestSetAndGetFileHash(t *testing.T) {
	store := newTestMetaStore(t)

	want := &FileHash{
		Path:      "internal/foo/bar.go",
		Mtime:     1_700_000_000_000_000_000,
		Size:      4321,
		SHA256:    "deadbeefcafef00d",
		IndexedAt: 1_700_000_001_000_000_000,
	}
	if err := store.SetFileHash(want); err != nil {
		t.Fatalf("SetFileHash: %v", err)
	}

	got, err := store.GetFileHash(want.Path)
	if err != nil {
		t.Fatalf("GetFileHash: %v", err)
	}
	if got == nil {
		t.Fatal("GetFileHash returned nil after SetFileHash")
	}
	if *got != *want {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", got, want)
	}
}

// TestSetFileHashReplace: SetFileHash on an existing path must overwrite,
// not duplicate (the schema's PRIMARY KEY plus INSERT OR REPLACE handles
// this). Verifies later writes win.
func TestSetFileHashReplace(t *testing.T) {
	store := newTestMetaStore(t)

	first := &FileHash{Path: "x.go", Mtime: 1, Size: 100, SHA256: "aaaa", IndexedAt: 1}
	second := &FileHash{Path: "x.go", Mtime: 2, Size: 200, SHA256: "bbbb", IndexedAt: 2}

	if err := store.SetFileHash(first); err != nil {
		t.Fatalf("first SetFileHash: %v", err)
	}
	if err := store.SetFileHash(second); err != nil {
		t.Fatalf("second SetFileHash: %v", err)
	}

	got, err := store.GetFileHash("x.go")
	if err != nil {
		t.Fatalf("GetFileHash: %v", err)
	}
	if got == nil || *got != *second {
		t.Errorf("expected overwrite by second SetFileHash:\n  got  %+v\n  want %+v", got, second)
	}
}

// TestDeleteFileHash: DeleteFileHash removes the row; subsequent
// GetFileHash returns (nil, nil). Deleting an absent path is a no-op
// (not an error) — important because the indexer calls DeleteFileHash on
// every removed file regardless of whether one was ever recorded.
func TestDeleteFileHash(t *testing.T) {
	store := newTestMetaStore(t)

	fh := &FileHash{Path: "gone.go", Mtime: 1, Size: 1, SHA256: "00", IndexedAt: 1}
	if err := store.SetFileHash(fh); err != nil {
		t.Fatalf("SetFileHash: %v", err)
	}

	if err := store.DeleteFileHash("gone.go"); err != nil {
		t.Fatalf("DeleteFileHash: %v", err)
	}
	got, err := store.GetFileHash("gone.go")
	if err != nil {
		t.Fatalf("GetFileHash after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}

	// Deleting a non-existent row should not error.
	if err := store.DeleteFileHash("never-existed.go"); err != nil {
		t.Errorf("DeleteFileHash on missing path returned error: %v", err)
	}
}

// TestClearAlsoWipesFileHashes: Clear() must drop file_hashes rows along
// with chunks. Otherwise a `zrok index build --force` (which calls Clear)
// leaves stale fingerprints that suppress re-indexing on the next
// Update.
func TestClearAlsoWipesFileHashes(t *testing.T) {
	store := newTestMetaStore(t)

	if err := store.SetFileHash(&FileHash{
		Path: "a.go", Mtime: 1, Size: 1, SHA256: "x", IndexedAt: 1,
	}); err != nil {
		t.Fatalf("SetFileHash: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, err := store.GetFileHash("a.go")
	if err != nil {
		t.Fatalf("GetFileHash after Clear: %v", err)
	}
	if got != nil {
		t.Errorf("expected Clear to wipe file_hashes; still got %+v", got)
	}
}

// TestSetFileHashNil: defensive — SetFileHash(nil) must return an error
// rather than panic. The indexer should never pass nil, but a future
// refactor might, and a panic in the indexing hot loop is worse than an
// error.
func TestSetFileHashNil(t *testing.T) {
	store := newTestMetaStore(t)
	if err := store.SetFileHash(nil); err == nil {
		t.Error("expected error from SetFileHash(nil), got nil")
	}
}
