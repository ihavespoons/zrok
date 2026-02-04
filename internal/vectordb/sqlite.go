package vectordb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/internal/chunk"
	_ "modernc.org/sqlite"
)

// SQLiteMetaStore stores chunk metadata in SQLite
type SQLiteMetaStore struct {
	db   *sql.DB
	path string
}

// NewSQLiteMetaStore creates a new SQLite metadata store
func NewSQLiteMetaStore(path string) (*SQLiteMetaStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &SQLiteMetaStore{
		db:   db,
		path: path,
	}

	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

// init creates the database schema
func (s *SQLiteMetaStore) init() error {
	schema := `
		CREATE TABLE IF NOT EXISTS chunks (
			id TEXT PRIMARY KEY,
			file TEXT NOT NULL,
			language TEXT NOT NULL,
			type TEXT NOT NULL,
			name TEXT NOT NULL,
			content TEXT NOT NULL,
			start_line INTEGER NOT NULL,
			end_line INTEGER NOT NULL,
			parent_id TEXT,
			parent_name TEXT,
			signature TEXT,
			content_hash TEXT NOT NULL,
			vector_idx INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks(file);
		CREATE INDEX IF NOT EXISTS idx_chunks_type ON chunks(type);
		CREATE INDEX IF NOT EXISTS idx_chunks_language ON chunks(language);
		CREATE INDEX IF NOT EXISTS idx_chunks_name ON chunks(name);
		CREATE INDEX IF NOT EXISTS idx_chunks_vector_idx ON chunks(vector_idx);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// Insert adds a chunk to the store
func (s *SQLiteMetaStore) Insert(c *chunk.Chunk, vectorIdx int) error {
	query := `
		INSERT OR REPLACE INTO chunks
		(id, file, language, type, name, content, start_line, end_line, parent_id, parent_name, signature, content_hash, vector_idx)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query,
		c.ID,
		c.File,
		c.Language,
		string(c.Type),
		c.Name,
		c.Content,
		c.StartLine,
		c.EndLine,
		c.ParentID,
		c.ParentName,
		c.Signature,
		c.ContentHash,
		vectorIdx,
	)

	return err
}

// Get retrieves a chunk by ID
func (s *SQLiteMetaStore) Get(id string) (*chunk.Chunk, int, error) {
	query := `
		SELECT id, file, language, type, name, content, start_line, end_line,
		       parent_id, parent_name, signature, content_hash, vector_idx
		FROM chunks WHERE id = ?
	`

	row := s.db.QueryRow(query, id)
	return s.scanChunk(row)
}

// GetByVectorIdx retrieves a chunk by its vector index
func (s *SQLiteMetaStore) GetByVectorIdx(vectorIdx int) (*chunk.Chunk, error) {
	query := `
		SELECT id, file, language, type, name, content, start_line, end_line,
		       parent_id, parent_name, signature, content_hash, vector_idx
		FROM chunks WHERE vector_idx = ?
	`

	row := s.db.QueryRow(query, vectorIdx)
	c, _, err := s.scanChunk(row)
	return c, err
}

// GetByFile retrieves all chunks for a file
func (s *SQLiteMetaStore) GetByFile(file string) ([]*chunk.Chunk, error) {
	query := `
		SELECT id, file, language, type, name, content, start_line, end_line,
		       parent_id, parent_name, signature, content_hash, vector_idx
		FROM chunks WHERE file = ?
		ORDER BY start_line
	`

	rows, err := s.db.Query(query, file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var chunks []*chunk.Chunk
	for rows.Next() {
		c, _, err := s.scanChunkRow(rows)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, c)
	}

	return chunks, rows.Err()
}

// GetVectorIdxByFile retrieves vector indices for all chunks in a file
func (s *SQLiteMetaStore) GetVectorIdxByFile(file string) ([]int, error) {
	query := `SELECT vector_idx FROM chunks WHERE file = ? AND vector_idx IS NOT NULL`

	rows, err := s.db.Query(query, file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var indices []int
	for rows.Next() {
		var idx int
		if err := rows.Scan(&idx); err != nil {
			return nil, err
		}
		indices = append(indices, idx)
	}

	return indices, rows.Err()
}

// Delete removes a chunk by ID
func (s *SQLiteMetaStore) Delete(id string) error {
	_, err := s.db.Exec("DELETE FROM chunks WHERE id = ?", id)
	return err
}

// DeleteByFile removes all chunks for a file
func (s *SQLiteMetaStore) DeleteByFile(file string) ([]int, error) {
	// First get the vector indices
	indices, err := s.GetVectorIdxByFile(file)
	if err != nil {
		return nil, err
	}

	// Then delete the chunks
	_, err = s.db.Exec("DELETE FROM chunks WHERE file = ?", file)
	if err != nil {
		return nil, err
	}

	return indices, nil
}

// Count returns the total number of chunks
func (s *SQLiteMetaStore) Count() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM chunks").Scan(&count)
	return count, err
}

// CountByFile returns the number of chunks for a file
func (s *SQLiteMetaStore) CountByFile(file string) (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM chunks WHERE file = ?", file).Scan(&count)
	return count, err
}

// Files returns all indexed file paths
func (s *SQLiteMetaStore) Files() ([]string, error) {
	query := `SELECT DISTINCT file FROM chunks ORDER BY file`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var files []string
	for rows.Next() {
		var file string
		if err := rows.Scan(&file); err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	return files, rows.Err()
}

// FilteredChunkIDs returns chunk IDs matching the filter
func (s *SQLiteMetaStore) FilteredChunkIDs(filter *Filter) (map[int]bool, error) {
	if filter == nil {
		return nil, nil // No filter means all chunks
	}

	var conditions []string
	var args []interface{}

	if len(filter.Files) > 0 {
		// Support glob patterns
		var fileConditions []string
		for _, pattern := range filter.Files {
			if strings.Contains(pattern, "*") {
				// Convert glob to SQL LIKE pattern
				likePattern := strings.ReplaceAll(pattern, "*", "%")
				fileConditions = append(fileConditions, "file LIKE ?")
				args = append(args, likePattern)
			} else {
				fileConditions = append(fileConditions, "file = ?")
				args = append(args, pattern)
			}
		}
		conditions = append(conditions, "("+strings.Join(fileConditions, " OR ")+")")
	}

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			placeholders[i] = "?"
			args = append(args, string(t))
		}
		conditions = append(conditions, "type IN ("+strings.Join(placeholders, ", ")+")")
	}

	if len(filter.Languages) > 0 {
		placeholders := make([]string, len(filter.Languages))
		for i, l := range filter.Languages {
			placeholders[i] = "?"
			args = append(args, l)
		}
		conditions = append(conditions, "language IN ("+strings.Join(placeholders, ", ")+")")
	}

	if len(conditions) == 0 {
		return nil, nil // No filter conditions
	}

	query := "SELECT vector_idx FROM chunks WHERE vector_idx IS NOT NULL AND " + strings.Join(conditions, " AND ")

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make(map[int]bool)
	for rows.Next() {
		var idx int
		if err := rows.Scan(&idx); err != nil {
			return nil, err
		}
		result[idx] = true
	}

	return result, rows.Err()
}

// Clear removes all data
func (s *SQLiteMetaStore) Clear() error {
	_, err := s.db.Exec("DELETE FROM chunks")
	return err
}

// Close closes the database connection
func (s *SQLiteMetaStore) Close() error {
	return s.db.Close()
}

// GetStats returns statistics about the store
func (s *SQLiteMetaStore) GetStats() (*StoreStats, error) {
	stats := &StoreStats{
		TypeCounts:     make(map[chunk.ChunkType]int),
		LanguageCounts: make(map[string]int),
	}

	// Total count
	if err := s.db.QueryRow("SELECT COUNT(*) FROM chunks").Scan(&stats.TotalChunks); err != nil {
		return nil, err
	}

	// File count
	if err := s.db.QueryRow("SELECT COUNT(DISTINCT file) FROM chunks").Scan(&stats.TotalFiles); err != nil {
		return nil, err
	}

	// Type counts
	rows, err := s.db.Query("SELECT type, COUNT(*) FROM chunks GROUP BY type")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var count int
		if err := rows.Scan(&t, &count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		stats.TypeCounts[chunk.ChunkType(t)] = count
	}
	_ = rows.Close()

	// Language counts
	rows, err = s.db.Query("SELECT language, COUNT(*) FROM chunks GROUP BY language")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var lang string
		var count int
		if err := rows.Scan(&lang, &count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		stats.LanguageCounts[lang] = count
	}
	_ = rows.Close()

	return stats, nil
}

// StoreStats contains statistics about the store
type StoreStats struct {
	TotalChunks    int
	TotalFiles     int
	TypeCounts     map[chunk.ChunkType]int
	LanguageCounts map[string]int
}

// MarshalJSON implements json.Marshaler for StoreStats
func (s *StoreStats) MarshalJSON() ([]byte, error) {
	type statsJSON struct {
		TotalChunks    int            `json:"total_chunks"`
		TotalFiles     int            `json:"total_files"`
		TypeCounts     map[string]int `json:"type_counts"`
		LanguageCounts map[string]int `json:"language_counts"`
	}

	js := statsJSON{
		TotalChunks:    s.TotalChunks,
		TotalFiles:     s.TotalFiles,
		TypeCounts:     make(map[string]int),
		LanguageCounts: s.LanguageCounts,
	}

	for k, v := range s.TypeCounts {
		js.TypeCounts[string(k)] = v
	}

	return json.Marshal(js)
}

// scanChunk scans a single row into a chunk
func (s *SQLiteMetaStore) scanChunk(row *sql.Row) (*chunk.Chunk, int, error) {
	var c chunk.Chunk
	var chunkType string
	var parentID, parentName, signature sql.NullString
	var vectorIdx sql.NullInt64

	err := row.Scan(
		&c.ID,
		&c.File,
		&c.Language,
		&chunkType,
		&c.Name,
		&c.Content,
		&c.StartLine,
		&c.EndLine,
		&parentID,
		&parentName,
		&signature,
		&c.ContentHash,
		&vectorIdx,
	)
	if err != nil {
		return nil, 0, err
	}

	c.Type = chunk.ChunkType(chunkType)
	if parentID.Valid {
		c.ParentID = parentID.String
	}
	if parentName.Valid {
		c.ParentName = parentName.String
	}
	if signature.Valid {
		c.Signature = signature.String
	}

	idx := 0
	if vectorIdx.Valid {
		idx = int(vectorIdx.Int64)
	}

	return &c, idx, nil
}

// scanChunkRow scans a row from rows.Next() into a chunk
func (s *SQLiteMetaStore) scanChunkRow(rows *sql.Rows) (*chunk.Chunk, int, error) {
	var c chunk.Chunk
	var chunkType string
	var parentID, parentName, signature sql.NullString
	var vectorIdx sql.NullInt64

	err := rows.Scan(
		&c.ID,
		&c.File,
		&c.Language,
		&chunkType,
		&c.Name,
		&c.Content,
		&c.StartLine,
		&c.EndLine,
		&parentID,
		&parentName,
		&signature,
		&c.ContentHash,
		&vectorIdx,
	)
	if err != nil {
		return nil, 0, err
	}

	c.Type = chunk.ChunkType(chunkType)
	if parentID.Valid {
		c.ParentID = parentID.String
	}
	if parentName.Valid {
		c.ParentName = parentName.String
	}
	if signature.Valid {
		c.Signature = signature.String
	}

	idx := 0
	if vectorIdx.Valid {
		idx = int(vectorIdx.Int64)
	}

	return &c, idx, nil
}
