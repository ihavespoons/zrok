package lsp

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
)

// Manager manages multiple LSP client instances, one per language
type Manager struct {
	clients  map[string]*Client // language -> client
	rootPath string
	mu       sync.RWMutex
}

// NewManager creates a new LSP manager
func NewManager(rootPath string) *Manager {
	return &Manager{
		clients:  make(map[string]*Client),
		rootPath: rootPath,
	}
}

// GetClient returns an LSP client for the given filename
// It lazily initializes clients as needed
func (m *Manager) GetClient(ctx context.Context, filename string) (*Client, error) {
	config, ok := GetServerForFile(filename)
	if !ok {
		return nil, fmt.Errorf("no language server configured for %s", filepath.Ext(filename))
	}

	return m.getOrCreateClient(ctx, config)
}

// GetClientForLanguage returns an LSP client for the given language
func (m *Manager) GetClientForLanguage(ctx context.Context, language string) (*Client, error) {
	config, ok := GetServerForLanguage(language)
	if !ok {
		return nil, fmt.Errorf("no language server configured for language %s", language)
	}

	return m.getOrCreateClient(ctx, config)
}

// getOrCreateClient returns an existing client or creates a new one
func (m *Manager) getOrCreateClient(ctx context.Context, config *ServerConfig) (*Client, error) {
	m.mu.RLock()
	client, exists := m.clients[config.Language]
	m.mu.RUnlock()

	if exists && client.Ready() {
		return client, nil
	}

	// Need to create a new client
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	client, exists = m.clients[config.Language]
	if exists && client.Ready() {
		return client, nil
	}

	// Check if server is available
	if !IsServerAvailable(config) {
		return nil, fmt.Errorf("language server %s not found in PATH", config.Command)
	}

	// Create new client
	client, err := NewClient(ctx, config, m.rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s: %w", config.Language, err)
	}

	// Initialize the client
	if err := client.Initialize(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to initialize %s: %w", config.Name, err)
	}

	m.clients[config.Language] = client
	return client, nil
}

// HasClient checks if a client for the given filename's language is available
func (m *Manager) HasClient(filename string) bool {
	config, ok := GetServerForFile(filename)
	if !ok {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	client, exists := m.clients[config.Language]
	return exists && client.Ready()
}

// CanHandle checks if a language server is configured and available for the given file
func (m *Manager) CanHandle(filename string) bool {
	config, ok := GetServerForFile(filename)
	if !ok {
		return false
	}
	return IsServerAvailable(config)
}

// CloseClient closes the client for a specific language
func (m *Manager) CloseClient(language string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.clients[language]
	if !exists {
		return nil
	}

	delete(m.clients, language)
	return client.Close()
}

// CloseAll closes all active clients
func (m *Manager) CloseAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for lang, client := range m.clients {
		if err := client.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close %s client: %w", lang, err)
		}
	}

	m.clients = make(map[string]*Client)
	return lastErr
}

// ActiveClients returns the languages of all active clients
func (m *Manager) ActiveClients() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	languages := make([]string, 0, len(m.clients))
	for lang := range m.clients {
		languages = append(languages, lang)
	}
	return languages
}

// RootPath returns the root path of the manager
func (m *Manager) RootPath() string {
	return m.rootPath
}
