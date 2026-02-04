package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OllamaProvider implements Provider using Ollama's local API
type OllamaProvider struct {
	config   *Config
	client   *http.Client
	endpoint string
}

// ollamaEmbedRequest is the request format for Ollama embeddings
type ollamaEmbedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// ollamaEmbedResponse is the response format for Ollama embeddings
type ollamaEmbedResponse struct {
	Embedding []float64 `json:"embedding"`
}

// NewOllamaProvider creates a new Ollama embedding provider
func NewOllamaProvider(config *Config) (*OllamaProvider, error) {
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}

	model := config.Model
	if model == "" {
		model = "nomic-embed-text"
	}

	return &OllamaProvider{
		config: &Config{
			Provider:  "ollama",
			Model:     model,
			Endpoint:  endpoint,
			Dimension: config.Dimension,
			BatchSize: config.BatchSize,
		},
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		endpoint: endpoint,
	}, nil
}

// Name returns the provider name
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// Dimension returns the embedding dimension
func (p *OllamaProvider) Dimension() int {
	if p.config.Dimension > 0 {
		return p.config.Dimension
	}
	return 768 // Default for nomic-embed-text
}

// Embed generates an embedding for a single text
func (p *OllamaProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody := ollamaEmbedRequest{
		Model:  p.config.Model,
		Prompt: text,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := p.endpoint + "/api/embeddings"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Ollama: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result ollamaEmbedResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert float64 to float32
	embedding := make([]float32, len(result.Embedding))
	for i, v := range result.Embedding {
		embedding[i] = float32(v)
	}

	return embedding, nil
}

// EmbedBatch generates embeddings for multiple texts
func (p *OllamaProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	// Ollama doesn't have a native batch API, so we process sequentially
	embeddings := make([][]float32, len(texts))

	batchSize := p.config.BatchSize
	if batchSize == 0 {
		batchSize = 32
	}

	for i, text := range texts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		embedding, err := p.Embed(ctx, text)
		if err != nil {
			return nil, fmt.Errorf("failed to embed text %d: %w", i, err)
		}
		embeddings[i] = embedding
	}

	return embeddings, nil
}

// Close releases resources
func (p *OllamaProvider) Close() error {
	return nil
}

// CheckAvailable checks if Ollama is available
func (p *OllamaProvider) CheckAvailable(ctx context.Context) error {
	url := p.endpoint + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama is not running at %s: %w", p.endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	return nil
}

// CheckModelAvailable checks if the configured model is available
func (p *OllamaProvider) CheckModelAvailable(ctx context.Context) error {
	url := p.endpoint + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	for _, model := range result.Models {
		if model.Name == p.config.Model || model.Name == p.config.Model+":latest" {
			return nil
		}
	}

	return fmt.Errorf("model %s not found in Ollama. Run: ollama pull %s", p.config.Model, p.config.Model)
}
