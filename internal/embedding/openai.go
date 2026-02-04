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

const openAIAPIURL = "https://api.openai.com/v1/embeddings"

// OpenAIProvider implements Provider using OpenAI's API
type OpenAIProvider struct {
	config *Config
	client *http.Client
	apiKey string
}

// openAIEmbedRequest is the request format for OpenAI embeddings
type openAIEmbedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

// openAIEmbedResponse is the response format for OpenAI embeddings
type openAIEmbedResponse struct {
	Object string `json:"object"`
	Data   []struct {
		Object    string    `json:"object"`
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
	Model string `json:"model"`
	Usage struct {
		PromptTokens int `json:"prompt_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

// NewOpenAIProvider creates a new OpenAI embedding provider
func NewOpenAIProvider(config *Config) (*OpenAIProvider, error) {
	apiKeyEnv := config.APIKeyEnv
	if apiKeyEnv == "" {
		apiKeyEnv = "OPENAI_API_KEY"
	}

	apiKey, err := GetAPIKey(apiKeyEnv)
	if err != nil {
		return nil, err
	}

	model := config.Model
	if model == "" {
		model = "text-embedding-3-small"
	}

	dimension := config.Dimension
	if dimension == 0 {
		// Set default dimension based on model
		switch model {
		case "text-embedding-3-small":
			dimension = 1536
		case "text-embedding-3-large":
			dimension = 3072
		case "text-embedding-ada-002":
			dimension = 1536
		default:
			dimension = 1536
		}
	}

	batchSize := config.BatchSize
	if batchSize == 0 {
		batchSize = 100
	}

	return &OpenAIProvider{
		config: &Config{
			Provider:  "openai",
			Model:     model,
			APIKeyEnv: apiKeyEnv,
			Dimension: dimension,
			BatchSize: batchSize,
		},
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		apiKey: apiKey,
	}, nil
}

// Name returns the provider name
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Dimension returns the embedding dimension
func (p *OpenAIProvider) Dimension() int {
	return p.config.Dimension
}

// Embed generates an embedding for a single text
func (p *OpenAIProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	embeddings, err := p.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	return embeddings[0], nil
}

// EmbedBatch generates embeddings for multiple texts
func (p *OpenAIProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return [][]float32{}, nil
	}

	// Process in batches
	batchSize := p.config.BatchSize
	allEmbeddings := make([][]float32, len(texts))

	for i := 0; i < len(texts); i += batchSize {
		end := i + batchSize
		if end > len(texts) {
			end = len(texts)
		}

		batch := texts[i:end]
		embeddings, err := p.embedBatchInternal(ctx, batch)
		if err != nil {
			return nil, err
		}

		for j, emb := range embeddings {
			allEmbeddings[i+j] = emb
		}
	}

	return allEmbeddings, nil
}

func (p *OpenAIProvider) embedBatchInternal(ctx context.Context, texts []string) ([][]float32, error) {
	reqBody := openAIEmbedRequest{
		Model: p.config.Model,
		Input: texts,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", openAIAPIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to OpenAI: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result openAIEmbedResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Error != nil {
		return nil, fmt.Errorf("OpenAI API error: %s (%s)", result.Error.Message, result.Error.Type)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Convert to float32 and ensure order matches input
	embeddings := make([][]float32, len(texts))
	for _, data := range result.Data {
		embedding := make([]float32, len(data.Embedding))
		for i, v := range data.Embedding {
			embedding[i] = float32(v)
		}
		embeddings[data.Index] = embedding
	}

	return embeddings, nil
}

// Close releases resources
func (p *OpenAIProvider) Close() error {
	return nil
}

// CheckAvailable checks if OpenAI API is accessible
func (p *OpenAIProvider) CheckAvailable(ctx context.Context) error {
	// Try to get a very small embedding to verify API access
	_, err := p.Embed(ctx, "test")
	if err != nil {
		return fmt.Errorf("OpenAI API not accessible: %w", err)
	}
	return nil
}
