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

const huggingFaceInferenceURL = "https://router.huggingface.co/hf-inference/models/"

// HuggingFaceProvider implements Provider using Hugging Face's Inference API
type HuggingFaceProvider struct {
	config *Config
	client *http.Client
	apiKey string
}

// huggingFaceRequest is the request format for Hugging Face embeddings
type huggingFaceRequest struct {
	Inputs  interface{}            `json:"inputs"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// NewHuggingFaceProvider creates a new Hugging Face embedding provider
func NewHuggingFaceProvider(config *Config) (*HuggingFaceProvider, error) {
	apiKeyEnv := config.APIKeyEnv
	if apiKeyEnv == "" {
		apiKeyEnv = "HF_API_KEY"
	}

	apiKey, err := GetAPIKey(apiKeyEnv)
	if err != nil {
		return nil, err
	}

	model := config.Model
	if model == "" {
		model = "BAAI/bge-small-en-v1.5"
	}

	dimension := config.Dimension
	if dimension == 0 {
		// Set default dimension based on common models
		switch model {
		case "BAAI/bge-small-en-v1.5":
			dimension = 384
		case "BAAI/bge-base-en-v1.5":
			dimension = 768
		case "BAAI/bge-large-en-v1.5":
			dimension = 1024
		case "sentence-transformers/all-MiniLM-L6-v2":
			dimension = 384
		case "sentence-transformers/all-mpnet-base-v2":
			dimension = 768
		default:
			dimension = 384
		}
	}

	batchSize := config.BatchSize
	if batchSize == 0 {
		batchSize = 32
	}

	// Configure transport with strict limits to prevent memory accumulation
	transport := &http.Transport{
		MaxIdleConns:        1,              // Minimize idle connection pool
		MaxIdleConnsPerHost: 1,              // Only 1 idle conn per host
		MaxConnsPerHost:     2,              // Limit concurrent connections
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,          // Keep-alive is fine, just limit pool
		ForceAttemptHTTP2:   false,          // HTTP/1.1 is simpler
	}

	return &HuggingFaceProvider{
		config: &Config{
			Provider:  "huggingface",
			Model:     model,
			APIKeyEnv: apiKeyEnv,
			Dimension: dimension,
			BatchSize: batchSize,
		},
		client: &http.Client{
			Timeout:   120 * time.Second, // HF can be slow on cold starts
			Transport: transport,
		},
		apiKey: apiKey,
	}, nil
}

// Name returns the provider name
func (p *HuggingFaceProvider) Name() string {
	return "huggingface"
}

// Dimension returns the embedding dimension
func (p *HuggingFaceProvider) Dimension() int {
	return p.config.Dimension
}

// Embed generates an embedding for a single text
func (p *HuggingFaceProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	embeddings, err := p.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	return embeddings[0], nil
}

// EmbedBatch generates embeddings for multiple texts
func (p *HuggingFaceProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
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

func (p *HuggingFaceProvider) embedBatchInternal(ctx context.Context, texts []string) ([][]float32, error) {
	var input interface{}
	if len(texts) == 1 {
		input = texts[0]
	} else {
		input = texts
	}

	reqBody := huggingFaceRequest{
		Inputs: input,
		Options: map[string]interface{}{
			"wait_for_model": true,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := huggingFaceInferenceURL + p.config.Model
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Hugging Face: %w", err)
	}
	defer func() {
		// Drain any remaining body to allow connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error message
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			body = nil // Release memory
			return nil, fmt.Errorf("hugging face API error: %s", errResp.Error)
		}
		errMsg := fmt.Errorf("hugging face API error (status %d): %s", resp.StatusCode, string(body))
		body = nil // Release memory
		return nil, errMsg
	}

	// Parse response - could be single embedding or batch
	embeddings, err := p.parseResponse(body, len(texts))
	body = nil // Release response body memory after parsing
	if err != nil {
		return nil, err
	}

	return embeddings, nil
}

func (p *HuggingFaceProvider) parseResponse(body []byte, expectedCount int) ([][]float32, error) {
	// Try to parse as 2D array (batch response)
	var batchResponse [][]float64
	if err := json.Unmarshal(body, &batchResponse); err == nil {
		embeddings := make([][]float32, len(batchResponse))
		for i, emb := range batchResponse {
			embeddings[i] = convertFloat64ToFloat32(emb)
		}
		return embeddings, nil
	}

	// Try to parse as 1D array (single response)
	var singleResponse []float64
	if err := json.Unmarshal(body, &singleResponse); err == nil {
		return [][]float32{convertFloat64ToFloat32(singleResponse)}, nil
	}

	// Try to parse as nested array with token-level embeddings (need to pool)
	var nestedResponse [][][]float64
	if err := json.Unmarshal(body, &nestedResponse); err == nil {
		embeddings := make([][]float32, len(nestedResponse))
		for i, tokenEmbeddings := range nestedResponse {
			// Mean pooling over tokens
			embeddings[i] = p.meanPool(tokenEmbeddings)
		}
		return embeddings, nil
	}

	// Try single nested (token-level for single input)
	var singleNested [][]float64
	if err := json.Unmarshal(body, &singleNested); err == nil {
		return [][]float32{p.meanPool(singleNested)}, nil
	}

	return nil, fmt.Errorf("failed to parse response: unexpected format")
}

// meanPool performs mean pooling over token embeddings
func (p *HuggingFaceProvider) meanPool(tokenEmbeddings [][]float64) []float32 {
	if len(tokenEmbeddings) == 0 {
		return nil
	}

	dim := len(tokenEmbeddings[0])
	pooled := make([]float32, dim)

	for _, tokenEmb := range tokenEmbeddings {
		for i, v := range tokenEmb {
			if i < dim {
				pooled[i] += float32(v)
			}
		}
	}

	n := float32(len(tokenEmbeddings))
	for i := range pooled {
		pooled[i] /= n
	}

	return pooled
}

// Close releases resources
func (p *HuggingFaceProvider) Close() error {
	return nil
}

// CheckAvailable checks if Hugging Face API is accessible
func (p *HuggingFaceProvider) CheckAvailable(ctx context.Context) error {
	// Try to get a very small embedding to verify API access
	_, err := p.Embed(ctx, "test")
	if err != nil {
		return fmt.Errorf("hugging face API not accessible: %w", err)
	}
	return nil
}

// convertFloat64ToFloat32 converts a slice of float64 to float32
func convertFloat64ToFloat32(input []float64) []float32 {
	output := make([]float32, len(input))
	for i, v := range input {
		output[i] = float32(v)
	}
	return output
}
