package embedding

import (
	"context"
	"fmt"
	"os"
	"strconv"
)

// Provider is the interface for embedding providers
type Provider interface {
	// Name returns the provider name
	Name() string
	// Embed generates an embedding for a single text
	Embed(ctx context.Context, text string) ([]float32, error)
	// EmbedBatch generates embeddings for multiple texts
	EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)
	// Dimension returns the embedding dimension
	Dimension() int
	// Close releases any resources
	Close() error
}

// Config contains configuration for embedding providers
type Config struct {
	// Provider is the provider name: "ollama", "openai", "huggingface"
	Provider string
	// Model is the model name
	Model string
	// Endpoint is the API endpoint (for ollama and custom endpoints)
	Endpoint string
	// APIKeyEnv is the environment variable name for the API key
	APIKeyEnv string
	// Dimension is the embedding dimension (if known)
	Dimension int
	// BatchSize is the maximum batch size for batch operations
	BatchSize int
}

// DefaultConfigs contains default configurations for each provider
// Batch sizes are very conservative to minimize memory pressure
var DefaultConfigs = map[string]*Config{
	"ollama": {
		Provider:  "ollama",
		Model:     "nomic-embed-text",
		Endpoint:  "http://localhost:11434",
		Dimension: 768,
		BatchSize: 64, // Ollama handles large batches well locally
	},
	"openai": {
		Provider:  "openai",
		Model:     "text-embedding-3-small",
		APIKeyEnv: "OPENAI_API_KEY",
		Dimension: 1536,
		BatchSize: 100, // OpenAI handles large batches efficiently
	},
	"huggingface": {
		Provider:  "huggingface",
		Model:     "BAAI/bge-small-en-v1.5",
		APIKeyEnv: "HF_API_KEY",
		Dimension: 384,
		BatchSize: 64, // HuggingFace Inference API handles large batches well
	},
}

// NewProvider creates a new embedding provider based on the config
func NewProvider(config *Config) (Provider, error) {
	switch config.Provider {
	case "ollama":
		return NewOllamaProvider(config)
	case "openai":
		return NewOpenAIProvider(config)
	case "huggingface":
		return NewHuggingFaceProvider(config)
	default:
		return nil, fmt.Errorf("unknown provider: %s", config.Provider)
	}
}

// NewProviderWithDefaults creates a provider using default configuration
func NewProviderWithDefaults(providerName string) (Provider, error) {
	defaultConfig, ok := DefaultConfigs[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	// Copy default config
	config := *defaultConfig

	return NewProvider(&config)
}

// GetAPIKey retrieves an API key from the environment
func GetAPIKey(envVar string) (string, error) {
	key := os.Getenv(envVar)
	if key == "" {
		return "", fmt.Errorf("environment variable %s not set", envVar)
	}
	return key, nil
}

// AvailableProviders returns a list of available providers
func AvailableProviders() []string {
	return []string{"ollama", "openai", "huggingface"}
}

// ValidateConfig validates a provider configuration
func ValidateConfig(config *Config) error {
	if config.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	switch config.Provider {
	case "ollama":
		if config.Endpoint == "" {
			config.Endpoint = DefaultConfigs["ollama"].Endpoint
		}
		if config.Model == "" {
			config.Model = DefaultConfigs["ollama"].Model
		}
	case "openai":
		if config.APIKeyEnv == "" {
			config.APIKeyEnv = DefaultConfigs["openai"].APIKeyEnv
		}
		if _, err := GetAPIKey(config.APIKeyEnv); err != nil {
			return fmt.Errorf("OpenAI API key not configured: %w", err)
		}
		if config.Model == "" {
			config.Model = DefaultConfigs["openai"].Model
		}
	case "huggingface":
		if config.APIKeyEnv == "" {
			config.APIKeyEnv = DefaultConfigs["huggingface"].APIKeyEnv
		}
		if _, err := GetAPIKey(config.APIKeyEnv); err != nil {
			return fmt.Errorf("hugging face API key not configured: %w", err)
		}
		if config.Model == "" {
			config.Model = DefaultConfigs["huggingface"].Model
		}
	default:
		return fmt.Errorf("unknown provider: %s", config.Provider)
	}

	if config.Dimension == 0 {
		defaultConfig, ok := DefaultConfigs[config.Provider]
		if ok {
			config.Dimension = defaultConfig.Dimension
		}
	}

	if config.BatchSize == 0 {
		defaultConfig, ok := DefaultConfigs[config.Provider]
		if ok {
			config.BatchSize = defaultConfig.BatchSize
		} else {
			config.BatchSize = 16
		}
	}

	// Allow env var override for batch size (ZROK_PROVIDER_BATCH_SIZE)
	if envVal := os.Getenv("ZROK_PROVIDER_BATCH_SIZE"); envVal != "" {
		if size, err := strconv.Atoi(envVal); err == nil && size > 0 {
			config.BatchSize = size
		}
	}

	return nil
}
