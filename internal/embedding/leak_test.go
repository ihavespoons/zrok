package embedding

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// fakeAPIKey is a sentinel value placed into a provider's apiKey field;
// it must never appear in any returned error message.
const fakeAPIKey = "sk-test-NEVER-LEAK-THIS-VALUE-1234567890abcdef"

// roundTripFunc is a small http.RoundTripper adapter for injecting fake
// upstream responses without a real network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// nopCloserReader is a strings.Reader with a no-op Close, suitable for use
// as an http.Response.Body.
type nopCloserReader struct {
	*strings.Reader
}

func (nopCloserReader) Close() error { return nil }

func newBodyReader(s string) *nopCloserReader {
	return &nopCloserReader{Reader: strings.NewReader(s)}
}

// TestOpenAIEmbed_ErrorDoesNotContainAPIKey_NormalError exercises the
// common error path: realistic OpenAI error body that does NOT echo the
// auth header. Verifies the API key is not present in the resulting error.
func TestOpenAIEmbed_ErrorDoesNotContainAPIKey_NormalError(t *testing.T) {
	p := &OpenAIProvider{
		config: &Config{
			Provider:  "openai",
			Model:     "text-embedding-3-small",
			Dimension: 1536,
			BatchSize: 1,
		},
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body := `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}`
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       newBodyReader(body),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Request:    req,
				}, nil
			}),
		},
		apiKey: fakeAPIKey,
	}

	_, err := p.Embed(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error from stub transport returning 401")
	}
	if strings.Contains(err.Error(), fakeAPIKey) {
		t.Errorf("API key leaked in error message: %s", err.Error())
	}
}

// TestOpenAIEmbed_ErrorDoesNotLeakKeyEvenIfUpstreamEchoesIt is the
// stronger guard: even when a hostile/buggy upstream echoes the
// Authorization header into the JSON error.message, the provider must
// redact the key before constructing the error.
func TestOpenAIEmbed_ErrorDoesNotLeakKeyEvenIfUpstreamEchoesIt(t *testing.T) {
	p := &OpenAIProvider{
		config: &Config{
			Provider:  "openai",
			Model:     "text-embedding-3-small",
			Dimension: 1536,
			BatchSize: 1,
		},
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				auth := req.Header.Get("Authorization")
				body := `{"error":{"message":"bad auth: ` + auth + `","type":"auth_error","code":"401"}}`
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       newBodyReader(body),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Request:    req,
				}, nil
			}),
		},
		apiKey: fakeAPIKey,
	}

	_, err := p.Embed(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error from stub transport returning 401")
	}
	if strings.Contains(err.Error(), fakeAPIKey) {
		t.Errorf("API key leaked in error message: %s", err.Error())
	}
	// Sanity: the redaction sentinel should be present in place of the key.
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("expected '[REDACTED]' marker in error after redaction, got: %s", err.Error())
	}
}

// TestOpenAIEmbed_ErrorDoesNotLeakKey_RawBodyPath covers the fallback
// branch in embedBatchInternal: status != 200 and the JSON .error field
// is absent — the provider includes the raw response body in the error.
// Even there the key must be redacted.
func TestOpenAIEmbed_ErrorDoesNotLeakKey_RawBodyPath(t *testing.T) {
	p := &OpenAIProvider{
		config: &Config{
			Provider:  "openai",
			Model:     "text-embedding-3-small",
			Dimension: 1536,
			BatchSize: 1,
		},
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				// Body has no .error field but echoes the auth header (raw HTML/text).
				auth := req.Header.Get("Authorization")
				body := `Internal server error. Request had auth: ` + auth
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       newBodyReader(body),
					Header:     http.Header{"Content-Type": []string{"text/plain"}},
					Request:    req,
				}, nil
			}),
		},
		apiKey: fakeAPIKey,
	}

	_, err := p.Embed(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error from stub transport returning 500")
	}
	if strings.Contains(err.Error(), fakeAPIKey) {
		t.Errorf("API key leaked in error message: %s", err.Error())
	}
}

// TestHuggingFaceEmbed_ErrorDoesNotContainAPIKey is the common-error guard
// for the Hugging Face provider (no auth header echo).
func TestHuggingFaceEmbed_ErrorDoesNotContainAPIKey(t *testing.T) {
	p := &HuggingFaceProvider{
		config: &Config{
			Provider:  "huggingface",
			Model:     "BAAI/bge-small-en-v1.5",
			Dimension: 384,
			BatchSize: 1,
		},
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body := `{"error":"Invalid token provided"}`
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       newBodyReader(body),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Request:    req,
				}, nil
			}),
		},
		apiKey: fakeAPIKey,
	}

	_, err := p.Embed(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error from stub transport returning 401")
	}
	if strings.Contains(err.Error(), fakeAPIKey) {
		t.Errorf("API key leaked in error message: %s", err.Error())
	}
}

// TestHuggingFaceEmbed_ErrorDoesNotLeakKeyEvenIfUpstreamEchoesIt is the
// hostile-upstream guard for the Hugging Face provider.
func TestHuggingFaceEmbed_ErrorDoesNotLeakKeyEvenIfUpstreamEchoesIt(t *testing.T) {
	p := &HuggingFaceProvider{
		config: &Config{
			Provider:  "huggingface",
			Model:     "BAAI/bge-small-en-v1.5",
			Dimension: 384,
			BatchSize: 1,
		},
		client: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				auth := req.Header.Get("Authorization")
				body := `{"error":"unauthorized: ` + auth + `"}`
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       newBodyReader(body),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Request:    req,
				}, nil
			}),
		},
		apiKey: fakeAPIKey,
	}

	_, err := p.Embed(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error from stub transport returning 401")
	}
	if strings.Contains(err.Error(), fakeAPIKey) {
		t.Errorf("API key leaked in error message: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Errorf("expected '[REDACTED]' marker in error after redaction, got: %s", err.Error())
	}
}

// TestRedactSecret_ShortSecretNotRedacted ensures the redactor declines to
// match very short or empty secrets — those would produce spurious matches.
func TestRedactSecret_ShortSecretNotRedacted(t *testing.T) {
	got := redactSecret("the quick brown fox", "the")
	if got != "the quick brown fox" {
		t.Errorf("expected short-secret guard to skip; got %q", got)
	}
	got = redactSecret("the quick brown fox", "")
	if got != "the quick brown fox" {
		t.Errorf("expected empty-secret guard to skip; got %q", got)
	}
}

// TestRedactSecret_NormalSecretIsRedacted ensures the redactor works on
// realistic key lengths.
func TestRedactSecret_NormalSecretIsRedacted(t *testing.T) {
	got := redactSecret("auth=sk-aaaaaaaaaa rest", "sk-aaaaaaaaaa")
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected redaction; got %q", got)
	}
	if strings.Contains(got, "sk-aaaaaaaaaa") {
		t.Errorf("secret survived redaction: %q", got)
	}
}
