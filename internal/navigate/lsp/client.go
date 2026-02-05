package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DefaultInitializeTimeout is the timeout for initialize requests
// Some servers like rust-analyzer can take longer on first run
const DefaultInitializeTimeout = 60 * time.Second

// DefaultRequestTimeout is the timeout for regular requests
const DefaultRequestTimeout = 10 * time.Second

// Client is an LSP client that communicates with a language server via stdin/stdout
type Client struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	stderr  io.ReadCloser
	nextID  int64
	pending map[int64]chan *Response
	mu      sync.Mutex
	rootURI string
	ready   bool
	closed  bool
	done    chan struct{}
	config  *ServerConfig
}

// NewClient creates a new LSP client and starts the language server
func NewClient(ctx context.Context, config *ServerConfig, rootPath string) (*Client, error) {
	cmd := exec.CommandContext(ctx, config.Command, config.Args...)
	cmd.Env = os.Environ()
	cmd.Dir = rootPath // Set working directory to project root for proper language server context
	// Create a new process group so we can kill all child processes
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start language server %s: %w", config.Command, err)
	}

	c := &Client{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  bufio.NewReader(stdout),
		stderr:  stderr,
		pending: make(map[int64]chan *Response),
		rootURI: pathToURI(rootPath),
		done:    make(chan struct{}),
		config:  config,
	}

	// Start response reader goroutine
	go c.readResponses()

	// Start stderr drainer to prevent buffer accumulation
	go c.drainStderr()

	return c, nil
}

// drainStderr reads and discards stderr to prevent buffer accumulation
func (c *Client) drainStderr() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-c.done:
			return
		default:
			_, err := c.stderr.Read(buf)
			if err != nil {
				return
			}
		}
	}
}

// Initialize sends the initialize request to the language server
func (c *Client) Initialize(ctx context.Context) error {
	params := InitializeParams{
		ProcessID: os.Getpid(),
		RootURI:   c.rootURI,
		Capabilities: ClientCapabilities{
			TextDocument: TextDocumentClientCapabilities{
				DocumentSymbol: DocumentSymbolClientCapabilities{
					HierarchicalDocumentSymbolSupport: true,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultInitializeTimeout)
	defer cancel()

	resp, err := c.call(ctx, "initialize", params)
	if err != nil {
		return fmt.Errorf("initialize failed: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("initialize error: %s", resp.Error.Message)
	}

	// Send initialized notification
	if err := c.notify("initialized", struct{}{}); err != nil {
		return fmt.Errorf("initialized notification failed: %w", err)
	}

	c.ready = true
	return nil
}

// DidOpen notifies the server that a document was opened
func (c *Client) DidOpen(ctx context.Context, uri, languageID, content string) error {
	params := DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:        uri,
			LanguageID: languageID,
			Version:    1,
			Text:       content,
		},
	}
	return c.notify("textDocument/didOpen", params)
}

// DidClose notifies the server that a document was closed
func (c *Client) DidClose(ctx context.Context, uri string) error {
	params := DidCloseTextDocumentParams{
		TextDocument: TextDocumentIdentifier{
			URI: uri,
		},
	}
	return c.notify("textDocument/didClose", params)
}

// DocumentSymbols requests document symbols from the server
func (c *Client) DocumentSymbols(ctx context.Context, uri string) ([]DocumentSymbol, error) {
	if !c.ready {
		return nil, fmt.Errorf("client not initialized")
	}

	params := DocumentSymbolParams{
		TextDocument: TextDocumentIdentifier{
			URI: uri,
		},
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultRequestTimeout)
	defer cancel()

	resp, err := c.call(ctx, "textDocument/documentSymbol", params)
	if err != nil {
		return nil, fmt.Errorf("documentSymbol failed: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("documentSymbol error: %s", resp.Error.Message)
	}

	// Handle both DocumentSymbol[] and SymbolInformation[] responses
	var symbols []DocumentSymbol
	if err := json.Unmarshal(resp.Result, &symbols); err != nil {
		// Try SymbolInformation format
		var symInfos []SymbolInformation
		if err2 := json.Unmarshal(resp.Result, &symInfos); err2 != nil {
			return nil, fmt.Errorf("failed to parse symbol response: %w (also tried: %v)", err, err2)
		}
		// Convert SymbolInformation to DocumentSymbol
		symbols = make([]DocumentSymbol, len(symInfos))
		for i, info := range symInfos {
			symbols[i] = DocumentSymbol{
				Name:           info.Name,
				Kind:           info.Kind,
				Range:          info.Location.Range,
				SelectionRange: info.Location.Range,
			}
		}
	}

	return symbols, nil
}

// Shutdown sends the shutdown request to the server
func (c *Client) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultRequestTimeout)
	defer cancel()

	resp, err := c.call(ctx, "shutdown", nil)
	if err != nil {
		return fmt.Errorf("shutdown failed: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("shutdown error: %s", resp.Error.Message)
	}

	return nil
}

// Close shuts down the server and cleans up resources
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// Try graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = c.Shutdown(ctx)

	// Send exit notification
	_ = c.notify("exit", nil)

	// Close pipes
	_ = c.stdin.Close()
	_ = c.stderr.Close()

	// Wait for process with timeout
	done := make(chan error, 1)
	go func() {
		done <- c.cmd.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Kill entire process group (negative pid) to ensure child processes are killed
		// This is important for LSP servers like solargraph that spawn child processes
		pgid := c.cmd.Process.Pid
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}

	close(c.done)
	return nil
}

// Ready returns whether the client has been initialized
func (c *Client) Ready() bool {
	return c.ready
}

// Config returns the server configuration
func (c *Client) Config() *ServerConfig {
	return c.config
}

// call sends a request and waits for a response
func (c *Client) call(ctx context.Context, method string, params interface{}) (*Response, error) {
	id := atomic.AddInt64(&c.nextID, 1)

	req := Request{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	respChan := make(chan *Response, 1)
	c.mu.Lock()
	c.pending[id] = respChan
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.send(req); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, fmt.Errorf("client closed")
	}
}

// notify sends a notification (no response expected)
func (c *Client) notify(method string, params interface{}) error {
	notif := Notification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	return c.send(notif)
}

// send writes a message to the server
func (c *Client) send(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.stdin.Write([]byte(header)); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := c.stdin.Write(data); err != nil {
		return fmt.Errorf("failed to write body: %w", err)
	}

	return nil
}

// readResponses continuously reads responses from the server
func (c *Client) readResponses() {
	for {
		select {
		case <-c.done:
			return
		default:
		}

		// Read headers
		var contentLength int
		for {
			line, err := c.stdout.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			if strings.HasPrefix(line, "Content-Length:") {
				lengthStr := strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:"))
				contentLength, _ = strconv.Atoi(lengthStr)
			}
		}

		if contentLength == 0 {
			continue
		}

		// Read body
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(c.stdout, body); err != nil {
			return
		}

		// Parse response
		var resp Response
		if err := json.Unmarshal(body, &resp); err != nil {
			// Might be a notification from server, ignore
			continue
		}

		// If no ID, it's a notification from the server, ignore
		if resp.ID == 0 && resp.Result == nil && resp.Error == nil {
			continue
		}

		// Dispatch to waiting caller
		c.mu.Lock()
		ch, ok := c.pending[resp.ID]
		c.mu.Unlock()

		if ok {
			select {
			case ch <- &resp:
			default:
			}
		}
	}
}

// pathToURI converts a file path to a file:// URI
func pathToURI(path string) string {
	// Ensure absolute path
	if !strings.HasPrefix(path, "/") {
		return "file://" + path
	}
	return "file://" + path
}

// URIToPath converts a file:// URI to a file path
func URIToPath(uri string) string {
	return strings.TrimPrefix(uri, "file://")
}
