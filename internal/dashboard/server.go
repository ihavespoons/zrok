package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/finding/export"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
)

//go:embed static/*
var staticFiles embed.FS

//go:embed templates/*.html
var templateFiles embed.FS

// Server represents the dashboard HTTP server
type Server struct {
	project      *project.Project
	port         int
	findingStore *finding.Store
	memoryStore  *memory.Store
	agentManager *agent.ConfigManager
	templates    *template.Template
	sseClients   map[chan SSEEvent]bool
	sseMu        sync.RWMutex
}

// SSEEvent represents a server-sent event
type SSEEvent struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// NewServer creates a new dashboard server
func NewServer(p *project.Project, port int) *Server {
	s := &Server{
		project:      p,
		port:         port,
		findingStore: finding.NewStore(p),
		memoryStore:  memory.NewStore(p),
		agentManager: agent.NewConfigManager(p, ""),
		sseClients:   make(map[chan SSEEvent]bool),
	}

	// Parse templates with custom functions
	funcs := template.FuncMap{
		"percentage": func(count, total int) int {
			if total == 0 {
				return 0
			}
			return (count * 100) / total
		},
	}

	var err error
	s.templates, err = template.New("").Funcs(funcs).ParseFS(templateFiles, "templates/*.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse templates: %v", err))
	}

	return s
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Static files
	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// HTML partials for htmx
	mux.HandleFunc("/partials/overview", s.handleOverviewPartial)
	mux.HandleFunc("/partials/findings", s.handleFindingsPartial)
	mux.HandleFunc("/partials/findings-list", s.handleFindingsListPartial)
	mux.HandleFunc("/partials/finding/", s.handleFindingDetailPartial)
	mux.HandleFunc("/partials/memories", s.handleMemoriesPartial)
	mux.HandleFunc("/partials/memory/", s.handleMemoryDetailPartial)
	mux.HandleFunc("/partials/agents", s.handleAgentsPartial)
	mux.HandleFunc("/partials/reports", s.handleReportsPartial)

	// API routes
	mux.HandleFunc("/api/project", s.handleProject)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/findings/", s.handleFinding)
	mux.HandleFunc("/api/memories", s.handleMemories)
	mux.HandleFunc("/api/memories/", s.handleMemory)
	mux.HandleFunc("/api/agents", s.handleAgents)
	mux.HandleFunc("/api/agents/", s.handleAgent)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/export", s.handleExport)
	mux.HandleFunc("/api/events", s.handleSSE)

	// Index page
	mux.HandleFunc("/", s.handleIndex)

	return http.ListenAndServe(fmt.Sprintf(":%d", s.port), mux)
}

// Broadcast sends an event to all SSE clients
func (s *Server) Broadcast(event SSEEvent) {
	s.sseMu.RLock()
	defer s.sseMu.RUnlock()

	for client := range s.sseClients {
		select {
		case client <- event:
		default:
			// Client buffer full, skip
		}
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index handler
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data, _ := staticFiles.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// SSE handler
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	client := make(chan SSEEvent, 10)

	s.sseMu.Lock()
	s.sseClients[client] = true
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, client)
		s.sseMu.Unlock()
		close(client)
	}()

	// Send initial connected event
	_, _ = fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	// Keep-alive ticker
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case event := <-client:
			data, _ := json.Marshal(event.Data)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Event, data)
			flusher.Flush()
		}
	}
}

// Partial handlers for htmx
func (s *Server) handleOverviewPartial(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.findingStore.Stats()
	findings, _ := s.findingStore.List(&finding.FilterOptions{Limit: 5})

	data := map[string]interface{}{
		"Stats":          stats,
		"RecentFindings": findings.Findings,
		"Project": map[string]interface{}{
			"Name":      s.project.Config.Name,
			"Path":      s.project.RootPath,
			"TechStack": s.project.Config.TechStack,
		},
	}

	s.renderTemplate(w, "overview", data)
}

func (s *Server) handleFindingsPartial(w http.ResponseWriter, r *http.Request) {
	opts := &finding.FilterOptions{
		Severity: finding.Severity(r.URL.Query().Get("severity")),
		Status:   finding.Status(r.URL.Query().Get("status")),
	}

	result, _ := s.findingStore.List(opts)

	s.renderTemplate(w, "findings", result)
}

func (s *Server) handleFindingsListPartial(w http.ResponseWriter, r *http.Request) {
	opts := &finding.FilterOptions{
		Severity: finding.Severity(r.URL.Query().Get("severity")),
		Status:   finding.Status(r.URL.Query().Get("status")),
	}

	result, _ := s.findingStore.List(opts)

	s.renderTemplate(w, "findings-list", result)
}

func (s *Server) handleFindingDetailPartial(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/partials/finding/")
	if id == "" {
		http.Error(w, "Finding ID required", http.StatusBadRequest)
		return
	}

	f, err := s.findingStore.Read(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.renderTemplate(w, "finding-detail", f)
}

func (s *Server) handleMemoriesPartial(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	typeFilter := memory.MemoryType(r.URL.Query().Get("type"))

	var result *memory.MemoryList
	var err error

	if query != "" {
		result, err = s.memoryStore.Search(query)
	} else {
		result, err = s.memoryStore.List(typeFilter)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.renderTemplate(w, "memories", result)
}

func (s *Server) handleMemoryDetailPartial(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/partials/memory/")
	if name == "" {
		http.Error(w, "Memory name required", http.StatusBadRequest)
		return
	}

	mem, err := s.memoryStore.ReadByName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	s.renderTemplate(w, "memory-detail", mem)
}

func (s *Server) handleAgentsPartial(w http.ResponseWriter, r *http.Request) {
	result, _ := s.agentManager.List()
	s.renderTemplate(w, "agents", result)
}

func (s *Server) handleReportsPartial(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.findingStore.Stats()

	data := map[string]interface{}{
		"Stats": stats,
	}

	s.renderTemplate(w, "reports", data)
}

// API handlers
func (s *Server) handleProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	s.writeJSON(w, map[string]interface{}{
		"name":       s.project.Config.Name,
		"path":       s.project.RootPath,
		"tech_stack": s.project.Config.TechStack,
		"scope":      s.project.Config.SecurityScope,
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		opts := &finding.FilterOptions{
			Severity: finding.Severity(r.URL.Query().Get("severity")),
			Status:   finding.Status(r.URL.Query().Get("status")),
			CWE:      r.URL.Query().Get("cwe"),
		}
		result, err := s.findingStore.List(opts)
		if err != nil {
			s.writeError(w, err, http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, result)

	case http.MethodPost:
		var f finding.Finding
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			s.writeError(w, err, http.StatusBadRequest)
			return
		}
		if err := s.findingStore.Create(&f); err != nil {
			s.writeError(w, err, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		s.writeJSON(w, f)

		// Broadcast event
		s.Broadcast(SSEEvent{Event: "finding-created", Data: map[string]string{"id": f.ID}})

	default:
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/findings/")
	if id == "" {
		s.writeError(w, fmt.Errorf("finding ID required"), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		f, err := s.findingStore.Read(id)
		if err != nil {
			s.writeError(w, err, http.StatusNotFound)
			return
		}
		s.writeJSON(w, f)

	case http.MethodPut:
		var f finding.Finding
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			s.writeError(w, err, http.StatusBadRequest)
			return
		}
		f.ID = id
		if err := s.findingStore.Update(&f); err != nil {
			s.writeError(w, err, http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, f)

		// Broadcast event
		s.Broadcast(SSEEvent{Event: "finding-updated", Data: map[string]string{"id": f.ID}})

	case http.MethodPatch:
		// Partial update (e.g., just status)
		var update map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			s.writeError(w, err, http.StatusBadRequest)
			return
		}

		f, err := s.findingStore.Read(id)
		if err != nil {
			s.writeError(w, err, http.StatusNotFound)
			return
		}

		if status, ok := update["status"].(string); ok {
			f.Status = finding.Status(status)
		}

		if err := s.findingStore.Update(f); err != nil {
			s.writeError(w, err, http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, f)

		// Broadcast event
		s.Broadcast(SSEEvent{Event: "finding-updated", Data: map[string]string{"id": f.ID}})

	case http.MethodDelete:
		if err := s.findingStore.Delete(id); err != nil {
			s.writeError(w, err, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleMemories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	typeFilter := memory.MemoryType(r.URL.Query().Get("type"))
	result, err := s.memoryStore.List(typeFilter)
	if err != nil {
		s.writeError(w, err, http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, result)
}

func (s *Server) handleMemory(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/memories/")
	if name == "" {
		s.writeError(w, fmt.Errorf("memory name required"), http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodGet {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	mem, err := s.memoryStore.ReadByName(name)
	if err != nil {
		s.writeError(w, err, http.StatusNotFound)
		return
	}
	s.writeJSON(w, mem)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	result, err := s.agentManager.List()
	if err != nil {
		s.writeError(w, err, http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, result)
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/agents/")
	if name == "" {
		s.writeError(w, fmt.Errorf("agent name required"), http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodGet {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	agent, err := s.agentManager.Get(name)
	if err != nil {
		s.writeError(w, err, http.StatusNotFound)
		return
	}
	s.writeJSON(w, agent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.findingStore.Stats()
	if err != nil {
		s.writeError(w, err, http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, stats)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, fmt.Errorf("method not allowed"), http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Format = "json"
	}

	result, err := s.findingStore.List(nil)
	if err != nil {
		s.writeError(w, err, http.StatusInternalServerError)
		return
	}

	exporter, err := export.GetExporter(req.Format)
	if err != nil {
		s.writeError(w, err, http.StatusBadRequest)
		return
	}

	data, err := exporter.Export(result.Findings)
	if err != nil {
		s.writeError(w, err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", exporter.ContentType())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings%s", exporter.FileExtension()))
	_, _ = w.Write(data)
}
