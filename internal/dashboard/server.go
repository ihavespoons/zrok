package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/finding/export"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
)

// Server represents the dashboard HTTP server
type Server struct {
	project      *project.Project
	port         int
	findingStore *finding.Store
	memoryStore  *memory.Store
	agentManager *agent.ConfigManager
}

// NewServer creates a new dashboard server
func NewServer(p *project.Project, port int) *Server {
	return &Server{
		project:      p,
		port:         port,
		findingStore: finding.NewStore(p),
		memoryStore:  memory.NewStore(p),
		agentManager: agent.NewConfigManager(p, ""),
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/project", s.handleProject)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/findings/", s.handleFinding)
	mux.HandleFunc("/api/memories", s.handleMemories)
	mux.HandleFunc("/api/memories/", s.handleMemory)
	mux.HandleFunc("/api/agents", s.handleAgents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/export", s.handleExport)

	// Static files and frontend
	mux.HandleFunc("/", s.handleIndex)

	return http.ListenAndServe(fmt.Sprintf(":%d", s.port), mux)
}

func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

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
	w.Write(data)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>zrok Dashboard</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .severity-critical { background-color: #dc2626; }
        .severity-high { background-color: #ea580c; }
        .severity-medium { background-color: #ca8a04; }
        .severity-low { background-color: #16a34a; }
        .severity-info { background-color: #2563eb; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <nav class="bg-gray-900 text-white p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold">zrok Dashboard</h1>
            <div id="project-name" class="text-gray-400"></div>
        </div>
    </nav>

    <main class="container mx-auto p-4">
        <!-- Stats Cards -->
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <div class="bg-white rounded-lg shadow p-4 text-center">
                <div class="text-3xl font-bold" id="stat-total">-</div>
                <div class="text-gray-500">Total</div>
            </div>
            <div class="bg-white rounded-lg shadow p-4 text-center">
                <div class="text-3xl font-bold text-red-600" id="stat-critical">-</div>
                <div class="text-gray-500">Critical</div>
            </div>
            <div class="bg-white rounded-lg shadow p-4 text-center">
                <div class="text-3xl font-bold text-orange-600" id="stat-high">-</div>
                <div class="text-gray-500">High</div>
            </div>
            <div class="bg-white rounded-lg shadow p-4 text-center">
                <div class="text-3xl font-bold text-yellow-600" id="stat-medium">-</div>
                <div class="text-gray-500">Medium</div>
            </div>
            <div class="bg-white rounded-lg shadow p-4 text-center">
                <div class="text-3xl font-bold text-green-600" id="stat-low">-</div>
                <div class="text-gray-500">Low</div>
            </div>
        </div>

        <!-- Filters -->
        <div class="bg-white rounded-lg shadow p-4 mb-4">
            <div class="flex flex-wrap gap-4">
                <select id="filter-severity" class="border rounded px-3 py-2" onchange="loadFindings()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select id="filter-status" class="border rounded px-3 py-2" onchange="loadFindings()">
                    <option value="">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="false_positive">False Positive</option>
                    <option value="fixed">Fixed</option>
                </select>
                <button onclick="exportFindings('sarif')" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                    Export SARIF
                </button>
                <button onclick="exportFindings('json')" class="bg-gray-600 text-white px-4 py-2 rounded hover:bg-gray-700">
                    Export JSON
                </button>
            </div>
        </div>

        <!-- Findings List -->
        <div class="bg-white rounded-lg shadow">
            <div id="findings-list" class="divide-y">
                <div class="p-8 text-center text-gray-500">Loading...</div>
            </div>
        </div>

        <!-- Finding Detail Modal -->
        <div id="modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50">
            <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
                <div class="p-6" id="modal-content"></div>
            </div>
        </div>
    </main>

    <script>
        let project = {};
        let findings = [];

        async function init() {
            // Load project info
            const projectRes = await fetch('/api/project');
            project = await projectRes.json();
            document.getElementById('project-name').textContent = project.name;

            // Load stats
            await loadStats();

            // Load findings
            await loadFindings();
        }

        async function loadStats() {
            const res = await fetch('/api/stats');
            const stats = await res.json();
            document.getElementById('stat-total').textContent = stats.total;
            document.getElementById('stat-critical').textContent = stats.by_severity?.critical || 0;
            document.getElementById('stat-high').textContent = stats.by_severity?.high || 0;
            document.getElementById('stat-medium').textContent = stats.by_severity?.medium || 0;
            document.getElementById('stat-low').textContent = stats.by_severity?.low || 0;
        }

        async function loadFindings() {
            const severity = document.getElementById('filter-severity').value;
            const status = document.getElementById('filter-status').value;

            let url = '/api/findings?';
            if (severity) url += 'severity=' + severity + '&';
            if (status) url += 'status=' + status;

            const res = await fetch(url);
            const data = await res.json();
            findings = data.findings || [];

            renderFindings();
        }

        function renderFindings() {
            const container = document.getElementById('findings-list');

            if (findings.length === 0) {
                container.innerHTML = '<div class="p-8 text-center text-gray-500">No findings</div>';
                return;
            }

            container.innerHTML = findings.map(f => ` + "`" + `
                <div class="p-4 hover:bg-gray-50 cursor-pointer" onclick="showFinding('${f.id}')">
                    <div class="flex items-center gap-3">
                        <span class="severity-${f.severity} text-white text-xs px-2 py-1 rounded uppercase font-bold">
                            ${f.severity}
                        </span>
                        <span class="font-medium flex-1">${f.title}</span>
                        <span class="text-gray-500 text-sm">${f.status}</span>
                    </div>
                    <div class="text-gray-500 text-sm mt-1">
                        ${f.location.file}:${f.location.line_start}
                        ${f.cwe ? '• ' + f.cwe : ''}
                    </div>
                </div>
            ` + "`" + `).join('');
        }

        async function showFinding(id) {
            const res = await fetch('/api/findings/' + id);
            const f = await res.json();

            document.getElementById('modal-content').innerHTML = ` + "`" + `
                <div class="flex justify-between items-start mb-4">
                    <div>
                        <span class="severity-${f.severity} text-white text-xs px-2 py-1 rounded uppercase font-bold mr-2">
                            ${f.severity}
                        </span>
                        <span class="text-gray-500">${f.id}</span>
                    </div>
                    <button onclick="closeModal()" class="text-gray-500 hover:text-gray-700">&times;</button>
                </div>
                <h2 class="text-xl font-bold mb-4">${f.title}</h2>

                <div class="grid grid-cols-2 gap-4 mb-4 text-sm">
                    <div><span class="text-gray-500">Status:</span> ${f.status}</div>
                    <div><span class="text-gray-500">Confidence:</span> ${f.confidence}</div>
                    ${f.cwe ? '<div><span class="text-gray-500">CWE:</span> ' + f.cwe + '</div>' : ''}
                    ${f.cvss ? '<div><span class="text-gray-500">CVSS:</span> ' + f.cvss.score + '</div>' : ''}
                </div>

                <div class="mb-4">
                    <h3 class="font-medium mb-2">Location</h3>
                    <code class="bg-gray-100 px-2 py-1 rounded text-sm">
                        ${f.location.file}:${f.location.line_start}${f.location.line_end ? '-' + f.location.line_end : ''}
                    </code>
                    ${f.location.function ? '<div class="text-sm text-gray-500 mt-1">Function: ' + f.location.function + '</div>' : ''}
                </div>

                ${f.location.snippet ? '<div class="mb-4"><h3 class="font-medium mb-2">Code</h3><pre class="bg-gray-900 text-gray-100 p-3 rounded text-sm overflow-x-auto">' + escapeHtml(f.location.snippet) + '</pre></div>' : ''}

                ${f.description ? '<div class="mb-4"><h3 class="font-medium mb-2">Description</h3><p class="text-gray-700">' + f.description + '</p></div>' : ''}

                ${f.impact ? '<div class="mb-4"><h3 class="font-medium mb-2">Impact</h3><p class="text-gray-700">' + f.impact + '</p></div>' : ''}

                ${f.remediation ? '<div class="mb-4"><h3 class="font-medium mb-2">Remediation</h3><p class="text-gray-700">' + f.remediation + '</p></div>' : ''}

                <div class="flex gap-2 mt-6">
                    <button onclick="updateStatus('${f.id}', 'confirmed')" class="bg-green-600 text-white px-3 py-1 rounded text-sm">Confirm</button>
                    <button onclick="updateStatus('${f.id}', 'false_positive')" class="bg-red-600 text-white px-3 py-1 rounded text-sm">False Positive</button>
                    <button onclick="updateStatus('${f.id}', 'fixed')" class="bg-blue-600 text-white px-3 py-1 rounded text-sm">Mark Fixed</button>
                </div>
            ` + "`" + `;

            document.getElementById('modal').classList.remove('hidden');
            document.getElementById('modal').classList.add('flex');
        }

        function closeModal() {
            document.getElementById('modal').classList.add('hidden');
            document.getElementById('modal').classList.remove('flex');
        }

        async function updateStatus(id, status) {
            const f = findings.find(f => f.id === id);
            if (!f) return;

            f.status = status;
            await fetch('/api/findings/' + id, {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(f)
            });

            closeModal();
            loadFindings();
            loadStats();
        }

        async function exportFindings(format) {
            const res = await fetch('/api/export', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({format})
            });

            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'findings.' + (format === 'sarif' ? 'sarif' : format);
            a.click();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Close modal on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        // Close modal on backdrop click
        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target === document.getElementById('modal')) closeModal();
        });

        init();
    </script>
</body>
</html>`
