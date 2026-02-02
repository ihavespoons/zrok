// zrok Dashboard JavaScript

// Initialize project info
async function loadProjectInfo() {
    try {
        const res = await fetch('/api/project');
        const project = await res.json();
        document.getElementById('project-name').textContent = project.name || 'Unknown Project';
    } catch (err) {
        console.error('Failed to load project info:', err);
    }
}

// Tab handling
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.tab-btn').forEach(b => {
            b.classList.remove('active', 'border-green-500', 'text-green-600');
            b.classList.add('border-transparent', 'text-gray-500');
        });
        this.classList.add('active', 'border-green-500', 'text-green-600');
        this.classList.remove('border-transparent', 'text-gray-500');
    });
});

// Modal handling
function openModal(content) {
    document.getElementById('modal-content').innerHTML = content;
    document.getElementById('modal').classList.remove('hidden');
    document.getElementById('modal').classList.add('flex');
}

function closeModal() {
    document.getElementById('modal').classList.add('hidden');
    document.getElementById('modal').classList.remove('flex');
}

// Close modal on escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});

// Close modal on backdrop click
document.getElementById('modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('modal')) closeModal();
});

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');

    const bgColor = {
        'success': 'bg-green-500',
        'error': 'bg-red-500',
        'warning': 'bg-yellow-500',
        'info': 'bg-blue-500'
    }[type] || 'bg-gray-500';

    toast.className = `toast ${bgColor} text-white px-4 py-3 rounded-lg shadow-lg flex items-center space-x-2`;
    toast.innerHTML = `
        <span>${escapeHtml(message)}</span>
        <button onclick="this.parentElement.remove()" class="ml-2 text-white/80 hover:text-white">&times;</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// HTML escaping
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// View finding detail
async function viewFinding(id) {
    try {
        const res = await fetch(`/partials/finding/${id}`);
        const html = await res.text();
        openModal(html);
    } catch (err) {
        showToast('Failed to load finding details', 'error');
    }
}

// Update finding status
async function updateFindingStatus(id, status) {
    try {
        const res = await fetch(`/api/findings/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status })
        });

        if (res.ok) {
            showToast(`Finding marked as ${status}`, 'success');
            closeModal();
            // Refresh findings list if on findings tab
            refreshIfOnTab('findings');
            refreshStats();
        } else {
            throw new Error('Update failed');
        }
    } catch (err) {
        showToast('Failed to update finding', 'error');
    }
}

// Export findings
async function exportFindings(format) {
    try {
        const res = await fetch('/api/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format })
        });

        if (!res.ok) throw new Error('Export failed');

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `findings.${format === 'sarif' ? 'sarif.json' : format}`;
        a.click();
        URL.revokeObjectURL(url);

        showToast(`Exported findings as ${format.toUpperCase()}`, 'success');
    } catch (err) {
        showToast('Export failed', 'error');
    }
}

// Refresh content if on specific tab
function refreshIfOnTab(tabName) {
    const activeTab = document.querySelector('.tab-btn.active');
    if (activeTab && activeTab.dataset.tab === tabName) {
        htmx.trigger(activeTab, 'click');
    }
}

// Refresh stats
function refreshStats() {
    const statsContainer = document.querySelector('[hx-get="/partials/stats"]');
    if (statsContainer) {
        htmx.trigger(statsContainer, 'refresh');
    }
}

// View memory detail
async function viewMemory(name) {
    try {
        const res = await fetch(`/partials/memory/${encodeURIComponent(name)}`);
        const html = await res.text();
        openModal(html);
    } catch (err) {
        showToast('Failed to load memory details', 'error');
    }
}

// Search memories
function searchMemories() {
    const query = document.getElementById('memory-search').value;
    const typeFilter = document.getElementById('memory-type-filter').value;

    let url = '/partials/memories?';
    if (query) url += `query=${encodeURIComponent(query)}&`;
    if (typeFilter) url += `type=${encodeURIComponent(typeFilter)}`;

    htmx.ajax('GET', url, '#memories-content');
}

// Filter findings
function filterFindings() {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;

    let url = '/partials/findings-list?';
    if (severity) url += `severity=${encodeURIComponent(severity)}&`;
    if (status) url += `status=${encodeURIComponent(status)}`;

    htmx.ajax('GET', url, '#findings-content');
}

// SSE Event handlers
document.body.addEventListener('sse:finding-created', function(evt) {
    showToast('New finding created', 'info');
    refreshIfOnTab('findings');
    refreshIfOnTab('overview');
});

document.body.addEventListener('sse:finding-updated', function(evt) {
    showToast('Finding updated', 'info');
    refreshIfOnTab('findings');
    refreshIfOnTab('overview');
});

document.body.addEventListener('sse:memory-created', function(evt) {
    showToast('New memory created', 'info');
    refreshIfOnTab('memories');
});

// Connection status
let sseConnected = false;

function updateConnectionStatus(connected) {
    const indicator = document.getElementById('connection-status');
    if (connected) {
        indicator.classList.remove('bg-red-500');
        indicator.classList.add('bg-green-500');
        indicator.title = 'Connected';
    } else {
        indicator.classList.remove('bg-green-500');
        indicator.classList.add('bg-red-500');
        indicator.title = 'Disconnected';
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    loadProjectInfo();

    // htmx event handlers for SSE connection status
    document.body.addEventListener('htmx:sseOpen', function() {
        updateConnectionStatus(true);
    });

    document.body.addEventListener('htmx:sseError', function() {
        updateConnectionStatus(false);
    });
});
