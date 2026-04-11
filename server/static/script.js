const API_BASE = "/api";

let editDeployments = [];
let isLogPaused = false;
let attackMapInstance = null;
let _serverInfoCache = null;

/**
 * Fetch server info (Kibana URL, etc.) from the API.
 * Results are cached to avoid repeated requests.
 */
async function getServerInfo() {
    if (_serverInfoCache) return _serverInfoCache;
    try {
        const resp = await fetch(`${API_BASE}/server_info`);
        _serverInfoCache = await resp.json();
    } catch (e) {
        // Fallback: auto-detect from current hostname
        _serverInfoCache = {
            kibana_url: `http://${window.location.hostname}:5601`,
            server_url: window.location.origin,
        };
    }
    return _serverInfoCache;
}

/**
 * Open the ELK/Kibana dashboard in a new tab.
 * Dynamically resolves the URL so it works on both localhost and EC2.
 */
async function openElkDashboard() {
    const info = await getServerInfo();
    window.open(info.kibana_url, '_blank');
}

// Theme System
let currentTheme = localStorage.getItem('aps_theme') || 'system';

function applyTheme(theme) {
    const isDarkOS = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const finalTheme = theme === 'system' ? (isDarkOS ? 'dark' : 'light') : theme;
    
    document.documentElement.setAttribute('data-theme', finalTheme);
    
    const iconEl = document.getElementById('theme-icon');
    if (iconEl && window.lucide) {
        if (theme === 'dark') iconEl.setAttribute('data-lucide', 'moon');
        else if (theme === 'light') iconEl.setAttribute('data-lucide', 'sun');
        else iconEl.setAttribute('data-lucide', 'monitor');
        lucide.createIcons({
            nameAttr: 'data-lucide',
            attrs: {
                class: "lucide"
            }
        });
    }
}

function toggleTheme() {
    const sequence = ['dark', 'light', 'system'];
    let nextIndex = (sequence.indexOf(currentTheme) + 1) % sequence.length;
    currentTheme = sequence[nextIndex];
    localStorage.setItem('aps_theme', currentTheme);
    applyTheme(currentTheme);
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (currentTheme === 'system') applyTheme('system');
});

// Wrap fetch to handle 401 (session expired) globally
const _originalFetch = window.fetch;
window.fetch = async function (...args) {
    const response = await _originalFetch.apply(this, args);
    if (response.status === 401) {
        window.location.href = "/login";
    }
    return response;
};

const Toast = {
    container: null,

    init() {
        this.container = document.getElementById("toast-container");
    },

    show(message, type = "info", duration = 4000) {
        if (!this.container) return;
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-message">${escapeHtml(message)}</span>
            <button class="toast-close" onclick="Toast.dismiss(this.parentElement)">x</button>
        `;
        this.container.appendChild(toast);
        setTimeout(() => this.dismiss(toast), duration);
    },

    dismiss(toast) {
        if (toast?.parentElement) toast.remove();
    },

    success(message) { this.show(message, "success"); },
    error(message) { this.show(message, "error", 6000); },
    info(message) { this.show(message, "info"); }
};

function escapeHtml(text) {
    if (text === null || text === undefined) return "";
    const div = document.createElement("div");
    div.textContent = String(text);
    return div.innerHTML;
}

function showSection(sectionId) {
    document.querySelectorAll(".content-section").forEach((item) => item.classList.add("hidden"));
    document.getElementById(sectionId)?.classList.remove("hidden");
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
    document.querySelector(`.nav-item[data-section="${sectionId}"]`)?.classList.add("active");

    if (sectionId === "dashboard") refreshData();
    if (sectionId === "agents") loadAgents();
    if (sectionId === "logs") loadLogConsole();
    // Attack Map lifecycle
    if (sectionId === "attackmap") {
        if (!attackMapInstance) {
            attackMapInstance = new AttackMap("attackmap-container");
        }
        attackMapInstance.start();
    } else {
        if (attackMapInstance) attackMapInstance.stop();
    }

    lucide.createIcons();
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

function normalizeConfigForUi(config) {
    return Array.isArray(config.deployments) ? config.deployments.map((deployment, index) => ({
        id: deployment.id || `deployment-${index + 1}`,
        name: deployment.name || `Deployment ${index + 1}`,
        type: deployment.type || deployment.template || "custom",
        template: deployment.template || deployment.type || "custom",
        enabled: deployment.enabled !== false,
        source_dir: deployment.source_dir || deployment.id || `deployment-${index + 1}`,
        log_paths: Array.isArray(deployment.log_paths) ? clone(deployment.log_paths) : [],
        files: Array.isArray(deployment.files) ? clone(deployment.files) : []
    })) : [];
}

async function refreshData() {
    try {
        await Promise.all([loadStats(), loadAgents(true)]);
    } catch (_error) {
        Toast.error("Failed to refresh dashboard data");
    }
}

async function loadStats() {
    const agents = await fetch(`${API_BASE}/agents`).then((response) => response.json());
    
    const countElem = document.getElementById("active-agents-count");
    if (countElem) countElem.textContent = agents.filter((agent) => agent.status === "Online").length;
    
    const logsReq = fetch(`${API_BASE}/recent_logs`).then(r => r.json()).catch(() => []);
    logsReq.then(logs => {
        const totalElem = document.getElementById("total-logs-count");
        if (totalElem) totalElem.textContent = logs.length;
        const alertsElem = document.getElementById("alerts-count");
        if (alertsElem) alertsElem.textContent = logs.filter((log) => log.protocol === "modbus").length;
    });
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "--:--:--";
    return date.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
    });
}

function formatRelativeTime(date) {
    if (!(date instanceof Date) || Number.isNaN(date.getTime())) return "unknown";
    const diff = Math.floor((Date.now() - date.getTime()) / 1000);
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return date.toLocaleDateString();
}

function parseMetadata(metadata) {
    if (!metadata) return {};
    if (typeof metadata === "object") return metadata;
    try {
        return JSON.parse(metadata);
    } catch (_error) {
        return {};
    }
}

function buildLogSummary(log, metadata) {
    if (log.protocol === "http") {
        return `${metadata["log.message"] || metadata["http.method"] || "HTTP request"}`;
    }
    if (log.protocol === "mqtt") {
        return `${metadata["log.message"] || metadata["mqtt.packet_type_name"] || metadata["mqtt.message"] || "MQTT event"}`;
    }
    return `${metadata["log.message"] || metadata["modbus.function_name"] || metadata["modbus.func_name"] || "Interaction"}`;
}

function formatActivity(log) {
    const metadata = parseMetadata(log.metadata);
    return escapeHtml(buildLogSummary(log, metadata));
}

function renderNetworkTopology(agents) {
    const container = document.getElementById("topology-container");
    const emptyState = document.getElementById("topology-empty");
    if (!container) return;
    
    if (!agents || !agents.length) {
        container.innerHTML = `
            <div class="table-empty-state" id="topology-empty">
                <i data-lucide="inbox"></i>
                <p>No nodes registered yet</p>
            </div>
        `;
        lucide.createIcons();
        return;
    }
    
    if (emptyState) emptyState.classList.add("hidden");
    
    let html = `
        <div class="topology-server-node">
            <div class="node-content server">
                <i data-lucide="server"></i>
                <div class="node-info">
                    <span class="node-title">APS Server</span>
                    <span class="node-subtitle text-success">Online</span>
                </div>
            </div>
            <div class="topology-children">
    `;
    
    agents.forEach(agent => {
        const isOnline = agent.status === "Online";
        const statusClass = isOnline ? "online" : "offline";
        const statusText = isOnline ? "Active" : "Disconnected";
        
        let childrenHtml = '';
        if (agent.runtime_status && Object.keys(agent.runtime_status).length > 0) {
            childrenHtml = `<div class="topology-children">`;
            Object.entries(agent.runtime_status).forEach(([depId, status]) => {
                const isActive = status.state === "running";
                const depClass = isActive ? "running" : "stopped";
                childrenHtml += `
                    <div class="topology-node">
                        <div class="node-content honeypot">
                            <i data-lucide="box"></i>
                            <div class="node-info">
                                <span class="node-title" title="${escapeHtml(depId)}">${escapeHtml(depId)}</span>
                                <span class="node-subtitle text-${isActive ? 'success' : 'muted'}" title="${escapeHtml(status.template || 'honeypot')}">${escapeHtml(status.template || 'honeypot')}</span>
                            </div>
                            <span class="node-badge ${depClass}"></span>
                        </div>
                    </div>
                `;
            });
            childrenHtml += `</div>`;
        }
        
        html += `
            <div class="topology-node">
                <div class="node-content client">
                    <i data-lucide="cpu"></i>
                    <div class="node-info">
                        <span class="node-title" title="${escapeHtml(agent.name || agent.node_id)}">${escapeHtml(agent.name || agent.node_id)}</span>
                        <span class="node-subtitle ${isOnline ? 'text-success' : 'text-danger'}" title="${statusText}">${statusText}</span>
                    </div>
                    <span class="node-badge ${statusClass}"></span>
                </div>
                ${childrenHtml}
            </div>
        `;
    });
    
    html += `
            </div>
        </div>
    `;
    
    container.innerHTML = `
        <div class="table-empty-state hidden" id="topology-empty">
            <i data-lucide="inbox"></i>
            <p>No nodes registered yet</p>
        </div>
    ` + html;
    lucide.createIcons();
}

async function loadLogConsole() {
    if (isLogPaused) return;
    const logs = await fetch(`${API_BASE}/recent_logs`).then((response) => response.json());
    const consoleEl = document.getElementById("log-console");
    consoleEl.innerHTML = "";

    if (!logs.length) {
        consoleEl.innerHTML = '<div class="log-entry info"><span class="log-time">[System]</span><span class="log-message">Waiting for logs...</span></div>';
        return;
    }

    logs.slice().reverse().forEach((log) => {
        const metadata = parseMetadata(log.metadata);
        const summary = `${log.node_id} ${log.protocol} ${buildLogSummary(log, metadata)}`;
        const entry = document.createElement("div");
        entry.className = "log-entry info";
        entry.innerHTML = `<span class="log-time">[${formatTime(log.timestamp)}]</span><span class="log-message">${escapeHtml(summary)}</span>`;
        consoleEl.appendChild(entry);
    });
}

async function loadAgents(isDashboardUpdate = false) {
    try {
        const agents = await fetch(`${API_BASE}/agents`).then((response) => response.json());
        
        const dashboardVisible = !document.getElementById("dashboard")?.classList.contains("hidden");
        if (dashboardVisible || isDashboardUpdate) {
            renderNetworkTopology(agents);
        }
        
        const grid = document.getElementById("agents-grid");
        if (!grid) return;
        grid.innerHTML = "";

        if (!agents.length) {
            grid.innerHTML = '<div class="empty-state"><i data-lucide="cpu"></i><p>No agents registered yet.</p></div>';
            lucide.createIcons();
            return;
        }

        agents.forEach((agent) => {
            const statuses = Object.entries(agent.runtime_status || {});
            const runtimeHtml = statuses.length ? statuses.map(([deploymentId, status]) => {
                const stateClass = escapeHtml(status.state || "unknown");
                return `
                    <div class="runtime-tag ${stateClass}">
                        <div class="pulse-dot"></div>
                        <strong>${escapeHtml(deploymentId)}</strong> · ${escapeHtml(status.template || "package")}
                    </div>
                `;
            }).join("") : '<div class="runtime-tag stopped"><div class="pulse-dot"></div><strong>idle</strong> · No deployments</div>';

            const isOnline = agent.status === "Online";

            const card = document.createElement("div");
            card.className = "agent-row";
            card.innerHTML = `
                <div class="agent-row-header">
                    <!-- Left Section: Identity -->
                    <div class="agent-identity">
                        <div class="agent-icon-wrap">
                            <i data-lucide="cpu"></i>
                            <div class="agent-status-dot ${isOnline ? "online" : "offline"}" title="${isOnline ? "Online" : "Offline"}"></div>
                        </div>
                        <div class="agent-title">
                            <h3 title="${escapeHtml(agent.name || agent.node_id)}">${escapeHtml(agent.name || agent.node_id)}</h3>
                            <div class="agent-title-meta">
                                <i data-lucide="map-pin" style="width:14px;height:14px;"></i>
                                <span title="IP Address">${escapeHtml(agent.ip || "0.0.0.0")}</span>
                            </div>
                        </div>
                    </div>

                    <!-- Middle Section: Attributes -->
                    <div class="agent-attributes">
                        <div class="agent-attr">
                            <span class="agent-attr-label">Node ID</span>
                            <div class="agent-attr-val">
                                <code title="${escapeHtml(agent.node_id)}">${escapeHtml(agent.node_id)}</code>
                                <button class="btn-copy" onclick='window.navigator.clipboard.writeText(${JSON.stringify(agent.node_id)});' title="Copy Node ID">
                                    <i data-lucide="copy"></i>
                                </button>
                            </div>
                        </div>
                        <div class="agent-attr">
                            <span class="agent-attr-label">Last Seen</span>
                            <span class="agent-attr-val">${formatRelativeTime(new Date(agent.last_heartbeat))}</span>
                        </div>
                        <div class="agent-attr">
                            <span class="agent-attr-label">Active</span>
                            <label class="switch" style="margin-top:2px;">
                                <input type="checkbox" ${agent.is_active ? "checked" : ""} onchange='toggleAgent(${JSON.stringify(agent.node_id)}, this.checked)'>
                                <span class="slider"></span>
                            </label>
                        </div>
                    </div>

                    <!-- Right Section: Actions -->
                    <div class="agent-actions">
                        <button class="btn btn-secondary btn-sm" onclick='window.location.href="/config/" + encodeURIComponent(${JSON.stringify(agent.node_id)})'>
                            <i data-lucide="settings"></i> Config
                        </button>
                        <button class="btn btn-warning btn-sm" onclick='resetAgent(${JSON.stringify(agent.node_id)})' title="Factory Reset">
                            <i data-lucide="rotate-ccw"></i>
                        </button>
                        <button class="btn btn-danger btn-sm" onclick='deleteAgent(${JSON.stringify(agent.node_id)})' title="Delete">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </div>

                <!-- Bottom Section: Deployments -->
                <div class="agent-deployments">
                    <span class="deployments-label">Deployments:</span>
                    ${runtimeHtml}
                </div>
            `;
            grid.appendChild(card);
        });
        lucide.createIcons();
    } catch (_error) {
        Toast.error("Failed to load agents");
    }
}

async function toggleAgent(nodeId, isActive) {
    try {
        await fetch(`${API_BASE}/agents/${nodeId}/toggle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ is_active: isActive })
        });
        Toast.success(`Agent ${isActive ? "activated" : "deactivated"}`);
        loadAgents();
    } catch (_error) {
        Toast.error("Failed to toggle agent state");
    }
}

async function resetAgent(nodeId) {
    if (!confirm(`Factory reset agent ${nodeId}? The server will forget this agent and it can re-register as new.`)) return;
    try {
        await fetch(`${API_BASE}/agents/${nodeId}/reset`, { method: "POST" });
        Toast.success("Agent factory reset - server has forgotten the agent");
        loadAgents();
    } catch (_error) {
        Toast.error("Failed to reset agent");
    }
}

async function deleteAgent(nodeId) {
    if (!confirm(`Delete agent ${nodeId}? This action cannot be undone.`)) return;
    try {
        await fetch(`${API_BASE}/agents/${nodeId}`, { method: "DELETE" });
        Toast.success("Agent deleted");
        loadAgents();
    } catch (_error) {
        Toast.error("Failed to delete agent");
    }
}


function toggleLogPause() {
    isLogPaused = !isLogPaused;
    document.getElementById("log-pause-btn").innerHTML = isLogPaused
        ? '<i data-lucide="play"></i><span>Resume</span>'
        : '<i data-lucide="pause"></i><span>Pause</span>';
    document.getElementById("console-status").innerHTML = isLogPaused
        ? '<span class="status-dot paused"></span>Paused'
        : '<span class="status-dot streaming"></span>Streaming';
    if (!isLogPaused) loadLogConsole();
    lucide.createIcons();
}

function clearLogConsole() {
    document.getElementById("log-console").innerHTML = '<div class="log-entry info"><span class="log-time">[System]</span><span class="log-message">Console cleared</span></div>';
}

Object.assign(window, {
    Toast,
    showSection,
    refreshData,
    loadAgents,
    loadLogConsole,
    toggleAgent,
    resetAgent,
    deleteAgent,
    toggleLogPause,
    clearLogConsole,
    toggleTheme,
    openElkDashboard,
});

document.addEventListener("DOMContentLoaded", async () => {
    applyTheme(currentTheme);
    Toast.init();
    await refreshData();
    setInterval(() => {
        const dashboardVisible = !document.getElementById("dashboard").classList.contains("hidden");
        const logsVisible = !document.getElementById("logs").classList.contains("hidden");
        if (dashboardVisible) loadAgents(true);
        if (logsVisible && !isLogPaused) loadLogConsole();
    }, 5000);
    lucide.createIcons();
});
