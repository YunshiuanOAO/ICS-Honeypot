// API Endpoints
const API_BASE = "/api";

// State
let agentConfig = null;
let DEPLOYMENT_TEMPLATES = [];
let PACKAGE_LIBRARY = [];
let currentView = 'agent-settings'; // 'agent-settings', 'deployment-{id}', 'file-{deploymentId}-{fileIndex}'

async function init() {
    Toast.init();
    await loadDeploymentTemplates();
    await loadPackageLibrary();
    await loadConfig();
}

const Toast = {
    container: null,
    init() { this.container = document.getElementById("toast-container"); },
    show(message, type = "info", duration = 4000) {
        if (!this.container) return;
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span class="toast-message">${escapeHtml(message)}</span><button class="toast-close" onclick="Toast.dismiss(this.parentElement)">x</button>`;
        this.container.appendChild(toast);
        setTimeout(() => this.dismiss(toast), duration);
    },
    dismiss(toast) { if (toast?.parentElement) toast.remove(); },
    success(message) { this.show(message, "success"); },
    error(message) { this.show(message, "error", 6000); }
};

function escapeHtml(text) {
    if (text === null || text === undefined) return "";
    const div = document.createElement("div");
    div.textContent = String(text);
    return div.innerHTML;
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

async function loadDeploymentTemplates() {
    try {
        DEPLOYMENT_TEMPLATES = await fetch(`${API_BASE}/deployment_templates`).then(r => r.json());
        renderTemplateDropdown();
    } catch (e) {
        console.error("Failed to load templates", e);
        DEPLOYMENT_TEMPLATES = [];
    }
}

async function loadPackageLibrary() {
    try {
        PACKAGE_LIBRARY = await fetch(`${API_BASE}/package_library`).then(r => r.json());
    } catch (e) {
        console.error("Failed to load package library", e);
        PACKAGE_LIBRARY = [];
    }
    renderPackageLibrary();
}

async function loadConfig() {
    try {
        const config = await fetch(`${API_BASE}/config/${NODE_ID}`).then(r => {
            if (!r.ok) throw new Error("Failed to fetch");
            return r.json();
        });
        
        // Normalize
        agentConfig = {
            node_id: config.node_id || NODE_ID,
            name: config.name || "",
            server_url: config.server_url || window.location.origin,
            deployments: Array.isArray(config.deployments) ? config.deployments.map((d, i) => ({
                id: d.id || `deployment-${i + 1}`,
                name: d.name || `Deployment ${i + 1}`,
                template: d.template || d.type || "custom",
                enabled: d.enabled !== false,
                source_dir: d.source_dir || d.id || `deployment-${i + 1}`,
                log_paths: Array.isArray(d.log_paths) ? clone(d.log_paths) : [],
                proxy: d.proxy ? clone(d.proxy) : undefined,
                files: Array.isArray(d.files) ? clone(d.files) : [],
                library_package_id: d.library_package_id || "",
                library_package_name: d.library_package_name || ""
            })) : []
        };
        
        document.getElementById('header-node-id').textContent = agentConfig.node_id;
        renderSidebar();
        selectView('agent-settings');
    } catch (e) {
        Toast.error("Failed to load agent configuration.");
    }
}

function renderTemplateDropdown() {
    const list = document.getElementById('template-dropdown-list');
    const templates = DEPLOYMENT_TEMPLATES.length ? [...DEPLOYMENT_TEMPLATES] : [{ id: "custom", name: "Custom Honeypot" }];
    
    // Add Blank Template option
    templates.push({ id: "blank", name: "Blank Template" });
    
    list.innerHTML = templates.map(t => `
        <div class="tree-item" onclick="addDeployment('${t.id}')">
            <span>${escapeHtml(t.name)}</span>
        </div>
    `).join('');
}

function addDeployment(templateId) {
    document.getElementById('template-dropdown').classList.add('hidden');
    
    let template;
    if (templateId === 'blank') {
        template = {
            id: "blank", name: "Blank Template", source_dir: "blank-honeypot",
            files: []
        };
    } else {
        template = DEPLOYMENT_TEMPLATES.find(t => t.id === templateId) || {
            id: "custom", name: "Custom Honeypot", source_dir: "custom-honeypot",
            files: [
                { path: "Dockerfile", content: "FROM alpine:3.20\nCMD [\"sh\", \"-c\", \"sleep infinity\"]\n" },
                { path: "docker-compose.yml", content: "services:\n  honeypot:\n    build: .\n    restart: unless-stopped\n" }
            ]
        };
    }
    
    const newId = `deployment-${Date.now()}`;
    agentConfig.deployments.push({
        id: newId,
        name: template.name,
        template: template.id,
        enabled: true,
        source_dir: template.source_dir || `${template.id}-honeypot`,
        log_paths: clone(template.log_paths || []),
        proxy: clone(template.proxy || undefined),
        files: clone(template.files || [])
    });
    
    renderSidebar();
    selectView(`deployment-${newId}`);
}

async function addDeploymentFromLibrary(packageId) {
    try {
        const pkg = await fetch(`${API_BASE}/package_library/${packageId}`).then(r => {
            if (!r.ok) throw new Error('Failed to load package');
            return r.json();
        });

        const newId = `deployment-${Date.now()}`;
        agentConfig.deployments.push({
            id: newId,
            name: pkg.name || 'Imported Package',
            template: 'library',
            enabled: true,
            source_dir: pkg.source_dir || 'imported-package',
            log_paths: [],
            files: clone(pkg.files || []),
            library_package_id: pkg.id,
            library_package_name: pkg.name || ''
        });

        renderSidebar();
        selectView(`deployment-${newId}`);
        Toast.success(`Added package ${pkg.name || packageId}`);
    } catch (error) {
        console.error(error);
        Toast.error(error.message || 'Failed to add package from library');
    }
}

function removeDeployment(deploymentId, event) {
    if (event) event.stopPropagation();
    if (!confirm("Are you sure you want to delete this deployment?")) return;
    
    agentConfig.deployments = agentConfig.deployments.filter(d => d.id !== deploymentId);
    renderSidebar();
    selectView('agent-settings');
}

function addFile(deploymentId, event) {
    if (event) event.stopPropagation();
    const deployment = agentConfig.deployments.find(d => d.id === deploymentId);
    if (!deployment) return;
    
    const newIndex = deployment.files.length;
    deployment.files.push({ path: `new-file-${newIndex + 1}.txt`, content: "" });
    renderSidebar();
    selectView(`file-${deploymentId}-${newIndex}`);
}

function triggerZipUpload(deploymentId, event) {
    if (event) event.stopPropagation();
    document.getElementById(`zip-upload-${makeDomId(deploymentId)}`)?.click();
}

function makeDomId(value) {
    return String(value || "item").replace(/[^a-zA-Z0-9_-]/g, '-');
}

async function handleZipUpload(deploymentId, input, event) {
    if (event) event.stopPropagation();

    const file = input?.files?.[0];
    if (!file) return;

    const deployment = agentConfig.deployments.find(d => d.id === deploymentId);
    if (!deployment) return;

    const formData = new FormData();
    formData.append('archive', file);

    try {
        const response = await fetch(`${API_BASE}/import_package_zip`, {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        if (!response.ok || data.status !== 'ok') {
            throw new Error(data.detail || data.message || 'Failed to import zip archive');
        }

        deployment.files = Array.isArray(data.files) ? data.files : [];
        if (data.source_dir) {
            deployment.source_dir = data.source_dir;
        }
        deployment.library_package_id = data.package_id || deployment.library_package_id || '';
        deployment.library_package_name = data.package_name || file.name;

        await loadPackageLibrary();
        renderSidebar();
        if (deployment.files.length) {
            selectView(`file-${deploymentId}-0`);
        } else {
            selectView(`deployment-${deploymentId}`);
        }
        Toast.success(`Imported ${deployment.files.length} files from ${file.name}`);
    } catch (error) {
        console.error(error);
        Toast.error(error.message || 'Failed to import zip archive');
    } finally {
        input.value = '';
    }
}

function removeFile(deploymentId, fileIndex, event) {
    if (event) event.stopPropagation();
    if (!confirm("Are you sure you want to delete this file?")) return;
    
    const deployment = agentConfig.deployments.find(d => d.id === deploymentId);
    if (!deployment) return;
    
    deployment.files.splice(fileIndex, 1);
    renderSidebar();
    selectView(`deployment-${deploymentId}`);
}

function renderSidebar() {
    const tree = document.getElementById('deployments-tree');
    
    if (!agentConfig.deployments.length) {
        tree.innerHTML = `<div class="tree-item" style="color:var(--text-muted); cursor:default;">No deployments found</div>`;
        return;
    }
    
    tree.innerHTML = agentConfig.deployments.map(d => `
        <div>
            <div class="tree-item level-1" id="nav-deployment-${d.id}" onclick="selectView('deployment-${d.id}')">
                <i data-lucide="${d.enabled ? 'box' : 'package-x'}"></i>
                <span class="tree-folder">${escapeHtml(d.name)}</span>
                <div class="tree-actions">
                    <button onclick="triggerZipUpload('${d.id}', event)" title="Import Zip"><i data-lucide="upload"></i></button>
                    <button onclick="addFile('${d.id}', event)" title="Add File"><i data-lucide="file-plus"></i></button>
                    <button onclick="removeDeployment('${d.id}', event)" title="Delete Deployment"><i data-lucide="trash-2"></i></button>
                </div>
            </div>
            <input id="zip-upload-${makeDomId(d.id)}" type="file" accept=".zip,application/zip" class="hidden" onchange="handleZipUpload('${d.id}', this, event)">
            ${d.files.map((f, i) => `
                <div class="tree-item level-2" id="nav-file-${d.id}-${i}" onclick="selectView('file-${d.id}-${i}')">
                    <i data-lucide="file-code"></i>
                    <span>${escapeHtml(f.path || 'Unnamed File')}</span>
                    <div class="tree-actions">
                        <button onclick="removeFile('${d.id}', ${i}, event)" title="Delete File"><i data-lucide="x"></i></button>
                    </div>
                </div>
            `).join('')}
        </div>
    `).join('');
    
    lucide.createIcons();
    updateSidebarSelection();
}

function renderPackageLibrary() {
    const tree = document.getElementById('package-library-list');
    if (!tree) return;

    if (!PACKAGE_LIBRARY.length) {
        tree.innerHTML = `<div class="tree-item" style="color:var(--text-muted); cursor:default;">No uploaded packages yet</div>`;
        return;
    }

    tree.innerHTML = PACKAGE_LIBRARY.map(pkg => `
        <div class="tree-item level-1" onclick="previewLibraryPackage('${pkg.id}')">
            <i data-lucide="archive"></i>
            <span>${escapeHtml(pkg.name || pkg.id)}</span>
            <div class="tree-actions" style="opacity:1;">
                <button onclick="event.stopPropagation(); addDeploymentFromLibrary('${pkg.id}')" title="Use Package"><i data-lucide="plus"></i></button>
            </div>
        </div>
    `).join('');

    lucide.createIcons();
}

async function previewLibraryPackage(packageId) {
    try {
        const pkg = await fetch(`${API_BASE}/package_library/${packageId}`).then(r => {
            if (!r.ok) throw new Error('Failed to load package preview');
            return r.json();
        });

        const header = document.getElementById('editor-header');
        const content = document.getElementById('editor-content');
        header.innerHTML = `Library / ${escapeHtml(pkg.name || pkg.id)}`;
        content.innerHTML = `
            <div class="settings-form">
                <h3 style="margin-top:0">Saved Honeypot Package</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>Package Name</label>
                        <input type="text" value="${escapeHtml(pkg.name || '')}" disabled>
                    </div>
                    <div class="form-group">
                        <label>Source Folder</label>
                        <input type="text" value="${escapeHtml(pkg.source_dir || '')}" disabled>
                    </div>
                </div>
                <div class="form-group">
                    <label>Files</label>
                    <textarea rows="12" style="resize:vertical;" disabled>${escapeHtml((pkg.files || []).map(file => file.path).join('\n'))}</textarea>
                </div>
                <div class="form-group">
                    <button class="btn btn-primary" type="button" onclick="addDeploymentFromLibrary('${pkg.id}')">
                        <i data-lucide="plus"></i>
                        <span>Use This Package</span>
                    </button>
                </div>
            </div>
        `;
        lucide.createIcons();
    } catch (error) {
        console.error(error);
        Toast.error(error.message || 'Failed to preview package');
    }
}

function selectView(viewId) {
    currentView = viewId;
    updateSidebarSelection();
    renderMainEditor();
}

function updateSidebarSelection() {
    document.querySelectorAll('.tree-item').forEach(el => el.classList.remove('active'));
    
    if (currentView === 'agent-settings') {
        const el = document.getElementById('nav-agent-settings');
        if (el) el.classList.add('active');
    } else if (currentView.startsWith('deployment-')) {
        const id = currentView.replace('deployment-', '');
        const el = document.getElementById(`nav-deployment-${id}`);
        if (el) el.classList.add('active');
    } else if (currentView.startsWith('file-')) {
        const el = document.getElementById(`nav-${currentView}`);
        if (el) el.classList.add('active');
    }
}

function renderMainEditor() {
    const header = document.getElementById('editor-header');
    const content = document.getElementById('editor-content');
    
    if (currentView === 'agent-settings') {
        header.innerHTML = `System / Agent Settings`;
        content.innerHTML = `
            <div class="settings-form">
                <h3 style="margin-top:0">Agent Identity</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>Node ID</label>
                        <input type="text" value="${escapeHtml(agentConfig.node_id)}" onchange="agentConfig.node_id = this.value">
                    </div>
                    <div class="form-group">
                        <label>Agent Name</label>
                        <input type="text" value="${escapeHtml(agentConfig.name)}" onchange="agentConfig.name = this.value">
                    </div>
                </div>
                <div class="form-group">
                    <label>Server URL</label>
                    <input type="text" value="${escapeHtml(agentConfig.server_url)}" onchange="agentConfig.server_url = this.value">
                </div>
            </div>
        `;
    } else if (currentView.startsWith('deployment-')) {
        const id = currentView.replace('deployment-', '');
        const deployment = agentConfig.deployments.find(d => d.id === id);
        
        if (!deployment) { selectView('agent-settings'); return; }
        
        const proxyEnabled = deployment.proxy?.enabled ?? false;
        const proxyProtocol = deployment.proxy?.protocol ?? 'tcp';
        const proxyListenPort = deployment.proxy?.listen_port ?? '';
        const proxyBackendPort = deployment.proxy?.backend_port ?? '';
        
        header.innerHTML = `Deployments / ${escapeHtml(deployment.name)}`;
        content.innerHTML = `
            <div class="settings-form">
                <h3 style="margin-top:0">Deployment Configuration</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>Service Name (ID)</label>
                        <input type="text" value="${escapeHtml(deployment.name)}" onchange="updateDeploymentName('${id}', this.value)">
                    </div>
                    <div class="form-group">
                        <label>Base Template</label>
                        <input type="text" value="${escapeHtml(deployment.template)}" disabled class="bg-muted">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Source Folder</label>
                        <input type="text" value="${escapeHtml(deployment.source_dir)}" onchange="deployment.source_dir = this.value">
                    </div>
                    <div class="form-group">
                        <label>Status</label>
                        <select onchange="updateDeploymentEnabled('${id}', this.value === 'true')">
                            <option value="true" ${deployment.enabled ? 'selected' : ''}>Enabled (Active)</option>
                            <option value="false" ${!deployment.enabled ? 'selected' : ''}>Disabled (Stopped)</option>
                        </select>
                    </div>
                </div>
                
                <div style="margin: 2rem 0; padding: 1.5rem; background: rgba(6, 182, 212, 0.08); border-left: 3px solid var(--accent); border-radius: 8px;">
                    <h4 style="margin-top:0; margin-bottom:1rem; color: var(--accent-light);">Protocol & Traffic Proxy</h4>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>Enable Proxy for Traffic Capture</label>
                            <select onchange="updateDeploymentProxy('${id}', 'enabled', this.value === 'true')">
                                <option value="false" ${!proxyEnabled ? 'selected' : ''}>Disabled (No Proxy)</option>
                                <option value="true" ${proxyEnabled ? 'selected' : ''}>Enabled (Proxy Traffic)</option>
                            </select>
                            <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                                Enable to intercept and log protocol-level traffic details
                            </small>
                        </div>
                    </div>
                    
                    ${proxyEnabled ? `
                    <div class="form-row">
                        <div class="form-group">
                            <label>Protocol Type</label>
                            <select onchange="updateDeploymentProxy('${id}', 'protocol', this.value)">
                                <option value="tcp" ${proxyProtocol === 'tcp' ? 'selected' : ''}>TCP (Generic)</option>
                                <option value="modbus" ${proxyProtocol === 'modbus' ? 'selected' : ''}>Modbus TCP</option>
                                <option value="http" ${proxyProtocol === 'http' ? 'selected' : ''}>HTTP/HTTPS</option>
                                <option value="mqtt" ${proxyProtocol === 'mqtt' ? 'selected' : ''}>MQTT</option>
                                <option value="s7comm" ${proxyProtocol === 's7comm' ? 'selected' : ''}>S7 Communication</option>
                                <option value="dnp3" ${proxyProtocol === 'dnp3' ? 'selected' : ''}>DNP3</option>
                            </select>
                            <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                                Select the protocol to enable intelligent parsing and logging
                            </small>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label>Proxy Listen Port</label>
                            <input type="number" min="1" max="65535" value="${escapeHtml(proxyListenPort)}" 
                                   onchange="updateDeploymentProxy('${id}', 'listen_port', parseInt(this.value) || 0)"
                                   placeholder="e.g., 5020">
                            <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                                Port on this agent to listen for incoming traffic
                            </small>
                        </div>
                        <div class="form-group">
                            <label>Backend Container Port</label>
                            <input type="number" min="1" max="65535" value="${escapeHtml(proxyBackendPort)}" 
                                   onchange="updateDeploymentProxy('${id}', 'backend_port', parseInt(this.value) || 0)"
                                   placeholder="e.g., 15020">
                            <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                                Port where the honeypot container listens
                            </small>
                        </div>
                    </div>
                    ` : ''}
                </div>
                
                <div class="form-group">
                    <label>Linked Library Package</label>
                    <input type="text" value="${escapeHtml(deployment.library_package_name || deployment.library_package_id || 'Not linked')}" disabled>
                </div>
                <div class="form-group">
                    <label>Observed Log Paths (One per line)</label>
                    <textarea rows="4" style="resize:vertical;" onchange="updateDeploymentLogPaths('${id}', this.value)">${escapeHtml(deployment.log_paths.join('\n'))}</textarea>
                </div>
                <div class="form-group zip-import-container">
                    <label>Import Source Zip</label>
                    <div style="display:flex; gap:0.75rem; align-items:center; flex-wrap:wrap; background: var(--bg-panel); padding: 1rem; border-radius: var(--radius-md); border: 1px dashed var(--accent);">
                        <button class="btn btn-secondary" type="button" onclick="triggerZipUpload('${id}', event)">
                            <i data-lucide="upload"></i>
                            <span style="color: var(--accent-light); font-weight: bold;">Upload Zip Archive</span>
                        </button>
                        <span class="text-muted">The server extracts the archive and replaces the current file list.</span>
                    </div>
                </div>
            </div>
        `;
    } else if (currentView.startsWith('file-')) {
        // file-{deploymentId}-{fileIndex}
        const parts = currentView.split('-');
        const deploymentId = parts.slice(1, -1).join('-');
        const fileIndex = parseInt(parts[parts.length - 1], 10);
        
        const deployment = agentConfig.deployments.find(d => d.id === deploymentId);
        if (!deployment || !deployment.files[fileIndex]) { selectView('agent-settings'); return; }
        
        const file = deployment.files[fileIndex];
        
        header.innerHTML = `
            <span style="opacity:0.7">Deployments / ${escapeHtml(deployment.name)} / </span> 
            <input type="text" value="${escapeHtml(file.path)}" style="background:transparent; border:none; color:inherit; font-family:inherit; font-size:inherit; outline:none; margin-left:8px; border-bottom:1px dashed var(--border); width: 300px;" 
            onchange="updateFilePath('${deploymentId}', ${fileIndex}, this.value)" placeholder="Filename (e.g. Dockerfile)">
        `;
        
        content.innerHTML = `
            <textarea class="code-textarea" onchange="updateFileContent('${deploymentId}', ${fileIndex}, this.value)">${escapeHtml(file.content)}</textarea>
        `;
    }
}

// Update helpers
function updateDeploymentName(id, name) {
    const d = agentConfig.deployments.find(x => x.id === id);
    if(d) { d.name = name; renderSidebar(); }
}
function updateDeploymentEnabled(id, enabled) {
    const d = agentConfig.deployments.find(x => x.id === id);
    if(d) { d.enabled = enabled; renderSidebar(); }
}
function updateDeploymentLogPaths(id, val) {
    const d = agentConfig.deployments.find(x => x.id === id);
    if(d) d.log_paths = val.split('\n').map(l => l.trim()).filter(Boolean);
}
function updateDeploymentProxy(id, field, value) {
    const d = agentConfig.deployments.find(x => x.id === id);
    if(d) {
        if (!d.proxy) d.proxy = {};
        d.proxy[field] = value;
        renderMainEditor(); // Re-render to show/hide conditional fields
    }
}
function updateFilePath(depId, idx, path) {
    const d = agentConfig.deployments.find(x => x.id === depId);
    if(d && d.files[idx]) { d.files[idx].path = path; renderSidebar(); }
}
function updateFileContent(depId, idx, content) {
    const d = agentConfig.deployments.find(x => x.id === depId);
    if(d && d.files[idx]) d.files[idx].content = content;
}

// Validate configuration before saving
function validateConfig() {
    if (!agentConfig) return true; // Empty config is ok
    
    const errors = [];
    const deploymentPorts = {};
    
    // Check each deployment
    for (const dep of agentConfig.deployments) {
        if (!dep.enabled) continue;
        
        const proxy = dep.proxy;
        if (!proxy || !proxy.enabled) continue;
        
        // Check if listen_port and backend_port are configured
        const listenPort = proxy.listen_port;
        const backendPort = proxy.backend_port;
        
        if (!listenPort || !backendPort) {
            errors.push(`Deployment "${dep.name}": Proxy enabled but ports not configured`);
            continue;
        }
        
        // Check for port conflicts
        if (deploymentPorts[listenPort]) {
            errors.push(`Port conflict: Listen port ${listenPort} is used by both "${dep.name}" and "${deploymentPorts[listenPort]}"`);
        }
        
        if (deploymentPorts[backendPort]) {
            errors.push(`Port conflict: Backend port ${backendPort} is used by both "${dep.name}" and "${deploymentPorts[backendPort]}"`);
        }
        
        // Validate port ranges
        if (listenPort < 1 || listenPort > 65535) {
            errors.push(`Deployment "${dep.name}": Invalid listen port ${listenPort} (must be 1-65535)`);
        }
        
        if (backendPort < 1 || backendPort > 65535) {
            errors.push(`Deployment "${dep.name}": Invalid backend port ${backendPort} (must be 1-65535)`);
        }
        
        // Warn if using privileged ports without explanation
        if (listenPort < 1024) {
            console.warn(`Deployment "${dep.name}": Using privileged port ${listenPort} (requires root/sudo)`);
        }
        
        deploymentPorts[listenPort] = dep.name;
        deploymentPorts[backendPort] = dep.name;
    }
    
    if (errors.length > 0) {
        Toast.error(errors.join("\n"));
        return false;
    }
    
    return true;
}

// Save back to server
async function saveConfig() {
    if (!agentConfig) return;
    
    // Validate configuration first
    if (!validateConfig()) {
        return;
    }
    
    // Original Node ID used for the endpoint to know who we are updating
    const originalNodeId = NODE_ID; 
    
    try {
        const response = await fetch(`${API_BASE}/update_agent_config`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                node_id: originalNodeId,
                new_node_id: agentConfig.node_id,
                name: agentConfig.name,
                config: agentConfig
            })
        });
        
        const data = await response.json();
        if (data.status !== "updated") {
            Toast.error(data.message || "Failed to save configuration");
            return;
        }
        
        Toast.success("Configuration saved successfully!");
        
        // If node ID changed, update the URL without refreshing
        if (agentConfig.node_id !== originalNodeId) {
            window.history.replaceState({}, '', `/config/${agentConfig.node_id}`);
            document.getElementById('header-node-id').textContent = agentConfig.node_id;
            // Update global NODE_ID variable so subsequent saves work
            window.sessionStorage.setItem('node_id_redirected', 'true');
            setTimeout(() => {
                window.location.reload(); 
            }, 1000);
        }
        
    } catch (e) {
        console.error(e);
        Toast.error("Failed to save configuration.");
    }
}

// Init when DOM loads
document.addEventListener('DOMContentLoaded', init);
