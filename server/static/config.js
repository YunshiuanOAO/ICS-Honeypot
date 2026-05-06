// API Endpoints
const API_BASE = "/api";

// State
let agentConfig = null;
let PACKAGE_LIBRARY = [];
let currentView = 'agent-settings'; // 'agent-settings', 'whitelist', 'deployment-{id}', 'file-{deploymentId}-{fileIndex}'
let _whitelistData = null; // Cached whitelist data for this agent

async function init() {
    Toast.init();
    await loadPackageLibrary();
    await Promise.all([loadConfig(), loadWhitelist()]);
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

// Normalize a deployment's proxy field(s) into a list. Accepts the new
// `proxies` array, the legacy `proxy` dict, or neither.
function normalizeProxies(deployment) {
    let raw = deployment && deployment.proxies;
    if (!Array.isArray(raw) || !raw.length) {
        if (deployment && deployment.proxy) {
            raw = [deployment.proxy];
        } else {
            raw = [];
        }
    }
    const seen = new Set();
    return raw.map((p, i) => {
        const proxy = clone(p || {});
        let name = (proxy.name || proxy.protocol || `proxy-${i + 1}`)
            .toString()
            .replace(/[^a-zA-Z0-9_-]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .toLowerCase() || `proxy-${i + 1}`;
        let candidate = name;
        let suffix = 2;
        while (seen.has(candidate)) {
            candidate = `${name}-${suffix++}`;
        }
        seen.add(candidate);
        proxy.name = candidate;
        return proxy;
    });
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
                proxies: normalizeProxies(d),
                files: Array.isArray(d.files) ? clone(d.files) : [],
                library_package_id: d.library_package_id || "",
                library_package_name: d.library_package_name || "",
                files_updated_at: d.files_updated_at || 0
            })) : []
        };
        
        document.getElementById('header-node-id').textContent = agentConfig.node_id;
        renderSidebar();
        selectView('agent-settings');
    } catch (e) {
        Toast.error("Failed to load agent configuration.");
    }
}

function addDeployment() {
    const newId = `deployment-${Date.now()}`;
    agentConfig.deployments.push({
        id: newId,
        name: "New Deployment",
        template: "custom",
        enabled: true,
        source_dir: newId,
        log_paths: [],
        files: []
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
        if (!response.ok) {
            let detail = 'Failed to import zip archive';
            try { detail = (await response.json()).detail || detail; } catch (_) {}
            throw new Error(detail);
        }
        const data = await response.json();
        if (data.status !== 'ok') {
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
                <button onclick="deleteLibraryPackage('${pkg.id}', event)" title="Delete Package"><i data-lucide="trash-2"></i></button>
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

async function deleteLibraryPackage(packageId, event) {
    if (event) event.stopPropagation();
    if (!confirm("Are you sure you want to delete this package from the library?")) return;

    try {
        const response = await fetch(`${API_BASE}/package_library/${packageId}`, {
            method: 'DELETE'
        });
        if (!response.ok) {
            let detail = 'Failed to delete package';
            try { detail = (await response.json()).detail || detail; } catch (_) {}
            throw new Error(detail);
        }
        Toast.success("Package deleted from library");
        await loadPackageLibrary();
    } catch (error) {
        console.error(error);
        Toast.error(error.message || 'Failed to delete package');
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
    } else if (currentView === 'whitelist') {
        const el = document.getElementById('nav-whitelist');
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
    } else if (currentView === 'whitelist') {
        header.innerHTML = `System / Whitelist`;
        renderWhitelistView(content);
        return;
    } else if (currentView.startsWith('deployment-')) {
        const id = currentView.replace('deployment-', '');
        const deployment = agentConfig.deployments.find(d => d.id === id);
        
        if (!deployment) { selectView('agent-settings'); return; }
        
        if (!Array.isArray(deployment.proxies)) deployment.proxies = [];
        const proxiesHtml = deployment.proxies.map((p, idx) => renderProxyEditor(id, p, idx)).join('');

        header.innerHTML = `Deployments / ${escapeHtml(deployment.name)}`;
        content.innerHTML = `
            <div class="settings-form">
                <h3 style="margin-top:0">Deployment Configuration</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>Service Name (ID)</label>
                        <input type="text" value="${escapeHtml(deployment.name)}" onchange="updateDeploymentName('${id}', this.value)">
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
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                        <h4 style="margin:0; color: var(--accent-light);">Protocol & Traffic Proxies</h4>
                        <button class="btn btn-secondary" type="button" onclick="addProxy('${id}')">
                            <i data-lucide="plus"></i>
                            <span>Add Proxy</span>
                        </button>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 13px; margin: 0 0 1rem;">
                        Define one proxy per port the service exposes. Each proxy listens on the agent and forwards to the container's backend port.
                    </p>
                    ${proxiesHtml || `<div style="color: var(--text-muted); padding: 1rem; text-align:center;">No proxies configured. Click "Add Proxy" to capture traffic for a port.</div>`}
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

    // Replace any <i data-lucide="..."> placeholders the editor just rendered.
    if (window.lucide && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
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
function renderProxyEditor(deploymentId, proxy, index) {
    const enabled = proxy.enabled !== false;
    const protocol = proxy.protocol || 'tcp';
    const listenPort = proxy.listen_port ?? '';
    const backendPort = proxy.backend_port ?? '';
    const containerPort = proxy.container_port ?? '';
    const name = proxy.name || `proxy-${index + 1}`;

    return `
        <div style="border:1px solid var(--border); border-radius:8px; padding:1rem 1.25rem; margin-bottom:1rem; background: rgba(0,0,0,0.15);">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:0.75rem; margin-bottom:0.75rem;">
                <strong style="color: var(--accent-light);">Proxy #${index + 1} <span style="opacity:0.6; font-weight:normal;">(${escapeHtml(name)})</span></strong>
                <button class="btn btn-danger" type="button" onclick="removeProxy('${deploymentId}', ${index})" title="Remove proxy">
                    <i data-lucide="trash-2"></i>
                </button>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Name (unique)</label>
                    <input type="text" value="${escapeHtml(name)}"
                           onchange="updateProxy('${deploymentId}', ${index}, 'name', this.value)"
                           placeholder="e.g. modbus or http">
                </div>
                <div class="form-group">
                    <label>Enabled</label>
                    <select onchange="updateProxy('${deploymentId}', ${index}, 'enabled', this.value === 'true')">
                        <option value="false" ${!enabled ? 'selected' : ''}>Disabled</option>
                        <option value="true" ${enabled ? 'selected' : ''}>Enabled</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Protocol</label>
                    <select onchange="updateProxy('${deploymentId}', ${index}, 'protocol', this.value)">
                        <option value="tcp" ${protocol === 'tcp' ? 'selected' : ''}>TCP (Generic)</option>
                        <option value="modbus" ${protocol === 'modbus' ? 'selected' : ''}>Modbus TCP</option>
                        <option value="http" ${protocol === 'http' ? 'selected' : ''}>HTTP/HTTPS</option>
                        <option value="mqtt" ${protocol === 'mqtt' ? 'selected' : ''}>MQTT</option>
                        <option value="s7comm" ${protocol === 's7comm' ? 'selected' : ''}>S7 Communication</option>
                        <option value="dnp3" ${protocol === 'dnp3' ? 'selected' : ''}>DNP3</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Listen Port (agent)</label>
                    <input type="number" min="1" max="65535" value="${escapeHtml(listenPort)}"
                           onchange="updateProxy('${deploymentId}', ${index}, 'listen_port', parseInt(this.value) || 0)"
                           placeholder="e.g. 502">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Backend Port (host->container)</label>
                    <input type="number" min="1" max="65535" value="${escapeHtml(backendPort)}"
                           onchange="updateProxy('${deploymentId}', ${index}, 'backend_port', parseInt(this.value) || 0)"
                           placeholder="e.g. 15020">
                    <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                        Available in compose as <code>$BACKEND_PORT_${escapeHtml((name||'').toUpperCase().replace(/[^A-Z0-9]/g,'_'))}</code>.
                    </small>
                </div>
                <div class="form-group">
                    <label>Container Port (optional)</label>
                    <input type="number" min="1" max="65535" value="${escapeHtml(containerPort)}"
                           onchange="updateProxy('${deploymentId}', ${index}, 'container_port', parseInt(this.value) || 0)"
                           placeholder="defaults to listen port">
                    <small style="color: var(--text-secondary); display: block; margin-top: 0.5rem;">
                        Used for Dockerfile-mode port mapping. Defaults to listen port.
                    </small>
                </div>
            </div>
        </div>
    `;
}

function addProxy(deploymentId) {
    const d = agentConfig.deployments.find(x => x.id === deploymentId);
    if (!d) return;
    if (!Array.isArray(d.proxies)) d.proxies = [];
    const idx = d.proxies.length + 1;
    d.proxies.push({
        name: `proxy-${idx}`,
        enabled: true,
        protocol: 'tcp',
        listen_port: 0,
        backend_port: 0
    });
    renderMainEditor();
}

function removeProxy(deploymentId, index) {
    const d = agentConfig.deployments.find(x => x.id === deploymentId);
    if (!d || !Array.isArray(d.proxies) || index < 0 || index >= d.proxies.length) return;
    if (!confirm("Remove this proxy?")) return;
    d.proxies.splice(index, 1);
    renderMainEditor();
}

function updateProxy(deploymentId, index, field, value) {
    const d = agentConfig.deployments.find(x => x.id === deploymentId);
    if (!d || !Array.isArray(d.proxies) || !d.proxies[index]) return;
    d.proxies[index][field] = value;
    // Re-render only on changes that affect the visible labels (name)
    if (field === 'name') renderMainEditor();
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
    if (!agentConfig) return true;

    const errors = [];
    const usedPorts = {};

    for (const dep of agentConfig.deployments) {
        if (!dep.enabled) continue;
        const proxies = Array.isArray(dep.proxies) ? dep.proxies : [];
        const namesSeen = new Set();

        for (let idx = 0; idx < proxies.length; idx++) {
            const proxy = proxies[idx];
            if (!proxy || !proxy.enabled) continue;

            const proxyName = proxy.name || `proxy-${idx + 1}`;
            const label = `"${dep.name}" / proxy "${proxyName}"`;

            if (namesSeen.has(proxyName)) {
                errors.push(`${label}: duplicate proxy name within deployment`);
            }
            namesSeen.add(proxyName);

            const listenPort = proxy.listen_port;
            const backendPort = proxy.backend_port;

            if (!listenPort || !backendPort) {
                errors.push(`${label}: Proxy enabled but ports not configured`);
                continue;
            }
            if (listenPort < 1 || listenPort > 65535) {
                errors.push(`${label}: Invalid listen port ${listenPort}`);
            }
            if (backendPort < 1 || backendPort > 65535) {
                errors.push(`${label}: Invalid backend port ${backendPort}`);
            }
            if (usedPorts[listenPort]) {
                errors.push(`Port conflict: Listen port ${listenPort} used by ${label} and ${usedPorts[listenPort]}`);
            }
            if (usedPorts[backendPort]) {
                errors.push(`Port conflict: Backend port ${backendPort} used by ${label} and ${usedPorts[backendPort]}`);
            }
            usedPorts[listenPort] = label;
            usedPorts[backendPort] = label;
        }
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
    
    // Mark each deployment with a timestamp so the client knows to re-sync files
    const now = Date.now();
    for (const d of agentConfig.deployments) {
        d.files_updated_at = now;
    }
    
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

        if (!response.ok) {
            let detail = "Failed to save configuration";
            try { detail = (await response.json()).detail || detail; } catch (_) {}
            Toast.error(detail);
            return;
        }
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

// ============ Whitelist (per-agent) ============

async function loadWhitelist() {
    try {
        const resp = await fetch(`${API_BASE}/whitelist?node_id=${encodeURIComponent(NODE_ID)}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        _whitelistData = await resp.json();
    } catch (_e) {
        _whitelistData = { enabled: true, ips: [], cidrs: [], description: "" };
    }
}

function renderWhitelistView(container) {
    const data = _whitelistData || { enabled: true, ips: [], cidrs: [] };
    container.innerHTML = `
        <div class="settings-form">
            <h3 style="margin-top:0">
                <span style="display:flex; align-items:center; gap:8px;">
                    <i data-lucide="shield-check" style="width:20px; height:20px;"></i>
                    Whitelist Configuration
                </span>
            </h3>
            <p style="opacity: 0.7; font-size: 13px; margin-bottom: 1.5rem;">
                One entry per line. Traffic from these sources is still forwarded to honeypots,
                but recorded in a separate log and excluded from the attack map.
                Changes are pushed to this agent on its next config fetch (within ~5s).
            </p>

            <div class="form-row">
                <div class="form-group">
                    <label>Whitelist Status</label>
                    <div style="display:flex; align-items:center; gap:10px; margin-top:4px;">
                        <label class="switch">
                            <input type="checkbox" id="wl-enabled" ${data.enabled ? 'checked' : ''}
                                onchange="document.getElementById('wl-status-label').textContent = this.checked ? 'Enabled' : 'Disabled'">
                            <span class="slider"></span>
                        </label>
                        <span id="wl-status-label" style="font-size:14px;">${data.enabled ? 'Enabled' : 'Disabled'}</span>
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>IPs (one per line)</label>
                    <textarea id="wl-ips" rows="8" style="resize:vertical; font-family:'JetBrains Mono',monospace; font-size:13px;"
                        placeholder="1.2.3.4&#10;203.0.113.7">${escapeHtml((data.ips || []).join('\n'))}</textarea>
                </div>
                <div class="form-group">
                    <label>CIDR ranges (one per line)</label>
                    <textarea id="wl-cidrs" rows="8" style="resize:vertical; font-family:'JetBrains Mono',monospace; font-size:13px;"
                        placeholder="10.0.0.0/8&#10;192.168.1.0/24">${escapeHtml((data.cidrs || []).join('\n'))}</textarea>
                </div>
            </div>

            <div style="display:flex; gap:8px; align-items:center; margin-bottom:2rem;">
                <button class="btn btn-primary" type="button" onclick="saveWhitelist()">
                    <i data-lucide="save"></i>
                    <span>Save Whitelist</span>
                </button>
                <span id="wl-save-status" style="font-size: 13px; opacity: 0.7;"></span>
            </div>

            <div style="margin-top:1rem; padding-top:1.5rem; border-top:1px solid var(--border);">
                <h4 style="margin-top:0; display:flex; align-items:center; gap:8px;">
                    <i data-lucide="list" style="width:16px; height:16px;"></i>
                    Recent Whitelist Logs
                    <span id="wl-log-count" style="font-size:12px; opacity:0.6; font-weight:normal;"></span>
                </h4>
                <div id="wl-logs-container">
                    <div style="text-align:center; opacity:0.5; padding:2rem;">Loading...</div>
                </div>
            </div>
        </div>
    `;
    lucide.createIcons();
    loadWhitelistLogs();
}

async function saveWhitelist() {
    const enabledEl = document.getElementById("wl-enabled");
    const ipsEl = document.getElementById("wl-ips");
    const cidrsEl = document.getElementById("wl-cidrs");
    const statusEl = document.getElementById("wl-save-status");

    const payload = {
        node_id: NODE_ID,
        enabled: !!(enabledEl && enabledEl.checked),
        ips: (ipsEl ? ipsEl.value : "").split("\n").map(s => s.trim()).filter(Boolean),
        cidrs: (cidrsEl ? cidrsEl.value : "").split("\n").map(s => s.trim()).filter(Boolean),
    };

    if (statusEl) statusEl.textContent = "Saving...";

    try {
        const resp = await fetch(`${API_BASE}/whitelist`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            let detail = `HTTP ${resp.status}`;
            try {
                const err = await resp.json();
                if (err && err.detail) detail = err.detail;
            } catch (_e2) { /* ignore */ }
            throw new Error(detail);
        }
        const data = await resp.json();
        _whitelistData = data.whitelist || payload;
        if (statusEl) statusEl.textContent = "Saved. Agent will pick up changes within ~5s.";
        Toast.success("Whitelist saved");
    } catch (e) {
        if (statusEl) statusEl.textContent = "";
        Toast.error(`Failed to save whitelist: ${e.message || e}`);
    }
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "--:--:--";
    return date.toLocaleTimeString("en-US", {
        hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
    });
}

async function loadWhitelistLogs() {
    const container = document.getElementById("wl-logs-container");
    const countEl = document.getElementById("wl-log-count");
    if (!container) return;

    try {
        const resp = await fetch(`${API_BASE}/whitelist_logs?limit=100&node_id=${encodeURIComponent(NODE_ID)}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const logs = await resp.json();

        if (countEl) countEl.textContent = `(${logs.length})`;

        if (!logs.length) {
            container.innerHTML = `<div style="text-align:center; opacity:0.5; padding:2rem;">No whitelist logs yet</div>`;
            return;
        }

        let html = `
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="text-align: left; opacity: 0.7;">
                            <th style="padding: 8px;">Time</th>
                            <th style="padding: 8px;">Protocol</th>
                            <th style="padding: 8px;">Source IP</th>
                            <th style="padding: 8px;">Summary</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        logs.forEach(log => {
            const meta = typeof log.metadata === 'string' ? (() => { try { return JSON.parse(log.metadata); } catch(_) { return {}; } })() : (log.metadata || {});
            const summary = meta["log.message"] || log.protocol || "Interaction";
            html += `
                <tr style="border-top: 1px solid var(--border);">
                    <td style="padding: 8px; font-family: 'JetBrains Mono', monospace;">${formatTime(log.timestamp)}</td>
                    <td style="padding: 8px;">${escapeHtml(log.protocol || "")}</td>
                    <td style="padding: 8px; font-family: 'JetBrains Mono', monospace;">${escapeHtml(log.attacker_ip || "")}</td>
                    <td style="padding: 8px;">${escapeHtml(summary)}</td>
                </tr>
            `;
        });
        html += `</tbody></table></div>`;
        container.innerHTML = html;
    } catch (_e) {
        container.innerHTML = `<div style="text-align:center; color:var(--danger); padding:2rem;">Failed to load whitelist logs</div>`;
    }
}

// Init when DOM loads
document.addEventListener('DOMContentLoaded', init);
